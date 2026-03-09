#!/usr/bin/env bash
# ==============================================================================
# manage-ssh.sh  —  Install OpenSSH, manage the SSH service, authorized keys,
#                   and interactive SSH configuration editing
# ==============================================================================
#
# Usage:
#   sudo ./manage-ssh.sh [--dry-run] [--help]
#
# Menu actions:
#   Install openssh-server        Start / enable the SSH service
#   Add / remove authorized keys  Edit SSH configuration
#
# Edit SSH configuration:
#   Each directive is explained inline. Enter 'h' at the value prompt for full
#   help. Values outside the recommended range trigger a warning and a
#   confirmation prompt (default: no) before applying.
#   Changes are written to /etc/ssh/sshd_config.d/99-hardened.conf, validated
#   with sshd -t, and applied via a service reload. The previous drop-in is
#   restored automatically on validation failure.
#
# Requirements: Ubuntu 22.04+ or Debian 11+. Run as root or via sudo.
#               --dry-run does not require root.
# ==============================================================================
set -euo pipefail

# ── Flags & env vars ──────────────────────────────────────────────────────────
DRY_RUN="${DRY_RUN:-false}"

for _arg in "$@"; do
    case "$_arg" in
        --dry-run)  DRY_RUN=true ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# =====/p' "$0" | sed 's/^# \{0,3\}//'
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$_arg" >&2
            printf "Run '%s --help' for usage.\n" "$0" >&2
            exit 1
            ;;
    esac
done
unset _arg

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED=$'\e[0;31m';  GREEN=$'\e[0;32m';  YELLOW=$'\e[1;33m'
    BLUE=$'\e[0;34m'; CYAN=$'\e[0;36m';   BOLD=$'\e[1m'
    DIM=$'\e[2m';     NC=$'\e[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Output helpers ────────────────────────────────────────────────────────────
info()    { printf "${CYAN}  >>>  ${NC}%s\n"   "$1"; }
ok()      { printf "${GREEN}  [+]  ${NC}%s\n"  "$1"; }
warn()    { printf "${YELLOW}  [!]  ${NC}%s\n" "$1"; }
err()     { printf "${RED}  [x]  ${NC}%s\n"    "$1" >&2; }
plain()   { printf "        %s\n"              "$1"; }
die()     { err "$1"; exit 1; }
section() { printf "\n${BOLD}  ── %s${NC}\n"   "$1"; }

# ── run() ─────────────────────────────────────────────────────────────────────
run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" "$*"
    else
        "$@"
    fi
}

# ── Prompt helpers ────────────────────────────────────────────────────────────
ask() {
    local question="$1" default="${2:-y}" prompt answer
    [[ "$default" == "y" ]] && prompt="[Y/n]" || prompt="[y/N]"
    read -rp $'\n'"${YELLOW}  ?  ${NC}${question} ${prompt}: " answer || true
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

ask_val() {
    local prompt="$1" default="${2:-}" val
    if [[ -n "$default" ]]; then
        read -rp "    ${YELLOW}>  ${NC}${prompt} [${default}]: " val || true
    else
        read -rp "    ${YELLOW}>  ${NC}${prompt}: " val || true
    fi
    printf '%s' "${val:-$default}"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0

preflight_checks() {
    [[ $EUID -eq 0 || "$DRY_RUN" == "true" ]] \
        || die "Root privileges required. Run as: sudo $0"

    [[ -f /etc/os-release ]] \
        || die "/etc/os-release not found — cannot detect OS."

    OS_ID=$(        grep "^ID="               /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_CODENAME=$(  grep "^VERSION_CODENAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_VERSION_ID=$(grep "^VERSION_ID="       /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_MAJOR="${OS_VERSION_ID%%.*}"

    [[ "$OS_MAJOR" =~ ^[0-9]+$ ]] \
        || die "Could not parse major version from VERSION_ID='${OS_VERSION_ID}'."

    case "$OS_ID" in
        ubuntu) (( OS_MAJOR >= 22 )) || die "Ubuntu ${OS_VERSION_ID} unsupported. Requires 22.04+." ;;
        debian) (( OS_MAJOR >= 11 )) || die "Debian ${OS_VERSION_ID} unsupported. Requires 11+." ;;
        *)      die "Unsupported OS '${OS_ID}'. Requires Ubuntu or Debian." ;;
    esac

    # Detect URL-fetch capability (curl preferred, wget as fallback; neither is fatal)
    CURL_AVAILABLE=false
    WGET_AVAILABLE=false
    command -v curl &>/dev/null && CURL_AVAILABLE=true || true
    command -v wget &>/dev/null && WGET_AVAILABLE=true || true
    URL_FETCH_AVAILABLE=false
    [[ "$CURL_AVAILABLE" == "true" || "$WGET_AVAILABLE" == "true" ]] && URL_FETCH_AVAILABLE=true || true
}

# ── Config paths ──────────────────────────────────────────────────────────────
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROP_IN="/etc/ssh/sshd_config.d/99-hardened.conf"

# ── URL fetch capability (set by preflight_checks) ────────────────────────────
CURL_AVAILABLE=false
WGET_AVAILABLE=false
URL_FETCH_AVAILABLE=false

# ── SSH config state (effective values from drop-in / sshd_config) ─────────────
# Populated by load_config_state(); OpenSSH compile-time defaults used as fallbacks.
CONF_PORT="22"
CONF_PUBKEY_AUTH="yes"
CONF_PASSWORD_AUTH="yes"
CONF_KBD_AUTH="yes"
CONF_PERMIT_ROOT_LOGIN="prohibit-password"
CONF_EMPTY_PASSWORDS="no"
CONF_MAX_AUTH_TRIES="6"
CONF_LOGIN_GRACE_TIME="120"
CONF_ALIVE_INTERVAL="0"
CONF_ALIVE_COUNT="3"
CONF_X11_FORWARDING="no"
CONF_TCP_FORWARDING="yes"
CONF_SET_ALGORITHMS=false

# ── sshd_eff_val <key> ────────────────────────────────────────────────────────
# Returns the effective value of an sshd directive.
# Drop-in takes precedence over the main config.
sshd_eff_val() {
    local key="$1" val=""
    val=$(grep -ih "^${key}[[:space:]]" "$SSHD_DROP_IN" 2>/dev/null \
        | tail -1 | awk '{print $2}' || true)
    if [[ -z "$val" ]]; then
        val=$(grep -ih "^${key}[[:space:]]" "$SSHD_CONFIG" 2>/dev/null \
            | tail -1 | awk '{print $2}' || true)
    fi
    printf '%s' "$val"
}

# ── load_config_state ─────────────────────────────────────────────────────────
# Reads effective sshd directives into CONF_* globals.
load_config_state() {
    local v
    v=$(sshd_eff_val "Port");                         CONF_PORT="${v:-22}"
    v=$(sshd_eff_val "PubkeyAuthentication");         CONF_PUBKEY_AUTH="${v:-yes}"
    v=$(sshd_eff_val "PasswordAuthentication");       CONF_PASSWORD_AUTH="${v:-yes}"
    v=$(sshd_eff_val "KbdInteractiveAuthentication"); CONF_KBD_AUTH="${v:-yes}"
    v=$(sshd_eff_val "PermitRootLogin");              CONF_PERMIT_ROOT_LOGIN="${v:-prohibit-password}"
    v=$(sshd_eff_val "PermitEmptyPasswords");         CONF_EMPTY_PASSWORDS="${v:-no}"
    v=$(sshd_eff_val "MaxAuthTries");                 CONF_MAX_AUTH_TRIES="${v:-6}"
    v=$(sshd_eff_val "LoginGraceTime");               CONF_LOGIN_GRACE_TIME="${v:-120}"
    v=$(sshd_eff_val "ClientAliveInterval");          CONF_ALIVE_INTERVAL="${v:-0}"
    v=$(sshd_eff_val "ClientAliveCountMax");          CONF_ALIVE_COUNT="${v:-3}"
    v=$(sshd_eff_val "X11Forwarding");                CONF_X11_FORWARDING="${v:-no}"
    v=$(sshd_eff_val "AllowTcpForwarding");           CONF_TCP_FORWARDING="${v:-yes}"
    grep -q "^HostKeyAlgorithms" "$SSHD_DROP_IN" 2>/dev/null \
        && CONF_SET_ALGORITHMS=true || CONF_SET_ALGORITHMS=false
}

# ── State ─────────────────────────────────────────────────────────────────────
SSH_PKG_INSTALLED=false
SSH_SVC_ACTIVE=false
SSH_SVC_ENABLED=false
SSH_PORT="22"

is_pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

is_svc_active() {
    systemctl is-active --quiet ssh 2>/dev/null \
        || systemctl is-active --quiet sshd 2>/dev/null
}

is_svc_enabled() {
    systemctl is-enabled --quiet ssh 2>/dev/null \
        || systemctl is-enabled --quiet sshd 2>/dev/null
}

get_port() {
    local port=""
    port=$(grep -ih "^Port[[:space:]]" "$SSHD_DROP_IN" 2>/dev/null \
        | tail -1 | awk '{print $2}' || true)
    if [[ -z "$port" ]]; then
        port=$(grep -i "^Port[[:space:]]" "$SSHD_CONFIG" 2>/dev/null \
            | tail -1 | awk '{print $2}' || true)
    fi
    printf '%s' "${port:-22}"
}

load_state() {
    SSH_PKG_INSTALLED=false
    is_pkg_installed openssh-server && SSH_PKG_INSTALLED=true || true

    SSH_SVC_ACTIVE=false
    is_svc_active && SSH_SVC_ACTIVE=true || true

    SSH_SVC_ENABLED=false
    is_svc_enabled && SSH_SVC_ENABLED=true || true

    SSH_PORT=$(get_port)

    [[ "$SSH_PKG_INSTALLED" == "true" ]] && load_config_state || true
}

count_keys() {
    local f="$1"
    [[ -f "$f" ]] || { printf '0'; return; }
    grep -c "^ssh-\|^ecdsa-\|^sk-" "$f" 2>/dev/null || printf '0'
}

# ── show_key_help ─────────────────────────────────────────────────────────────
# Explains how to generate an SSH key on Ubuntu/Linux and Windows, then how to
# provide it here (paste or URL).
show_key_help() {
    printf '\n'
    section "How to create an SSH key"
    printf '\n'
    printf "  ${BOLD}Ubuntu / Linux / macOS${NC}\n\n"
    plain "1. Open a terminal on your local machine."
    plain "2. Generate a key pair:"
    plain "      ssh-keygen -t ed25519 -C \"you@example.com\""
    plain "   Accept the default path (~/.ssh/id_ed25519) and set a passphrase."
    plain "3. Print your public key:"
    plain "      cat ~/.ssh/id_ed25519.pub"
    plain "4. Copy the full output — it begins with 'ssh-ed25519 AAAA...'"
    printf '\n'
    printf "  ${BOLD}Windows${NC}\n\n"
    plain "Option A — PowerShell (OpenSSH built in on Windows 10 / 11):"
    plain "   1. Open PowerShell."
    plain "   2. Generate a key pair:"
    plain "         ssh-keygen -t ed25519 -C \"you@example.com\""
    plain "   3. Print your public key:"
    plain "         Get-Content \$env:USERPROFILE\.ssh\id_ed25519.pub"
    printf '\n'
    plain "Option B — Git Bash:"
    plain "   1. Open Git Bash (installed with Git for Windows)."
    plain "   2. Follow the same steps as Ubuntu above."
    printf '\n'
    plain "Once you have your public key:"
    plain "  [p]  Paste it directly into this prompt."
    plain "  [u]  Upload it to GitHub/GitLab first, then fetch via URL (see [h] in the URL prompt)."
    printf '\n'
}

# ── show_url_help ──────────────────────────────────────────────────────────────
# Explains how to add SSH keys to GitHub / GitLab and use the .keys URL.
show_url_help() {
    printf '\n'
    section "How to use a Git hosting URL for SSH keys"
    printf '\n'
    plain "GitHub and GitLab publish all your SSH public keys at a URL."
    plain "Use this option to import every key in your account in one step."
    printf '\n'
    printf "  ${BOLD}Step 1 — Add your public key to your account${NC}\n\n"
    plain "  GitHub:  https://github.com/settings/keys"
    plain "  GitLab:  https://gitlab.com/-/profile/keys"
    plain "  Gitea:   https://<your-gitea>/user/settings/keys"
    printf '\n'
    printf "  ${BOLD}Step 2 — Use the auto-generated keys URL${NC}\n\n"
    plain "  GitHub:  https://github.com/USERNAME.keys"
    plain "  GitLab:  https://gitlab.com/USERNAME.keys"
    plain "  Gitea:   https://<your-gitea>/USERNAME.keys"
    printf '\n'
    plain "Paste that URL at the prompt — all public keys in the account are fetched"
    plain "and added automatically. Only valid SSH public keys are written."
    printf '\n'
}

# ── write_authorized_keys <user> <home> <auth_file> <keys_block> <label> ─────
# Appends unique, valid public keys from keys_block to auth_file.
# Writes a labelled section header so duplicate runs are idempotent.
write_authorized_keys() {
    local user="$1" home="$2" auth_file="$3" keys_block="$4" label="$5"
    local added=0 datestamp; datestamp=$(date '+%Y-%m-%d')

    if [[ "$DRY_RUN" == "true" ]]; then
        local n; n=$(printf '%s' "$keys_block" | grep -c "^ssh-\|^ecdsa-\|^sk-" || printf '0')
        printf "    ${DIM}[dry-run]${NC} Would add up to %s key(s) from '%s' → %s\n" \
            "$n" "$label" "$auth_file"
        return
    fi

    mkdir -p "${home}/.ssh"
    chmod 700 "${home}/.ssh"
    touch "$auth_file"

    if ! grep -qF "# Source: ${label}" "$auth_file" 2>/dev/null; then
        printf '\n# Source: %s  (added %s by manage-ssh.sh)\n' \
            "$label" "$datestamp" >> "$auth_file"
    fi

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        printf '%s' "$key" | grep -q "^ssh-\|^ecdsa-\|^sk-" || continue
        local key_body; key_body=$(printf '%s' "$key" | awk '{print $1" "$2}')
        grep -qF "$key_body" "$auth_file" 2>/dev/null && continue
        printf '%s\n' "$key" >> "$auth_file"
        added=$((added + 1))
    done < <(printf '%s\n' "$keys_block" | grep "^ssh-\|^ecdsa-\|^sk-" || true)

    chmod 600 "$auth_file"
    chown -R "${user}:${user}" "${home}/.ssh" 2>/dev/null \
        || chown -R "$user" "${home}/.ssh" 2>/dev/null \
        || true

    if [[ $added -gt 0 ]]; then
        ok "Added ${added} new key(s) from '${label}' → ${auth_file}"
    else
        ok "All keys from '${label}' already present in ${auth_file}"
    fi
}

# ── State display ─────────────────────────────────────────────────────────────
show_state() {
    section "SSH Service"
    printf '\n'

    if [[ "$SSH_PKG_INSTALLED" == "true" ]]; then
        local ver; ver=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || printf '?')
        printf "    %-14s ${GREEN}%-14s${NC} %s\n" "Package:" "installed" "(${ver})"
        local col_active col_enabled
        [[ "$SSH_SVC_ACTIVE"  == "true" ]] && col_active="${GREEN}"  || col_active="${RED}"
        [[ "$SSH_SVC_ENABLED" == "true" ]] && col_enabled="${GREEN}" || col_enabled="${YELLOW}"
        printf "    %-14s ${col_active}%-14s${NC} ${col_enabled}%s${NC}\n" \
            "Service:" \
            "$( [[ "$SSH_SVC_ACTIVE"  == "true" ]] && printf active   || printf inactive )" \
            "$( [[ "$SSH_SVC_ENABLED" == "true" ]] && printf enabled  || printf disabled )"
        printf "    %-14s %s\n" "Port:" "$SSH_PORT"
    else
        printf "    %-14s ${RED}%s${NC}\n" "Package:" "not installed"
        printf "    %-14s ${DIM}%s${NC}\n" "Service:" "n/a"
    fi

    if [[ "$SSH_PKG_INSTALLED" == "true" ]]; then
        section "SSH Configuration"
        printf '\n'
        local _dc _dv
        printf -v _dc '%*s' 30 ''; _dc="${_dc// /─}"
        printf -v _dv '%*s' 22 ''; _dv="${_dv// /─}"
        printf "    ${BOLD}%-30s %s${NC}\n" "Setting" "Effective value"
        printf "    %s %s\n" "$_dc" "$_dv"
        local _color _val
        for _entry in \
            "PasswordAuthentication:$CONF_PASSWORD_AUTH" \
            "PubkeyAuthentication:$CONF_PUBKEY_AUTH" \
            "PermitRootLogin:$CONF_PERMIT_ROOT_LOGIN" \
            "MaxAuthTries:$CONF_MAX_AUTH_TRIES" \
            "X11Forwarding:$CONF_X11_FORWARDING" \
            "AllowTcpForwarding:$CONF_TCP_FORWARDING"
        do
            local _dname="${_entry%%:*}" _dval="${_entry#*:}"
            _color=$(_conf_color "$_dname" "$_dval")
            printf "    ${_color}%-30s %s${NC}\n" "$_dname" "$_dval"
        done
        printf '\n'
    fi

    section "Authorized Keys"
    printf '\n'

    local dv_user dv_uid dv_keys dv_home
    printf -v dv_user '%*s' 18 ''; dv_user="${dv_user// /─}"
    printf -v dv_uid  '%*s' 6  ''; dv_uid="${dv_uid// /─}"
    printf -v dv_keys '%*s' 5  ''; dv_keys="${dv_keys// /─}"
    printf -v dv_home '%*s' 28 ''; dv_home="${dv_home// /─}"

    printf "    ${BOLD}%-4s %-18s %-6s %-5s %s${NC}\n" "#" "Username" "UID" "Keys" "Home"
    printf "    %-4s %s %s %s %s\n" "────" "$dv_user" "$dv_uid" "$dv_keys" "$dv_home"

    local _i=0
    while IFS=: read -r _u _ _uid _ _ _home _; do
        _i=$((_i + 1))
        local _ak="${_home}/.ssh/authorized_keys"
        local _kc; _kc=$(count_keys "$_ak")
        if [[ "$_kc" -gt 0 ]]; then
            printf "    %-4s %-18s %-6s ${GREEN}%-5s${NC} %s\n" \
                "$_i" "$_u" "$_uid" "$_kc" "$_home"
        else
            printf "    %-4s %-18s %-6s ${DIM}%-5s${NC} %s\n" \
                "$_i" "$_u" "$_uid" "0" "$_home"
        fi
    done < <(
        getent passwd root
        getent passwd | awk -F: '$3>=1000 && $3<65534 {print}' | sort -t: -k3 -n
    )
    printf '\n'
}

# ── Menu ──────────────────────────────────────────────────────────────────────
declare -a _MENU_ACTIONS=()
_MENU_MAX=0

_show_menu() {
    _MENU_ACTIONS=()
    local n=0
    printf "\n${BOLD}  Actions${NC}\n\n"

    if [[ "$SSH_PKG_INSTALLED" == "false" ]]; then
        n=$((n+1)); _MENU_ACTIONS[$n]="install"
        printf "    ${CYAN}%d)${NC}  Install openssh-server\n" "$n"
    fi

    if [[ "$SSH_PKG_INSTALLED" == "true" ]]; then
        if [[ "$SSH_SVC_ACTIVE" == "false" ]]; then
            n=$((n+1)); _MENU_ACTIONS[$n]="start"
            printf "    ${CYAN}%d)${NC}  Start SSH service\n" "$n"
        fi
        if [[ "$SSH_SVC_ENABLED" == "false" ]]; then
            n=$((n+1)); _MENU_ACTIONS[$n]="enable"
            printf "    ${CYAN}%d)${NC}  Enable SSH service at boot\n" "$n"
        fi
        n=$((n+1)); _MENU_ACTIONS[$n]="add_keys"
        printf "    ${CYAN}%d)${NC}  Add authorized keys\n" "$n"
        n=$((n+1)); _MENU_ACTIONS[$n]="remove_key"
        printf "    ${CYAN}%d)${NC}  Remove an authorized key\n" "$n"
        n=$((n+1)); _MENU_ACTIONS[$n]="edit_config"
        printf "    ${CYAN}%d)${NC}  Edit SSH configuration\n" "$n"
    fi

    n=$((n+1)); _MENU_ACTIONS[$n]="exit"
    printf "    ${CYAN}%d)${NC}  Exit\n" "$n"
    _MENU_MAX=$n
}

_menu_default() {
    local i
    for i in "${!_MENU_ACTIONS[@]}"; do
        case "${_MENU_ACTIONS[$i]}" in
            install) [[ "$SSH_PKG_INSTALLED" == "false" ]] && { printf '%d' "$i"; return; } ;;
            start)   [[ "$SSH_SVC_ACTIVE"    == "false" ]] && { printf '%d' "$i"; return; } ;;
            enable)  [[ "$SSH_SVC_ENABLED"   == "false" ]] && { printf '%d' "$i"; return; } ;;
        esac
    done
    printf ''
}

# ── Action: install ───────────────────────────────────────────────────────────
action_install() {
    section "Install openssh-server"
    printf '\n'
    info "Installing openssh-server via apt..."
    run apt-get install -y openssh-server
    if [[ "$DRY_RUN" != "true" ]]; then
        systemctl enable --now ssh 2>/dev/null \
            || systemctl enable --now sshd 2>/dev/null \
            || true
        ok "openssh-server installed and service enabled"
    else
        printf "    ${DIM}[dry-run]${NC} systemctl enable --now ssh\n"
    fi
}

# ── Action: start service ─────────────────────────────────────────────────────
action_start_service() {
    section "Start SSH Service"
    printf '\n'
    info "Starting SSH service..."
    if [[ "$DRY_RUN" != "true" ]]; then
        systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true
        ok "SSH service started"
    else
        printf "    ${DIM}[dry-run]${NC} systemctl start ssh\n"
    fi
}

# ── Action: enable service ────────────────────────────────────────────────────
action_enable_service() {
    section "Enable SSH at Boot"
    printf '\n'
    info "Enabling SSH service at boot..."
    if [[ "$DRY_RUN" != "true" ]]; then
        systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
        ok "SSH service enabled at boot"
    else
        printf "    ${DIM}[dry-run]${NC} systemctl enable ssh\n"
    fi
}

# ── Action: add authorized keys ───────────────────────────────────────────────
action_add_keys() {
    section "Add Authorized Keys"
    printf '\n'
    if [[ "$URL_FETCH_AVAILABLE" == "true" ]]; then
        info "Tip: GitHub and GitLab expose all your keys at one URL:"
        plain "  https://github.com/USERNAME.keys   or   https://gitlab.com/USERNAME.keys"
    else
        warn "URL key fetching is disabled — neither curl nor wget is installed."
        plain "Install curl to enable it:  apt install curl"
        if ask "Install curl now?" "y"; then
            run apt-get install -y curl
            if [[ "$DRY_RUN" != "true" ]]; then
                CURL_AVAILABLE=true
                URL_FETCH_AVAILABLE=true
                ok "curl installed — URL key fetching is now available."
            fi
        else
            info "Continuing without URL fetching. You can still paste keys manually."
        fi
    fi
    printf '\n'

    # Build candidate users
    local _users=() _uids=() _homes=()
    while IFS=: read -r _u _ _uid _ _ _home _; do
        _users+=("$_u"); _uids+=("$_uid"); _homes+=("$_home")
    done < <(
        getent passwd root
        getent passwd | awk -F: '$3>=1000 && $3<65534 {print}' | sort -t: -k3 -n
    )

    if [[ ${#_users[@]} -eq 0 ]]; then
        warn "No system users found."; return 0
    fi

    # Print table
    local dv; printf -v dv '%*s' 55 ''; printf "    %s\n" "${dv// /─}"
    printf "    ${BOLD}%-4s %-18s %-6s %-5s %s${NC}\n" "#" "Username" "UID" "Keys" "Home"
    printf "    %s\n" "${dv// /─}"
    local _i
    for _i in "${!_users[@]}"; do
        local _ak="${_homes[$_i]}/.ssh/authorized_keys"
        local _kc; _kc=$(count_keys "$_ak")
        if [[ "$_kc" -gt 0 ]]; then
            printf "    %-4s %-18s %-6s ${GREEN}%-5s${NC} %s\n" \
                "$((_i+1))" "${_users[$_i]}" "${_uids[$_i]}" "$_kc" "${_homes[$_i]}"
        else
            printf "    %-4s %-18s %-6s ${DIM}%-5s${NC} %s\n" \
                "$((_i+1))" "${_users[$_i]}" "${_uids[$_i]}" "0" "${_homes[$_i]}"
        fi
    done
    printf '\n'

    # Pick user
    local raw_sel
    raw_sel=$(ask_val "User (number or username, blank to cancel)" "")
    [[ -z "$raw_sel" ]] && { info "Cancelled."; return 0; }

    local key_user=""
    if [[ "$raw_sel" =~ ^[0-9]+$ ]]; then
        local idx=$(( raw_sel - 1 ))
        if [[ "$idx" -ge 0 && "$idx" -lt "${#_users[@]}" ]]; then
            key_user="${_users[$idx]}"
        else
            warn "No user with number ${raw_sel}."; return 0
        fi
    else
        id "$raw_sel" &>/dev/null || { warn "User '${raw_sel}' does not exist."; return 0; }
        key_user="$raw_sel"
    fi

    local key_home; key_home=$(getent passwd "$key_user" | cut -d: -f6)
    local auth_file="${key_home}/.ssh/authorized_keys"

    # Key source loop
    while true; do
        local cur_kc; cur_kc=$(count_keys "$auth_file")
        printf '\n'
        if [[ "$cur_kc" -gt 0 ]]; then
            printf "  ${BOLD}── %s${NC}  ${GREEN}(%s key(s) in place)${NC}\n" "$key_user" "$cur_kc"
        else
            printf "  ${BOLD}── %s${NC}  ${DIM}(no keys yet)${NC}\n" "$key_user"
        fi
        printf '\n'
        if [[ "$URL_FETCH_AVAILABLE" == "true" ]]; then
            printf "    ${CYAN}[u]${NC}  Fetch from a URL    (GitHub, GitLab, Gitea, etc.)\n"
        else
            printf "    ${DIM}[u]  Fetch from a URL    (disabled — install curl or wget)${NC}\n"
        fi
        printf "    ${CYAN}[p]${NC}  Paste keys manually\n"
        printf "    ${CYAN}[h]${NC}  Help — how to create and provide a key\n"
        printf "    ${CYAN}[d]${NC}  Done\n"
        printf '\n'

        local action_choice; action_choice=$(ask_val "Action" "d")
        case "${action_choice,,}" in
            h)
                show_key_help
                continue
                ;;
            u)
                if [[ "$URL_FETCH_AVAILABLE" == "false" ]]; then
                    warn "URL fetching is unavailable — install curl or wget first."
                    continue
                fi
                local url=""
                while true; do
                    url=$(ask_val "Keys URL  (h for help, x to cancel, e.g. https://github.com/USERNAME.keys)" "")
                    [[ -z "$url" ]] && { warn "URL cannot be blank — enter x to cancel."; continue; }
                    if [[ "${url,,}" == "h" ]]; then show_url_help; continue; fi
                    if [[ "${url,,}" == "x" ]]; then info "Cancelled."; url=""; break; fi
                    break
                done
                [[ -z "$url" ]] && continue
                info "Fetching keys from ${url} ..."
                local keys_block
                if [[ "$CURL_AVAILABLE" == "true" ]]; then
                    if ! keys_block=$(curl -fsSL --max-time 15 "$url" 2>/tmp/manage_ssh_fetch.err); then
                        warn "curl failed to fetch keys from ${url}"
                        sed 's/^/        /' /tmp/manage_ssh_fetch.err >&2 || true
                        rm -f /tmp/manage_ssh_fetch.err
                        continue
                    fi
                else
                    if ! keys_block=$(wget -qO- --timeout=15 "$url" 2>/tmp/manage_ssh_fetch.err); then
                        warn "wget failed to fetch keys from ${url}"
                        sed 's/^/        /' /tmp/manage_ssh_fetch.err >&2 || true
                        rm -f /tmp/manage_ssh_fetch.err
                        continue
                    fi
                fi
                rm -f /tmp/manage_ssh_fetch.err
                local n; n=$(printf '%s\n' "$keys_block" | grep -c "^ssh-\|^ecdsa-\|^sk-" || printf '0')
                if [[ "$n" -eq 0 ]]; then
                    warn "No valid SSH public keys found at that URL."; continue
                fi
                ok "Fetched ${n} key(s)"
                local label; label=$(printf '%s' "$url" | sed 's|.*/||; s|\.keys$||')
                write_authorized_keys "$key_user" "$key_home" "$auth_file" "$keys_block" "$label"
                ;;
            p)
                local label="manual"
                printf '\n'
                info "Paste public keys (ssh-ed25519 / rsa / ecdsa-), one per line."
                plain "Press Enter then Ctrl+D when done."
                printf '\n'
                local manual_keys; manual_keys=$(cat)
                local n; n=$(printf '%s\n' "$manual_keys" | grep -c "^ssh-\|^ecdsa-\|^sk-" || printf '0')
                if [[ "$n" -eq 0 ]]; then
                    warn "No valid SSH public keys detected."; continue
                fi
                ok "Detected ${n} key(s)"
                write_authorized_keys "$key_user" "$key_home" "$auth_file" "$manual_keys" "$label"
                ;;
            d|"")
                local final_kc; final_kc=$(count_keys "$auth_file")
                if [[ "$final_kc" -gt 0 ]]; then
                    ok "${key_user} — ${final_kc} authorized key(s) in place"
                else
                    warn "${key_user} — no authorized keys configured"
                fi
                break
                ;;
            *)
                warn "Unknown option '${action_choice}' — enter u, p, h, or d."
                ;;
        esac
    done
}

# ── Action: remove authorized key ─────────────────────────────────────────────
action_remove_key() {
    section "Remove Authorized Key"
    printf '\n'

    # Find users who have at least one key
    local users_wk=() homes_wk=()
    while IFS=: read -r _u _ _ _ _ _home _; do
        local _ak="${_home}/.ssh/authorized_keys"
        grep -q "^ssh-\|^ecdsa-\|^sk-" "$_ak" 2>/dev/null || continue
        users_wk+=("$_u"); homes_wk+=("$_home")
    done < <(
        getent passwd root
        getent passwd | awk -F: '$3>=1000 && $3<65534 {print}' | sort -t: -k3 -n
    )

    if [[ ${#users_wk[@]} -eq 0 ]]; then
        warn "No authorized keys found on this system."; return 0
    fi

    local dv; printf -v dv '%*s' 50 ''; printf "    %s\n" "${dv// /─}"
    printf "    ${BOLD}%-4s %-18s %s${NC}\n" "#" "Username" "Home"
    printf "    %s\n" "${dv// /─}"
    local _i
    for _i in "${!users_wk[@]}"; do
        printf "    %-4s %-18s %s\n" "$((_i+1))" "${users_wk[$_i]}" "${homes_wk[$_i]}"
    done
    printf '\n'

    local raw_sel; raw_sel=$(ask_val "User (number or username, blank to cancel)" "")
    [[ -z "$raw_sel" ]] && { info "Cancelled."; return 0; }

    local key_user="" key_home=""
    if [[ "$raw_sel" =~ ^[0-9]+$ ]]; then
        local idx=$(( raw_sel - 1 ))
        if [[ "$idx" -ge 0 && "$idx" -lt "${#users_wk[@]}" ]]; then
            key_user="${users_wk[$idx]}"; key_home="${homes_wk[$idx]}"
        else
            warn "No user with number ${raw_sel}."; return 0
        fi
    else
        local found=false _i
        for _i in "${!users_wk[@]}"; do
            if [[ "${users_wk[$_i]}" == "$raw_sel" ]]; then
                key_user="$raw_sel"; key_home="${homes_wk[$_i]}"; found=true; break
            fi
        done
        [[ "$found" == "true" ]] \
            || { warn "User '${raw_sel}' not found or has no keys."; return 0; }
    fi

    local auth_file="${key_home}/.ssh/authorized_keys"

    # List keys for this user
    local keys=()
    while IFS= read -r line; do
        printf '%s' "$line" | grep -q "^ssh-\|^ecdsa-\|^sk-" || continue
        keys+=("$line")
    done < "$auth_file"

    if [[ ${#keys[@]} -eq 0 ]]; then
        warn "No valid keys found in ${auth_file}"; return 0
    fi

    printf '\n'
    printf "    ${BOLD}Keys for %s:${NC}\n\n" "$key_user"
    local _i
    for _i in "${!keys[@]}"; do
        local _type _blob _comment _short
        read -r _type _blob _comment <<< "${keys[$_i]}" || true
        _short="${_blob:0:24}…${_blob: -8}"
        printf "    ${CYAN}%d)${NC}  %-22s  %s  %s\n" \
            "$((_i+1))" "$_type" "$_short" "${_comment:-}"
    done
    printf '\n'

    local pick; pick=$(ask_val "Key number to remove (blank to cancel)" "")
    [[ -z "$pick" ]] && { info "Cancelled."; return 0; }
    [[ "$pick" =~ ^[0-9]+$ ]] || { warn "Invalid input."; return 0; }
    local pidx=$(( pick - 1 ))
    if [[ "$pidx" -lt 0 || "$pidx" -ge "${#keys[@]}" ]]; then
        warn "No key number ${pick}."; return 0
    fi

    local target_key="${keys[$pidx]}"
    local _type _blob _comment
    read -r _type _blob _comment <<< "$target_key" || true

    printf '\n'
    warn "About to remove:  ${_type} ${_blob:0:24}…  ${_comment:-}"
    ask "Confirm removal?" "n" || { info "Cancelled."; return 0; }

    if [[ "$DRY_RUN" != "true" ]]; then
        local key_body; key_body=$(printf '%s %s' "$_type" "$_blob")
        local bak="${auth_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$auth_file" "$bak"
        grep -vF "$key_body" "$auth_file" > "${auth_file}.tmp" \
            && mv "${auth_file}.tmp" "$auth_file"
        ok "Key removed from ${auth_file}"
        ok "Backup saved to  ${bak}"
    else
        printf "    ${DIM}[dry-run]${NC} Would remove key: %s %s...\n" "$_type" "${_blob:0:20}"
    fi
}

# ── _conf_color <directive> <value> ──────────────────────────────────────────
# Returns the ANSI colour code appropriate for a directive/value pair.
_conf_color() {
    local dir="$1" val="${2,,}" raw="$2"
    case "$dir" in
        PubkeyAuthentication)
            [[ "$val" == "yes" ]] && printf '%s' "$GREEN" || printf '%s' "$RED" ;;
        PasswordAuthentication|KbdInteractiveAuthentication|PermitEmptyPasswords|X11Forwarding)
            [[ "$val" == "no"  ]] && printf '%s' "$GREEN" || printf '%s' "$RED" ;;
        PermitRootLogin)
            if   [[ "$val" == "no" || "$val" == "prohibit-password" ]]; then printf '%s' "$GREEN"
            elif [[ "$val" == "yes" ]];                                  then printf '%s' "$RED"
            else                                                              printf '%s' "$YELLOW"
            fi ;;
        AllowTcpForwarding)
            [[ "$val" == "no"  ]] && printf '%s' "$GREEN" || printf '%s' "$YELLOW" ;;
        MaxAuthTries)
            if [[ "$raw" =~ ^[0-9]+$ ]]; then
                (( raw <= 5 )) && printf '%s' "$GREEN" || printf '%s' "$RED"
            else printf '%s' "$YELLOW"; fi ;;
        LoginGraceTime)
            if [[ "$raw" =~ ^[0-9]+$ ]]; then
                (( raw > 0 && raw <= 60 )) && printf '%s' "$GREEN" || printf '%s' "$YELLOW"
            else printf '%s' "$YELLOW"; fi ;;
        ClientAliveInterval)
            if [[ "$raw" =~ ^[0-9]+$ ]]; then
                (( raw > 0 )) && printf '%s' "$GREEN" || printf '%s' "$RED"
            else printf '%s' "$YELLOW"; fi ;;
        ClientAliveCountMax)
            if [[ "$raw" =~ ^[0-9]+$ ]]; then
                (( raw > 0 )) && printf '%s' "$GREEN" || printf '%s' "$YELLOW"
            else printf '%s' "$YELLOW"; fi ;;
        *)  printf '%s' "$YELLOW" ;;
    esac
}

# ── _show_full_config_table ───────────────────────────────────────────────────
# Prints a numbered, colour-coded table of all manageable SSH directives.
_show_full_config_table() {
    local dn dk dv
    printf -v dn '%*s' 4  ''; dn="${dn// /─}"
    printf -v dk '%*s' 32 ''; dk="${dk// /─}"
    printf -v dv '%*s' 20 ''; dv="${dv// /─}"
    printf '\n'
    printf "    ${BOLD}%-4s %-32s %s${NC}\n" "#" "Setting" "Effective value"
    printf "    %s %s %s\n" "$dn" "$dk" "$dv"

    local -a _dirs _vals
    _dirs=()
    _vals=()
    _dirs+=("Port");                         _vals+=("$CONF_PORT")
    _dirs+=("PubkeyAuthentication");         _vals+=("$CONF_PUBKEY_AUTH")
    _dirs+=("PasswordAuthentication");       _vals+=("$CONF_PASSWORD_AUTH")
    _dirs+=("KbdInteractiveAuthentication"); _vals+=("$CONF_KBD_AUTH")
    _dirs+=("PermitRootLogin");              _vals+=("$CONF_PERMIT_ROOT_LOGIN")
    _dirs+=("PermitEmptyPasswords");         _vals+=("$CONF_EMPTY_PASSWORDS")
    _dirs+=("MaxAuthTries");                 _vals+=("$CONF_MAX_AUTH_TRIES")
    _dirs+=("LoginGraceTime");               _vals+=("$CONF_LOGIN_GRACE_TIME")
    _dirs+=("ClientAliveInterval");          _vals+=("$CONF_ALIVE_INTERVAL")
    _dirs+=("ClientAliveCountMax");          _vals+=("$CONF_ALIVE_COUNT")
    _dirs+=("X11Forwarding");                _vals+=("$CONF_X11_FORWARDING")
    _dirs+=("AllowTcpForwarding");           _vals+=("$CONF_TCP_FORWARDING")
    local _av; [[ "$CONF_SET_ALGORITHMS" == "true" ]] && _av="enforced" || _av="default"
    _dirs+=("Algorithms (modern set)");      _vals+=("$_av")

    local _i
    for _i in "${!_dirs[@]}"; do
        local _d="${_dirs[$_i]}" _v="${_vals[$_i]}" _c
        if [[ "$_d" == "Algorithms (modern set)" ]]; then
            [[ "$CONF_SET_ALGORITHMS" == "true" ]] && _c="$GREEN" || _c="$YELLOW"
        else
            _c=$(_conf_color "$_d" "$_v")
        fi
        printf "    ${CYAN}%-4s${NC} ${_c}%-32s %s${NC}\n" "$((_i+1)))" "$_d" "$_v"
    done
    printf '\n'
}

# ── _print_directive_desc <directive> ────────────────────────────────────────
# Prints a two-line summary: what the directive does and its allowed values.
_print_directive_desc() {
    case "$1" in
        Port)
            plain "TCP port sshd listens on. Default is 22 (IANA-assigned well-known port)."
            plain "Allowed values: 1–65535 (integer)." ;;
        PubkeyAuthentication)
            plain "Allow authentication via SSH public/private key pairs."
            plain "Allowed values: yes | no.  Recommended: yes." ;;
        PasswordAuthentication)
            plain "Allow authentication via password. Disable to require key-only logins."
            plain "Allowed values: yes | no.  Recommended: no." ;;
        KbdInteractiveAuthentication)
            plain "Allow keyboard-interactive (challenge-response) auth, including PAM passwords."
            plain "Allowed values: yes | no.  Recommended: no." ;;
        PermitRootLogin)
            plain "Whether the root account may log in directly via SSH."
            plain "Allowed values: yes | no | prohibit-password | forced-commands-only.  Recommended: no." ;;
        PermitEmptyPasswords)
            plain "Allow accounts with no password to authenticate without a credential."
            plain "Allowed values: yes | no.  Recommended: no." ;;
        MaxAuthTries)
            plain "Maximum authentication attempts per connection before disconnecting."
            plain "Allowed values: 1–100 (integer).  Recommended: ≤5." ;;
        LoginGraceTime)
            plain "Seconds allowed for authentication to complete. 0 = no limit."
            plain "Allowed values: 0–3600 (integer, seconds).  Recommended: 30–60." ;;
        ClientAliveInterval)
            plain "Seconds between keep-alive probes sent to idle clients. 0 disables idle timeout."
            plain "Allowed values: 0–3600 (integer, seconds).  Recommended: 300." ;;
        ClientAliveCountMax)
            plain "Consecutive missed keep-alive probes before disconnecting the client."
            plain "Allowed values: 0–100 (integer).  Recommended: 2." ;;
        X11Forwarding)
            plain "Allow forwarding of graphical X11 applications over SSH."
            plain "Allowed values: yes | no.  Recommended: no." ;;
        AllowTcpForwarding)
            plain "Allow TCP port forwarding (tunneling) through this SSH server."
            plain "Allowed values: yes | no | local | remote | all.  Recommended: no." ;;
        "Algorithms (modern set)")
            plain "Write explicit modern algorithm stanzas to the drop-in."
            plain "Allowed values: yes | no.  yes = enforce modern set; no = rely on OpenSSH defaults." ;;
    esac
}

# ── _print_directive_help <directive> ────────────────────────────────────────
# Prints detailed help text for a directive (shown when user enters 'h').
_print_directive_help() {
    printf '\n'
    section "Help: $1"
    printf '\n'
    case "$1" in
        Port)
            plain "sshd listens for incoming SSH connections on this TCP port."
            plain ""
            plain "Port 22 is the IANA-assigned default. Using a non-standard port"
            plain "reduces automated scan noise, but is not a security boundary —"
            plain "a full port scan will find it. Pair with a firewall to restrict"
            plain "access by source IP for stronger protection."
            plain ""
            plain "Changing the port requires updating any firewall rules, and"
            plain "clients must specify the new port:  ssh -p <port> user@host" ;;
        PubkeyAuthentication)
            plain "Public-key authentication uses a cryptographic key pair. The"
            plain "private key stays on the client; the public key is stored in"
            plain "~/.ssh/authorized_keys on the server."
            plain ""
            plain "This is the foundation of secure SSH access. Disabling it forces"
            plain "users onto weaker authentication methods. Keep it enabled." ;;
        PasswordAuthentication)
            plain "When enabled, users may authenticate by typing their account password."
            plain ""
            plain "Password authentication is vulnerable to brute-force and credential-"
            plain "stuffing attacks. Disable it once all accounts have SSH keys in place."
            plain ""
            plain "Note: also set KbdInteractiveAuthentication no to fully prevent"
            plain "PAM-based password challenges." ;;
        KbdInteractiveAuthentication)
            plain "Keyboard-interactive auth is a generic challenge-response mechanism."
            plain "On most systems it is wired to PAM, making it functionally equivalent"
            plain "to password authentication."
            plain ""
            plain "Set to no alongside PasswordAuthentication no to ensure passwords"
            plain "cannot be used, even through PAM." ;;
        PermitRootLogin)
            plain "Controls whether the root account may authenticate via SSH."
            plain ""
            plain "  yes                Root may log in with any auth method."
            plain "  prohibit-password  Root may log in with keys only (no password)."
            plain "  forced-commands-only  Root key login only when 'command=' is set."
            plain "  no                 Root login is completely disabled."
            plain ""
            plain "Recommended: no. Use a sudo-capable regular account instead." ;;
        PermitEmptyPasswords)
            plain "When enabled, accounts whose password field is empty can"
            plain "authenticate via SSH without entering any credential."
            plain ""
            plain "This should always be no unless you have an extremely controlled"
            plain "and well-understood use case." ;;
        MaxAuthTries)
            plain "Maximum authentication attempts accepted per connection."
            plain "After half this number of failures, additional failures are logged."
            plain ""
            plain "Lower values slow brute-force attacks that cycle through many keys"
            plain "per connection. 3–5 is a good balance: clients with many keys can"
            plain "still connect (they retry in a new connection), but attackers'"
            plain "per-session throughput is limited." ;;
        LoginGraceTime)
            plain "How long (seconds) sshd waits for a client to complete authentication"
            plain "before dropping the unauthenticated connection."
            plain ""
            plain "A long grace period lets unauthenticated connections occupy sshd"
            plain "slots, potentially contributing to resource exhaustion."
            plain "30–60 seconds is sufficient for any interactive login."
            plain "Setting 0 disables the timeout entirely (not recommended)." ;;
        ClientAliveInterval)
            plain "Interval (seconds) between keep-alive messages sent to the client."
            plain "If the client does not respond after ClientAliveCountMax probes,"
            plain "the session is terminated."
            plain ""
            plain "Setting 0 disables keep-alive entirely — idle sessions will never"
            plain "be automatically disconnected."
            plain ""
            plain "Recommended: 300 (5 min). Combined with ClientAliveCountMax 2,"
            plain "sessions idle for ~10 minutes are dropped." ;;
        ClientAliveCountMax)
            plain "Number of unanswered keep-alive probes before the session is dropped."
            plain ""
            plain "With ClientAliveInterval 300 and ClientAliveCountMax 2, a session"
            plain "is terminated after ~600 seconds (10 min) of silence."
            plain ""
            plain "Setting this to 0 while interval is non-zero causes the session to"
            plain "be dropped after the very first missed probe." ;;
        X11Forwarding)
            plain "When enabled, clients can forward graphical X11 applications from"
            plain "the server to their local display using 'ssh -X'."
            plain ""
            plain "X11 forwarding adds attack surface: a server-side process can"
            plain "intercept or inject events into the forwarded display."
            plain "Disable unless you specifically rely on this feature." ;;
        AllowTcpForwarding)
            plain "Controls whether clients can use SSH as a general TCP tunnel."
            plain ""
            plain "  yes / all   Both local (-L) and remote (-R) forwarding allowed."
            plain "  local       Only local port forwarding (-L) allowed."
            plain "  remote      Only remote port forwarding (-R) allowed."
            plain "  no          All TCP forwarding disabled."
            plain ""
            plain "TCP forwarding can bypass network controls or expose internal"
            plain "services. Disable unless you have a specific, understood need." ;;
        "Algorithms (modern set)")
            plain "When set to 'yes', the drop-in will include explicit stanzas"
            plain "restricting sshd to vetted modern algorithms:"
            plain ""
            plain "  HostKeyAlgorithms    ssh-ed25519, rsa-sha2-512, rsa-sha2-256"
            plain "  PubkeyAcceptedAlgos  ssh-ed25519, sk-ssh-ed25519, rsa-sha2-512, rsa-sha2-256"
            plain "  KexAlgorithms        curve25519-sha256, diffie-hellman-group16-sha512, …"
            plain "  Ciphers              chacha20-poly1305, aes256-gcm, aes128-gcm"
            plain "  MACs                 hmac-sha2-256-etm, hmac-sha2-512-etm"
            plain ""
            plain "When set to 'no', OpenSSH's compiled-in defaults are used. These"
            plain "are reasonable on modern systems, but explicit stanzas prevent"
            plain "regressions after package upgrades." ;;
    esac
    printf '\n'
}

# ── _validate_directive <directive> <value> ───────────────────────────────────
# Returns 0 if value is syntactically valid for the directive; 1 otherwise.
# Prints a warn message on failure.
_validate_directive() {
    local dir="$1" val="$2"
    case "$dir" in
        Port)
            if ! [[ "$val" =~ ^[0-9]+$ ]] || (( val < 1 || val > 65535 )); then
                warn "Port must be an integer between 1 and 65535."
                return 1
            fi ;;
        PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|\
PermitEmptyPasswords|X11Forwarding)
            if [[ "${val,,}" != "yes" && "${val,,}" != "no" ]]; then
                warn "'${dir}' accepts: yes | no"
                return 1
            fi ;;
        PermitRootLogin)
            case "${val,,}" in
                yes|no|prohibit-password|forced-commands-only) ;;
                *) warn "'PermitRootLogin' accepts: yes | no | prohibit-password | forced-commands-only"
                   return 1 ;;
            esac ;;
        AllowTcpForwarding)
            case "${val,,}" in
                yes|no|local|remote|all) ;;
                *) warn "'AllowTcpForwarding' accepts: yes | no | local | remote | all"
                   return 1 ;;
            esac ;;
        MaxAuthTries)
            if ! [[ "$val" =~ ^[0-9]+$ ]] || (( val < 1 || val > 100 )); then
                warn "MaxAuthTries must be an integer between 1 and 100."
                return 1
            fi ;;
        LoginGraceTime)
            if ! [[ "$val" =~ ^[0-9]+$ ]] || (( val > 3600 )); then
                warn "LoginGraceTime must be an integer between 0 and 3600 (seconds)."
                return 1
            fi ;;
        ClientAliveInterval)
            if ! [[ "$val" =~ ^[0-9]+$ ]] || (( val > 3600 )); then
                warn "ClientAliveInterval must be an integer between 0 and 3600 (seconds)."
                return 1
            fi ;;
        ClientAliveCountMax)
            if ! [[ "$val" =~ ^[0-9]+$ ]] || (( val > 100 )); then
                warn "ClientAliveCountMax must be an integer between 0 and 100."
                return 1
            fi ;;
        "Algorithms (modern set)")
            if [[ "${val,,}" != "yes" && "${val,,}" != "no" ]]; then
                warn "'Algorithms (modern set)' accepts: yes | no"
                return 1
            fi ;;
    esac
    return 0
}

# ── _is_recommended <directive> <value> ──────────────────────────────────────
# Returns 0 if value is within the recommended secure range; 1 otherwise.
_is_recommended() {
    local dir="$1" val="${2,,}" raw="$2"
    case "$dir" in
        PubkeyAuthentication)
            [[ "$val" == "yes" ]]                                          || return 1 ;;
        PasswordAuthentication|KbdInteractiveAuthentication|\
PermitEmptyPasswords|X11Forwarding)
            [[ "$val" == "no"  ]]                                          || return 1 ;;
        PermitRootLogin)
            [[ "$val" == "no" || "$val" == "prohibit-password" ]]          || return 1 ;;
        AllowTcpForwarding)
            [[ "$val" == "no"  ]]                                          || return 1 ;;
        MaxAuthTries)
            [[ "$raw" =~ ^[0-9]+$ ]] && (( raw <= 5 ))                    || return 1 ;;
        LoginGraceTime)
            [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 && raw <= 60 ))        || return 1 ;;
        ClientAliveInterval)
            [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 ))                     || return 1 ;;
        ClientAliveCountMax)
            [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 ))                     || return 1 ;;
        "Algorithms (modern set)")
            [[ "$val" == "yes" ]]                                          || return 1 ;;
    esac
    return 0
}

# ── _print_recommendation_warning <directive> <value> ────────────────────────
# Explains why a value is outside the recommended range.
_print_recommendation_warning() {
    local dir="$1" val="$2"
    case "$dir" in
        PubkeyAuthentication)
            plain "Disabling public-key auth forces all users onto weaker methods"
            plain "and breaks key-based automation." ;;
        PasswordAuthentication)
            plain "Password auth exposes the server to brute-force and credential-"
            plain "stuffing attacks. Prefer key-based authentication." ;;
        KbdInteractiveAuthentication)
            plain "Enabling keyboard-interactive auth effectively re-enables password"
            plain "login via PAM, even when PasswordAuthentication is no." ;;
        PermitEmptyPasswords)
            plain "Accounts with no password set can authenticate without any"
            plain "credential — this is almost never safe." ;;
        PermitRootLogin)
            plain "Direct root SSH access means a compromised key gives an attacker"
            plain "immediate full system access with no account separation." ;;
        AllowTcpForwarding)
            plain "TCP forwarding can be used to bypass firewall rules or tunnel"
            plain "traffic to internal services through this host." ;;
        X11Forwarding)
            plain "X11 forwarding lets a server-side process intercept keyboard and"
            plain "mouse events on the client's display." ;;
        MaxAuthTries)
            plain "A limit above 5 allows more attempts per connection, giving"
            plain "brute-force tools greater throughput per TCP session." ;;
        LoginGraceTime)
            if [[ "$val" == "0" ]]; then
                plain "Setting LoginGraceTime 0 disables the grace period entirely."
                plain "Unauthenticated connections will never be automatically dropped."
            else
                plain "A grace period above 60 s lets stalled connections occupy sshd"
                plain "slots longer, increasing denial-of-service exposure."
            fi ;;
        ClientAliveInterval)
            plain "Setting ClientAliveInterval 0 disables keep-alive probes entirely."
            plain "Idle sessions will never be automatically disconnected." ;;
        ClientAliveCountMax)
            plain "Setting ClientAliveCountMax 0 drops a session after the very first"
            plain "missed probe — sessions may terminate unexpectedly on flaky networks." ;;
        "Algorithms (modern set)")
            plain "Relying on OpenSSH defaults means algorithm selection is governed"
            plain "by the installed package version and may weaken after upgrades." ;;
    esac
}

# ── write_config_dropin ───────────────────────────────────────────────────────
# Writes all CONF_* values to the hardening drop-in, validates with sshd -t,
# and reloads sshd. On validation failure the previous drop-in is restored.
write_config_dropin() {
    section "Applying Configuration"
    printf '\n'
    info "Target: ${SSHD_DROP_IN}"

    if [[ "$DRY_RUN" == "true" ]]; then
        printf '\n'
        printf "    ${DIM}[dry-run]${NC} Would write %s:\n" "$SSHD_DROP_IN"
        printf "    ${DIM}[dry-run]${NC}   Port                          %s\n" "$CONF_PORT"
        printf "    ${DIM}[dry-run]${NC}   PubkeyAuthentication          %s\n" "$CONF_PUBKEY_AUTH"
        printf "    ${DIM}[dry-run]${NC}   PasswordAuthentication        %s\n" "$CONF_PASSWORD_AUTH"
        printf "    ${DIM}[dry-run]${NC}   KbdInteractiveAuthentication  %s\n" "$CONF_KBD_AUTH"
        printf "    ${DIM}[dry-run]${NC}   PermitRootLogin               %s\n" "$CONF_PERMIT_ROOT_LOGIN"
        printf "    ${DIM}[dry-run]${NC}   PermitEmptyPasswords          %s\n" "$CONF_EMPTY_PASSWORDS"
        printf "    ${DIM}[dry-run]${NC}   MaxAuthTries                  %s\n" "$CONF_MAX_AUTH_TRIES"
        printf "    ${DIM}[dry-run]${NC}   LoginGraceTime                %s\n" "$CONF_LOGIN_GRACE_TIME"
        printf "    ${DIM}[dry-run]${NC}   ClientAliveInterval           %s\n" "$CONF_ALIVE_INTERVAL"
        printf "    ${DIM}[dry-run]${NC}   ClientAliveCountMax           %s\n" "$CONF_ALIVE_COUNT"
        printf "    ${DIM}[dry-run]${NC}   X11Forwarding                 %s\n" "$CONF_X11_FORWARDING"
        printf "    ${DIM}[dry-run]${NC}   AllowTcpForwarding            %s\n" "$CONF_TCP_FORWARDING"
        [[ "$CONF_SET_ALGORITHMS" == "true" ]] \
            && printf "    ${DIM}[dry-run]${NC}   (modern algorithm stanzas)\n"
        return 0
    fi

    mkdir -p /etc/ssh/sshd_config.d

    # Back up existing drop-in
    local ts; ts=$(date '+%Y%m%d_%H%M%S')
    local bak="${SSHD_DROP_IN}.bak.${ts}"
    if [[ -f "$SSHD_DROP_IN" ]]; then
        cp "$SSHD_DROP_IN" "$bak"
        ok "Backed up existing drop-in → ${bak}"
    fi

    # Build optional algorithm block
    local algo_block=""
    if [[ "$CONF_SET_ALGORITHMS" == "true" ]]; then
        algo_block=$(cat << 'ALGEOF'

# ── Modern algorithms only ────────────────────────────────────────────────────
# ssh-rsa (SHA-1) is disabled in OpenSSH 8.8+; rsa-sha2-* is the replacement.
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
ALGEOF
)
    fi

    # Compute idle timeout comment
    local idle_comment
    if [[ "$CONF_ALIVE_INTERVAL" =~ ^[0-9]+$ && "$CONF_ALIVE_COUNT" =~ ^[0-9]+$ ]] \
        && (( CONF_ALIVE_INTERVAL > 0 && CONF_ALIVE_COUNT > 0 )); then
        local _mins=$(( (CONF_ALIVE_INTERVAL * CONF_ALIVE_COUNT + 59) / 60 ))
        idle_comment="disconnects idle sessions after ~${_mins}min"
    else
        idle_comment="idle timeout disabled"
    fi

    # Write the drop-in
    cat > "$SSHD_DROP_IN" << DROPIN
# ── SSH Hardening drop-in ─────────────────────────────────────────────────────
# Written by manage-ssh.sh on $(date)
# Overrides /etc/ssh/sshd_config without modifying it.
# Re-run manage-ssh.sh to update.

# ── Port ──────────────────────────────────────────────────────────────────────
Port ${CONF_PORT}

# ── Authentication ────────────────────────────────────────────────────────────
PubkeyAuthentication ${CONF_PUBKEY_AUTH}
PasswordAuthentication ${CONF_PASSWORD_AUTH}
PermitEmptyPasswords ${CONF_EMPTY_PASSWORDS}
KbdInteractiveAuthentication ${CONF_KBD_AUTH}
UsePAM yes

# ── Root login policy ─────────────────────────────────────────────────────────
PermitRootLogin ${CONF_PERMIT_ROOT_LOGIN}

# ── Authorized keys location ─────────────────────────────────────────────────
AuthorizedKeysFile .ssh/authorized_keys

# ── Brute-force mitigation ────────────────────────────────────────────────────
MaxAuthTries ${CONF_MAX_AUTH_TRIES}
MaxSessions 10
LoginGraceTime ${CONF_LOGIN_GRACE_TIME}

# ── Idle timeout (${idle_comment}) ──────────────────────────────────────────
ClientAliveInterval ${CONF_ALIVE_INTERVAL}
ClientAliveCountMax ${CONF_ALIVE_COUNT}

# ── Reduce attack surface ─────────────────────────────────────────────────────
X11Forwarding ${CONF_X11_FORWARDING}
AllowTcpForwarding ${CONF_TCP_FORWARDING}
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# ── Skip reverse DNS on connect (faster logins on LAN) ───────────────────────
UseDNS no
${algo_block}
DROPIN

    # Validate before reloading
    if sshd -t 2>/tmp/manage_ssh_sshd_test.err; then
        systemctl reload ssh 2>/dev/null \
            || systemctl reload sshd 2>/dev/null \
            || true
        ok "sshd configuration validated and service reloaded"
        rm -f /tmp/manage_ssh_sshd_test.err
    else
        err "sshd config validation FAILED — reverting to previous configuration."
        sed 's/^/    /' /tmp/manage_ssh_sshd_test.err >&2 || true
        rm -f /tmp/manage_ssh_sshd_test.err
        if [[ -f "$bak" ]]; then
            cp "$bak" "$SSHD_DROP_IN"
            ok "Restored previous drop-in from ${bak}"
        else
            rm -f "$SSHD_DROP_IN"
            ok "Removed invalid drop-in (no prior version to restore)"
        fi
        systemctl reload ssh 2>/dev/null \
            || systemctl reload sshd 2>/dev/null \
            || true
        warn "Configuration change aborted — previous configuration has been restored."
        return 1
    fi
}

# ── Action: edit SSH configuration ────────────────────────────────────────────
action_edit_config() {
    section "Edit SSH Configuration"
    printf '\n'

    if [[ "$SSH_PKG_INSTALLED" == "false" ]]; then
        warn "openssh-server is not installed."
        plain "Install it first before editing SSH configuration."
        return 0
    fi

    load_config_state

    local -a _edit_dirs=(
        "Port"
        "PubkeyAuthentication"
        "PasswordAuthentication"
        "KbdInteractiveAuthentication"
        "PermitRootLogin"
        "PermitEmptyPasswords"
        "MaxAuthTries"
        "LoginGraceTime"
        "ClientAliveInterval"
        "ClientAliveCountMax"
        "X11Forwarding"
        "AllowTcpForwarding"
        "Algorithms (modern set)"
    )

    _show_full_config_table

    local choice
    while true; do
        choice=$(ask_val "Setting number to edit (blank to cancel)" "")
        [[ -z "$choice" ]] && { info "Cancelled."; return 0; }
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#_edit_dirs[@]} )); then
            break
        fi
        warn "Enter a number between 1 and ${#_edit_dirs[@]}, or blank to cancel."
    done

    local idx=$(( choice - 1 ))
    local directive="${_edit_dirs[$idx]}"

    # Resolve current value from CONF_*
    local current
    case "$directive" in
        "Port")                         current="$CONF_PORT" ;;
        "PubkeyAuthentication")         current="$CONF_PUBKEY_AUTH" ;;
        "PasswordAuthentication")       current="$CONF_PASSWORD_AUTH" ;;
        "KbdInteractiveAuthentication") current="$CONF_KBD_AUTH" ;;
        "PermitRootLogin")              current="$CONF_PERMIT_ROOT_LOGIN" ;;
        "PermitEmptyPasswords")         current="$CONF_EMPTY_PASSWORDS" ;;
        "MaxAuthTries")                 current="$CONF_MAX_AUTH_TRIES" ;;
        "LoginGraceTime")               current="$CONF_LOGIN_GRACE_TIME" ;;
        "ClientAliveInterval")          current="$CONF_ALIVE_INTERVAL" ;;
        "ClientAliveCountMax")          current="$CONF_ALIVE_COUNT" ;;
        "X11Forwarding")                current="$CONF_X11_FORWARDING" ;;
        "AllowTcpForwarding")           current="$CONF_TCP_FORWARDING" ;;
        "Algorithms (modern set)")
            [[ "$CONF_SET_ALGORITHMS" == "true" ]] && current="yes" || current="no" ;;
    esac

    printf '\n'
    printf "    ${BOLD}%s${NC}  (current: ${CYAN}%s${NC})\n" "$directive" "$current"
    printf '\n'
    _print_directive_desc "$directive"
    printf '\n'

    # Prompt for new value; 'h' shows full help, blank cancels
    local new_val
    while true; do
        new_val=$(ask_val "New value (h for detailed help, blank to cancel)" "")
        [[ -z "$new_val" ]] && { info "Cancelled — no changes made."; return 0; }
        if [[ "${new_val,,}" == "h" ]]; then
            _print_directive_help "$directive"
            continue
        fi
        _validate_directive "$directive" "$new_val" && break
        # _validate_directive already printed the warning; loop back
    done

    # Normalise case for keyword values
    case "${new_val,,}" in
        yes|no|local|remote|all|prohibit-password|forced-commands-only)
            new_val="${new_val,,}" ;;
    esac

    # No-op check
    if [[ "${new_val,,}" == "${current,,}" ]]; then
        ok "${directive} is already '${new_val}' — nothing to change."
        return 0
    fi

    # Recommendation check — warn and require explicit confirmation to proceed
    if ! _is_recommended "$directive" "$new_val"; then
        printf '\n'
        warn "'${new_val}' is outside the recommended configuration for ${directive}."
        _print_recommendation_warning "$directive" "$new_val"
        printf '\n'
        ask "Proceed with this value anyway?" "n" \
            || { info "Cancelled — no changes made."; return 0; }
    fi

    # Apply: update CONF_* then write the drop-in
    case "$directive" in
        "Port")                         CONF_PORT="$new_val" ;;
        "PubkeyAuthentication")         CONF_PUBKEY_AUTH="$new_val" ;;
        "PasswordAuthentication")       CONF_PASSWORD_AUTH="$new_val" ;;
        "KbdInteractiveAuthentication") CONF_KBD_AUTH="$new_val" ;;
        "PermitRootLogin")              CONF_PERMIT_ROOT_LOGIN="$new_val" ;;
        "PermitEmptyPasswords")         CONF_EMPTY_PASSWORDS="$new_val" ;;
        "MaxAuthTries")                 CONF_MAX_AUTH_TRIES="$new_val" ;;
        "LoginGraceTime")               CONF_LOGIN_GRACE_TIME="$new_val" ;;
        "ClientAliveInterval")          CONF_ALIVE_INTERVAL="$new_val" ;;
        "ClientAliveCountMax")          CONF_ALIVE_COUNT="$new_val" ;;
        "X11Forwarding")                CONF_X11_FORWARDING="$new_val" ;;
        "AllowTcpForwarding")           CONF_TCP_FORWARDING="$new_val" ;;
        "Algorithms (modern set)")
            [[ "$new_val" == "yes" ]] && CONF_SET_ALGORITHMS=true || CONF_SET_ALGORITHMS=false ;;
    esac

    if write_config_dropin; then
        ok "${directive} changed to '${new_val}'"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    preflight_checks
    load_state

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                    manage-ssh.sh                    │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    # ── Interactive menu loop ─────────────────────────────────────────────────
    while true; do
        load_state
        show_state
        _show_menu

        local default; default=$(_menu_default)
        local choice
        if [[ -n "$default" ]]; then
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}, default ${default}]: " \
                choice || true
            choice="${choice:-$default}"
        else
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}]: " choice || true
        fi

        [[ -z "$choice" ]] && continue

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > _MENU_MAX )); then
            warn "Please enter 1–${_MENU_MAX}."
            continue
        fi

        local act="${_MENU_ACTIONS[$choice]:-}"
        case "$act" in
            install)    action_install ;;
            start)      action_start_service ;;
            enable)     action_enable_service ;;
            add_keys)   action_add_keys ;;
            remove_key) action_remove_key ;;
            edit_config) action_edit_config ;;
            exit)       info "Exiting."; break ;;
            *)          warn "Please enter 1–${_MENU_MAX}." ;;
        esac
        printf '\n'
    done
}

main
