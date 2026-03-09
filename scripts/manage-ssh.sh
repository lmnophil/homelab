#!/usr/bin/env bash
# ==============================================================================
# manage-ssh.sh  —  Install OpenSSH, manage the SSH service, and authorized keys
# ==============================================================================
#
# Usage:
#   sudo ./manage-ssh.sh [--dry-run] [--help]
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
            exit)       info "Exiting."; break ;;
            *)          warn "Please enter 1–${_MENU_MAX}." ;;
        esac
        printf '\n'
    done
}

main
