#!/usr/bin/env bash
# ==============================================================================
# harden-ssh.sh  —  Audit sshd configuration and apply security hardening
# ==============================================================================
#
# Usage:
#   sudo ./harden-ssh.sh [--dry-run] [--status] [--help]
#
# Checks performed:
#   PubkeyAuthentication    PasswordAuthentication   KbdInteractiveAuthentication
#   PermitRootLogin         PermitEmptyPasswords      MaxAuthTries
#   LoginGraceTime          Idle timeout              X11Forwarding
#   AllowTcpForwarding      Modern algorithms
#
# Fixes are collected interactively and written in a single drop-in:
#   /etc/ssh/sshd_config.d/99-hardened.conf
# The base sshd_config is never modified. A timestamped backup is taken before
# any write. sshd -t validates the config before reloading; the prior config is
# restored automatically on failure.
#
# Requirements: Ubuntu 22.04+ or Debian 11+. Run as root or via sudo.
#               --dry-run and --status do not require root.
# ==============================================================================
set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────────────
DRY_RUN="${DRY_RUN:-false}"
STATUS_MODE="${STATUS_MODE:-false}"

for _arg in "$@"; do
    case "$_arg" in
        --dry-run)  DRY_RUN=true     ;;
        --status)   STATUS_MODE=true ;;
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

# ── Status helpers ────────────────────────────────────────────────────────────
STATUS_PASS=()
STATUS_FAIL=()
status_pass() { STATUS_PASS+=("$1|${2:-}"); }
status_fail() { STATUS_FAIL+=("$1|${2:-}"); }

_emit_status() {
    printf '%s\n' "$(basename "$0" .sh)"
    local entry id detail
    for entry in "${STATUS_PASS[@]+"${STATUS_PASS[@]}"}"; do
        id="${entry%%|*}"; detail="${entry#*|}"
        [[ -n "$detail" ]] \
            && printf '  PASS  %s  %s\n' "$id" "$detail" \
            || printf '  PASS  %s\n'    "$id"
    done
    for entry in "${STATUS_FAIL[@]+"${STATUS_FAIL[@]}"}"; do
        id="${entry%%|*}"; detail="${entry#*|}"
        printf '  FAIL  %s\n' "$id"
        [[ -n "$detail" ]] && printf '        %s\n' "$detail"
    done
}

header() {
    local title=" $1 " w=60
    local pad=$(( (w - ${#title}) / 2 ))
    local line; printf -v line '%*s' "$w" ''; line="${line// /─}"
    printf "\n${BLUE}${BOLD}%s\n" "$line"
    printf "%${pad}s%s\n" "" "$title"
    printf "%s${NC}\n\n" "$line"
}

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
    [[ $EUID -eq 0 || "$DRY_RUN" == "true" || "$STATUS_MODE" == "true" ]] \
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

    # ── openssh-server: offer to install if missing ───────────────────────────
    if ! dpkg-query -W -f='${Status}' openssh-server 2>/dev/null \
            | grep -q "install ok installed"; then
        warn "openssh-server is not installed."
        if [[ "$DRY_RUN" == "true" || "$STATUS_MODE" == "true" ]]; then
            die "openssh-server is required. Install it first: sudo apt install openssh-server"
        fi
        if ask "Install openssh-server now?" "y"; then
            info "Running: apt-get install -y openssh-server"
            apt-get install -y openssh-server \
                || die "Installation failed. Install openssh-server manually and re-run."
            ok "openssh-server installed."
        else
            die "openssh-server is required. Install it and re-run this script."
        fi
    fi

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

# ── Desired configuration (populated in compute_state, modified by checks) ───
CONF_PORT="22"
CONF_PUBKEY_AUTH="yes"
CONF_PASSWORD_AUTH="no"
CONF_KBD_AUTH="no"
CONF_PERMIT_ROOT_LOGIN="no"
CONF_EMPTY_PASSWORDS="no"
CONF_MAX_AUTH_TRIES="3"
CONF_LOGIN_GRACE_TIME="30"
CONF_ALIVE_INTERVAL="300"
CONF_ALIVE_COUNT="2"
CONF_X11_FORWARDING="no"
CONF_TCP_FORWARDING="no"
CONF_SET_ALGORITHMS=false

DIRTY=false

# ── Check tracking ────────────────────────────────────────────────────────────
CHECKS_PASSED=()
CHECKS_FIXED=()
CHECKS_DECLINED=()

# ── Proposed-fix arrays (populated by detect_issues) ─────────────────────────
# Parallel arrays; one entry per issue found.
PROP_ID=()        # internal key, e.g. "password_auth"
PROP_NAME=()      # display name, e.g. "PasswordAuthentication"
PROP_CURRENT=()   # current effective value
PROP_TARGET=()    # recommended secure value
PROP_REASON=()    # one-line rationale
PROP_ACCEPTED=()  # "true" / "false" — filled by review_proposed_changes

# Add one proposed fix to the arrays (default: accepted).
_propose() {
    local id="$1" name="$2" current="$3" target="$4" reason="$5"
    PROP_ID+=("$id")
    PROP_NAME+=("$name")
    PROP_CURRENT+=("$current")
    PROP_TARGET+=("$target")
    PROP_REASON+=("$reason")
    PROP_ACCEPTED+=("true")
}

# ── sshd_eff_val <key> ────────────────────────────────────────────────────────
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

# ── compute_state ─────────────────────────────────────────────────────────────
compute_state() {
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

# ── check_all_pass ────────────────────────────────────────────────────────────
check_all_pass() {
    [[ "${CONF_PUBKEY_AUTH,,}"       == "yes" ]] || return 1
    [[ "${CONF_PASSWORD_AUTH,,}"     == "no"  ]] || return 1
    [[ "${CONF_KBD_AUTH,,}"          == "no"  ]] || return 1
    local rl="${CONF_PERMIT_ROOT_LOGIN,,}"
    [[ "$rl" == "no" || "$rl" == "prohibit-password" ]] || return 1
    [[ "${CONF_EMPTY_PASSWORDS,,}"   == "no"  ]] || return 1
    (( CONF_MAX_AUTH_TRIES  <= 5    )) || return 1
    local lgt="$CONF_LOGIN_GRACE_TIME"
    [[ "$lgt" =~ ^[0-9]+$ ]] && (( lgt > 0 && lgt <= 60 )) || return 1
    (( CONF_ALIVE_INTERVAL   >  0   )) || return 1
    (( CONF_ALIVE_COUNT      >  0   )) || return 1
    [[ "${CONF_X11_FORWARDING,,}"    == "no"  ]] || return 1
    [[ "${CONF_TCP_FORWARDING,,}"    == "no"  ]] || return 1
    [[ "$CONF_SET_ALGORITHMS"        == "true" ]] || return 1
    return 0
}

# ── show_state ────────────────────────────────────────────────────────────────
show_state() {
    local div_key div_val
    printf -v div_key '%*s' 36 ''; div_key="${div_key// /─}"
    printf -v div_val '%*s' 20 ''; div_val="${div_val// /─}"

    printf "    ${BOLD}%-36s %s${NC}\n" "Setting" "Effective value"
    printf "    %s %s\n" "$div_key" "$div_val"

    _show_row "PubkeyAuthentication"         "$CONF_PUBKEY_AUTH"       "yes"  "no"
    _show_row "PasswordAuthentication"       "$CONF_PASSWORD_AUTH"     "no"   "yes"
    _show_row "KbdInteractiveAuthentication" "$CONF_KBD_AUTH"          "no"   "yes"
    _show_row "PermitRootLogin"              "$CONF_PERMIT_ROOT_LOGIN" ""     "yes"
    _show_row "PermitEmptyPasswords"         "$CONF_EMPTY_PASSWORDS"   "no"   "yes"
    _show_row "MaxAuthTries"                 "$CONF_MAX_AUTH_TRIES"    ""     ""
    _show_row "LoginGraceTime"               "$CONF_LOGIN_GRACE_TIME"  ""     ""
    _show_row "ClientAliveInterval"          "$CONF_ALIVE_INTERVAL"    ""     ""
    _show_row "ClientAliveCountMax"          "$CONF_ALIVE_COUNT"       ""     ""
    _show_row "X11Forwarding"               "$CONF_X11_FORWARDING"     "no"   "yes"
    _show_row "AllowTcpForwarding"           "$CONF_TCP_FORWARDING"    "no"   ""
    _show_row "Algorithms (explicit)"        \
        "$( [[ "$CONF_SET_ALGORITHMS" == "true" ]] && printf 'set' || printf 'unset' )" \
        "set" ""

    printf '\n'

    local dv_u dv_k dv_h
    printf -v dv_u '%*s' 18 ''; dv_u="${dv_u// /─}"
    printf -v dv_k '%*s' 5  ''; dv_k="${dv_k// /─}"
    printf -v dv_h '%*s' 28 ''; dv_h="${dv_h// /─}"

    printf "    ${BOLD}%-18s %-5s %s${NC}\n" "Sudo user" "Keys" "Home"
    printf "    %s %s %s\n" "$dv_u" "$dv_k" "$dv_h"

    local sudo_members; sudo_members=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n')
    local any_sudo=false
    while IFS= read -r member; do
        [[ -z "$member" || "$member" == "root" ]] && continue
        any_sudo=true
        local _home; _home=$(getent passwd "$member" 2>/dev/null | cut -d: -f6 || true)
        [[ -z "$_home" ]] && continue
        local _ak="${_home}/.ssh/authorized_keys"
        local _kc=0
        if [[ -f "$_ak" ]]; then
            _kc=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$_ak" 2>/dev/null) || _kc=0
        fi
        if [[ "$_kc" -gt 0 ]]; then
            printf "    ${GREEN}%-18s %-5s${NC} %s\n" "$member" "$_kc" "$_home"
        else
            printf "    ${RED}%-18s ${DIM}%-5s${NC} %s\n" "$member" "0" "$_home"
        fi
    done <<< "$sudo_members"

    if [[ "$any_sudo" == "false" ]]; then
        printf "    ${YELLOW}%s${NC}\n" "(no non-root sudo group members)"
    fi

    printf '\n'
}

_show_row() {
    local key="$1" val="$2" good="$3" bad="$4"
    local color="$YELLOW"
    local lval="${val,,}"
    [[ -n "$good" && "${lval}" == "${good,,}" ]] && color="$GREEN"
    [[ -n "$bad"  && "${lval}" == "${bad,,}"  ]] && color="$RED"
    if [[ "$key" == "PermitRootLogin" ]]; then
        if [[ "$lval" == "no" || "$lval" == "prohibit-password" ]]; then
            color="$GREEN"
        elif [[ "$lval" == "yes" ]]; then
            color="$RED"
        fi
    fi
    if [[ "$key" == "MaxAuthTries" && "$val" =~ ^[0-9]+$ ]]; then
        (( val <= 5 )) && color="$GREEN" || color="$RED"
    fi
    if [[ "$key" == "LoginGraceTime" && "$val" =~ ^[0-9]+$ ]]; then
        (( val <= 60 )) && color="$GREEN" || color="$YELLOW"
    fi
    if [[ "$key" == "ClientAliveInterval" && "$val" =~ ^[0-9]+$ ]]; then
        (( val > 0 )) && color="$GREEN" || color="$RED"
    fi
    if [[ "$key" == "ClientAliveCountMax" && "$val" =~ ^[0-9]+$ ]]; then
        (( val > 0 )) && color="$GREEN" || color="$YELLOW"
    fi
    printf "    ${color}%-36s %s${NC}\n" "$key" "$val"
}

# ── show_key_help ─────────────────────────────────────────────────────────────
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

# ── write_authorized_keys ─────────────────────────────────────────────────────
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
        printf '\n# Source: %s  (added %s by harden-ssh.sh)\n' \
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

# ══════════════════════════════════════════════════════════════════════════════
# DETECTION FUNCTIONS
# Populate STATUS_PASS/STATUS_FAIL (--status mode) or PROP_* arrays (normal).
# No interactive prompting here.
# ══════════════════════════════════════════════════════════════════════════════

sudo_ssh_user_exists() {
    local member
    while IFS= read -r member; do
        [[ -z "$member" || "$member" == "root" ]] && continue
        local _home; _home=$(getent passwd "$member" 2>/dev/null | cut -d: -f6 || true)
        [[ -z "$_home" ]] && continue
        grep -q "^ssh-\|^ecdsa-\|^sk-" "${_home}/.ssh/authorized_keys" 2>/dev/null \
            && return 0
    done < <( getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' )
    return 1
}

detect_pubkey_auth() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_PUBKEY_AUTH,,}" == "yes" ]] \
            && status_pass "pubkey_auth" \
            || status_fail "pubkey_auth" \
                "PubkeyAuthentication is '${CONF_PUBKEY_AUTH}'  expected: yes"
        return
    fi
    [[ "${CONF_PUBKEY_AUTH,,}" == "yes" ]] && return
    _propose "pubkey_auth" "PubkeyAuthentication" "$CONF_PUBKEY_AUTH" "yes" \
        "Key-based login is currently disabled; password lockout won't be safe without it"
}

detect_password_auth() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_PASSWORD_AUTH,,}" == "no" ]] \
            && status_pass "password_auth" \
            || status_fail "password_auth" \
                "PasswordAuthentication is '${CONF_PASSWORD_AUTH}'  expected: no"
        return
    fi
    [[ "${CONF_PASSWORD_AUTH,,}" == "no" ]] && return
    _propose "password_auth" "PasswordAuthentication" "$CONF_PASSWORD_AUTH" "no" \
        "Password auth exposes the server to brute-force attacks"
}

detect_kbd_auth() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_KBD_AUTH,,}" == "no" ]] \
            && status_pass "kbd_auth" \
            || status_fail "kbd_auth" \
                "KbdInteractiveAuthentication is '${CONF_KBD_AUTH}'  expected: no"
        return
    fi
    [[ "${CONF_KBD_AUTH,,}" == "no" ]] && return
    _propose "kbd_auth" "KbdInteractiveAuthentication" "$CONF_KBD_AUTH" "no" \
        "Can allow password-style prompts even when PasswordAuthentication is off"
}

detect_permit_root_login() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        local _cur="${CONF_PERMIT_ROOT_LOGIN,,}"
        if [[ "$_cur" == "no" || "$_cur" == "prohibit-password" ]]; then
            status_pass "permit_root_login" "$CONF_PERMIT_ROOT_LOGIN"
        else
            status_fail "permit_root_login" \
                "PermitRootLogin is '${CONF_PERMIT_ROOT_LOGIN}'  expected: no or prohibit-password"
        fi
        return
    fi
    local cur="${CONF_PERMIT_ROOT_LOGIN,,}"
    [[ "$cur" == "no" || "$cur" == "prohibit-password" ]] && return
    _propose "permit_root_login" "PermitRootLogin" "$CONF_PERMIT_ROOT_LOGIN" "no" \
        "Direct root login increases blast radius if a key is ever compromised"
}

detect_empty_passwords() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_EMPTY_PASSWORDS,,}" == "no" ]] \
            && status_pass "permit_empty_passwords" \
            || status_fail "permit_empty_passwords" \
                "currently: ${CONF_EMPTY_PASSWORDS}  expected: no"
        return
    fi
    [[ "${CONF_EMPTY_PASSWORDS,,}" == "no" ]] && return
    _propose "empty_passwords" "PermitEmptyPasswords" "$CONF_EMPTY_PASSWORDS" "no" \
        "Accounts with empty passwords could be accessed without any credential"
}

detect_max_auth_tries() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        local _cur="$CONF_MAX_AUTH_TRIES"
        if [[ "$_cur" =~ ^[0-9]+$ ]] && (( _cur <= 5 )); then
            status_pass "max_auth_tries" "${_cur} (≤5)"
        else
            status_fail "max_auth_tries" "currently: ${_cur}  expected: ≤5"
        fi
        return
    fi
    local cur="$CONF_MAX_AUTH_TRIES"
    [[ "$cur" =~ ^[0-9]+$ ]] && (( cur <= 5 )) && return
    _propose "max_auth_tries" "MaxAuthTries" "$cur" "3" \
        "High limit lets attackers try many keys per connection (recommended: 3–5)"
}

detect_login_grace_time() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        local _cur="$CONF_LOGIN_GRACE_TIME"
        if [[ "$_cur" =~ ^[0-9]+$ ]] && (( _cur > 0 && _cur <= 60 )); then
            status_pass "login_grace_time" "${_cur}s (≤60)"
        else
            status_fail "login_grace_time" "currently: ${_cur}s  expected: 1–60"
        fi
        return
    fi
    local cur="$CONF_LOGIN_GRACE_TIME"
    [[ "$cur" =~ ^[0-9]+$ ]] && (( cur > 0 && cur <= 60 )) && return
    _propose "login_grace_time" "LoginGraceTime" "$cur" "30" \
        "Long grace period lets unauthenticated connections tie up sshd slots"
}

detect_idle_timeout() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        local _iv="$CONF_ALIVE_INTERVAL" _ic="$CONF_ALIVE_COUNT"
        if [[ "$_iv" =~ ^[0-9]+$ && "$_ic" =~ ^[0-9]+$ ]] \
            && (( _iv > 0 && _ic > 0 )); then
            local _mins=$(( (_iv * _ic + 59) / 60 ))
            status_pass "idle_timeout" "~${_mins}min (${_iv}s × ${_ic})"
        else
            status_fail "idle_timeout" \
                "ClientAliveInterval=${_iv}  ClientAliveCountMax=${_ic}  expected: both >0"
        fi
        return
    fi
    local iv="$CONF_ALIVE_INTERVAL" ic="$CONF_ALIVE_COUNT"
    [[ "$iv" =~ ^[0-9]+$ && "$ic" =~ ^[0-9]+$ ]] && (( iv > 0 && ic > 0 )) && return
    _propose "idle_timeout" "ClientAlive (timeout)" \
        "Interval=${iv} Count=${ic}" "Interval=300 Count=2" \
        "Idle sessions stay open indefinitely — ~10min timeout recommended"
}

detect_x11_forwarding() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_X11_FORWARDING,,}" == "no" ]] \
            && status_pass "x11_forwarding" \
            || status_fail "x11_forwarding" "currently: ${CONF_X11_FORWARDING}  expected: no"
        return
    fi
    [[ "${CONF_X11_FORWARDING,,}" == "no" ]] && return
    _propose "x11_forwarding" "X11Forwarding" "$CONF_X11_FORWARDING" "no" \
        "Exposes the server's X display and can allow session hijacking"
}

detect_tcp_forwarding() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "${CONF_TCP_FORWARDING,,}" == "no" ]] \
            && status_pass "tcp_forwarding" \
            || status_fail "tcp_forwarding" "currently: ${CONF_TCP_FORWARDING}  expected: no"
        return
    fi
    [[ "${CONF_TCP_FORWARDING,,}" == "no" ]] && return
    _propose "tcp_forwarding" "AllowTcpForwarding" "$CONF_TCP_FORWARDING" "no" \
        "Enables port-forwarding and SOCKS proxying through this host"
}

detect_algorithms() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        [[ "$CONF_SET_ALGORITHMS" == "true" ]] \
            && status_pass "algorithms" \
            || status_fail "algorithms" "no explicit algorithm stanzas in drop-in"
        return
    fi
    [[ "$CONF_SET_ALGORITHMS" == "true" ]] && return
    _propose "algorithms" "Crypto algorithms" "(none set explicitly)" \
        "ed25519, rsa-sha2-*, chacha20, aes-gcm, etm MACs" \
        "Locks in the modern cipher/kex set; prevents regression after upgrades"
}

# ── detect_issues ──────────────────────────────────────────────────────────────
# Runs all detectors; populates PROP_* arrays.
detect_issues() {
    detect_pubkey_auth
    detect_password_auth
    detect_kbd_auth
    detect_permit_root_login
    detect_empty_passwords
    detect_max_auth_tries
    detect_login_grace_time
    detect_idle_timeout
    detect_x11_forwarding
    detect_tcp_forwarding
    detect_algorithms
}

# ── show_proposed_changes ──────────────────────────────────────────────────────
# Prints a numbered table of all proposed fixes.
show_proposed_changes() {
    local n="${#PROP_ID[@]}"
    if [[ "$n" -eq 0 ]]; then return; fi

    local w_name=32 w_cur=24 w_tgt=32
    local div_n    div_name    div_cur    div_tgt
    printf -v div_n    '%*s' 3       ''; div_n="${div_n// /─}"
    printf -v div_name '%*s' $w_name ''; div_name="${div_name// /─}"
    printf -v div_cur  '%*s' $w_cur  ''; div_cur="${div_cur// /─}"
    printf -v div_tgt  '%*s' $w_tgt  ''; div_tgt="${div_tgt// /─}"

    printf "\n    ${BOLD}%-3s  %-${w_name}s %-${w_cur}s %s${NC}\n" \
        "#" "Setting" "Current" "Proposed"
    printf "    %s  %s %s %s\n" "$div_n" "$div_name" "$div_cur" "$div_tgt"

    local i
    for i in "${!PROP_ID[@]}"; do
        local accepted="${PROP_ACCEPTED[$i]}"
        local marker color
        if [[ "$accepted" == "true" ]]; then
            marker="✓"; color="$GREEN"
        else
            marker="✗"; color="$RED"
        fi
        printf "    ${color}%-3s${NC}  ${BOLD}%-${w_name}s${NC} ${RED}%-${w_cur}s${NC} ${GREEN}%s${NC}\n" \
            "${marker} $((i+1))" \
            "${PROP_NAME[$i]}" \
            "${PROP_CURRENT[$i]}" \
            "${PROP_TARGET[$i]}"
        printf "         ${DIM}%s${NC}\n" "${PROP_REASON[$i]}"
    done
    printf '\n'
}

# ── review_proposed_changes ────────────────────────────────────────────────────
# Shows the proposed-fix table, then lets the user:
#   [A]ccept all  — accept every proposed change as-is
#   [R]eview      — step through each fix, with option to edit the target value
#   [N]one        — reject all changes
review_proposed_changes() {
    local n="${#PROP_ID[@]}"
    if [[ "$n" -eq 0 ]]; then
        ok "No issues detected — nothing to propose."
        return
    fi

    header "Proposed Changes"
    show_proposed_changes

    # Warn about lockout risk when password auth would be disabled without a key
    local has_pwd_fix=false
    local i
    for i in "${!PROP_ID[@]}"; do
        [[ "${PROP_ID[$i]}" == "password_auth" ]] && has_pwd_fix=true && break
    done
    if [[ "$has_pwd_fix" == "true" ]] && ! sudo_ssh_user_exists; then
        printf '\n'
        warn "No non-root sudoer with an SSH key exists on this system."
        warn "Disabling password auth without one may lock you out."
        plain "Consider adding a key for a sudo user first (see check_sudo_ssh_user)."
        printf '\n'
    fi

    printf "    ${CYAN}[A]${NC}  Accept all proposed changes\n"
    printf "    ${CYAN}[R]${NC}  Review each change individually\n"
    printf "    ${CYAN}[N]${NC}  Reject all — make no changes\n"
    printf '\n'

    local choice
    while true; do
        read -rp "    ${YELLOW}>  ${NC}Choice [A/r/n]: " choice || true
        choice="${choice:-a}"
        case "${choice,,}" in
            a)
                # All already default to accepted=true
                ok "Accepting all ${n} proposed change(s)."
                break
                ;;
            r)
                _review_each
                break
                ;;
            n)
                for i in "${!PROP_ID[@]}"; do
                    PROP_ACCEPTED[$i]="false"
                done
                warn "All changes rejected — sshd configuration will not be modified."
                break
                ;;
            *)
                warn "Enter A, R, or N."
                ;;
        esac
    done
}

# ── _review_each ───────────────────────────────────────────────────────────────
# Steps through each proposed fix; user can accept, edit the target value,
# or reject each one individually.
_review_each() {
    local i n="${#PROP_ID[@]}"
    printf '\n'
    info "Reviewing ${n} proposed change(s). Press Enter to accept each, or choose an option."
    printf '\n'

    for i in "${!PROP_ID[@]}"; do
        local id="${PROP_ID[$i]}"
        local name="${PROP_NAME[$i]}"
        local cur="${PROP_CURRENT[$i]}"
        local tgt="${PROP_TARGET[$i]}"
        local reason="${PROP_REASON[$i]}"

        printf "    ${BOLD}── $((i+1))/${n}  ${name}${NC}\n"
        printf "       ${DIM}%s${NC}\n" "$reason"
        printf "       Current:  ${RED}%s${NC}\n" "$cur"
        printf "       Proposed: ${GREEN}%s${NC}\n" "$tgt"
        printf '\n'
        printf "       ${CYAN}[Y]${NC}  Accept  "
        printf "  ${CYAN}[E]${NC}  Edit proposed value  "
        printf "  ${CYAN}[N]${NC}  Skip\n"

        local item_choice
        while true; do
            read -rp "       ${YELLOW}>  ${NC}[Y/e/n]: " item_choice || true
            item_choice="${item_choice:-y}"
            case "${item_choice,,}" in
                y|yes|"")
                    PROP_ACCEPTED[$i]="true"
                    ok "  Accepted: ${name} → ${tgt}"
                    break
                    ;;
                e|edit)
                    local new_val
                    new_val=$(ask_val "New value for ${name}" "$tgt")
                    if [[ -z "$new_val" ]]; then
                        warn "  Value cannot be empty — keeping proposed value '${tgt}'."
                        PROP_ACCEPTED[$i]="true"
                    else
                        PROP_TARGET[$i]="$new_val"
                        PROP_ACCEPTED[$i]="true"
                        ok "  Accepted: ${name} → ${new_val}"
                    fi
                    break
                    ;;
                n|no|skip)
                    PROP_ACCEPTED[$i]="false"
                    warn "  Skipped: ${name} remains ${cur}"
                    break
                    ;;
                *)
                    warn "  Enter Y, E, or N."
                    ;;
            esac
        done
        printf '\n'
    done

    # After review, show the final table
    header "Review Summary"
    show_proposed_changes
}

# ── apply_accepted_fixes ──────────────────────────────────────────────────────
# Translates accepted PROP_* entries into CONF_* variable updates, sets DIRTY.
apply_accepted_fixes() {
    local i
    for i in "${!PROP_ID[@]}"; do
        [[ "${PROP_ACCEPTED[$i]}" != "true" ]] && continue

        local id="${PROP_ID[$i]}"
        local tgt="${PROP_TARGET[$i]}"
        local name="${PROP_NAME[$i]}"

        case "$id" in
            pubkey_auth)
                CONF_PUBKEY_AUTH="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("PubkeyAuthentication set to ${tgt}")
                ;;
            password_auth)
                CONF_PASSWORD_AUTH="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("PasswordAuthentication set to ${tgt}")
                ;;
            kbd_auth)
                CONF_KBD_AUTH="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("KbdInteractiveAuthentication set to ${tgt}")
                ;;
            permit_root_login)
                CONF_PERMIT_ROOT_LOGIN="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("PermitRootLogin set to ${tgt}")
                ;;
            empty_passwords)
                CONF_EMPTY_PASSWORDS="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("PermitEmptyPasswords set to ${tgt}")
                ;;
            max_auth_tries)
                CONF_MAX_AUTH_TRIES="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("MaxAuthTries set to ${tgt}")
                ;;
            login_grace_time)
                CONF_LOGIN_GRACE_TIME="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("LoginGraceTime set to ${tgt}s")
                ;;
            idle_timeout)
                # tgt is "Interval=N Count=M" — parse it
                local iv ic
                iv=$(printf '%s' "$tgt" | grep -oP '(?<=Interval=)\d+')
                ic=$(printf '%s' "$tgt" | grep -oP '(?<=Count=)\d+')
                CONF_ALIVE_INTERVAL="${iv:-300}"
                CONF_ALIVE_COUNT="${ic:-2}"
                DIRTY=true
                CHECKS_FIXED+=("Idle timeout set to ${CONF_ALIVE_INTERVAL}s × ${CONF_ALIVE_COUNT}")
                ;;
            x11_forwarding)
                CONF_X11_FORWARDING="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("X11Forwarding set to ${tgt}")
                ;;
            tcp_forwarding)
                CONF_TCP_FORWARDING="$tgt"
                DIRTY=true
                CHECKS_FIXED+=("AllowTcpForwarding set to ${tgt}")
                ;;
            algorithms)
                CONF_SET_ALGORITHMS=true
                DIRTY=true
                CHECKS_FIXED+=("Modern algorithm stanzas added")
                ;;
        esac
    done

    # Collect declined items
    for i in "${!PROP_ID[@]}"; do
        [[ "${PROP_ACCEPTED[$i]}" == "false" ]] || continue
        CHECKS_DECLINED+=("${PROP_NAME[$i]} not changed (skipped)")
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# check_sudo_ssh_user — interactive key-provisioning pre-condition
# Unchanged from original (no detection-mode needed; doesn't write sshd config)
# ══════════════════════════════════════════════════════════════════════════════

check_sudo_ssh_user() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if sudo_ssh_user_exists; then
            local _m _found=()
            while IFS= read -r _m; do
                [[ -z "$_m" || "$_m" == "root" ]] && continue
                local _h; _h=$(getent passwd "$_m" 2>/dev/null | cut -d: -f6 || true)
                [[ -z "$_h" ]] && continue
                grep -q "^ssh-\|^ecdsa-\|^sk-" "${_h}/.ssh/authorized_keys" \
                    2>/dev/null || continue
                _found+=("$_m")
            done < <( getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' )
            local _str; _str=$(IFS=', '; printf '%s' "${_found[*]}")
            status_pass "sudo_ssh_key" "$_str"
        else
            local _has_members=false _m
            while IFS= read -r _m; do
                [[ -z "$_m" || "$_m" == "root" ]] && continue
                getent passwd "$_m" &>/dev/null && _has_members=true && break
            done < <( getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' )
            if [[ "$_has_members" == "false" ]]; then
                status_fail "sudo_ssh_key" \
                    "sudo group has no non-root members — add one first"
            else
                status_fail "sudo_ssh_key" \
                    "no non-root sudo member has an authorized_keys entry"
            fi
        fi
        return 0
    fi

    if sudo_ssh_user_exists; then
        local _member _found_names=()
        while IFS= read -r _member; do
            [[ -z "$_member" || "$_member" == "root" ]] && continue
            local _home; _home=$(getent passwd "$_member" 2>/dev/null | cut -d: -f6 || true)
            [[ -z "$_home" ]] && continue
            grep -q "^ssh-\|^ecdsa-\|^sk-" "${_home}/.ssh/authorized_keys" 2>/dev/null \
                || continue
            _found_names+=("$_member")
        done < <( getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' )
        local _names_str; _names_str=$(IFS=', '; printf '%s' "${_found_names[*]}")
        ok "Non-root sudoer(s) with SSH key: ${_names_str}"
        CHECKS_PASSED+=("Non-root sudoer(s) with SSH key (${_names_str})")
        return 0
    fi

    printf '\n'
    warn "No non-root member of the sudo group has an authorized SSH key."
    plain "If you disable password auth or restrict root login without a working"
    plain "key-based sudo user in place, you risk losing all SSH access."
    printf '\n'

    local sudo_users=() sudo_homes=()
    while IFS= read -r _m; do
        [[ -z "$_m" || "$_m" == "root" ]] && continue
        local _h; _h=$(getent passwd "$_m" 2>/dev/null | cut -d: -f6 || true)
        [[ -z "$_h" ]] && continue
        sudo_users+=("$_m")
        sudo_homes+=("$_h")
    done < <( getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' )

    if [[ ${#sudo_users[@]} -eq 0 ]]; then
        warn "The sudo group has no non-root members — cannot add keys here."
        plain "Add a user to the sudo group first, then re-run this script."
        CHECKS_DECLINED+=("No non-root sudoer exists — key setup skipped")
        return 0
    fi

    if ! ask "Add an SSH key for a sudo user now?" "y"; then
        warn "Skipped — no authorized key added. This is a lockout risk."
        CHECKS_DECLINED+=("Non-root sudoer SSH key not added (risk accepted)")
        return 0
    fi

    printf '\n'
    local dv; printf -v dv '%*s' 50 ''; printf "    %s\n" "${dv// /─}"
    printf "    ${BOLD}%-4s %-18s %s${NC}\n" "#" "Username" "Home"
    printf "    %s\n" "${dv// /─}"
    local _i
    for _i in "${!sudo_users[@]}"; do
        local _ak="${sudo_homes[$_i]}/.ssh/authorized_keys"
        local _kc=0
        [[ -f "$_ak" ]] && _kc=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$_ak" 2>/dev/null || printf '0')
        printf "    %-4s %-18s %s  ${DIM}(%s key(s))${NC}\n" \
            "$((_i+1))" "${sudo_users[$_i]}" "${sudo_homes[$_i]}" "$_kc"
    done
    printf '\n'

    local key_user="" key_home=""
    while true; do
        local raw_sel; raw_sel=$(ask_val "User (number or username)" "1")
        if [[ "$raw_sel" =~ ^[0-9]+$ ]]; then
            local idx=$(( raw_sel - 1 ))
            if [[ "$idx" -ge 0 && "$idx" -lt "${#sudo_users[@]}" ]]; then
                key_user="${sudo_users[$idx]}"
                key_home="${sudo_homes[$idx]}"
                break
            else
                warn "No user with number ${raw_sel} — try again."
            fi
        else
            local found=false
            for _i in "${!sudo_users[@]}"; do
                if [[ "${sudo_users[$_i]}" == "$raw_sel" ]]; then
                    key_user="$raw_sel"
                    key_home="${sudo_homes[$_i]}"
                    found=true; break
                fi
            done
            [[ "$found" == "true" ]] && break
            warn "'${raw_sel}' is not a sudo group member — try again."
        fi
    done

    local auth_file="${key_home}/.ssh/authorized_keys"

    if [[ "$URL_FETCH_AVAILABLE" == "true" ]]; then
        info "Tip: GitHub and GitLab expose all your keys at one URL:"
        plain "  https://github.com/USERNAME.keys   or   https://gitlab.com/USERNAME.keys"
    else
        warn "URL key fetching is disabled — neither curl nor wget is installed."
        plain "Install curl to enable it:  apt install curl"
    fi
    printf '\n'

    local key_added=false
    while true; do
        local cur_kc=0
        [[ -f "$auth_file" ]] && cur_kc=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$auth_file" 2>/dev/null || printf '0')
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
                    if ! keys_block=$(curl -fsSL --max-time 15 "$url" 2>/tmp/harden_ssh_fetch.err); then
                        warn "curl failed to fetch keys from ${url}"
                        sed 's/^/        /' /tmp/harden_ssh_fetch.err >&2 || true
                        rm -f /tmp/harden_ssh_fetch.err
                        continue
                    fi
                else
                    if ! keys_block=$(wget -qO- --timeout=15 "$url" 2>/tmp/harden_ssh_fetch.err); then
                        warn "wget failed to fetch keys from ${url}"
                        sed 's/^/        /' /tmp/harden_ssh_fetch.err >&2 || true
                        rm -f /tmp/harden_ssh_fetch.err
                        continue
                    fi
                fi
                rm -f /tmp/harden_ssh_fetch.err
                local n; n=$(printf '%s\n' "$keys_block" | grep -c "^ssh-\|^ecdsa-\|^sk-" || printf '0')
                if [[ "$n" -eq 0 ]]; then
                    warn "No valid SSH public keys found at that URL."; continue
                fi
                ok "Fetched ${n} key(s)"
                local label; label=$(printf '%s' "$url" | sed 's|.*/||; s|\.keys$||')
                write_authorized_keys "$key_user" "$key_home" "$auth_file" "$keys_block" "$label"
                key_added=true
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
                key_added=true
                ;;
            d|"")
                break
                ;;
            *)
                warn "Unknown option '${action_choice}' — enter u, p, h, or d."
                ;;
        esac
    done

    if [[ "$key_added" == "true" ]] || sudo_ssh_user_exists; then
        CHECKS_FIXED+=("SSH key added for sudo user ${key_user}")
    else
        warn "No keys were added for ${key_user}. This is a lockout risk."
        CHECKS_DECLINED+=("Non-root sudoer SSH key not added (risk accepted)")
    fi
}

# ── apply_fixes ───────────────────────────────────────────────────────────────
apply_fixes() {
    section "Writing Hardening Drop-in"
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
        return
    fi

    mkdir -p /etc/ssh/sshd_config.d

    local ts; ts=$(date '+%Y%m%d_%H%M%S')
    local bak="${SSHD_DROP_IN}.bak.${ts}"
    if [[ -f "$SSHD_DROP_IN" ]]; then
        cp "$SSHD_DROP_IN" "$bak"
        ok "Backed up existing drop-in → ${bak}"
    fi

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

    local idle_comment
    if (( CONF_ALIVE_INTERVAL > 0 && CONF_ALIVE_COUNT > 0 )); then
        local _mins=$(( (CONF_ALIVE_INTERVAL * CONF_ALIVE_COUNT + 59) / 60 ))
        idle_comment="disconnects idle sessions after ~${_mins}min"
    else
        idle_comment="idle timeout disabled"
    fi

    cat > "$SSHD_DROP_IN" << DROPIN
# ── SSH Hardening drop-in ─────────────────────────────────────────────────────
# Written by harden-ssh.sh on $(date)
# Overrides /etc/ssh/sshd_config without modifying it.
# Re-run harden-ssh.sh to update.

# ── Port ──────────────────────────────────────────────────────────────────────
Port ${CONF_PORT}

# ── Authentication: public key only ──────────────────────────────────────────
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

    if sshd -t 2>/tmp/harden_ssh_sshd_test.err; then
        systemctl reload ssh 2>/dev/null \
            || systemctl reload sshd 2>/dev/null \
            || true
        ok "sshd configuration validated and service reloaded"
        rm -f /tmp/harden_ssh_sshd_test.err
    else
        err "sshd config validation FAILED — reverting to previous configuration."
        sed 's/^/    /' /tmp/harden_ssh_sshd_test.err >&2 || true
        rm -f /tmp/harden_ssh_sshd_test.err
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
        die "Hardening aborted — your original configuration has been restored."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    preflight_checks
    compute_state

    # ── --status mode ──────────────────────────────────────────────────────────
    if [[ "$STATUS_MODE" == "true" ]]; then
        check_sudo_ssh_user
        detect_pubkey_auth
        detect_password_auth
        detect_kbd_auth
        detect_permit_root_login
        detect_empty_passwords
        detect_max_auth_tries
        detect_login_grace_time
        detect_idle_timeout
        detect_x11_forwarding
        detect_tcp_forwarding
        detect_algorithms
        _emit_status
        [[ ${#STATUS_FAIL[@]} -eq 0 ]] && exit 0 || exit 1
    fi

    # ── Banner ─────────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                    harden-ssh.sh                    │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    header "Current SSH Configuration"
    show_state

    # ── Pre-condition: ensure a non-root sudoer has an SSH key ────────────────
    section "Pre-condition Check"
    printf '\n'
    check_sudo_ssh_user

    # ── All-pass early exit ───────────────────────────────────────────────────
    if check_all_pass; then
        ok "All hardening checks pass. No action needed."
        if [[ -f "$SSHD_DROP_IN" ]]; then
            plain "Drop-in: ${SSHD_DROP_IN}"
        fi
        printf '\n'
        printf "  ${BOLD}Summary${NC}\n\n"
        for msg in "${CHECKS_PASSED[@]+"${CHECKS_PASSED[@]}"}"; do
            printf "  ${GREEN}  ✓${NC}  %s\n" "$msg"
        done
        printf '\n'
        exit 0
    fi

    # ── Detect all issues, then let the user review them in bulk ─────────────
    detect_issues

    # Record already-passing checks for the summary
    local already_passing=(
        "pubkey_auth:PubkeyAuthentication"
        "password_auth:PasswordAuthentication"
        "kbd_auth:KbdInteractiveAuthentication"
        "permit_root_login:PermitRootLogin"
        "empty_passwords:PermitEmptyPasswords"
        "max_auth_tries:MaxAuthTries"
        "login_grace_time:LoginGraceTime"
        "idle_timeout:ClientAlive idle timeout"
        "x11_forwarding:X11Forwarding"
        "tcp_forwarding:AllowTcpForwarding"
        "algorithms:Crypto algorithms"
    )
    for entry in "${already_passing[@]}"; do
        local chk_id="${entry%%:*}" chk_name="${entry#*:}"
        local found=false
        local pi
        for pi in "${!PROP_ID[@]}"; do
            [[ "${PROP_ID[$pi]}" == "$chk_id" ]] && found=true && break
        done
        [[ "$found" == "false" ]] && CHECKS_PASSED+=("${chk_name} — already hardened")
    done

    review_proposed_changes
    apply_accepted_fixes

    # ── Apply accepted fixes ──────────────────────────────────────────────────
    printf '\n'
    if [[ "$DIRTY" == "true" ]]; then
        apply_fixes
    else
        info "No fixes accepted — sshd configuration unchanged."
    fi

    # ── Final state ───────────────────────────────────────────────────────────
    if [[ "$DIRTY" == "true" && "$DRY_RUN" != "true" ]]; then
        compute_state
        header "Updated SSH Configuration"
        show_state
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    printf "  ${BOLD}Summary${NC}\n\n"
    for msg in "${CHECKS_PASSED[@]+"${CHECKS_PASSED[@]}"}"; do
        printf "  ${GREEN}  ✓${NC}  %s\n" "$msg"
    done
    for msg in "${CHECKS_FIXED[@]+"${CHECKS_FIXED[@]}"}"; do
        printf "  ${CYAN}  ~${NC}  %s\n" "$msg"
    done
    for msg in "${CHECKS_DECLINED[@]+"${CHECKS_DECLINED[@]}"}"; do
        printf "  ${YELLOW}  !${NC}  %s\n" "$msg"
    done
    printf '\n'

    if   (( ${#CHECKS_DECLINED[@]} > 0 )); then
        warn "Some checks were skipped. Re-run $(basename "$0") to address them."
    elif (( ${#CHECKS_FIXED[@]} > 0 )); then
        ok "All accepted fixes applied. Re-run $(basename "$0") to confirm."
    fi
}

main
