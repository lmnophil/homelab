#!/usr/bin/env bash
# ==============================================================================
# harden-ssh.sh  —  Audit sshd configuration and apply security hardening
# ==============================================================================
#
# Usage:
#   sudo ./harden-ssh.sh [--dry-run] [--help]
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
#               --dry-run does not require root.
# ==============================================================================
set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────────────
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

    dpkg-query -W -f='${Status}' openssh-server 2>/dev/null \
        | grep -q "install ok installed" \
        || die "openssh-server is not installed. Install it first: sudo apt install openssh-server"

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
# Values here are the recommended secure defaults. Check functions compare the
# effective config against these; when a fix is accepted they stay as-is;
# when declined they are updated to the current effective value so the drop-in
# preserves the status quo for that directive.
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
CONF_SET_ALGORITHMS=false   # true → write explicit algorithm stanzas in drop-in

DIRTY=false   # set to true when any fix is accepted

# ── Check tracking ────────────────────────────────────────────────────────────
CHECKS_PASSED=()
CHECKS_FIXED=()
CHECKS_DECLINED=()

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

# ── compute_state ─────────────────────────────────────────────────────────────
# Reads the effective sshd config and initialises CONF_* to current values.
# Check functions will then override CONF_* to the secure value when fixed, or
# leave them at the current value when declined.
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

    # Modern algorithms: check whether the drop-in already sets them
    grep -q "^HostKeyAlgorithms" "$SSHD_DROP_IN" 2>/dev/null \
        && CONF_SET_ALGORITHMS=true || CONF_SET_ALGORITHMS=false
}

# ── check_all_pass ────────────────────────────────────────────────────────────
# Returns 0 if every check would pass right now, 1 otherwise.
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

    # ── Sudo users key inventory ───────────────────────────────────────────────
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

# _show_row <key> <value> <good_val_or_empty> <bad_val_or_empty>
# good="" → green only when value != <default>/<unset>
# good="x" → green only when value equals "x"  (case-insensitive)
# bad="x"  → red when value equals "x"          (case-insensitive)
_show_row() {
    local key="$1" val="$2" good="$3" bad="$4"
    local color="$YELLOW"
    local lval="${val,,}"
    [[ -n "$good" && "${lval}" == "${good,,}" ]] && color="$GREEN"
    [[ -n "$bad"  && "${lval}" == "${bad,,}"  ]] && color="$RED"
    # Special: PermitRootLogin — "no" and "prohibit-password" are both green
    if [[ "$key" == "PermitRootLogin" ]]; then
        if [[ "$lval" == "no" || "$lval" == "prohibit-password" ]]; then
            color="$GREEN"
        elif [[ "$lval" == "yes" ]]; then
            color="$RED"
        fi
    fi
    # MaxAuthTries — green ≤5, red >6
    if [[ "$key" == "MaxAuthTries" && "$val" =~ ^[0-9]+$ ]]; then
        (( val <= 5 )) && color="$GREEN" || color="$RED"
    fi
    # LoginGraceTime — green ≤60, yellow >60
    if [[ "$key" == "LoginGraceTime" && "$val" =~ ^[0-9]+$ ]]; then
        (( val <= 60 )) && color="$GREEN" || color="$YELLOW"
    fi
    # ClientAliveInterval / Count — green >0, red ==0
    if [[ "$key" == "ClientAliveInterval" && "$val" =~ ^[0-9]+$ ]]; then
        (( val > 0 )) && color="$GREEN" || color="$RED"
    fi
    if [[ "$key" == "ClientAliveCountMax" && "$val" =~ ^[0-9]+$ ]]; then
        (( val > 0 )) && color="$GREEN" || color="$YELLOW"
    fi

    printf "    ${color}%-36s %s${NC}\n" "$key" "$val"
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
# CHECK FUNCTIONS
# Each function: query state → return early if passing → explain → ask → fix.
# ══════════════════════════════════════════════════════════════════════════════

# ── sudo_ssh_user_exists ──────────────────────────────────────────────────────
# Returns 0 if at least one non-root member of the sudo group has an authorized
# SSH key. Used as a safety pre-condition before recommending lockdown of
# PasswordAuthentication and PermitRootLogin.
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

# ── check_sudo_ssh_user ───────────────────────────────────────────────────────
# Ensures there is at least one non-root sudoer with an SSH key in place.
# When none exists, lists eligible users and offers to add keys inline using
# the same URL / paste options as manage-ssh.sh.
# This is a pre-condition check — not included in check_all_pass and does not
# write sshd config. It appends to CHECKS_FIXED / CHECKS_DECLINED like all
# other checks so the summary reflects the outcome.
check_sudo_ssh_user() {
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

    # Build list of eligible sudo members (non-root, must exist in passwd)
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

    # Pick which sudo user to add a key for
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

    # Key source loop — URL / paste, same as manage-ssh.sh
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

check_pubkey_auth() {
    local cur="${CONF_PUBKEY_AUTH,,}"
    if [[ "$cur" == "yes" ]]; then
        ok "PubkeyAuthentication is yes"
        CHECKS_PASSED+=("PubkeyAuthentication yes")
        return 0
    fi

    printf '\n'
    warn "PubkeyAuthentication is '${CONF_PUBKEY_AUTH}' — should be 'yes'."
    plain "Without this, key-based login is disabled and you cannot lock out passwords safely."

    if ask "Set PubkeyAuthentication yes?" "y"; then
        CONF_PUBKEY_AUTH="yes"
        DIRTY=true
        CHECKS_FIXED+=("PubkeyAuthentication set to yes")
    else
        warn "Skipped — PubkeyAuthentication remains ${CONF_PUBKEY_AUTH}."
        CHECKS_DECLINED+=("PubkeyAuthentication not enabled (risk accepted)")
    fi
}

check_password_auth() {
    local cur="${CONF_PASSWORD_AUTH,,}"
    if [[ "$cur" == "no" ]]; then
        ok "PasswordAuthentication is no"
        CHECKS_PASSED+=("PasswordAuthentication no")
        return 0
    fi

    printf '\n'
    warn "PasswordAuthentication is '${CONF_PASSWORD_AUTH}' — should be 'no'."
    plain "Password auth exposes the server to brute-force attacks."
    plain "Ensure at least one authorized key is in place before disabling passwords."

    # Safety: warn if no non-root sudoer has a key (lockout risk)
    if ! sudo_ssh_user_exists; then
        printf '\n'
        warn "No non-root sudoer with an SSH key exists on this system."
        warn "Disabling password auth without one may lock you out."
        plain "Run manage-ssh.sh to add a key for a sudo user first."
    fi

    if ask "Set PasswordAuthentication no?" "y"; then
        CONF_PASSWORD_AUTH="no"
        DIRTY=true
        CHECKS_FIXED+=("PasswordAuthentication set to no")
    else
        warn "Skipped — PasswordAuthentication remains ${CONF_PASSWORD_AUTH}."
        CHECKS_DECLINED+=("PasswordAuthentication not disabled (risk accepted)")
    fi
}

check_kbd_auth() {
    local cur="${CONF_KBD_AUTH,,}"
    if [[ "$cur" == "no" ]]; then
        ok "KbdInteractiveAuthentication is no"
        CHECKS_PASSED+=("KbdInteractiveAuthentication no")
        return 0
    fi

    printf '\n'
    warn "KbdInteractiveAuthentication is '${CONF_KBD_AUTH}' — should be 'no'."
    plain "This is the modern replacement for ChallengeResponseAuthentication."
    plain "Leaving it enabled can allow password-style prompts even when PasswordAuthentication is off."

    if ask "Set KbdInteractiveAuthentication no?" "y"; then
        CONF_KBD_AUTH="no"
        DIRTY=true
        CHECKS_FIXED+=("KbdInteractiveAuthentication set to no")
    else
        warn "Skipped — KbdInteractiveAuthentication remains ${CONF_KBD_AUTH}."
        CHECKS_DECLINED+=("KbdInteractiveAuthentication not disabled (risk accepted)")
    fi
}

check_permit_root_login() {
    local cur="${CONF_PERMIT_ROOT_LOGIN,,}"
    if [[ "$cur" == "no" || "$cur" == "prohibit-password" ]]; then
        ok "PermitRootLogin is ${CONF_PERMIT_ROOT_LOGIN}"
        CHECKS_PASSED+=("PermitRootLogin ${CONF_PERMIT_ROOT_LOGIN}")
        return 0
    fi

    printf '\n'
    warn "PermitRootLogin is '${CONF_PERMIT_ROOT_LOGIN}' — should be 'no' or 'prohibit-password'."
    plain "Direct root login increases blast radius if a key is compromised."
    plain "Recommended: log in as a normal user and use sudo."

    if ask "Set PermitRootLogin no?" "y"; then
        CONF_PERMIT_ROOT_LOGIN="no"
        DIRTY=true
        CHECKS_FIXED+=("PermitRootLogin set to no")
    else
        warn "Skipped — PermitRootLogin remains ${CONF_PERMIT_ROOT_LOGIN}."
        CHECKS_DECLINED+=("PermitRootLogin not restricted (risk accepted)")
    fi
}

check_empty_passwords() {
    local cur="${CONF_EMPTY_PASSWORDS,,}"
    if [[ "$cur" == "no" ]]; then
        ok "PermitEmptyPasswords is no"
        CHECKS_PASSED+=("PermitEmptyPasswords no")
        return 0
    fi

    printf '\n'
    warn "PermitEmptyPasswords is '${CONF_EMPTY_PASSWORDS}' — should be 'no'."
    plain "Accounts with empty passwords could be logged into over SSH without any credential."

    if ask "Set PermitEmptyPasswords no?" "y"; then
        CONF_EMPTY_PASSWORDS="no"
        DIRTY=true
        CHECKS_FIXED+=("PermitEmptyPasswords set to no")
    else
        warn "Skipped — PermitEmptyPasswords remains ${CONF_EMPTY_PASSWORDS}."
        CHECKS_DECLINED+=("PermitEmptyPasswords not restricted (risk accepted)")
    fi
}

check_max_auth_tries() {
    local cur="$CONF_MAX_AUTH_TRIES"
    if [[ "$cur" =~ ^[0-9]+$ ]] && (( cur <= 5 )); then
        ok "MaxAuthTries is ${cur}"
        CHECKS_PASSED+=("MaxAuthTries ${cur} (≤5)")
        return 0
    fi

    printf '\n'
    warn "MaxAuthTries is '${cur}' — recommended ≤5."
    plain "A high limit lets attackers try many keys per connection before the connection drops."
    plain "Set to 3–5; clients with many keys can still connect, just not in a single attempt."

    if ask "Set MaxAuthTries 3?" "y"; then
        CONF_MAX_AUTH_TRIES="3"
        DIRTY=true
        CHECKS_FIXED+=("MaxAuthTries set to 3")
    else
        warn "Skipped — MaxAuthTries remains ${cur}."
        CHECKS_DECLINED+=("MaxAuthTries not reduced (risk accepted)")
    fi
}

check_login_grace_time() {
    local cur="$CONF_LOGIN_GRACE_TIME"
    if [[ "$cur" =~ ^[0-9]+$ ]] && (( cur > 0 && cur <= 60 )); then
        ok "LoginGraceTime is ${cur}s"
        CHECKS_PASSED+=("LoginGraceTime ${cur}s (≤60)")
        return 0
    fi

    printf '\n'
    warn "LoginGraceTime is '${cur}' — recommended 30–60s."
    plain "A long grace period lets unauthenticated connections tie up sshd slots."

    if ask "Set LoginGraceTime 30?" "y"; then
        CONF_LOGIN_GRACE_TIME="30"
        DIRTY=true
        CHECKS_FIXED+=("LoginGraceTime set to 30s")
    else
        warn "Skipped — LoginGraceTime remains ${cur}."
        CHECKS_DECLINED+=("LoginGraceTime not tightened (risk accepted)")
    fi
}

check_idle_timeout() {
    local iv="$CONF_ALIVE_INTERVAL" ic="$CONF_ALIVE_COUNT"
    if [[ "$iv" =~ ^[0-9]+$ && "$ic" =~ ^[0-9]+$ ]] \
        && (( iv > 0 && ic > 0 )); then
        local mins=$(( (iv * ic + 59) / 60 ))
        ok "Idle timeout: ${iv}s × ${ic} missed = ~${mins}min"
        CHECKS_PASSED+=("Idle timeout active (~${mins}min)")
        return 0
    fi

    printf '\n'
    warn "Idle timeout is disabled (ClientAliveInterval=${iv}, ClientAliveCountMax=${ic})."
    plain "Idle sessions stay open indefinitely — a risk if a workstation is left unattended."
    plain "Recommended: 300s × 2 = sessions drop after ~10 minutes of inactivity."

    if ask "Enable idle timeout (300s × 2)?" "y"; then
        CONF_ALIVE_INTERVAL="300"
        CONF_ALIVE_COUNT="2"
        DIRTY=true
        CHECKS_FIXED+=("Idle timeout set to 300s × 2 (~10min)")
    else
        warn "Skipped — idle timeout remains disabled."
        CHECKS_DECLINED+=("Idle timeout not enabled (risk accepted)")
    fi
}

check_x11_forwarding() {
    local cur="${CONF_X11_FORWARDING,,}"
    if [[ "$cur" == "no" ]]; then
        ok "X11Forwarding is no"
        CHECKS_PASSED+=("X11Forwarding no")
        return 0
    fi

    printf '\n'
    warn "X11Forwarding is '${CONF_X11_FORWARDING}' — should be 'no'."
    plain "X11 forwarding exposes the server's display and can allow session hijacking."
    plain "Disable unless you specifically need to forward graphical applications over SSH."

    if ask "Set X11Forwarding no?" "y"; then
        CONF_X11_FORWARDING="no"
        DIRTY=true
        CHECKS_FIXED+=("X11Forwarding set to no")
    else
        warn "Skipped — X11Forwarding remains ${CONF_X11_FORWARDING}."
        CHECKS_DECLINED+=("X11Forwarding not disabled (risk accepted)")
    fi
}

check_tcp_forwarding() {
    local cur="${CONF_TCP_FORWARDING,,}"
    if [[ "$cur" == "no" ]]; then
        ok "AllowTcpForwarding is no"
        CHECKS_PASSED+=("AllowTcpForwarding no")
        return 0
    fi

    printf '\n'
    warn "AllowTcpForwarding is '${CONF_TCP_FORWARDING}' — should be 'no'."
    plain "TCP forwarding enables port-forwarding and SOCKS proxying through this host."
    plain "Disable unless you actively rely on these features."

    if ask "Set AllowTcpForwarding no?" "y"; then
        CONF_TCP_FORWARDING="no"
        DIRTY=true
        CHECKS_FIXED+=("AllowTcpForwarding set to no")
    else
        warn "Skipped — AllowTcpForwarding remains ${CONF_TCP_FORWARDING}."
        CHECKS_DECLINED+=("AllowTcpForwarding not disabled (risk accepted)")
    fi
}

check_algorithms() {
    if [[ "$CONF_SET_ALGORITHMS" == "true" ]]; then
        ok "Explicit modern algorithm stanzas are present in the drop-in"
        CHECKS_PASSED+=("Modern algorithms explicitly configured")
        return 0
    fi

    printf '\n'
    warn "No explicit algorithm configuration found."
    plain "OpenSSH's defaults are reasonable on current versions, but do not disable"
    plain "legacy options on older systems. Writing explicit stanzas locks in the"
    plain "modern set and prevents regressions after package upgrades."
    plain ""
    plain "The following will be written:"
    plain "  HostKeyAlgorithms    ssh-ed25519, rsa-sha2-512, rsa-sha2-256"
    plain "  PubkeyAcceptedAlgos  ssh-ed25519, sk-ssh-ed25519, rsa-sha2-512, rsa-sha2-256"
    plain "  KexAlgorithms        curve25519-sha256, diffie-hellman-group16-sha512, …"
    plain "  Ciphers              chacha20-poly1305, aes256-gcm, aes128-gcm"
    plain "  MACs                 hmac-sha2-256-etm, hmac-sha2-512-etm"

    if ask "Write modern algorithm stanzas?" "y"; then
        CONF_SET_ALGORITHMS=true
        DIRTY=true
        CHECKS_FIXED+=("Modern algorithm stanzas added")
    else
        warn "Skipped — algorithm configuration left to OpenSSH defaults."
        CHECKS_DECLINED+=("Algorithm stanzas not written (risk accepted)")
    fi
}

# ── apply_fixes ───────────────────────────────────────────────────────────────
# Writes the hardening drop-in, validates with sshd -t, reloads.
# Restores previous config automatically on validation failure.
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
    if (( CONF_ALIVE_INTERVAL > 0 && CONF_ALIVE_COUNT > 0 )); then
        local _mins=$(( (CONF_ALIVE_INTERVAL * CONF_ALIVE_COUNT + 59) / 60 ))
        idle_comment="disconnects idle sessions after ~${_mins}min"
    else
        idle_comment="idle timeout disabled"
    fi

    # Write the drop-in
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

    # Validate before reloading
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

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                    harden-ssh.sh                    │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    # Show current effective configuration
    header "Current SSH Configuration"
    show_state

    # ── Pre-condition: ensure a non-root sudoer has an SSH key ────────────────
    # Runs unconditionally — even on a fully-hardened system this check must
    # not be skipped, because the all-pass exit below would otherwise hide it.
    section "Pre-condition Check"
    printf '\n'
    check_sudo_ssh_user

    # ── All-pass early exit ───────────────────────────────────────────────────
    if check_all_pass; then
        ok "All hardening checks pass. No action needed."
        if [[ -f "$SSHD_DROP_IN" ]]; then
            plain "Drop-in: ${SSHD_DROP_IN}"
        fi
        # Still print summary so the sudo key outcome is visible
        printf '\n'
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
        exit 0
    fi

    # ── Run checks ────────────────────────────────────────────────────────────
    section "Hardening Checks"
    printf '\n'
    info "Press Enter to accept the recommended fix, or answer n to skip each check."
    printf '\n'

    check_pubkey_auth
    check_password_auth
    check_kbd_auth
    check_permit_root_login
    check_empty_passwords
    check_max_auth_tries
    check_login_grace_time
    check_idle_timeout
    check_x11_forwarding
    check_tcp_forwarding
    check_algorithms

    # ── Apply accepted fixes ──────────────────────────────────────────────────
    printf '\n'
    if [[ "$DIRTY" == "true" ]]; then
        apply_fixes
    else
        info "No fixes accepted — sshd configuration unchanged."
    fi

    # ── Final state ───────────────────────────────────────────────────────────
    if [[ "$DIRTY" == "true" && "$DRY_RUN" != "true" ]]; then
        # Re-read effective values now that the drop-in has been written
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
