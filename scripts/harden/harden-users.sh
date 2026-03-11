#!/usr/bin/env bash
# ==============================================================================
# harden-users.sh — Account hardening for fresh Debian/Ubuntu systems
# ==============================================================================
# Intended for fresh Proxmox LXC containers (Ubuntu 24.04 template).
# Compatible with Debian 11+ and Ubuntu 22.04+.
#
# Usage:
#   sudo ./harden-users.sh [--dry-run]
#
# Options:
#   --dry-run          Print commands without executing them
#   --help             Show this help text
#
# Checks performed (in order):
#   1. At least one non-root user exists in the sudo group
#   2. The root account password is locked
#
# Each check is idempotent — re-running with everything already in place
# reports all-clear and exits without prompting. If a check requires action,
# the operator is shown the current state, given the rationale, and prompted.
# Declining a fix is always allowed, but a warning is recorded in the summary.
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

ask_secret() {
    local prompt="$1" val
    read -rsp "    ${YELLOW}>  ${NC}${prompt}: " val || true
    printf '\n' >&2
    printf '%s' "$val"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
# Sets globals: OS_ID  OS_CODENAME  OS_VERSION_ID  OS_MAJOR
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0

# ── User count globals (set by compute_user_counts; read by menu / checks) ───
HUMAN_COUNT=0; SUDO_COUNT=0

# ── Result globals for pick / prompt helpers ─────────────────────────────────
# Using globals avoids $() command substitution capturing display output.
_PICK_RESULT=''
_USERNAME_RESULT=''
_PASSWORD_RESULT=''

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
}

# ── User state queries ────────────────────────────────────────────────────────
is_sudo_member()   { getent group sudo   2>/dev/null | grep -qw "$1"; }
is_docker_member() { getent group docker 2>/dev/null | grep -qw "$1"; }

is_root_pw_enabled() {
    local s
    s=$(passwd -S root 2>/dev/null | awk '{print $2}')
    [[ "$s" == "P" ]]
}

get_user_status() {
    local s
    s=$(passwd -S "$1" 2>/dev/null | awk '{print $2}')
    case "$s" in
        L)  printf 'locked'    ;;
        NP) printf 'no-passwd' ;;
        *)  printf 'active'    ;;
    esac
}

compute_user_counts() {
    HUMAN_COUNT=$(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' \
        | wc -l || true)
    HUMAN_COUNT="${HUMAN_COUNT//[[:space:]]/}"

    SUDO_COUNT=0
    local u
    while IFS= read -r u; do
        is_sudo_member "$u" && (( SUDO_COUNT++ )) || true
    done < <(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' || true)
}

list_human_users() {
    local docker_exists=false
    getent group docker &>/dev/null && docker_exists=true

    local users
    users=$(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' \
        | sort || true)

    if [[ -z "$users" ]]; then
        plain "(no non-root accounts found)"
        return
    fi

    printf "    ${BOLD}%-20s  %-4s" "Username" "Sudo"
    [[ "$docker_exists" == "true" ]] && printf "  %-6s" "Docker"
    printf "  %-8s  %s${NC}\n" "Status" "Shell"

    local div_width; [[ "$docker_exists" == "true" ]] && div_width=58 || div_width=50
    local div; printf -v div '%*s' "$div_width" ''; printf "    %s\n" "${div// /─}"

    local u status shell_name
    while IFS= read -r u; do
        printf "    %-20s" "$u"

        if   is_sudo_member "$u"; then printf "  ${GREEN}yes ${NC}"
        else                           printf "  ${DIM}no  ${NC}"; fi

        if [[ "$docker_exists" == "true" ]]; then
            if   is_docker_member "$u"; then printf "  ${GREEN}yes   ${NC}"
            else                             printf "  ${DIM}no    ${NC}"; fi
        fi

        status=$(get_user_status "$u")
        case "$status" in
            locked)    printf "  ${YELLOW}locked  ${NC}" ;;
            no-passwd) printf "  ${RED}no-passwd${NC}" ;;
            *)         printf "  ${GREEN}active  ${NC}" ;;
        esac

        shell_name=$(getent passwd "$u" | cut -d: -f7)
        printf "  %s\n" "${shell_name##*/}"
    done <<< "$users"
}

# ── Pick / prompt helpers ─────────────────────────────────────────────────────
# pick_human_user PROMPT
# Prompts for a valid non-root username. Retries on bad input.
# Sets _PICK_RESULT; returns 1 (with info "Cancelled.") on blank input or when
# no eligible users exist.  Never call with $() — use the global instead.
# The caller is responsible for displaying the user list before calling this.
pick_human_user() {
    local prompt="$1" u users=()
    _PICK_RESULT=''
    while IFS= read -r u; do
        users+=("$u")
    done < <(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' \
        | sort || true)

    if [[ ${#users[@]} -eq 0 ]]; then
        warn "No eligible non-root accounts found."
        return 1
    fi

    local chosen found
    while true; do
        chosen=$(ask_val "${prompt} (Enter to cancel)")
        if [[ -z "$chosen" ]]; then
            info "Cancelled."
            return 1
        fi
        found=false
        for u in "${users[@]}"; do
            [[ "$u" == "$chosen" ]] && found=true && break
        done
        if [[ "$found" == "true" ]]; then
            _PICK_RESULT="$chosen"
            return 0
        fi
        warn "User '${chosen}' not found — please try again."
    done
}

_prompt_new_username() {
    _USERNAME_RESULT=''
    local candidate
    while true; do
        candidate=$(ask_val "New username (Enter to cancel)")
        if [[ -z "$candidate" ]]; then
            info "Cancelled."
            return 1
        fi
        if ! [[ "$candidate" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            warn "Invalid username '${candidate}'."
            plain "Lowercase letters, digits, hyphens, underscores only."
            plain "Must start with a letter or underscore; 32 chars max."
            continue
        fi
        if id "$candidate" &>/dev/null; then
            warn "User '${candidate}' already exists."; continue
        fi
        _USERNAME_RESULT="$candidate"
        return 0
    done
}

_prompt_password() {
    _PASSWORD_RESULT=''
    local username="$1" pw1 pw2
    info "Leave both password fields blank to cancel."
    while true; do
        pw1=$(ask_secret "Password for ${username}")
        pw2=$(ask_secret "Confirm password")
        if [[ -z "$pw1" && -z "$pw2" ]]; then
            info "Cancelled."
            return 1
        fi
        if [[ "$pw1" != "$pw2" ]]; then
            warn "Passwords do not match — try again."
            continue
        fi
        if [[ -z "$pw1" ]]; then
            warn "Password is blank — the account will have no password set."
            ask "Continue with a blank password?" "n" || continue
        elif (( ${#pw1} < 8 )); then
            warn "Password is only ${#pw1} character(s) — 8 or more is recommended."
            ask "Continue with this short password?" "n" || continue
        fi
        _PASSWORD_RESULT="$pw1"
        return 0
    done
}

# _apply_password USERNAME PASSWORD
# Empty password clears the password entry (passwd -d); non-empty uses chpasswd.
_apply_password() {
    local user="$1" pw="$2"
    if [[ "$DRY_RUN" == "true" ]]; then
        [[ -z "$pw" ]] \
            && printf "    ${DIM}[dry-run]${NC} passwd -d %s  # clear password\n" "$user" \
            || printf "    ${DIM}[dry-run]${NC} chpasswd  # set password for %s\n" "$user"
        return
    fi
    if [[ -z "$pw" ]]; then
        passwd -d "$user"
    else
        printf '%s:%s\n' "$user" "$pw" | chpasswd
    fi
}

# ── State display ─────────────────────────────────────────────────────────────
show_harden_state() {
    compute_user_counts

    local sudo_names=() u
    while IFS= read -r u; do
        is_sudo_member "$u" && sudo_names+=("$u") || true
    done < <(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' || true)

    printf "    ${BOLD}%-34s  %s${NC}\n" "Check" "Status"
    local div; printf -v div '%*s' 52 ''; printf "    %s\n" "${div// /─}"

    if (( ${#sudo_names[@]} > 0 )); then
        local names_str
        names_str=$(printf '%s, ' "${sudo_names[@]}")
        printf "    %-34s  ${GREEN}[  PASS  ]${NC}  %s\n" \
            "Non-root sudo user exists" "${names_str%, }"
    else
        printf "    %-34s  ${RED}[  FAIL  ]${NC}  %s\n" \
            "Non-root sudo user exists" "none found"
    fi

    if is_root_pw_enabled; then
        printf "    %-34s  ${RED}[  FAIL  ]${NC}  %s\n" \
            "Root password locked" "active password is set"
    else
        printf "    %-34s  ${GREEN}[  PASS  ]${NC}  %s\n" \
            "Root password locked" "locked or no password"
    fi

    printf '\n'
}

# ── Check 1 — Ensure at least one non-root sudo user exists ──────────────────
check_sudo_users() {
    compute_user_counts

    if (( SUDO_COUNT > 0 )); then
        local sudo_names=() u
        while IFS= read -r u; do
            is_sudo_member "$u" && sudo_names+=("$u") || true
        done < <(getent passwd 2>/dev/null \
            | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' || true)
        local names_str
        names_str=$(printf '%s, ' "${sudo_names[@]}")
        ok "Non-root sudo user exists: ${names_str%, }"
        CHECKS_PASSED+=("Non-root sudo user exists (${SUDO_COUNT} found)")
        return 0
    fi

    printf '\n'
    warn "No non-root users have sudo access."
    plain "All privileged operations will require logging in as root directly,"
    plain "bypassing the audit trail sudo provides."
    printf '\n'

    local resolved=false sub_choice

    while [[ "$resolved" == "false" ]]; do
        printf "  ${BOLD}How would you like to address this?${NC}\n"
        if (( HUMAN_COUNT > 0 )); then
            printf "    1)  Grant sudo to an existing user\n"
            printf "    2)  Create a new user with sudo access\n"
            printf "    3)  Skip — I understand the risk\n"
        else
            plain "(No non-root accounts exist yet)"
            printf "    1)  Create a new user with sudo access\n"
            printf "    2)  Skip — I understand the risk\n"
        fi

        sub_choice=""
        read -rp "    ${YELLOW}>  ${NC}Choice: " sub_choice || true

        if (( HUMAN_COUNT > 0 )); then
            case "$sub_choice" in
                1)
                    printf '\n'
                    list_human_users
                    printf '\n'
                    pick_human_user "Username to grant sudo" || continue
                    local target="$_PICK_RESULT"
                    run usermod -aG sudo "$target"
                    ok "'${target}' added to the sudo group."
                    CHECKS_FIXED+=("Granted sudo to '${target}'")
                    resolved=true
                    ;;
                2)
                    _create_sudo_user && resolved=true || true
                    ;;
                3)
                    warn "Skipped — root remains the only privileged account."
                    CHECKS_DECLINED+=("No non-root sudo user (risk accepted)")
                    resolved=true
                    ;;
                *)  warn "Please enter 1, 2, or 3." ;;
            esac
        else
            case "$sub_choice" in
                1)
                    _create_sudo_user && resolved=true || true
                    ;;
                2)
                    warn "Skipped — root remains the only privileged account."
                    CHECKS_DECLINED+=("No non-root sudo user (risk accepted)")
                    resolved=true
                    ;;
                *)  warn "Please enter 1 or 2." ;;
            esac
        fi
    done
}

_create_sudo_user() {
    _prompt_new_username || return 1
    local new_user="$_USERNAME_RESULT"

    _prompt_password "$new_user" || return 1
    local new_password="$_PASSWORD_RESULT"

    local _user_ref="$new_user"
    _harden_user_cleanup() {
        if [[ "$DRY_RUN" == "false" ]] && id "$_user_ref" &>/dev/null; then
            warn "Removing partially created user '${_user_ref}' due to error..."
            userdel -r "$_user_ref" 2>/dev/null || true
        fi
    }
    trap _harden_user_cleanup ERR

    run useradd -m -s /bin/bash "$new_user"
    _apply_password "$new_user" "$new_password"
    run usermod -aG sudo "$new_user"

    trap - ERR

    printf '\n'
    ok "User '${new_user}' created and added to sudo."
    plain "Home:  /home/${new_user}   Shell: /bin/bash"

    local local_ip
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    printf '\n'
    info "Verify the new account in a new terminal before logging out:"
    [[ -n "${local_ip:-}" ]] \
        && plain "  ssh ${new_user}@${local_ip}" \
        || plain "  ssh ${new_user}@<host-ip>"

    CHECKS_FIXED+=("Created sudo user '${new_user}'")
    return 0
}

# ── Check 2 — Ensure root password is locked ─────────────────────────────────
check_root_locked() {
    if ! is_root_pw_enabled; then
        ok "Root password is locked."
        CHECKS_PASSED+=("Root password is already locked")
        return 0
    fi

    printf '\n'
    warn "Root has an active password."
    plain "A root password is an unnecessary attack surface when sudo users exist."
    plain "Locking it forces all privileged access through sudo (/var/log/auth.log)."
    plain "This does NOT prevent root access — any sudo user can still run 'sudo -i'."

    if ask "Lock the root password now?" "y"; then
        run passwd -l root
        ok "Root password locked."
        CHECKS_FIXED+=("Root password locked")
    else
        warn "Skipped — root password remains active."
        CHECKS_DECLINED+=("Root password not locked (risk accepted)")
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    preflight_checks

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                   harden-users.sh                   │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    CHECKS_PASSED=()
    CHECKS_FIXED=()
    CHECKS_DECLINED=()

    compute_user_counts
    if (( SUDO_COUNT > 0 )) && ! is_root_pw_enabled; then
        show_harden_state
        ok "All hardening checks pass. No action needed."
        exit 0
    fi

    section "Check 1 — Non-Root Sudo User"
    check_sudo_users

    section "Check 2 — Root Password"
    check_root_locked

    # ── Final state + summary ─────────────────────────────────────────────────
    header "Hardening State"
    show_harden_state

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
    elif (( ${#CHECKS_FIXED[@]}   > 0 )); then
        ok   "All accepted fixes applied. Re-run $(basename "$0") to confirm."
    fi
}

main