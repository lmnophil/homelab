#!/usr/bin/env bash
# ==============================================================================
# manage-users.sh — User account management for Debian/Ubuntu systems
# ==============================================================================
# Intended for fresh Proxmox LXC containers (Ubuntu 24.04 template).
# Compatible with Debian 11+ and Ubuntu 22.04+.
#
# Usage:
#   sudo ./manage-users.sh [--dry-run]
#
# Options:
#   --dry-run          Print commands without executing them
#   --help             Show this help text
#
# Menu actions:
#   1)  Create a user
#   2)  Delete a user
#   3)  Disable a user (lock password + optionally revoke SSH key auth)
#   4)  Re-enable a user (unlock password + optionally restore SSH key auth)
#   5)  Change password
#   6)  Rename user
#   7)  Change login shell (e.g. bash → zsh, fish)
#   8)  Grant / revoke sudo access
#   9)  Grant / revoke Docker access  (only shown when docker group exists)
#   10) Set / lock root password
#   11) Exit
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

# The human who invoked sudo (or empty if running directly as root).
# Set in main() before any action runs; used by action functions to detect
# and warn/block self-targeting operations.
CURRENT_OPERATOR=''
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

# would_lose_all_admin TARGET
# Returns 0 (true) if removing admin rights from TARGET would leave NO privileged
# path into the system: root password is locked AND no other sudo users exist.
# Used to hard-block actions that would permanently lock the operator out.
would_lose_all_admin() {
    local target="$1"
    is_sudo_member "$target" || return 1  # target has no sudo — action can't remove admin access
    is_root_pw_enabled && return 1        # root pw active → root can still fix things
    local u other_sudo=0
    while IFS= read -r u; do
        [[ "$u" == "$target" ]] && continue
        is_sudo_member "$u" && (( other_sudo++ )) || true
    done < <(getent passwd 2>/dev/null \
        | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' || true)
    (( other_sudo == 0 ))
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
# Result globals — set by the pick/prompt helpers below.
# Callers read these instead of using $() command substitution, which would
# capture all display output (warn/info/list_human_users) along with the value.
_PICK_RESULT=''
_USERNAME_RESULT=''
_PASSWORD_RESULT=''

# pick_human_user PROMPT
# Displays the user table, prompts for a valid username, retries on bad input.
# Sets _PICK_RESULT; returns 1 (and prints "Cancelled.") on blank input or if
# no eligible users exist.  Never call with $() — use the global instead.
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

    printf '\n'
    list_human_users
    printf '\n'
    printf "    ${DIM}Available users: "
    printf '%s  ' "${users[@]}"
    printf "${NC}\n\n"

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
        warn "User '${chosen}' not found — try again, or Enter to cancel."
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

# ── Action: Create user ───────────────────────────────────────────────────────
action_create() {
    section "Create User"

    _prompt_new_username || return 0
    local new_user="$_USERNAME_RESULT"

    _prompt_password "$new_user" || return 0
    local new_password="$_PASSWORD_RESULT"

    local _user_ref="$new_user"
    _create_cleanup() {
        if [[ "$DRY_RUN" == "false" ]] && id "$_user_ref" &>/dev/null; then
            warn "Removing partially created user '${_user_ref}' due to error..."
            userdel -r "$_user_ref" 2>/dev/null || true
        fi
    }
    trap _create_cleanup ERR

    run useradd -m -s /bin/bash "$new_user"
    _apply_password "$new_user" "$new_password"

    trap - ERR

    printf '\n'
    ok "User '${new_user}' created.  Home: /home/${new_user}   Shell: bash"

    if ask "Add '${new_user}' to the sudo group?" "y"; then
        run usermod -aG sudo "$new_user"
        ok "'${new_user}' added to sudo."
    fi

    if getent group docker &>/dev/null; then
        if ask "Add '${new_user}' to the docker group?" "n"; then
            run usermod -aG docker "$new_user"
            ok "'${new_user}' added to docker."
        fi
    fi

    printf '\n'
    local local_ip
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    info "Verify the new account in a new terminal before logging out:"
    [[ -n "${local_ip:-}" ]] \
        && plain "  ssh ${new_user}@${local_ip}" \
        || plain "  ssh ${new_user}@<host-ip>"
}

# ── Action: Delete ───────────────────────────────────────────────────────
action_delete() {
    section "Delete User"

    pick_human_user "Username to delete" || return 0
    local target="$_PICK_RESULT"

    # Self-targeting checks
    if [[ -n "$CURRENT_OPERATOR" && "$target" == "$CURRENT_OPERATOR" ]]; then
        printf '\n'
        if would_lose_all_admin "$target"; then
            err "Blocked: deleting your own account would lock you out of this system."
            plain "Root password is locked and you are the only sudo user."
            plain "To proceed safely, do one of these first:"
            plain "  • Create another sudo user (option 1)"
            plain "  • Enable the root password (option 9 or 10)"
            info "Action cancelled."
            return 0
        fi
        warn "You are about to delete your own account ('${target}')."
        plain "You will not be able to log back in as this user."
        ask "Continue anyway?" "n" || { info "Cancelled."; return 0; }
    fi

    # Check for active login sessions
    if who 2>/dev/null | awk '{print $1}' | grep -qx "$target"; then
        printf '\n'
        warn "'${target}' has an active login session. Deletion may leave orphaned processes."
        ask "Continue anyway?" "n" || { info "Cancelled."; return 0; }
    fi

    # Check for running processes
    local proc_list
    proc_list=$(ps -u "$target" --no-headers -o pid,comm 2>/dev/null || true)
    if [[ -n "$proc_list" ]]; then
        printf '\n'
        warn "'${target}' has running processes:"
        while IFS= read -r line; do plain "  $line"; done <<< "$proc_list"
        if ask "Kill all processes owned by '${target}' before deletion?" "n"; then
            run pkill -u "$target" || true
            sleep 1
            if [[ "$DRY_RUN" == "false" ]] && pgrep -u "$target" &>/dev/null; then
                run pkill -9 -u "$target" || true
                ok "Processes force-killed."
            else
                ok "Processes killed."
            fi
        else
            plain "Proceeding without killing processes — orphaned processes may remain."
        fi
    fi

    local home_dir remove_home=false
    home_dir=$(getent passwd "$target" | cut -d: -f6 || true)

    printf '\n'
    warn "This will permanently delete '${target}'."
    if [[ -d "${home_dir:-}" ]]; then
        ask "Also delete home directory (${home_dir}) and mail spool?" "n" \
            && remove_home=true
    fi

    printf '\n'
    warn "Type the username to confirm deletion, or Enter to cancel:"
    local confirm
    confirm=$(ask_val "Confirm username")
    if [[ "$confirm" != "$target" ]]; then
        info "Cancelled — username did not match."
        return 0
    fi

    if [[ "$remove_home" == "true" ]]; then
        run userdel -r "$target"
        ok "User '${target}' and home directory deleted."
    else
        run userdel "$target"
        ok "User '${target}' deleted.  Home directory preserved: ${home_dir}"
    fi
}

# ── Action: Disable user ──────────────────────────────────────────────────────
# Blocks password logins; SSH key auth still works unless also revoked.
action_disable() {
    section "Disable User"

    pick_human_user "Username to disable" || return 0
    local target="$_PICK_RESULT"

    # Resolve SSH key status early — needed by both the self-warning and the main flow.
    local auth_keys="/home/${target}/.ssh/authorized_keys"
    local keys_active=false
    [[ -f "$auth_keys" ]] && keys_active=true

    # Self-targeting checks
    if [[ -n "$CURRENT_OPERATOR" && "$target" == "$CURRENT_OPERATOR" ]]; then
        printf '\n'
        if would_lose_all_admin "$target"; then
            err "Blocked: disabling your own account would lock you out of this system."
            plain "Root password is locked and you are the only sudo user."
            plain "Locking your password also breaks sudo — sudo requires your password."
            plain "To proceed safely, do one of these first:"
            plain "  • Create another sudo user (option 1)"
            plain "  • Enable the root password (option 9 or 10)"
            info "Action cancelled."
            return 0
        fi
        warn "You are about to disable your own currently logged-in account ('${target}')."
        plain "Locking your password will:"
        plain "  • Block password-based SSH and console logins"
        plain "  • Break sudo (sudo requires your password by default)"
        if [[ "$keys_active" == "true" ]]; then
            plain "  You have SSH authorized_keys — you can still SSH in, but sudo will fail."
        else
            plain "  You have no SSH authorized_keys — you will be completely locked out."
        fi
        ask "Continue anyway?" "n" || { info "Cancelled."; return 0; }
    fi

    printf '\n'
    local status
    status=$(get_user_status "$target")

    if [[ "$status" == "locked" ]]; then
        info "'${target}' is already disabled (password locked)."
        if [[ "$keys_active" == "true" ]]; then
            warn "'${target}' still has an authorized_keys file — SSH key logins remain active."
            if ask "Disable SSH key auth now (rename authorized_keys)?" "y"; then
                run mv "$auth_keys" "${auth_keys}.disabled"
                ok "SSH authorized_keys renamed to authorized_keys.disabled."
            fi
        else
            info "No SSH authorized_keys file found — SSH key logins are already inactive."
        fi
        return 0
    fi

    warn "Locking '${target}' will block password logins and break sudo for this user."
    if [[ "$keys_active" == "true" ]]; then
        plain "They have SSH authorized_keys — SSH key logins will stay active"
        plain "unless you also revoke the authorized_keys file in the step below."
    else
        plain "They have no SSH authorized_keys — all logins will be blocked."
    fi

    ask "Disable '${target}'?" "y" || { info "No changes made."; return 0; }

    run usermod -L "$target"
    ok "'${target}' disabled (password locked)."

    if [[ "$keys_active" == "true" ]]; then
        if ask "Also disable SSH key auth for '${target}' (rename authorized_keys)?" "y"; then
            run mv "$auth_keys" "${auth_keys}.disabled"
            ok "SSH authorized_keys renamed to authorized_keys.disabled."
        else
            warn "'${target}' can still log in via SSH key — password login is blocked only."
        fi
    else
        info "No SSH authorized_keys file found — SSH key logins already inactive."
    fi
}

# ── Action: Re-enable (unlock password + optionally restore SSH key auth) ──
action_enable() {
    section "Re-enable User"

    pick_human_user "Username to re-enable" || return 0
    local target="$_PICK_RESULT"

    printf '\n'
    local status
    status=$(get_user_status "$target")

    if [[ "$status" != "locked" ]]; then
        info "'${target}' is not disabled (status: ${status})."
        return 0
    fi

    if ask "Unlock '${target}'s password?" "y"; then
        run usermod -U "$target"
        ok "'${target}' re-enabled."

        local auth_keys_disabled="/home/${target}/.ssh/authorized_keys.disabled"
        if [[ -f "$auth_keys_disabled" ]]; then
            if ask "Also restore SSH authorized_keys?" "y"; then
                run mv "$auth_keys_disabled" "/home/${target}/.ssh/authorized_keys"
                ok "SSH authorized_keys restored."
            fi
        fi
    else
        info "No changes made."
    fi
}

# ── Action: Change password ──────────────────────────────────────────────
action_change_password() {
    section "Change Password"

    pick_human_user "Username" || return 0
    local target="$_PICK_RESULT"

    printf '\n'
    _prompt_password "$target" || return 0
    _apply_password "$target" "$_PASSWORD_RESULT"

    ok "Password updated for '${target}'."
}

# ── Action: Rename user ───────────────────────────────────────────────────────
# Changes the login name, renames the home directory, and renames the
# primary group if it matches the old username (the Debian/Ubuntu default).
# The user must not be logged in when this runs.
action_rename() {
    section "Rename User"

    pick_human_user "Username to rename" || return 0
    local target="$_PICK_RESULT"

    if who 2>/dev/null | awk '{print $1}' | grep -qx "$target"; then
        printf '\n'
        warn "'${target}' is currently logged in. Cannot rename an active session."
        info "Ask the user to log out, then retry."
        return 0
    fi

    # Warn if renaming own account
    if [[ -n "$CURRENT_OPERATOR" && "$target" == "$CURRENT_OPERATOR" ]]; then
        printf '\n'
        warn "You are about to rename your own account ('${target}')."
        plain "Your current session will continue, but you must use the new name"
        plain "for all future logins and sudo commands."
        ask "Continue anyway?" "n" || { info "Cancelled."; return 0; }
    fi

    printf '\n'
    local new_name
    while true; do
        new_name=$(ask_val "New username for '${target}' (Enter to cancel)")
        if [[ -z "$new_name" ]]; then
            info "Cancelled."
            return 0
        fi
        if ! [[ "$new_name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            warn "Invalid username '${new_name}'."
            plain "Lowercase letters, digits, hyphens, underscores only."
            plain "Must start with a letter or underscore; 32 chars max."
            continue
        fi
        if id "$new_name" &>/dev/null; then
            warn "'${new_name}' already exists."; continue
        fi
        break
    done

    local old_home="/home/${target}" new_home="/home/${new_name}"
    local has_primary_group=false
    getent group "$target" &>/dev/null && has_primary_group=true

    printf '\n'
    plain "  Login:  ${target}  →  ${new_name}"
    [[ -d "$old_home" ]]             && plain "  Home:   ${old_home}  →  ${new_home}"
    [[ "$has_primary_group" == "true" ]] && plain "  Group:  ${target}  →  ${new_name}"
    ask "Proceed?" "y" || { info "No changes made."; return 0; }

    run usermod -l "$new_name" "$target"

    if [[ -d "$old_home" ]]; then
        run usermod -d "$new_home" -m "$new_name"
    fi

    if [[ "$has_primary_group" == "true" ]]; then
        run groupmod -n "$new_name" "$target"
        ok "Primary group renamed '${target}' → '${new_name}'."
    fi

    ok "Renamed '${target}' → '${new_name}'."
    [[ -d "$new_home" ]] && plain "Home directory moved to ${new_home}."
}

# ── Action: Change shell ─────────────────────────────────────────────────
action_change_shell() {
    section "Change Login Shell"
    plain "Sets the default command interpreter that starts when this user logs in."
    plain "Common choices: /bin/bash (default), /bin/zsh, /bin/fish"
    plain "The change takes effect the next time the user opens a new session."

    pick_human_user "Username" || return 0
    local target="$_PICK_RESULT"

    # Build list from /etc/shells, excluding nologin/false/sync entries
    local shells=()
    while IFS= read -r sh; do
        [[ "$sh" =~ (nologin|false|sync|shutdown|halt) ]] && continue
        [[ -x "$sh" ]] && shells+=("$sh")
    done < <(grep -v '^#' /etc/shells 2>/dev/null || true)

    if [[ ${#shells[@]} -eq 0 ]]; then
        warn "No valid login shells found in /etc/shells."
        return 0
    fi

    local current_shell
    current_shell=$(getent passwd "$target" | cut -d: -f7)

    printf '\n'
    printf "    Current shell: ${BOLD}%s${NC}\n\n" "$current_shell"
    printf "    Available shells:\n"
    local i=1
    for sh in "${shells[@]}"; do
        if [[ "$sh" == "$current_shell" ]]; then
            printf "    ${GREEN}%d)  %s  (current)${NC}\n" "$i" "$sh"
        else
            printf "    %d)  %s\n" "$i" "$sh"
        fi
        (( i++ ))
    done

    printf '\n'
    local choice idx new_shell
    while true; do
        choice=$(ask_val "Shell number [1-${#shells[@]}], or Enter to cancel")
        if [[ -z "$choice" ]]; then
            info "Cancelled."
            return 0
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#shells[@]} )); then
            idx=$(( choice - 1 ))
            new_shell="${shells[$idx]}"
            break
        fi
        warn "Please enter a number between 1 and ${#shells[@]}, or Enter to cancel."
    done

    if [[ "$new_shell" == "$current_shell" ]]; then
        info "Shell unchanged (already ${new_shell})."
        return 0
    fi

    run usermod -s "$new_shell" "$target"
    ok "'${target}' login shell set to ${new_shell}."
    plain "Open a new session as '${target}' to start using ${new_shell##*/}."
}

# ── Action: Toggle sudo membership ───────────────────────────────────────
action_toggle_sudo() {
    section "Grant / Revoke Sudo Access"

    pick_human_user "Username to modify" || return 0
    local target="$_PICK_RESULT"

    printf '\n'
    if is_sudo_member "$target"; then
        warn "'${target}' currently has sudo access."
        if [[ -n "$CURRENT_OPERATOR" && "$target" == "$CURRENT_OPERATOR" ]]; then
            if would_lose_all_admin "$target"; then
                printf '\n'
                err "Blocked: removing your own sudo access would lock you out of this system."
                plain "Root password is locked and you are the only sudo user."
                plain "To proceed safely, do one of these first:"
                plain "  • Create another sudo user (option 1)"
                plain "  • Enable the root password (option 9 or 10)"
                info "Action cancelled."
                return 0
            fi
            warn "This is your own account — removing sudo means you will no longer"
            plain "be able to run privileged commands until another admin re-adds you."
        fi
        if ask "Remove '${target}' from sudo?" "n"; then
            run gpasswd -d "$target" sudo
            ok "'${target}' removed from sudo."
        else
            info "No changes made."
        fi
    else
        warn "'${target}' does not have sudo access."
        if ask "Grant '${target}' sudo access?" "y"; then
            run usermod -aG sudo "$target"
            ok "'${target}' added to sudo."
            plain "They must log out and back in for this to take effect."
        else
            info "No changes made."
        fi
    fi
}

# ── Action: Toggle Docker group membership ───────────────────────────────
action_toggle_docker() {
    section "Docker Membership"

    if ! getent group docker &>/dev/null; then
        printf '\n'
        warn "The docker group does not exist on this system."
        plain "Install Docker first: https://docs.docker.com/engine/install/"
        return 0
    fi

    pick_human_user "Username to modify" || return 0
    local target="$_PICK_RESULT"

    printf '\n'
    if is_docker_member "$target"; then
        warn "'${target}' is in the docker group."
        if ask "Remove '${target}' from docker?" "n"; then
            run gpasswd -d "$target" docker
            ok "'${target}' removed from docker."
        else
            info "No changes made."
        fi
    else
        warn "'${target}' is not in the docker group."
        plain "docker group membership grants effective root access via container escapes."
        if ask "Add '${target}' to docker?" "y"; then
            run usermod -aG docker "$target"
            ok "'${target}' added to docker."
            plain "They must log out and back in for this to take effect."
        else
            info "No changes made."
        fi
    fi
}

# ── Action: Manage root password ─────────────────────────────────────────
action_manage_root() {
    section "Set / Lock Root Password"

    printf '\n'
    if is_root_pw_enabled; then
        warn "Root has an active password."
        plain "With sudo users in place this is an unnecessary attack surface."
        plain "Locking still allows 'sudo -i' access for any sudo user."

        if ask "Lock the root password?" "y"; then
            run passwd -l root
            ok "Root password locked."
        else
            info "No changes made."
        fi
    else
        local root_status
        root_status=$(passwd -S root 2>/dev/null | awk '{print $2}' || printf 'L')
        [[ "$root_status" == "NP" ]] \
            && info "Root has no password." \
            || info "Root password is locked."

        warn "Setting a root password is not recommended — use 'sudo -i' instead."
        if ask "Set a root password anyway?" "n"; then
            _prompt_password "root" || return 0
            _apply_password "root" "$_PASSWORD_RESULT"
            if [[ "$DRY_RUN" == "false" ]]; then
                passwd -u root 2>/dev/null || true
            else
                printf "    ${DIM}[dry-run]${NC} passwd -u root  # unlock account\n"
            fi
            ok "Root password set and unlocked."
            warn "Run harden-users.sh to lock it again when no longer needed."
        else
            info "No changes made."
        fi
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

# _show_menu — dynamic: Docker option only shown when group exists
_show_menu() {
    local docker_exists=false
    getent group docker &>/dev/null && docker_exists=true

    local root_label
    if is_root_pw_enabled; then
        root_label="Set / lock root password  ${DIM}(active — consider locking)${NC}"
    else
        root_label="Set / lock root password  ${DIM}(locked)${NC}"
    fi

    printf "\n  ${BOLD}Actions${NC}\n\n"
    printf "    1)  Create user\n"
    printf "    2)  Delete user\n"
    printf "    3)  Disable user\n"
    printf "    4)  Re-enable user\n"
    printf "    5)  Change password\n"
    printf "    6)  Rename user\n"
    printf "    7)  Change login shell  ${DIM}(e.g. bash → zsh, fish)${NC}\n"
    printf "    8)  Grant / revoke sudo access\n"
    if [[ "$docker_exists" == "true" ]]; then
        printf "    9)  Grant / revoke Docker access\n"
        printf "   10)  %b\n" "$root_label"
        printf "   11)  Exit\n"
        _MENU_MAX=11
    else
        printf "    9)  %b\n" "$root_label"
        printf "   10)  Exit\n"
        _MENU_MAX=10
    fi
}

# _menu_default — nudge toward the most useful action based on current state
_menu_default() {
    (( HUMAN_COUNT == 0 )) && printf '1' && return
    (( SUDO_COUNT  == 0 )) && printf '8' && return
    printf ''
}

_MENU_MAX=10

main() {
    preflight_checks

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                   manage-users.sh                   │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    # The human who invoked sudo (or empty if running directly as root).
    CURRENT_OPERATOR="${SUDO_USER:-}"

    if [[ -n "${SUDO_USER:-}" ]]; then
        info "Running as root via sudo (operator: ${SUDO_USER})."
    else
        warn "Running directly as root (no sudo context detected)."
    fi

    printf '\n'
    list_human_users
    compute_user_counts

    while true; do
        _show_menu

        MENU_DEFAULT=$(_menu_default)
        local choice=""
        if [[ -n "$MENU_DEFAULT" ]]; then
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}, default ${MENU_DEFAULT}]: " choice || true
            choice="${choice:-$MENU_DEFAULT}"
        else
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}]: " choice || true
        fi

        if getent group docker &>/dev/null; then
            case "$choice" in
                1)  action_create          ;;
                2)  action_delete          ;;
                3)  action_disable         ;;
                4)  action_enable          ;;
                5)  action_change_password ;;
                6)  action_rename          ;;
                7)  action_change_shell    ;;
                8)  action_toggle_sudo     ;;
                9)  action_toggle_docker   ;;
                10) action_manage_root     ;;
                11) info "Exiting."; break ;;
                *)  warn "Please enter 1–11." ;;
            esac
        else
            case "$choice" in
                1)  action_create          ;;
                2)  action_delete          ;;
                3)  action_disable         ;;
                4)  action_enable          ;;
                5)  action_change_password ;;
                6)  action_rename          ;;
                7)  action_change_shell    ;;
                8)  action_toggle_sudo     ;;
                9)  action_manage_root     ;;
                10) info "Exiting."; break ;;
                *)  warn "Please enter 1–10." ;;
            esac
        fi

        printf '\n'
        list_human_users
        compute_user_counts
    done
}

main
