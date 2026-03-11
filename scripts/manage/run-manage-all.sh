#!/usr/bin/env bash
# ==============================================================================
# run-manage-all.sh  —  Launcher menu for all manage-*.sh scripts in the same folder
# ==============================================================================
#
# Usage:
#   sudo ./run-manage-all.sh [--help]
#
# Description:
#   Discovers every manage-*.sh script in the same directory (excluding itself),
#   presents the domain names as a numbered menu, and launches the selected
#   script. When the selected script exits (for any reason), control returns
#   to this menu automatically.
#
# Requirements: Ubuntu 22.04+ or Debian 11+. Run as root or via sudo.
# ==============================================================================
set -euo pipefail

# ── Flags & env vars ──────────────────────────────────────────────────────────
DRY_RUN="${DRY_RUN:-false}"

for _arg in "$@"; do
    case "$_arg" in
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

# ── Script discovery ──────────────────────────────────────────────────────────
# Resolves the canonical directory of this script even when called via a
# symlink, then collects every manage-*.sh in that directory except itself.

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SELF="$(readlink -f "$0")"

_discover_scripts() {
    MANAGE_SCRIPTS=()
    MANAGE_LABELS=()

    local f label
    for f in "$SCRIPT_DIR"/manage-*.sh; do
        [[ -f "$f" ]] || continue
        [[ "$(readlink -f "$f")" == "$SELF" ]] && continue
        label="$(basename "$f" .sh)"   # manage-ssh
        label="${label#manage-}"       # ssh
        MANAGE_SCRIPTS+=( "$f" )
        MANAGE_LABELS+=( "$label" )
    done
}

# Module-level arrays (must exist before any function reads them)
MANAGE_SCRIPTS=()
MANAGE_LABELS=()

# ── Banner ────────────────────────────────────────────────────────────────────
_banner() {
    printf "\n${BLUE}${BOLD}"
    printf "  ┌─────────────────────────────────────────────────┐\n"
    printf "  │              run-manage-all  —  launcher             │\n"
    printf "  └─────────────────────────────────────────────────┘\n"
    printf "${NC}\n"
}

# ── Menu ──────────────────────────────────────────────────────────────────────
_show_menu() {
    section "Available management scripts"
    printf '\n'

    if [[ ${#MANAGE_LABELS[@]} -eq 0 ]]; then
        warn "No manage-*.sh scripts found in ${SCRIPT_DIR}"
        printf '\n'
    else
        local i
        for i in "${!MANAGE_LABELS[@]}"; do
            printf "  ${BOLD}%2d)${NC}  %s\n" $(( i + 1 )) "${MANAGE_LABELS[$i]}"
        done
        printf '\n'
    fi

    printf "  ${BOLD}%2d)${NC}  exit\n" $(( ${#MANAGE_LABELS[@]} + 1 ))
    printf '\n'
}

_menu_default() {
    printf '%s' $(( ${#MANAGE_LABELS[@]} + 1 ))
}

# ── Launcher ──────────────────────────────────────────────────────────────────
_launch() {
    local idx="$1"
    local target="${MANAGE_SCRIPTS[$idx]}"

    if [[ ! -x "$target" ]]; then
        warn "${target} is not executable — running with bash explicitly."
        plain "To silence this warning: chmod +x $(basename "$target")"
    fi

    section "Launching: manage-${MANAGE_LABELS[$idx]}"
    printf '\n'

    # Run in a subshell so exits and errors in the child do not terminate
    # run-manage-all. The || true absorbs any non-zero exit from the child.
    if [[ -x "$target" ]]; then
        ( "$target" ) || true
    else
        ( bash "$target" ) || true
    fi

    printf '\n'
    info "Returned to run-manage-all."
}

# ── Preflight ─────────────────────────────────────────────────────────────────
preflight_checks() {
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root or via sudo."
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    preflight_checks

    _banner

    local choice exit_opt raw
    while true; do
        _discover_scripts
        _show_menu

        exit_opt=$(( ${#MANAGE_LABELS[@]} + 1 ))

        read -rp "  ${YELLOW}Select [1-${exit_opt}]:${NC} " raw || { printf '\n'; break; }
        choice="${raw:-$(_menu_default)}"

        # Validate: must be an integer in range
        if ! [[ "$choice" =~ ^[0-9]+$ ]] \
           || (( choice < 1 )) \
           || (( choice > exit_opt )); then
            warn "Invalid selection — enter a number between 1 and ${exit_opt}."
            continue
        fi

        if (( choice == exit_opt )); then
            info "Goodbye."
            printf '\n'
            exit 0
        fi

        if [[ ${#MANAGE_SCRIPTS[@]} -eq 0 ]]; then
            warn "No scripts available to launch."
            continue
        fi

        _launch $(( choice - 1 ))
    done
}

main "$@"
