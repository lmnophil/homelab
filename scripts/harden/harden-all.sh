#!/usr/bin/env bash
# ==============================================================================
# harden-all.sh — Orchestrate all harden-*.sh scripts in the current directory
# ==============================================================================
# Discovers every harden-*.sh file in the current directory (excluding itself),
# runs each with --status to produce a unified report, then offers to run the
# full interactive script for every domain that has outstanding failures.
#
# Usage:
#   sudo ./harden-all.sh [--status] [--dry-run] [--help]
#
# Options:
#   --status    Run all harden-*.sh in status mode and report; no prompts
#   --dry-run   Pass --dry-run through to each harden script; no state changes
#   --help      Show this help text
#
# Exit codes:
#   0  All checks pass across all discovered scripts
#   1  One or more checks are failing, or no scripts were found
# ==============================================================================
set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────────────
DRY_RUN="${DRY_RUN:-false}"
STATUS_MODE="${STATUS_MODE:-false}"

for _arg in "$@"; do
    case "$_arg" in
        --dry-run)  DRY_RUN=true ;;
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

# ── Pre-flight ────────────────────────────────────────────────────────────────
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0

preflight_checks() {
    # Status mode is read-only (each child script self-enforces); no root needed.
    # Interactive mode will invoke child scripts that mutate state; root required.
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
}

# ── Script discovery ──────────────────────────────────────────────────────────
# Populated by discover_scripts(); consumed by run_status_all() and main().
SCRIPTS=()

discover_scripts() {
    local self; self=$(basename "$0")
    local path
    for path in harden-*.sh; do
        [[ -f "$path" ]] || continue
        [[ "$(basename "$path")" == "$self" ]] && continue
        SCRIPTS+=("$path")
    done
}

# ── Per-script status state ───────────────────────────────────────────────────
# Parallel arrays indexed to SCRIPTS[].
SCRIPT_NAMES=()    # basename without .sh
SCRIPT_STATUS=()   # "pass" | "fail"
SCRIPT_OUTPUT=()   # raw captured --status output
SCRIPT_PASS_CT=()  # count of PASS lines
SCRIPT_FAIL_CT=()  # count of FAIL lines

run_status_all() {
    local path name output exit_code pass_ct fail_ct
    for path in "${SCRIPTS[@]}"; do
        name=$(basename "$path" .sh)
        exit_code=0
        output=$(bash "$path" --status 2>&1) || exit_code=$?

        pass_ct=$(printf '%s\n' "$output" | grep -c '^  PASS ' || true)
        fail_ct=$(printf '%s\n' "$output" | grep -c '^  FAIL ' || true)

        SCRIPT_NAMES+=("$name")
        SCRIPT_OUTPUT+=("$output")
        SCRIPT_PASS_CT+=("$pass_ct")
        SCRIPT_FAIL_CT+=("$fail_ct")
        if [[ $exit_code -eq 0 ]]; then
            SCRIPT_STATUS+=("pass")
        else
            SCRIPT_STATUS+=("fail")
        fi
    done
}

_reset_status_arrays() {
    SCRIPTS=()
    SCRIPT_NAMES=()
    SCRIPT_STATUS=()
    SCRIPT_OUTPUT=()
    SCRIPT_PASS_CT=()
    SCRIPT_FAIL_CT=()
}

# ── Aggregate counts ──────────────────────────────────────────────────────────
count_total_pass() {
    local total=0 i
    for i in "${!SCRIPT_PASS_CT[@]}"; do
        total=$(( total + SCRIPT_PASS_CT[i] ))
    done
    printf '%d' "$total"
}

count_total_fail() {
    local total=0 i
    for i in "${!SCRIPT_FAIL_CT[@]}"; do
        total=$(( total + SCRIPT_FAIL_CT[i] ))
    done
    printf '%d' "$total"
}

count_scripts_failing() {
    local count=0 s
    for s in "${SCRIPT_STATUS[@]+"${SCRIPT_STATUS[@]}"}"; do
        if [[ "$s" == "fail" ]]; then count=$(( count + 1 )); fi
    done
    printf '%d' "$count"
}

# ── show_status_detail ────────────────────────────────────────────────────────
# Prints the full per-check PASS/FAIL results for every script, grouped by
# script. Passes first within each script, then fails — matching the order
# already emitted by the child scripts.
show_status_detail() {
    local i
    for i in "${!SCRIPTS[@]}"; do
        local name="${SCRIPT_NAMES[$i]}"

        # Script heading
        printf '\n'
        if [[ "${SCRIPT_STATUS[$i]}" == "pass" ]]; then
            printf "  ${GREEN}${BOLD}%s${NC}\n" "$name"
        else
            printf "  ${RED}${BOLD}%s${NC}\n" "$name"
        fi

        local line in_detail=false
        while IFS= read -r line; do
            case "$line" in
                "  PASS  "*)
                    local rest="${line#  PASS  }"
                    local id="${rest%%  *}"
                    local detail=""
                    [[ "$rest" == *"  "* ]] && detail="${rest#*  }"
                    if [[ -n "$detail" ]]; then
                        printf "    ${GREEN}✓${NC}  %-36s %s\n" "$id" "$detail"
                    else
                        printf "    ${GREEN}✓${NC}  %s\n" "$id"
                    fi
                    in_detail=false
                    ;;
                "  FAIL  "*)
                    local id="${line#  FAIL  }"
                    printf "    ${RED}✗${NC}  ${RED}%s${NC}\n" "$id"
                    in_detail=true
                    ;;
                "        "*)
                    if [[ "$in_detail" == "true" ]]; then
                        printf "       ${DIM}%s${NC}\n" "${line#        }"
                    fi
                    ;;
                *)
                    in_detail=false
                    ;;
            esac
        done <<< "${SCRIPT_OUTPUT[$i]}"
    done
    printf '\n'
}

# ── show_summary_report ───────────────────────────────────────────────────────
# Prints a totals bar and, if there are failures, a flat list of every failing
# check across all scripts — the "what still needs attention" view.
show_summary_report() {
    local total_pass; total_pass=$(count_total_pass)
    local total_fail; total_fail=$(count_total_fail)
    local total_checks=$(( total_pass + total_fail ))

    # ── Totals bar ────────────────────────────────────────────────────────────
    printf "  ${BOLD}%d script(s)  ·  %d check(s)${NC}" "${#SCRIPTS[@]}" "$total_checks"
    if [[ $total_fail -eq 0 ]]; then
        printf "  ·  ${GREEN}${BOLD}all passing${NC}"
    else
        printf "  ·  ${GREEN}%d passed${NC}  ·  ${RED}${BOLD}%d failed${NC}" \
            "$total_pass" "$total_fail"
    fi
    printf '\n\n'

    # ── Per-script pass/fail counts ───────────────────────────────────────────
    local n_w=26 p_w=6 f_w=6
    local div_n div_p div_f
    printf -v div_n '%*s' "$n_w" ''; div_n="${div_n// /─}"
    printf -v div_p '%*s' "$p_w" ''; div_p="${div_p// /─}"
    printf -v div_f '%*s' "$f_w" ''; div_f="${div_f// /─}"

    printf "    ${BOLD}%-${n_w}s  %${p_w}s  %${f_w}s${NC}\n" "Script" "Passed" "Failed"
    printf "    %s  %s  %s\n" "$div_n" "$div_p" "$div_f"

    local i
    for i in "${!SCRIPTS[@]}"; do
        local pc="${SCRIPT_PASS_CT[$i]}"
        local fc="${SCRIPT_FAIL_CT[$i]}"
        if [[ "${SCRIPT_STATUS[$i]}" == "pass" ]]; then
            printf "    ${GREEN}%-${n_w}s  %${p_w}s  %${f_w}s${NC}\n" \
                "${SCRIPT_NAMES[$i]}" "$pc" "$fc"
        else
            printf "    ${RED}%-${n_w}s${NC}  ${GREEN}%${p_w}s${NC}  ${RED}%${f_w}s${NC}\n" \
                "${SCRIPT_NAMES[$i]}" "$pc" "$fc"
        fi
    done

    # ── Failure detail list ───────────────────────────────────────────────────
    if [[ $total_fail -gt 0 ]]; then
        printf '\n'
        printf "    ${RED}${BOLD}Failures${NC}\n"
        local div_fail; printf -v div_fail '%*s' 56 ''; div_fail="${div_fail// /─}"
        printf "    %s\n" "$div_fail"

        for i in "${!SCRIPTS[@]}"; do
            [[ "${SCRIPT_STATUS[$i]}" == "pass" ]] && continue
            local name="${SCRIPT_NAMES[$i]}"
            local line in_detail=false last_id=""
            while IFS= read -r line; do
                case "$line" in
                    "  FAIL  "*)
                        last_id="${line#  FAIL  }"
                        printf "    ${RED}✗${NC}  ${BOLD}%-20s${NC}  %s\n" "$name" "$last_id"
                        in_detail=true
                        ;;
                    "        "*)
                        if [[ "$in_detail" == "true" ]]; then
                            printf "       %-20s  ${DIM}%s${NC}\n" "" "${line#        }"
                        fi
                        ;;
                    *)
                        in_detail=false
                        ;;
                esac
            done <<< "${SCRIPT_OUTPUT[$i]}"
        done
    fi
    printf '\n'
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    preflight_checks

    # ── Discover scripts ──────────────────────────────────────────────────────
    discover_scripts
    if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
        die "No harden-*.sh scripts found in the current directory."
    fi

    # ── Status mode ───────────────────────────────────────────────────────────
    # Shows per-check results for every discovered script, then a summary report.
    if [[ "$STATUS_MODE" == "true" ]]; then
        run_status_all
        show_status_detail
        header "Summary"
        show_summary_report
        local total_fail; total_fail=$(count_total_fail)
        [[ $total_fail -eq 0 ]] && exit 0 || exit 1
    fi

    # ── Banner ────────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │                   harden-all.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    local script_list; script_list=$(printf '%s  ' "${SCRIPTS[@]}")
    info "Found ${#SCRIPTS[@]} script(s):  ${script_list}"

    # ── Run --status on all scripts ───────────────────────────────────────────
    section "Status Check"
    printf '\n'
    local path
    for path in "${SCRIPTS[@]}"; do
        info "Checking $(basename "$path") ..."
    done

    run_status_all

    local scripts_failing; scripts_failing=$(count_scripts_failing)

    header "Status Summary"
    show_status_detail
    header "Summary"
    show_summary_report

    # ── All pass — nothing to do ──────────────────────────────────────────────
    if (( scripts_failing == 0 )); then
        ok "All hardening checks pass. No action needed."
        exit 0
    fi

    # ── Offer remediation for failing scripts ─────────────────────────────────
    section "Remediation"
    printf '\n'
    if (( scripts_failing == 1 )); then
        warn "1 script has failing checks."
    else
        warn "${scripts_failing} scripts have failing checks."
    fi
    plain "Each will be run interactively so you can review and apply fixes."
    plain "Declining any individual fix inside a script is always allowed."
    printf '\n'

    if ! ask "Proceed with remediation?" "y"; then
        info "Remediation skipped. Re-run $(basename "$0") to check status again."
        exit 1
    fi

    local extra_args=()
    [[ "$DRY_RUN" == "true" ]] && extra_args+=("--dry-run")

    local i
    for i in "${!SCRIPTS[@]}"; do
        [[ "${SCRIPT_STATUS[$i]}" == "pass" ]] && continue

        printf '\n'
        local div; printf -v div '%*s' 56 ''; printf "${BLUE}${BOLD}  %s${NC}\n" "${div// /─}"
        printf "${BLUE}${BOLD}  Running: %s${NC}\n" "${SCRIPTS[$i]}"
        printf "${BLUE}${BOLD}  %s${NC}\n" "${div// /─}"

        bash "${SCRIPTS[$i]}" "${extra_args[@]+"${extra_args[@]}"}" || true
    done

    # ── Re-run status to show final state ─────────────────────────────────────
    _reset_status_arrays
    discover_scripts
    run_status_all

    total_pass=$(count_total_pass)
    total_fail=$(count_total_fail)
    scripts_failing=$(count_scripts_failing)
    total_checks=$(( total_pass + total_fail ))

    header "Final Status"
    show_status_detail
    header "Summary"
    show_summary_report

    local total_fail; total_fail=$(count_total_fail)
    if [[ $total_fail -eq 0 ]]; then
        ok "All checks now pass."
    else
        warn "Some checks are still failing. Re-run $(basename "$0") to address them."
    fi
}

main