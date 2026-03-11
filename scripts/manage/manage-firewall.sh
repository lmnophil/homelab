#!/usr/bin/env bash
# ==============================================================================
# manage-firewall.sh — Interactive ufw firewall management for Proxmox LXC
# ==============================================================================
#
# Usage:
#   sudo ./manage-firewall.sh [--dry-run] [--help]
#
# Description:
#   Interactive menu for managing ufw firewall rules on Proxmox LXC containers.
#   Designed to make it easy to:
#     • Add / remove port rules safely with lockout protection
#     • Configure rules for common exposure models (LAN-only, Cloudflare Tunnel,
#       Pangolin/Newt Tunnel, VPN, direct/public IP)
#     • Temporarily open all traffic for debugging
#     • Reset the firewall to a safe known state
#     • Review and manage Cloudflare IP allowlists
#
#   Exposure models:
#     lan        — services visible only inside your home network
#     cloudflare — outbound cloudflared tunnel; no inbound ports needed
#     pangolin   — outbound WireGuard via Newt to a self-hosted VPS (Pangolin)
#     vpn        — services reachable only via Tailscale / WireGuard
#     direct     — public IP with router port-forwarding (80/443 open)
#
#   ⚠ This script allows you to deviate from best practices for debugging.
#     All non-recommended actions are clearly labelled.
#
# Environment variables:
#   DRY_RUN=true   Print commands without executing them (no root required)
#
# ──────────────────────────────────────────────────────────────────────────────
# Every action refreshes the state table so you always see current status.
# ==============================================================================

set -euo pipefail

# ── Argument parsing ───────────────────────────────────────────────────────────

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

# ── Colors ─────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED=$'\e[0;31m';  GREEN=$'\e[0;32m';  YELLOW=$'\e[1;33m'
    BLUE=$'\e[0;34m'; CYAN=$'\e[0;36m';   BOLD=$'\e[1m'
    DIM=$'\e[2m';     NC=$'\e[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Output helpers ─────────────────────────────────────────────────────────────

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

# ── run() — dry-run wrapper ────────────────────────────────────────────────────

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" "$*"
    else
        "$@"
    fi
}

# ── Prompt helpers ─────────────────────────────────────────────────────────────

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

# ── OS detection ───────────────────────────────────────────────────────────────

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
}

# ── Module-level globals (required by set -u) ──────────────────────────────────

_MENU_MAX=10
MENU_DEFAULT=''
_PICK_RESULT=''
_PORT_RESULT=''
_PROTO_RESULT=''

# Cloudflare fallback IPs (used when live fetch fails)
CF_IPS_FALLBACK="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 \
198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"

# ── State helpers ──────────────────────────────────────────────────────────────

is_pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
ufw_active()       { ufw status 2>/dev/null | grep -q "^Status: active"; }

detect_ssh_port() {
    local port
    # sshd -T dumps the merged effective config — most reliable source
    port=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')
    # ss fallback — POSIX awk: split on ':', take last field
    if [[ -z "$port" ]]; then
        port=$(ss -tlnp 2>/dev/null \
            | awk '/sshd/ {n=split($4,a,":"); if(n>0) print a[n]}' \
            | head -1)
    fi
    # Config file fallback
    [[ -z "$port" ]] && port=$(grep -i "^Port " /etc/ssh/sshd_config 2>/dev/null \
        | awk '{print $2}' | head -1)
    [[ -z "$port" ]] && port=$(grep -ri "^Port " /etc/ssh/sshd_config.d/ 2>/dev/null \
        | awk '{print $2}' | head -1)
    printf '%s' "${port:-22}"
}

detect_lan_subnet() {
    local iface subnet
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    [[ -z "$iface" ]] && return
    subnet=$(ip -4 addr show "$iface" 2>/dev/null \
        | awk '/inet / {print $2}' \
        | python3 -c "
import sys, ipaddress
for line in sys.stdin:
    line = line.strip()
    if line:
        net = ipaddress.IPv4Interface(line).network
        print(str(net))
        break
" 2>/dev/null || true)
    printf '%s' "$subnet"
}

fetch_cf_ips() {
    local fetched
    fetched=$(curl -fsSL --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null || true)
    if [[ -n "$fetched" ]]; then
        printf '%s' "$(printf '%s' "$fetched" | tr '\n' ' ')"
    else
        warn "Could not reach cloudflare.com — using built-in fallback IP list."
        printf '%s' "$CF_IPS_FALLBACK"
    fi
}

ufw_numbered_rules() {
    ufw status numbered 2>/dev/null | grep -E "^\[ *[0-9]+" || true
}

# ── ufw_factory_reset() ────────────────────────────────────────────────────────
# A true factory reset must do more than 'ufw --force reset'.
#
# ufw --force reset:
#   ✓ wipes all user rules (user.rules, user6.rules)
#   ✓ restores before/after.rules to package versions
#   ✓ sets ENABLED=no in ufw.conf
#   ✗ does NOT restore DEFAULT_INPUT_POLICY in /etc/default/ufw
#   ✗ does NOT restore DEFAULT_OUTPUT_POLICY in /etc/default/ufw
#   ✗ does NOT restore DEFAULT_FORWARD_POLICY in /etc/default/ufw
#   ✗ does NOT reset LOGLEVEL
#
# If a previous operator ran "ufw default allow incoming" those settings survive
# a plain reset. This helper explicitly writes back the package defaults to both
# config files so the result is identical to a fresh apt install of ufw.
#
# Package defaults (ufw 0.36 / Ubuntu 22.04+, Debian 11+):
#   /etc/default/ufw:  DEFAULT_INPUT_POLICY="DROP"    (ufw shows this as "deny")
#                      DEFAULT_OUTPUT_POLICY="ACCEPT"  (ufw shows this as "allow")
#                      DEFAULT_FORWARD_POLICY="DROP"
#                      DEFAULT_APPLICATION_POLICY="SKIP"
#                      IPV6="yes"
#                      MANAGE_BUILTINS="no"
#   /etc/ufw/ufw.conf: ENABLED=no
#                      LOGLEVEL=low
ufw_factory_reset() {
    local ts; ts=$(date +%Y%m%d%H%M%S)
    local default_ufw="/etc/default/ufw"
    local ufw_conf="/etc/ufw/ufw.conf"

    # Back up config files before touching them
    if [[ -f "$default_ufw" ]]; then
        run cp "$default_ufw" "${default_ufw}.bak.${ts}"
        info "Backed up ${default_ufw} → ${default_ufw}.bak.${ts}"
    fi
    if [[ -f "$ufw_conf" ]]; then
        run cp "$ufw_conf" "${ufw_conf}.bak.${ts}"
        info "Backed up ${ufw_conf} → ${ufw_conf}.bak.${ts}"
    fi

    # Step 1: wipe all user rules and restore before/after.rules
    run ufw --force reset

    # Step 2: restore factory default policies in /etc/default/ufw.
    # Updates existing directive (commented or not), or appends if absent.
    _ufw_set_conf() {
        local file="$1" key="$2" val="$3"
        if [[ "$DRY_RUN" == "true" ]]; then
            printf "    ${DIM}[dry-run]${NC} set %s=%s in %s\n" "$key" "$val" "$file"
            return
        fi
        if grep -qE "^#?[[:space:]]*${key}=" "$file" 2>/dev/null; then
            sed -i "s|^#\?[[:space:]]*${key}=.*|${key}=${val}|" "$file"
        else
            printf '%s=%s\n' "$key" "$val" >> "$file"
        fi
    }

    if [[ -f "$default_ufw" ]]; then
        _ufw_set_conf "$default_ufw" 'DEFAULT_INPUT_POLICY'       '"DROP"'
        _ufw_set_conf "$default_ufw" 'DEFAULT_OUTPUT_POLICY'      '"ACCEPT"'
        _ufw_set_conf "$default_ufw" 'DEFAULT_FORWARD_POLICY'     '"DROP"'
        _ufw_set_conf "$default_ufw" 'DEFAULT_APPLICATION_POLICY' '"SKIP"'
        _ufw_set_conf "$default_ufw" 'IPV6'                       '"yes"'
        _ufw_set_conf "$default_ufw" 'MANAGE_BUILTINS'            '"no"'
        ok "Restored factory default policies in ${default_ufw}"
    else
        warn "${default_ufw} not found — skipping policy restore."
        plain "This is unexpected on Ubuntu/Debian with ufw installed."
    fi

    # Step 3: ensure ufw.conf has ENABLED=no and LOGLEVEL=low
    if [[ -f "$ufw_conf" ]]; then
        _ufw_set_conf "$ufw_conf" 'ENABLED'  'no'
        _ufw_set_conf "$ufw_conf" 'LOGLEVEL' 'low'
        ok "Restored factory defaults in ${ufw_conf}"
    else
        warn "${ufw_conf} not found — skipping."
        plain "This is unexpected on Ubuntu/Debian with ufw installed."
    fi
}

# ── State table ────────────────────────────────────────────────────────────────

show_state() {
    printf '\n'

    if ! is_pkg_installed "ufw"; then
        printf "  ${RED}${BOLD}ufw: NOT INSTALLED${NC}\n"
        printf '\n'
        plain "Install ufw first:  apt install ufw"
        plain "Or run:             harden-firewall.sh"
        return
    fi

    local status_color status_label
    if ufw_active; then
        status_color="$GREEN"; status_label="active"
    else
        status_color="$RED"; status_label="inactive"
    fi

    # Header
    local div; printf -v div '%*s' 58 ''; div="${div// /─}"
    printf "  ${BOLD}Firewall Status:  ${status_color}%s${NC}\n\n" "$status_label"
    printf "  %s\n" "$div"
    printf "  ${BOLD}%-30s %-10s %-14s${NC}\n" "To" "Action" "From"
    printf "  %s\n" "$div"

    if ufw_active; then
        local num_rules
        num_rules=$(ufw_numbered_rules | wc -l)
        if [[ "$num_rules" -eq 0 ]]; then
            printf "  ${DIM}  (no rules configured)${NC}\n"
        else
            # ufw status numbered produces lines like:
            #   [ 1] 22/tcp                     ALLOW IN    Anywhere           # SSH
            #   [ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
            # Strip the leading "[ N] " prefix, then parse using the fact that
            # ufw separates To/Action/From with multiple spaces.
            # ufw status numbered columns are separated by 2+ spaces.
            # awk -F'  +' reliably splits To / "ACTION [DIR]" / From
            # even when To contains spaces (e.g. "22/tcp (v6)", "Nginx Full").
            ufw status numbered 2>/dev/null \
                | grep -E "^\[ *[0-9]+" \
                | sed 's/^\[ *[0-9]*\] *//' \
                | while IFS= read -r line; do
                    local col_action to action_raw action from
                    to=$(        printf '%s' "$line" | awk -F'  +' '{print $1}')
                    action_raw=$(printf '%s' "$line" | awk -F'  +' '{print $2}')
                    from=$(      printf '%s' "$line" | awk -F'  +' '{print $3}')
                    # "ALLOW IN" / "DENY IN" / "LIMIT IN" — keep only the verb
                    action=$(printf '%s' "$action_raw" | awk '{print $1}')
                    # Strip inline comment (ufw appends "  # label")
                    from="${from%% # *}"
                    from="${from%"${from##*[! ]}"}"
                    [[ -z "$from" ]] && from="Anywhere"

                    case "$action" in
                        ALLOW) col_action="${GREEN}"  ;;
                        DENY|REJECT) col_action="${RED}" ;;
                        LIMIT) col_action="${YELLOW}" ;;
                        *)     col_action="${NC}"     ;;
                    esac
                    printf "  %-30s ${col_action}%-6s${NC}  %s\n" "$to" "$action" "$from"
                  done
        fi

        printf "  %s\n" "$div"

        # ufw status verbose Default line:
        #   Default: deny (incoming), allow (outgoing), disabled (routed)
        # Extract word immediately before each parenthesised keyword.
        local defaults_line def_in def_out
        defaults_line=$(ufw status verbose 2>/dev/null | grep "^Default:" || true)
        def_in=$( printf '%s' "$defaults_line" | grep -oE '[a-z]+[[:space:]]*\(incoming\)' \
                    | grep -oE '^[a-z]+' || true)
        def_out=$(printf '%s' "$defaults_line" | grep -oE '[a-z]+[[:space:]]*\(outgoing\)' \
                    | grep -oE '^[a-z]+' || true)
        printf '\n'
        printf "  Default incoming: "
        [[ "$def_in" == "deny" ]] \
            && printf "${GREEN}deny${NC}  ✓\n" \
            || printf "${RED}%s${NC}  ⚠ (best practice: deny)\n" "${def_in:-unknown}"
        printf "  Default outgoing: "
        [[ "$def_out" == "allow" ]] \
            && printf "${GREEN}allow${NC} ✓\n" \
            || printf "${RED}%s${NC}  ⚠ (best practice: allow)\n" "${def_out:-unknown}"

        # Note: tunnel detection (cloudflared, newt) is not done here — the agent
        # may run on another host. Use harden-firewall.sh to audit by exposure model.
    else
        printf "  ${DIM}  (ufw is inactive — no rules enforced)${NC}\n"
        printf "  %s\n" "$div"
    fi
    printf '\n'
}

# ── Menu ───────────────────────────────────────────────────────────────────────
# Options are conditionally shown based on system state.

_show_menu() {
    local n=1
    printf "\n${BOLD}  Options${NC}\n"

    _MENU_ITEMS=()   # parallel array: item index → option number
    local ufw_inst=false ufw_on=false
    is_pkg_installed "ufw" && ufw_inst=true
    ufw_active && ufw_on=true

    if [[ "$ufw_inst" == "false" ]]; then
        printf "  ${DIM}  (most options are hidden — ufw is not installed)${NC}\n\n"
        printf "  %2d)  Install ufw\n" "$n"; _MENU_ITEMS+=("install_ufw");      (( n++ ))
        printf "  %2d)  Help — what is ufw and why does it matter?\n" "$n"
        _MENU_ITEMS+=("help_ufw"); (( n++ ))
        printf "  %2d)  Exit\n" "$n"; _MENU_ITEMS+=("exit"); _MENU_MAX=$n; return
    fi

    if [[ "$ufw_on" == "false" ]]; then
        printf "  %2d)  Enable ufw (adds SSH rule first to prevent lockout)\n" "$n"
        _MENU_ITEMS+=("enable_ufw"); (( n++ ))
    else
        printf "  %2d)  ${YELLOW}Disable ufw${NC} — remove all firewall enforcement ${DIM}[⚠ not recommended]${NC}\n" "$n"
        _MENU_ITEMS+=("disable_ufw"); (( n++ ))
    fi

    printf "  %2d)  Add a port rule\n" "$n";               _MENU_ITEMS+=("add_rule");      (( n++ ))
    printf "  %2d)  Remove a port rule\n" "$n";            _MENU_ITEMS+=("remove_rule");   (( n++ ))
    printf "  %2d)  Allow a source IP / subnet\n" "$n";    _MENU_ITEMS+=("allow_source");  (( n++ ))
    printf "  %2d)  Deny a source IP / subnet\n" "$n";     _MENU_ITEMS+=("deny_source");   (( n++ ))
    printf "  %2d)  Set default policies\n" "$n";          _MENU_ITEMS+=("set_defaults");  (( n++ ))

    printf "\n  ${BOLD}── Exposure model setup${NC}\n"
    printf "  %2d)  Setup: LAN-only\n" "$n";               _MENU_ITEMS+=("setup_lan");           (( n++ ))
    printf "  %2d)  Setup: Cloudflare Tunnel\n" "$n";      _MENU_ITEMS+=("setup_cloudflare");    (( n++ ))
    printf "  %2d)  Setup: Pangolin / Newt Tunnel (VPS)\n" "$n"
    _MENU_ITEMS+=("setup_pangolin"); (( n++ ))
    printf "  %2d)  Setup: VPN only (Tailscale / WireGuard)\n" "$n"
    _MENU_ITEMS+=("setup_vpn"); (( n++ ))
    printf "  %2d)  Setup: Direct / public IP (router port-forward)\n" "$n"
    _MENU_ITEMS+=("setup_direct"); (( n++ ))

    printf "\n  ${BOLD}── Cloudflare IP management${NC}\n"
    printf "  %2d)  Update / view allowed Cloudflare IPs\n" "$n"
    _MENU_ITEMS+=("manage_cf_ips"); (( n++ ))

    printf "\n  ${BOLD}── Maintenance${NC}\n"
    printf "  %2d)  ${YELLOW}Open all traffic${NC} ${DIM}(temporary debug mode — not recommended)${NC}\n" "$n"
    _MENU_ITEMS+=("open_all"); (( n++ ))
    printf "  %2d)  Reset firewall to safe defaults\n" "$n"
    _MENU_ITEMS+=("reset_defaults"); (( n++ ))
    printf "  %2d)  Help — Docker + ufw bypass explained\n" "$n"
    _MENU_ITEMS+=("help_docker"); (( n++ ))
    printf "  %2d)  Help — exposure model guide\n" "$n"
    _MENU_ITEMS+=("help_exposure"); (( n++ ))

    printf '\n'
    printf "  %2d)  Exit\n" "$n"; _MENU_ITEMS+=("exit")
    _MENU_MAX=$n
}

_menu_default() {
    is_pkg_installed "ufw" || { printf '1'; return; }
    ufw_active             || { printf '1'; return; }
    printf ''
}

# ── Action: install ufw ────────────────────────────────────────────────────────

action_install_ufw() {
    if is_pkg_installed "ufw"; then
        ok "ufw is already installed."
        return 0
    fi
    printf '\n'
    info "Installing ufw..."
    run apt-get install -y ufw
    ok "ufw installed. It is not yet active — use the Enable option."
}

# ── Action: enable ufw ────────────────────────────────────────────────────────
# Critical: always ensure SSH is allowed before enabling.

action_enable_ufw() {
    if ufw_active; then
        ok "ufw is already active."
        return 0
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)

    printf '\n'
    section "Enable ufw"
    info "Detected SSH port: ${ssh_port}"
    plain "Before enabling, a rule for SSH will be added (if not already present)"
    plain "to prevent locking yourself out."
    plain ""
    plain "Current ufw rules (will be applied when activated):"
    ufw status 2>/dev/null | grep -E "ALLOW|DENY|REJECT" | sed 's/^/    /' || plain "  (none)"

    if ! ufw status 2>/dev/null | grep -qE "^${ssh_port}[/[:space:]].*ALLOW"; then
        warn "SSH (port ${ssh_port}) is not in the rules — it will be added automatically."
    fi

    if ask "Add SSH rule for port ${ssh_port} (if needed) and enable ufw?" "y"; then
        if ! ufw status 2>/dev/null | grep -qE "^${ssh_port}[/[:space:]].*ALLOW"; then
            run ufw allow "${ssh_port}/tcp" comment 'SSH'
            ok "SSH rule added for port ${ssh_port}."
        fi
        run ufw --force enable
        ok "ufw is now active."
    else
        info "Cancelled."
    fi
}

# ── Action: disable ufw ────────────────────────────────────────────────────────

action_disable_ufw() {
    printf '\n'
    section "Disable ufw"
    warn "Disabling ufw removes all firewall enforcement."
    plain "Any port that a service is listening on becomes immediately reachable"
    plain "from the network — including Docker ports and services bound to 0.0.0.0."
    plain ""
    plain "This should only be done for:"
    plain "  • Debugging a connectivity problem (re-enable immediately after)"
    plain "  • Before reconfiguring from scratch"
    plain ""
    plain "If you need to allow a specific service, use 'Add a port rule' instead."

    if ask "Disable ufw? (NOT recommended for normal operation)" "n"; then
        run ufw disable
        warn "ufw disabled. Run 'sudo ufw enable' to re-activate."
    else
        info "Cancelled — ufw remains active."
    fi
}

# ── Validation helpers ─────────────────────────────────────────────────────────

_PORT_RESULT=''
_prompt_port() {
    _PORT_RESULT=''
    local candidate
    while true; do
        candidate=$(ask_val "Port number (1–65535, or range like 8000:8100, Enter to cancel)")
        [[ -z "$candidate" ]] && { info "Cancelled."; return 1; }
        if [[ "$candidate" =~ ^([0-9]+)(:([0-9]+))?$ ]]; then
            local p1="${BASH_REMATCH[1]}" p2="${BASH_REMATCH[3]:-}"
            if (( p1 >= 1 && p1 <= 65535 )) && { [[ -z "$p2" ]] || (( p2 >= 1 && p2 <= 65535 && p2 > p1 )); }; then
                _PORT_RESULT="$candidate"
                return 0
            fi
        fi
        warn "'${candidate}' is not a valid port or range. Examples: 8080, 443, 8000:8100"
    done
}

_PROTO_RESULT=''
_prompt_proto() {
    _PROTO_RESULT=''
    local candidate
    while true; do
        candidate=$(ask_val "Protocol (tcp / udp / any)" "tcp")
        [[ -z "$candidate" ]] && { info "Cancelled."; return 1; }
        case "${candidate,,}" in
            tcp|udp|any) _PROTO_RESULT="${candidate,,}"; return 0 ;;
            *) warn "Enter 'tcp', 'udp', or 'any'." ;;
        esac
    done
}

_validate_cidr() {
    local cidr="$1"
    # Accept plain IPs, IPs with /prefix, or hostnames/keywords like 'Anywhere'
    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && return 0
    [[ "$cidr" =~ ^[a-zA-Z0-9._-]+$ ]] && return 0
    return 1
}

# ── Action: add rule ───────────────────────────────────────────────────────────

action_add_rule() {
    printf '\n'
    section "Add Port Rule"
    info "Add a rule to allow inbound traffic on a port."
    plain ""
    plain "Examples of when you need this:"
    plain "  • SSH (22) — always needed if you haven't set it up"
    plain "  • Tailscale direct (41641/udp)"
    plain "  • A game server or VoIP service that must accept inbound connections"
    plain ""
    plain "Examples of when you do NOT need this:"
    plain "  • Services accessed via Cloudflare Tunnel or Pangolin/Newt"
    plain "    (cloudflared and newt dial OUT — no inbound ports needed)"
    plain "  • Docker containers — bind them to 127.0.0.1 instead"
    plain "    (Docker bypasses ufw; use ports: [\"127.0.0.1:XXXX:XXXX\"])"

    _prompt_port    || return 0
    local port="$_PORT_RESULT"

    _prompt_proto   || return 0
    local proto="$_PROTO_RESULT"

    local from
    from=$(ask_val "Allow from (IP, CIDR, or 'any')" "any")
    [[ -z "$from" ]] && from="any"

    local comment
    comment=$(ask_val "Comment / label (optional)")

    local rule_str
    if [[ "$from" == "any" ]]; then
        rule_str="${port}/${proto}"
    else
        rule_str="from ${from} to any port ${port} proto ${proto}"
    fi

    printf '\n'
    info "Rule to be added: ufw allow ${rule_str}"
    [[ -n "$comment" ]] && plain "Comment: ${comment}"

    # Warn if opening a port that is commonly unnecessary for tunnel setups
    if [[ "$port" == "80" || "$port" == "443" ]]; then
        printf '\n'
        warn "Opening port ${port} is not needed if you use a Cloudflare Tunnel or Pangolin/Newt."
        plain "Those tunnel agents dial OUT — no inbound port 80/443 is required."
        plain "If you use a tunnel, opening this port exposes you to direct-to-IP"
        plain "attacks that bypass your tunnel's DDoS and bot protections."
        plain ""
        plain "You should open port ${port} only if:"
        plain "  • You are running a direct/public IP setup (router port-forwarding)"
        plain "  • You have a specific non-HTTP service that needs this port"
        if ! ask "Confirm you need port ${port} open?" "n"; then
            info "Cancelled."
            return 0
        fi
    fi

    if ask "Add this rule?" "y"; then
        if [[ -n "$comment" ]]; then
            run ufw allow "$rule_str" comment "$comment"
        else
            run ufw allow "$rule_str"
        fi
        run ufw reload
        ok "Rule added: ${rule_str}"
    else
        info "Cancelled."
    fi
}

# ── Action: remove rule ────────────────────────────────────────────────────────

action_remove_rule() {
    printf '\n'
    section "Remove Port Rule"

    local numbered
    numbered=$(ufw_numbered_rules)
    if [[ -z "$numbered" ]]; then
        warn "No rules to remove — ufw has no rules configured."
        return 0
    fi

    printf '\n'
    info "Current numbered rules:"
    printf '%s\n' "$numbered" | sed 's/^/    /'
    printf '\n'

    # Protect SSH from removal
    local ssh_port
    ssh_port=$(detect_ssh_port)

    local num_choice
    while true; do
        num_choice=$(ask_val "Enter rule number to remove (Enter to cancel)")
        [[ -z "$num_choice" ]] && { info "Cancelled."; return 0; }
        [[ "$num_choice" =~ ^[0-9]+$ ]] && break
        warn "Enter a number."
    done

    # Extract what rule that number refers to
    local rule_line
    rule_line=$(printf '%s\n' "$numbered" | grep -E "^\[ *${num_choice}\]" || true)
    if [[ -z "$rule_line" ]]; then
        warn "No rule with number ${num_choice}."
        return 0
    fi

    # Warn if deleting SSH
    if printf '%s' "$rule_line" | grep -qE "${ssh_port}[/[:space:]]"; then
        warn "This rule appears to allow SSH (port ${ssh_port})."
        plain "Removing the SSH rule will lock you out of this container unless"
        plain "you have another way in (console access via Proxmox, another allowed IP, etc.)."
        if ! ask "Remove the SSH rule anyway? (DANGEROUS)" "n"; then
            info "Cancelled — SSH rule preserved."
            return 0
        fi
    fi

    info "Rule selected: ${rule_line}"
    if ask "Delete rule [${num_choice}]?" "n"; then
        run ufw --force delete "$num_choice"
        run ufw reload
        ok "Rule ${num_choice} deleted."
    else
        info "Cancelled."
    fi
}

# ── Action: allow source IP/subnet ────────────────────────────────────────────

action_allow_source() {
    printf '\n'
    section "Allow Source IP / Subnet"
    info "Allow all traffic from a specific IP address or CIDR range."
    plain ""
    plain "Use this for:"
    plain "  • Allowing full LAN access from your home subnet (e.g. 192.168.1.0/24)"
    plain "  • Adding a management machine that needs unrestricted access"
    plain "  • Allowing Cloudflare IP ranges (use 'Manage CF IPs' instead)"
    plain ""
    warn "Allowing an entire subnet gives every host on that network full access."
    plain "Be specific when possible — allow individual IPs rather than wide ranges."

    local src
    while true; do
        src=$(ask_val "Source IP or CIDR (Enter to cancel)")
        [[ -z "$src" ]] && { info "Cancelled."; return 0; }
        _validate_cidr "$src" && break
        warn "'${src}' does not look like a valid IP or CIDR. Example: 192.168.1.0/24"
    done

    if ask "Allow all traffic from ${src}?" "y"; then
        run ufw allow from "$src"
        run ufw reload
        ok "Allowed all traffic from ${src}."
    else
        info "Cancelled."
    fi
}

# ── Action: deny source IP/subnet ─────────────────────────────────────────────

action_deny_source() {
    printf '\n'
    section "Deny Source IP / Subnet"
    info "Explicitly block traffic from a specific IP address or CIDR range."
    plain ""
    plain "Use this for:"
    plain "  • Blocking a known attacker IP"
    plain "  • Isolating a subnet that should never reach this container"
    plain ""
    plain "Note: ufw processes rules in order. If an ALLOW rule for a port exists"
    plain "and appears before this DENY rule, the ALLOW may take precedence."
    plain "Use 'ufw status numbered' to check rule ordering."

    local src
    while true; do
        src=$(ask_val "Source IP or CIDR to block (Enter to cancel)")
        [[ -z "$src" ]] && { info "Cancelled."; return 0; }
        _validate_cidr "$src" && break
        warn "'${src}' does not look like a valid IP or CIDR."
    done

    if ask "Deny all traffic from ${src}?" "y"; then
        run ufw deny from "$src"
        run ufw reload
        ok "Blocked traffic from ${src}."
    else
        info "Cancelled."
    fi
}

# ── Action: set default policies ─────────────────────────────────────────────

action_set_defaults() {
    printf '\n'
    section "Set Default Policies"
    info "Default policies determine what happens to traffic that matches no rule."
    plain ""
    plain "Best practice (and the only sane choice for a server):"
    plain "  • Default INCOMING: deny  — block everything unless explicitly allowed"
    plain "  • Default OUTGOING: allow — permit all outbound traffic by default"
    plain ""
    plain "Changing these from best practice is almost never the right solution."
    plain "If you are trying to restrict outbound traffic, add specific DENY rules"
    plain "instead of changing the default outgoing policy."
    printf '\n'

    local cur_in cur_out
    cur_in=$(ufw status verbose 2>/dev/null  | grep "^Default:" | grep -o "deny\|allow\|reject" | head -1 || true)
    cur_out=$(ufw status verbose 2>/dev/null | grep "^Default:" | awk '{for(i=1;i<=NF;i++) if($i=="(outgoing)") print $(i-1)}' || true)
    info "Current defaults:  incoming=${cur_in:-unknown}  outgoing=${cur_out:-unknown}"
    info "Recommended:       incoming=deny  outgoing=allow"

    printf '\n'
    local new_in new_out
    new_in=$(ask_val  "Default INCOMING policy (deny / allow / reject)" "deny")
    new_out=$(ask_val "Default OUTGOING policy (deny / allow / reject)" "allow")

    if [[ "$new_in" != "deny" ]]; then
        warn "Setting incoming to '${new_in}' means new services are reachable by default."
        plain "This is against best practice for any server."
        ask "Set incoming to '${new_in}' anyway?" "n" || { info "Cancelled."; return 0; }
    fi
    if [[ "$new_out" != "allow" ]]; then
        warn "Setting outgoing to '${new_out}' will break Cloudflare Tunnel, Pangolin/Newt,"
        plain "Tailscale, apt updates, DNS, and most other outbound services."
        plain "You will need to explicitly allow each outbound destination."
        ask "Set outgoing to '${new_out}' anyway?" "n" || { info "Cancelled."; return 0; }
    fi

    run ufw default "$new_in" incoming
    run ufw default "$new_out" outgoing
    run ufw reload
    ok "Default policies updated: incoming=${new_in}  outgoing=${new_out}"
}

# ── Action: setup LAN-only ────────────────────────────────────────────────────

action_setup_lan() {
    printf '\n'
    section "Setup: LAN-only"
    info "This mode configures the firewall for a container whose services are"
    info "only ever accessed inside your home network. Nothing is exposed to the"
    info "internet. This is the lowest-risk configuration."
    plain ""
    plain "What this setup does:"
    plain "  1. Resets ufw to a clean state"
    plain "  2. Sets default: deny incoming, allow outgoing"
    plain "  3. Allows SSH (so you don't get locked out)"
    plain "  4. Optionally allows all traffic from your LAN subnet"
    plain "     (so LAN hosts can reach any service on this container)"
    plain ""
    plain "What this does NOT do:"
    plain "  • Does not open port 80/443 — not needed for LAN-only"
    plain "  • Does not touch Docker — still bind containers to 127.0.0.1"

    local ssh_port lan
    ssh_port=$(detect_ssh_port)
    lan=$(detect_lan_subnet)
    info "Detected SSH port: ${ssh_port}"
    [[ -n "$lan" ]] && info "Detected LAN subnet: ${lan}"

    if ! ask "Apply LAN-only firewall setup?" "y"; then
        info "Cancelled."
        return 0
    fi

    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    _lan_setup_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during setup — attempting to recover..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _lan_setup_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'

    if [[ -n "$lan" ]]; then
        if ask "Allow all traffic from LAN subnet ${lan}?" "y"; then
            run ufw allow from "$lan" comment 'LAN access'
            ok "LAN subnet ${lan} allowed."
        fi
    fi

    run ufw --force enable
    trap - ERR

    ok "LAN-only firewall configured."
    plain "Services on this container are now only accessible from your LAN."
    plain "SSH is allowed. Everything else requires an explicit rule."
}

# ── Action: setup Cloudflare Tunnel ───────────────────────────────────────────

action_setup_cloudflare() {
    printf '\n'
    section "Setup: Cloudflare Tunnel (cloudflared)"
    info "Cloudflare Tunnel creates an outbound encrypted connection from this"
    info "container to Cloudflare's network. Visitors reach your services through"
    info "Cloudflare — no inbound ports are needed on this machine."
    plain ""
    plain "How it works:"
    plain "  • You run 'cloudflared tunnel run' (usually as a systemd service)"
    plain "  • cloudflared dials OUT to Cloudflare — ufw's allow-outgoing covers it"
    plain "  • Cloudflare forwards requests inbound to cloudflared over that connection"
    plain "  • cloudflared proxies to your local service (e.g. localhost:8080)"
    plain ""
    plain "What this setup does:"
    plain "  1. Resets ufw to a clean state"
    plain "  2. Sets default: deny incoming, allow outgoing"
    plain "  3. Allows SSH"
    plain "  4. Does NOT open 80/443 — cloudflared doesn't need them open inbound"
    plain "  5. Optionally restricts HTTP access to Cloudflare IPs only"
    plain "     (adds a belt-and-suspenders block for direct-to-IP probing)"
    plain ""
    warn "Docker containers should be bound to 127.0.0.1:"
    plain "  Use: ports: [\"127.0.0.1:8080:8080\"]   (not: ports: [\"8080:8080\"])"
    plain "  Docker's wide bindings bypass ufw and would let anyone reach the"
    plain "  container port directly, bypassing Cloudflare entirely."
    plain ""
    warn "CrowdSec / fail2ban notes:"
    plain "  All requests appear to come from Cloudflare IPs at the network layer."
    plain "  The real visitor IP is in the CF-Connecting-IP header (HTTP layer)."
    plain "  If using CrowdSec, use the Caddy CrowdSec middleware — not the"
    plain "  nftables bouncer — so blocking is done per real IP via that header."

    local ssh_port
    ssh_port=$(detect_ssh_port)
    info "Detected SSH port: ${ssh_port}"

    if ! ask "Apply Cloudflare Tunnel firewall setup?" "y"; then
        info "Cancelled."
        return 0
    fi

    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    _cf_setup_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during setup — attempting to recover SSH access..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _cf_setup_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'

    # Optional: only allow CF IPs if they try to reach HTTP ports directly
    if ask "Fetch and add Cloudflare IPs as allowed sources for 80/443? (optional extra layer)" "n"; then
        info "Fetching Cloudflare IP list..."
        local cf_ips
        cf_ips=$(fetch_cf_ips)
        local count=0
        for ip in $cf_ips; do
            run ufw allow from "$ip" to any port 80 proto tcp comment 'Cloudflare IP'
            run ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare IP'
            (( count++ ))
        done
        ok "Added ${count} Cloudflare IP ranges for ports 80/443."
    fi

    run ufw --force enable
    trap - ERR

    ok "Cloudflare Tunnel firewall configured."
    plain "cloudflared outbound connections are allowed (covered by allow-outgoing)."
    plain "No inbound ports 80/443 are open — correct for this setup."
}

# ── Action: setup Pangolin / Newt ─────────────────────────────────────────────

action_setup_pangolin() {
    printf '\n'
    section "Setup: Pangolin / Newt Tunnel (self-hosted VPS)"
    info "Pangolin is a self-hosted alternative to Cloudflare Tunnel. You run a"
    info "VPS (Oracle Free Tier, Hetzner, etc.) with Pangolin, and install 'newt'"
    info "(the agent) on this container. newt creates an outbound WireGuard tunnel"
    info "to your VPS — similar in concept to Cloudflare Tunnel, but you own the VPS."
    plain ""
    plain "How it works:"
    plain "  • newt dials OUT to your Pangolin VPS over WireGuard (UDP)"
    plain "  • Visitors hit your VPS's public IP on port 80/443"
    plain "  • Pangolin proxies the request through the WireGuard tunnel to newt"
    plain "  • newt forwards to your local service (e.g. localhost:8080)"
    plain ""
    plain "Firewall needs on THIS container (where newt runs):"
    plain "  • SSH — to manage the container"
    plain "  • Outgoing WireGuard (UDP) — covered by allow-outgoing"
    plain "  • NO inbound 80/443 needed"
    plain ""
    plain "Firewall needs on YOUR VPS (Pangolin side):"
    plain "  • 80/tcp and 443/tcp — for public web traffic"
    plain "  • 51820/udp (or your configured WireGuard port) — for newt connections"
    plain "  • SSH — for VPS management"
    plain "  These must be opened on the VPS separately (not by this script)."
    plain ""
    warn "Docker containers on this host should be bound to 127.0.0.1, same as"
    plain "with Cloudflare Tunnel. The WireGuard bypass risk is the same."

    local ssh_port
    ssh_port=$(detect_ssh_port)
    info "Detected SSH port: ${ssh_port}"

    if ! ask "Apply Pangolin/Newt firewall setup for this container?" "y"; then
        info "Cancelled."
        return 0
    fi

    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    _pangolin_setup_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during setup — attempting to recover SSH access..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _pangolin_setup_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'

    # Newt's WireGuard tunnel is outbound UDP — covered by allow-outgoing.
    # But if the user also runs Pangolin *on this machine* (not typical for an LXC),
    # they may need inbound WireGuard.
    if ask "Does this container also run Pangolin itself (unusual — most people run Pangolin on VPS)?" "n"; then
        local wg_port
        wg_port=$(ask_val "WireGuard port Pangolin listens on" "51820")
        run ufw allow "${wg_port}/udp" comment 'Pangolin WireGuard'
        run ufw allow 80/tcp  comment 'Pangolin HTTP'
        run ufw allow 443/tcp comment 'Pangolin HTTPS'
        ok "Added Pangolin VPS rules (WireGuard + HTTP/S)."
    fi

    run ufw --force enable
    trap - ERR

    ok "Pangolin/Newt tunnel firewall configured for this container."
    plain "newt outbound WireGuard is allowed (covered by allow-outgoing)."
    plain "No inbound 80/443 needed on this container."
}

# ── Action: setup VPN-only ────────────────────────────────────────────────────

action_setup_vpn() {
    printf '\n'
    section "Setup: VPN only (Tailscale / WireGuard)"
    info "In this mode, services are only reachable by devices on your VPN."
    info "Nothing is exposed to the public internet. The VPN creates an encrypted"
    info "private network between your devices."
    plain ""
    plain "Tailscale notes:"
    plain "  • Tailscale itself needs no inbound ports to function (uses DERP relay)"
    plain "  • Opening UDP 41641 enables direct peer-to-peer connections (faster)"
    plain "  • Without it, traffic relays through Tailscale's servers (slower but works)"
    plain ""
    plain "WireGuard notes:"
    plain "  • WireGuard requires one inbound UDP port (default 51820)"
    plain "  • This is only for the WireGuard gateway — not needed on clients"
    plain ""
    plain "What this setup does:"
    plain "  1. Resets ufw to a clean state"
    plain "  2. Sets default: deny incoming, allow outgoing"
    plain "  3. Allows SSH"
    plain "  4. Optionally adds Tailscale direct-connect port"
    plain "  5. Optionally adds WireGuard server port"

    local ssh_port
    ssh_port=$(detect_ssh_port)
    info "Detected SSH port: ${ssh_port}"

    if ! ask "Apply VPN-only firewall setup?" "y"; then
        info "Cancelled."
        return 0
    fi

    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    _vpn_setup_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during setup — recovering SSH access..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _vpn_setup_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'

    if ask "Allow UDP 41641 for Tailscale direct peer connections? (recommended for Tailscale)" "y"; then
        run ufw allow 41641/udp comment 'Tailscale direct peer connections'
        ok "Tailscale direct-connect port 41641/udp allowed."
    fi

    if ask "Is this container a WireGuard gateway/server? (not needed for WireGuard clients)" "n"; then
        local wg_port
        wg_port=$(ask_val "WireGuard listen port" "51820")
        run ufw allow "${wg_port}/udp" comment 'WireGuard'
        ok "WireGuard port ${wg_port}/udp allowed."
    fi

    run ufw --force enable
    trap - ERR

    ok "VPN-only firewall configured."
    plain "Services are now only reachable over your VPN."
}

# ── Action: setup direct/public ───────────────────────────────────────────────

action_setup_direct() {
    printf '\n'
    section "Setup: Direct / Public IP"
    info "In this mode, your router forwards port 80/443 directly to this container."
    info "You manage your own domain and TLS certificates (e.g. via Caddy + Let's Encrypt)."
    plain ""
    plain "This has the highest attack surface of all exposure models:"
    plain "  • Your container's HTTP/S ports are directly reachable from the internet"
    plain "  • You are responsible for TLS, rate limiting, and bot protection"
    plain "  • You should run CrowdSec or fail2ban to block malicious IPs"
    plain "  • Strong recommendation: use Caddy as reverse proxy + automatic HTTPS"
    plain ""
    warn "This mode is NOT recommended unless you have a specific reason to avoid"
    plain "Cloudflare Tunnel or a similar solution. Consider Cloudflare Tunnel or"
    plain "Pangolin/Newt for better DDoS protection and simpler TLS management."
    plain ""
    plain "What this setup does:"
    plain "  1. Resets ufw to a clean state"
    plain "  2. Sets default: deny incoming, allow outgoing"
    plain "  3. Allows SSH"
    plain "  4. Opens port 80/tcp and 443/tcp"
    plain "  5. Optionally allows additional ports"

    warn "Are you sure you want to expose this container directly to the internet?"
    if ! ask "Continue with direct/public IP setup?" "n"; then
        info "Cancelled. Consider using Cloudflare Tunnel or Pangolin instead."
        return 0
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)
    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    _direct_setup_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during setup — recovering SSH access..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _direct_setup_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'
    run ufw allow 80/tcp            comment 'HTTP'
    run ufw allow 443/tcp           comment 'HTTPS'
    ok "Ports 80 (HTTP) and 443 (HTTPS) opened."

    while true; do
        local extra_port
        extra_port=$(ask_val "Additional port to allow (Enter to skip)")
        [[ -z "$extra_port" ]] && break
        local extra_proto
        extra_proto=$(ask_val "Protocol (tcp/udp)" "tcp")
        run ufw allow "${extra_port}/${extra_proto}"
        ok "Allowed ${extra_port}/${extra_proto}."
    done

    run ufw --force enable
    trap - ERR

    ok "Direct/public IP firewall configured."
    warn "Your container is now reachable from the internet on ports 80 and 443."
    plain "Ensure you have Caddy (or another reverse proxy) handling TLS."
    plain "Consider installing CrowdSec to block malicious IPs automatically."
}

# ── Action: manage Cloudflare IPs ─────────────────────────────────────────────

action_manage_cf_ips() {
    printf '\n'
    section "Cloudflare IP Management"
    info "Cloudflare publishes the IP ranges their network uses to send requests"
    info "to origin servers. These ranges change occasionally as Cloudflare"
    info "expands. You should refresh this list periodically."
    plain ""
    plain "Current use cases for Cloudflare IP rules:"
    plain "  • Restricting ports 80/443 to Cloudflare IPs only (belt-and-suspenders)"
    plain "    — prevents direct-to-IP access that bypasses Cloudflare protections"
    plain "  • Whitelisting Cloudflare IPs in CrowdSec/fail2ban so they're never"
    plain "    banned (required if using network-layer intrusion detection)"
    plain ""
    plain "Live list:     https://www.cloudflare.com/ips-v4"
    plain "Documentation: https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"

    printf '\n'
    printf "  ${BOLD}1)${NC}  View current Cloudflare IPs (fetch from cloudflare.com)\n"
    printf "  ${BOLD}2)${NC}  Add/refresh Cloudflare IP rules for port 80/443\n"
    printf "  ${BOLD}3)${NC}  Remove all Cloudflare IP rules\n"
    printf "  ${BOLD}4)${NC}  Back\n"
    printf '\n'

    local choice
    read -rp "    ${YELLOW}>  ${NC}Choice [1-4]: " choice || true
    case "$choice" in
        1)
            info "Fetching current Cloudflare IPs..."
            local cf_ips
            cf_ips=$(fetch_cf_ips)
            printf '\n'
            info "Cloudflare IPv4 ranges:"
            for ip in $cf_ips; do
                plain "  $ip"
            done
            ;;
        2)
            info "Fetching current Cloudflare IP list..."
            local cf_ips count=0
            cf_ips=$(fetch_cf_ips)
            # Remove any existing CF comment rules first
            info "Removing stale Cloudflare IP rules (if any)..."
            while ufw status numbered 2>/dev/null | grep -q "Cloudflare IP"; do
                local rule_num
                rule_num=$(ufw status numbered 2>/dev/null \
                    | grep "Cloudflare IP" \
                    | head -1 \
                    | grep -o '^\[ *[0-9]\+\]' \
                    | tr -d '[] ')
                [[ -z "$rule_num" ]] && break
                run ufw --force delete "$rule_num"
            done
            for ip in $cf_ips; do
                run ufw allow from "$ip" to any port 80  proto tcp comment 'Cloudflare IP'
                run ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare IP'
                (( count++ ))
            done
            run ufw reload
            ok "Added/refreshed rules for ${count} Cloudflare IP ranges."
            ;;
        3)
            if ! ufw status numbered 2>/dev/null | grep -q "Cloudflare IP"; then
                info "No Cloudflare IP rules found."
                return 0
            fi
            if ask "Remove all rules labelled 'Cloudflare IP'?" "n"; then
                while ufw status numbered 2>/dev/null | grep -q "Cloudflare IP"; do
                    local rule_num
                    rule_num=$(ufw status numbered 2>/dev/null \
                        | grep "Cloudflare IP" \
                        | head -1 \
                        | grep -o '^\[ *[0-9]\+\]' \
                        | tr -d '[] ')
                    [[ -z "$rule_num" ]] && break
                    run ufw --force delete "$rule_num"
                done
                run ufw reload
                ok "All Cloudflare IP rules removed."
            else
                info "Cancelled."
            fi
            ;;
        *) info "Cancelled." ;;
    esac
}

# ── Action: open all traffic (debug mode) ─────────────────────────────────────

action_open_all() {
    printf '\n'
    section "⚠ Open All Traffic — Debug Mode"
    warn "This will allow ALL inbound traffic from ANY source on ALL ports."
    plain ""
    plain "This is ONLY appropriate for:"
    plain "  • Diagnosing whether a firewall rule is blocking something"
    plain "  • Testing connectivity from a fresh state"
    plain ""
    plain "This completely bypasses all your firewall protection. Any service"
    plain "running on this container becomes reachable from the network."
    plain ""
    plain "You MUST reverse this after debugging by running 'Reset firewall'"
    plain "or by re-applying an exposure model setup."
    warn "Do NOT leave this in place. This is a debugging tool only."
    printf '\n'

    if ! ask "Allow ALL inbound traffic? (NOT for production use)" "n"; then
        info "Cancelled — firewall unchanged."
        return 0
    fi

    # Second confirmation — require typing YES
    warn "Type YES (all caps) to confirm, or press Enter to cancel:"
    local confirm
    confirm=$(ask_val "Confirm")
    if [[ "$confirm" != "YES" ]]; then
        info "Cancelled — did not type YES."
        return 0
    fi

    run ufw default allow incoming
    run ufw reload
    warn "All inbound traffic is now allowed. Remember to reset when done."
    plain "Run 'Reset firewall to safe defaults' from the menu when finished."
}

# ── Action: reset to safe defaults ────────────────────────────────────────────

action_reset_defaults() {
    printf '\n'
    section "Reset Firewall to Safe Defaults"
    info "This performs a true factory reset of ufw — identical to a fresh install:"
    plain "  1. All user rules wiped"
    plain "  2. /etc/default/ufw restored: INPUT=DROP, OUTPUT=ACCEPT, FORWARD=DROP"
    plain "  3. /etc/ufw/ufw.conf restored: ENABLED=no, LOGLEVEL=low"
    plain "  4. SSH rule added, then ufw enabled"
    plain ""
    plain "Config files are backed up with a timestamped .bak suffix first."
    plain "After this, only SSH works. Use an exposure model setup to add services."
    printf '\n'

    local ssh_port
    ssh_port=$(detect_ssh_port)
    info "Detected SSH port: ${ssh_port}"

    local ssh_port_override
    ssh_port_override=$(ask_val "SSH port to allow" "$ssh_port")
    [[ -n "$ssh_port_override" ]] && ssh_port="$ssh_port_override"

    warn "This will WIPE ALL existing ufw rules and start fresh."
    if ! ask "Reset firewall to safe defaults?" "n"; then
        info "Cancelled."
        return 0
    fi

    # Require typing RESET for extra safety
    warn "Type RESET to confirm wiping all rules, or press Enter to cancel:"
    local confirm
    confirm=$(ask_val "Confirm")
    if [[ "$confirm" != "RESET" ]]; then
        info "Cancelled — did not type RESET."
        return 0
    fi

    _reset_cleanup() {
        [[ "$DRY_RUN" == "true" ]] && return
        warn "Error during reset — attempting to ensure SSH access..."
        ufw allow "${ssh_port}/tcp" 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
    }
    trap _reset_cleanup ERR

    ufw_factory_reset
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "${ssh_port}/tcp" comment 'SSH'
    run ufw --force enable
    trap - ERR

    ok "Firewall reset to safe defaults."
    plain "Only SSH (port ${ssh_port}) is allowed. Run an exposure model setup to"
    plain "configure services."
}

# ── Help: Docker bypass ────────────────────────────────────────────────────────

action_help_docker() {
    printf '\n'
    header "Docker + ufw Bypass"
    printf "  ${BOLD}The problem${NC}\n\n"
    plain "Docker manages iptables directly and bypasses ufw entirely for"
    plain "published ports. When you write:"
    plain ""
    plain "    ports:"
    plain "      - \"8080:8080\""
    plain ""
    plain "Docker injects an iptables ACCEPT rule for port 8080 on all interfaces."
    plain "ufw never sees this traffic — your ufw rules have no effect on it."
    plain "The port is reachable from your LAN (and possibly the internet if your"
    plain "router forwards it) regardless of what ufw says."
    printf '\n'
    printf "  ${BOLD}The fix${NC}\n\n"
    plain "Bind the container to localhost only:"
    plain ""
    plain "    ports:"
    plain "      - \"127.0.0.1:8080:8080\""
    plain ""
    plain "Now only processes on this host (your reverse proxy, cloudflared, newt)"
    plain "can reach the container. External hosts cannot."
    printf '\n'
    printf "  ${BOLD}How your reverse proxy still works${NC}\n\n"
    plain "Tools like Caddy, cloudflared, and newt all run on the same host and"
    plain "connect to localhost — so 127.0.0.1 binding is not a problem for them."
    plain ""
    plain "Example Caddy config:"
    plain "    example.com {"
    plain "        reverse_proxy localhost:8080"
    plain "    }"
    printf '\n'
    printf "  ${BOLD}One-liner to check for badly bound containers${NC}\n\n"
    plain "    docker ps --format '{{.Ports}}' | grep -v '127.0.0.1'"
    plain ""
    plain "Any output shows containers that are exposed on all interfaces."
    printf '\n'
    read -rp "    Press Enter to continue..." _ || true
}

# ── Help: ufw overview ────────────────────────────────────────────────────────

action_help_ufw() {
    printf '\n'
    header "What is ufw and why does it matter?"
    plain "ufw (Uncomplicated Firewall) is a frontend to iptables — the Linux kernel's"
    plain "built-in packet filtering system. It lets you write simple rules like"
    plain "'allow port 22' or 'deny from 1.2.3.4' instead of raw iptables syntax."
    printf '\n'
    printf "  ${BOLD}Why you need it on a Proxmox LXC${NC}\n\n"
    plain "An LXC container shares the host's network bridge. By default, any port"
    plain "a service opens is reachable from your LAN. Without a firewall:"
    plain "  • A misconfigured service that binds to 0.0.0.0 is immediately exposed"
    plain "  • Docker published ports are reachable without any review"
    plain "  • There is no second line of defence if a service has a vulnerability"
    printf '\n'
    printf "  ${BOLD}The default-deny principle${NC}\n\n"
    plain "Best practice: block everything by default, then explicitly allow only"
    plain "what is needed. This means new services are safe-by-default rather than"
    plain "open-by-default. One misconfiguration does not become a breach."
    printf '\n'
    read -rp "    Press Enter to continue..." _ || true
}

# ── Help: exposure models ──────────────────────────────────────────────────────

action_help_exposure() {
    printf '\n'
    header "Exposure Model Guide"
    printf "  ${BOLD}LAN-only${NC}\n\n"
    plain "Services are only reachable from inside your home network."
    plain "Zero internet exposure. Use this for Proxmox management, internal tools,"
    plain "and anything you only ever access from home."
    printf '\n'
    printf "  ${BOLD}Cloudflare Tunnel (cloudflared)${NC}\n\n"
    plain "Free, zero-config reverse proxy + CDN. cloudflared dials OUT to Cloudflare."
    plain "Cloudflare handles HTTPS certificates, DDoS protection, and bot filtering."
    plain "No ports need to be open on your container. Recommended for most homelabs."
    plain "Limitation: Cloudflare sees your traffic (it terminates TLS)."
    printf '\n'
    printf "  ${BOLD}Pangolin / Newt (self-hosted VPS tunnel)${NC}\n\n"
    plain "Self-hosted alternative to Cloudflare Tunnel. You run Pangolin on a cheap"
    plain "VPS (Oracle Free Tier, Hetzner, etc.) and newt on your container."
    plain "newt tunnels over WireGuard to the VPS. Your traffic stays under your control."
    plain "More setup, but you own the full stack. Good for privacy-sensitive services."
    printf '\n'
    printf "  ${BOLD}VPN (Tailscale / WireGuard)${NC}\n\n"
    plain "Services only reachable from devices on your VPN. Great for admin tools,"
    plain "dashboards, and anything only you or trusted users need to access."
    plain "Tailscale is zero-config; WireGuard requires more setup."
    printf '\n'
    printf "  ${BOLD}Direct / Public IP${NC}\n\n"
    plain "Your router forwards port 80/443 to this container. You manage TLS and"
    plain "security yourself. Highest attack surface — not recommended unless you"
    plain "have a specific reason to avoid a tunnel."
    printf '\n'
    read -rp "    Press Enter to continue..." _ || true
}

# ── Menu dispatch ──────────────────────────────────────────────────────────────

dispatch_action() {
    local action="$1"
    case "$action" in
        install_ufw)      action_install_ufw    ;;
        enable_ufw)       action_enable_ufw     ;;
        disable_ufw)      action_disable_ufw    ;;
        add_rule)         action_add_rule        ;;
        remove_rule)      action_remove_rule     ;;
        allow_source)     action_allow_source    ;;
        deny_source)      action_deny_source     ;;
        set_defaults)     action_set_defaults    ;;
        setup_lan)        action_setup_lan       ;;
        setup_cloudflare) action_setup_cloudflare ;;
        setup_pangolin)   action_setup_pangolin   ;;
        setup_vpn)        action_setup_vpn        ;;
        setup_direct)     action_setup_direct     ;;
        manage_cf_ips)    action_manage_cf_ips    ;;
        open_all)         action_open_all         ;;
        reset_defaults)   action_reset_defaults   ;;
        help_docker)      action_help_docker      ;;
        help_ufw)         action_help_ufw         ;;
        help_exposure)    action_help_exposure    ;;
        exit)             info "Exiting."; return 1 ;;
        *)                warn "Unknown action: ${action}" ;;
    esac
    return 0
}

# ── main ───────────────────────────────────────────────────────────────────────

main() {
    preflight_checks

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              manage-firewall.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n"            "$DRY_RUN"

    while true; do
        show_state
        _show_menu

        MENU_DEFAULT=$(_menu_default)
        local choice
        if [[ -n "$MENU_DEFAULT" ]]; then
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}, default ${MENU_DEFAULT}]: " \
                choice || true
            choice="${choice:-$MENU_DEFAULT}"
        else
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [1-${_MENU_MAX}]: " choice || true
        fi

        [[ -z "$choice" ]] && continue
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > _MENU_MAX )); then
            warn "Please enter a number between 1 and ${_MENU_MAX}."
            continue
        fi

        local idx=$(( choice - 1 ))
        local action="${_MENU_ITEMS[$idx]:-}"
        [[ -z "$action" ]] && { warn "Invalid choice."; continue; }

        printf '\n'
        dispatch_action "$action" || break

        printf '\n'
    done
}

main "$@"