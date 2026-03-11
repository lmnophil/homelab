#!/usr/bin/env bash
# ==============================================================================
# harden-firewall.sh — Audit and harden ufw firewall for Proxmox LXC containers
# ==============================================================================
#
# Usage:
#   sudo ./harden-firewall.sh [--dry-run] [--status] [--help]
#
# Description:
#   Audits the ufw firewall configuration against best practices for Proxmox
#   LXC containers. Checks whether ufw is installed and active, default policies
#   are correctly set, SSH is protected, and the exposure model matches what is
#   actually configured. Offers interactive remediation for each failed check.
#
#   Supports three common exposure models:
#     lan        — services only accessible inside your home network
#     cloudflare — outbound tunnel via cloudflared; no inbound ports needed
#     vpn        — services only reachable via Tailscale / WireGuard
#     pangolin   — outbound WireGuard tunnel to a VPS running Pangolin/Newt
#     direct     — public IP with ports forwarded from your router
#
# Environment variables:
#   DRY_RUN=true      Print commands without executing them (no root required)
#   STATUS_MODE=true  Emit structured pass/fail per check and exit (no root required)
#
# ──────────────────────────────────────────────────────────────────────────────
# Safe to re-run: exits cleanly when everything already passes.
# Declining any fix is always allowed; skipped items appear in the summary.
# ==============================================================================

set -euo pipefail

# ── Argument parsing ───────────────────────────────────────────────────────────

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

# ── Status helpers ────────────────────────────────────────────────────────────
# Used only in --status mode. Each entry is stored as "id|detail".
# Detail is printed on the same line for PASS, indented below for FAIL.
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
EXPOSURE_MODEL=''

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
}

# ── State helpers ──────────────────────────────────────────────────────────────

is_pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

ufw_active()         { ufw status 2>/dev/null | grep -q "^Status: active"; }
ufw_default_deny_in(){ ufw status verbose 2>/dev/null | grep -q "^Default:.*deny (incoming)"; }
ufw_default_allow_out(){ ufw status verbose 2>/dev/null | grep -q "^Default:.*allow (outgoing)"; }
ufw_allows_port()    { ufw status 2>/dev/null | grep -qE "^${1}[[:space:]].*ALLOW"; }

# Returns the current SSH port.
# Strategy:
#   1. Ask sshd itself — 'sshd -T' prints the full effective config including
#      drop-in overrides; the Port directive is always present in its output.
#   2. Fall back to parsing ss output (POSIX-safe: extract last colon-field).
#   3. Final fallback: grep sshd_config directly.
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

# Returns live Cloudflare IPv4 ranges (fallback to hardcoded if fetch fails)
CF_IPS_FALLBACK="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 \
198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"

fetch_cf_ips() {
    local fetched
    fetched=$(curl -fsSL --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null || true)
    if [[ -n "$fetched" ]]; then
        printf '%s' "$(printf '%s' "$fetched" | tr '\n' ' ')"
    else
        printf '%s' "$CF_IPS_FALLBACK"
    fi
}

# Print formatted ufw rules (used in state displays)
show_ufw_rules() {
    if ufw_active; then
        ufw status verbose 2>/dev/null \
            | grep -v "^$" \
            | sed 's/^/        /'
    else
        plain "(ufw is not active)"
    fi
}

# ── Check functions ────────────────────────────────────────────────────────────

check_ufw_installed() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_pkg_installed "ufw"; then
            status_pass "ufw_installed"
        else
            status_fail "ufw_installed" "ufw is not installed — apt install ufw"
        fi
        return 0
    fi

    if is_pkg_installed "ufw"; then
        ok "ufw is installed."
        CHECKS_PASSED+=("ufw installed")
        return 0
    fi

    printf '\n'
    warn "ufw is not installed."
    plain "ufw (Uncomplicated Firewall) is the standard host-based firewall for"
    plain "Debian/Ubuntu. Without it, this container has no network filtering —"
    plain "any port a service opens is reachable from your LAN (or the internet)."

    if ask "Install ufw now?" "y"; then
        run apt-get install -y ufw
        ok "ufw installed."
        CHECKS_FIXED+=("ufw installed")
    else
        warn "Skipped — ufw remains absent. All subsequent firewall checks will fail."
        CHECKS_DECLINED+=("ufw not installed (risk accepted)")
    fi
}

check_ufw_active() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if ! is_pkg_installed "ufw"; then
            status_fail "ufw_active" "ufw not installed"
            return 0
        fi
        if ufw_active; then
            status_pass "ufw_active"
        else
            status_fail "ufw_active" "ufw installed but not active — run: ufw enable"
        fi
        return 0
    fi

    if ! is_pkg_installed "ufw"; then
        warn "Skipping active-check — ufw is not installed."
        CHECKS_DECLINED+=("ufw active-check skipped (not installed)")
        return 0
    fi

    if ufw_active; then
        ok "ufw is active (enabled)."
        CHECKS_PASSED+=("ufw active")
        return 0
    fi

    printf '\n'
    warn "ufw is installed but not active."
    plain "An inactive firewall provides no protection. Services are currently"
    plain "reachable by any host on the network."
    printf '\n'
    plain "Before enabling, this check will ensure SSH is allowed so you cannot"
    plain "lock yourself out."

    local ssh_port
    ssh_port=$(detect_ssh_port)
    info "Detected SSH port: ${ssh_port}"

    if ! ufw status 2>/dev/null | grep -qE "^${ssh_port}[[:space:]].*ALLOW|^${ssh_port}/tcp[[:space:]].*ALLOW"; then
        warn "SSH (port ${ssh_port}) is not in the current ufw rules."
        plain "It will be added before enabling so you are not locked out."
        if ask "Add SSH rule for port ${ssh_port} and enable ufw?" "y"; then
            run ufw allow "${ssh_port}/tcp" comment 'SSH'
            run ufw --force enable
            ok "SSH allowed on port ${ssh_port}; ufw enabled."
            CHECKS_FIXED+=("ufw enabled (SSH rule added first)")
        else
            warn "Skipped — ufw remains inactive."
            CHECKS_DECLINED+=("ufw not enabled (risk accepted)")
        fi
    else
        if ask "Enable ufw? (SSH is already in the rules.)" "y"; then
            run ufw --force enable
            ok "ufw enabled."
            CHECKS_FIXED+=("ufw enabled")
        else
            warn "Skipped — ufw remains inactive."
            CHECKS_DECLINED+=("ufw not enabled (risk accepted)")
        fi
    fi
}

check_default_policies() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if ! is_pkg_installed "ufw" || ! ufw_active; then
            status_fail "default_policies" "ufw not active"
            return 0
        fi
        if ufw_default_deny_in && ufw_default_allow_out; then
            status_pass "default_policies"
        else
            local _detail=""
            ufw_default_deny_in   || _detail+="incoming not set to deny; "
            ufw_default_allow_out || _detail+="outgoing not set to allow"
            status_fail "default_policies" "${_detail%%; }"
        fi
        return 0
    fi

    if ! is_pkg_installed "ufw" || ! ufw_active; then
        return 0
    fi

    local deny_in allow_out both_ok=true
    ufw_default_deny_in  || both_ok=false
    ufw_default_allow_out || both_ok=false

    if [[ "$both_ok" == "true" ]]; then
        ok "Default policies: deny incoming, allow outgoing."
        CHECKS_PASSED+=("Default policies correct")
        return 0
    fi

    printf '\n'
    warn "Default policies are not set to best practice."
    plain "Best practice: deny all incoming traffic by default, allow all outgoing."
    plain "This means only explicitly allowed ports are reachable — everything else"
    plain "is silently dropped. Without this, new services are open by default."
    printf '\n'
    ufw_default_deny_in  || plain "  FAIL — incoming default is not 'deny'"
    ufw_default_allow_out || plain "  FAIL — outgoing default is not 'allow'"

    if ask "Set default policies (deny incoming / allow outgoing)?" "y"; then
        run ufw default deny incoming
        run ufw default allow outgoing
        ok "Default policies set."
        CHECKS_FIXED+=("Default policies set")
    else
        warn "Skipped — default policies remain non-standard."
        CHECKS_DECLINED+=("Default policies not fixed (risk accepted)")
    fi
}

check_ssh_rule() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if ! is_pkg_installed "ufw" || ! ufw_active; then
            status_fail "ssh_rule" "ufw not active"
            return 0
        fi
        local _ssh_port; _ssh_port=$(detect_ssh_port)
        if ufw status 2>/dev/null | grep -qE "^${_ssh_port}[/[:space:]].*ALLOW"; then
            status_pass "ssh_rule" "port ${_ssh_port} allowed"
        else
            status_fail "ssh_rule" "SSH port ${_ssh_port} not in ufw rules"
        fi
        return 0
    fi

    if ! is_pkg_installed "ufw" || ! ufw_active; then
        return 0
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)

    if ufw status 2>/dev/null | grep -qE "^${ssh_port}[/[:space:]].*ALLOW"; then
        ok "SSH port ${ssh_port} is allowed in ufw."
        CHECKS_PASSED+=("SSH port ${ssh_port} allowed")
        return 0
    fi

    printf '\n'
    warn "SSH port ${ssh_port} is NOT explicitly allowed in ufw."
    plain "This is dangerous — if this is the only way into this container,"
    plain "adding an unrelated deny rule (or changing the default policy) could"
    plain "lock you out completely."
    plain "Detected port by inspecting sshd and /etc/ssh/sshd_config."

    if ask "Add ufw rule to allow SSH on port ${ssh_port}?" "y"; then
        run ufw allow "${ssh_port}/tcp" comment 'SSH'
        run ufw reload
        ok "SSH port ${ssh_port} allowed."
        CHECKS_FIXED+=("SSH port ${ssh_port} allowed")
    else
        warn "Skipped — SSH is not in the firewall rules. Proceed with caution."
        CHECKS_DECLINED+=("SSH rule not added (risk accepted)")
    fi
}

check_no_wide_open_rules() {
    if ! is_pkg_installed "ufw" || ! ufw_active; then
        return 0
    fi

    # Look for rules that allow all traffic to any port (no port restriction in the To field)
    local wide_rules
    wide_rules=$(ufw status 2>/dev/null \
        | grep "ALLOW" \
        | grep -vE "^[0-9]+(:[0-9]+)?(/[a-z]+)?[[:space:]]" \
        | grep "^Anywhere" || true)

    if [[ "$STATUS_MODE" == "true" ]]; then
        if [[ -z "$wide_rules" ]]; then
            status_pass "no_wide_open_rules"
        else
            status_fail "no_wide_open_rules" \
                "overly broad ALLOW rules found — review with manage-firewall.sh"
        fi
        return 0
    fi

    if [[ -z "$wide_rules" ]]; then
        ok "No overly broad ALLOW-all rules detected."
        CHECKS_PASSED+=("No wide-open rules")
        return 0
    fi

    printf '\n'
    warn "Overly broad rules detected — ALLOW without a port restriction:"
    printf '%s\n' "$wide_rules" | sed 's/^/        /'
    plain "Rules with no port restriction allow the source to reach every open"
    plain "service on this host. Each allowed service should have its own explicit"
    plain "port rule instead."
    plain "Use manage-firewall.sh to review and remove these rules."

    warn "Cannot auto-fix — use manage-firewall.sh to remove specific rules."
    CHECKS_DECLINED+=("Wide-open rules found — review with manage-firewall.sh")
}

# ── Exposure model: ask the user, then audit accordingly ──────────────────────
# The tunnel agent (cloudflared, newt) may be running on a completely different
# machine — a router, another LXC, a Docker container on the Proxmox host.
# Binary/service detection on THIS container is therefore unreliable.
# We ask the user what their intended setup is and audit against that intent.

ask_exposure_model() {
    printf '\n'
    section "Exposure Model"
    info "How are web services on this container accessed from outside your LAN?"
    plain "This determines which ports should (and should not) be open."
    plain "The tunnel agent does not need to be on THIS machine — it may run on"
    plain "your router, another LXC, or a separate host entirely."
    plain ""
    plain "  1  LAN-only          — services only reachable inside your home network"
    plain "  2  Cloudflare Tunnel — cloudflared agent proxies requests (any host)"
    plain "  3  Pangolin / Newt   — self-hosted VPS tunnel via WireGuard (any host)"
    plain "  4  VPN only          — Tailscale / WireGuard; no public exposure"
    plain "  5  Direct / public   — router forwards port 80/443 to this container"
    plain "  6  Skip              — don't audit exposure model this run"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Your exposure model (1–6)")
        case "$choice" in
            1) EXPOSURE_MODEL="lan";        return 0 ;;
            2) EXPOSURE_MODEL="cloudflare"; return 0 ;;
            3) EXPOSURE_MODEL="pangolin";   return 0 ;;
            4) EXPOSURE_MODEL="vpn";        return 0 ;;
            5) EXPOSURE_MODEL="direct";     return 0 ;;
            6) EXPOSURE_MODEL="skip";       return 0 ;;
            *) warn "Please enter a number from 1 to 6." ;;
        esac
    done
}

check_tunnel_exposure() {
    if ! is_pkg_installed "ufw" || ! ufw_active; then
        return 0
    fi

    if [[ "$STATUS_MODE" == "true" ]]; then
        # Exposure model requires interactive input — report ports 80/443 state directly
        local _open=()
        ufw status 2>/dev/null | grep -qE "^80[/[:space:]].*ALLOW"  && _open+=("80")
        ufw status 2>/dev/null | grep -qE "^443[/[:space:]].*ALLOW" && _open+=("443")
        if [[ ${#_open[@]} -eq 0 ]]; then
            status_pass "exposure_ports" "ports 80/443 not open (tunnel-safe)"
        else
            status_pass "exposure_ports" \
                "ports ${_open[*]} open — confirm this matches your exposure model"
        fi
        return 0
    fi

    ask_exposure_model

    case "$EXPOSURE_MODEL" in
        skip)
            warn "Exposure model check skipped."
            CHECKS_DECLINED+=("Exposure model check skipped")
            return 0
            ;;
        lan|vpn)
            _check_ports_closed_for_tunnel "$EXPOSURE_MODEL"
            ;;
        cloudflare)
            _check_cloudflare_tunnel
            ;;
        pangolin)
            _check_pangolin_tunnel
            ;;
        direct)
            ok "Direct/public exposure — ports 80/443 are expected to be open."
            plain "Ensure you have a reverse proxy (Caddy) handling TLS and rate limiting."
            CHECKS_PASSED+=("Exposure model: direct (80/443 open — expected)")
            return 0
            ;;
    esac
}

# Shared helper: for tunnel/vpn/lan setups, ports 80/443 should not be open
_check_ports_closed_for_tunnel() {
    local model="$1"
    local label
    case "$model" in
        lan)        label="LAN-only" ;;
        vpn)        label="VPN-only" ;;
        cloudflare) label="Cloudflare Tunnel" ;;
        pangolin)   label="Pangolin/Newt Tunnel" ;;
        *)          label="$model" ;;
    esac

    local bad_ports=()
    ufw status 2>/dev/null | grep -qE "^80[/[:space:]].*ALLOW"  && bad_ports+=("80")
    ufw status 2>/dev/null | grep -qE "^443[/[:space:]].*ALLOW" && bad_ports+=("443")

    if [[ ${#bad_ports[@]} -eq 0 ]]; then
        ok "Ports 80/443 are not open — correct for ${label}."
        CHECKS_PASSED+=("Ports 80/443 correctly closed (${label})")
        return 0
    fi

    printf '\n'
    warn "Ports ${bad_ports[*]} are open but should not be for ${label}."
    plain "For ${label}, no inbound HTTP/S ports are needed on this container."
    plain "Open ports are unnecessary attack surface — direct-to-IP probing can"
    plain "reach this host without going through your tunnel's protections."

    if ask "Remove port(s) ${bad_ports[*]} from ufw?" "y"; then
        for p in "${bad_ports[@]}"; do
            run ufw delete allow "${p}/tcp" 2>/dev/null || true
            run ufw delete allow "${p}"     2>/dev/null || true
        done
        run ufw reload
        ok "Port(s) ${bad_ports[*]} removed."
        CHECKS_FIXED+=("Removed unnecessary port(s) ${bad_ports[*]} (${label})")
    else
        warn "Skipped — port(s) ${bad_ports[*]} remain open."
        CHECKS_DECLINED+=("Ports ${bad_ports[*]} left open despite ${label} (risk accepted)")
    fi
}

_check_cloudflare_tunnel() {
    section "Cloudflare Tunnel"
    info "cloudflared dials OUT to Cloudflare — no inbound ports are needed here."
    plain ""
    plain "Important implications for this container:"
    plain "  • Ports 80/443 should NOT be open — cloudflared doesn't need them inbound"
    plain "  • All HTTP/S traffic arrives from Cloudflare IPs, not real visitor IPs"
    plain "  • Docker containers must bind to 127.0.0.1 to prevent direct-to-IP bypass"
    plain "    (use: ports: [\"127.0.0.1:8080:8080\"]  — not: ports: [\"8080:8080\"])"
    plain "  • CrowdSec/fail2ban: use the Caddy HTTP middleware — NOT the nftables"
    plain "    bouncer. The real visitor IP is in the CF-Connecting-IP request header;"
    plain "    at the network layer all traffic appears to come from Cloudflare IPs."

    _check_ports_closed_for_tunnel "cloudflare"
}

_check_pangolin_tunnel() {
    section "Pangolin / Newt Tunnel"
    info "newt dials OUT over WireGuard to your VPS — no inbound ports needed here."
    plain ""
    plain "Important implications for this container:"
    plain "  • Ports 80/443 should NOT be open on this container"
    plain "  • Ports 80/443 DO need to be open on your VPS (Oracle, Hetzner, etc.)"
    plain "  • Docker containers must bind to 127.0.0.1 (same as Cloudflare Tunnel)"
    plain "  • newt's WireGuard connection is outbound UDP — covered by allow-outgoing"
    plain "  • Your VPS Pangolin config handles TLS and routing; this container is"
    plain "    purely an upstream target reached through the tunnel"

    _check_ports_closed_for_tunnel "pangolin"
}

check_docker_bypass() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_pkg_installed "docker.io" || is_pkg_installed "docker-ce"; then
            status_pass "docker_bypass_warning" \
                "Docker installed — verify containers bind to 127.0.0.1"
        else
            status_pass "docker_bypass_warning" "Docker not installed"
        fi
        return 0
    fi

    if ! is_pkg_installed "docker.io" && ! is_pkg_installed "docker-ce"; then
        ok "Docker not installed — Docker bypass check not applicable."
        CHECKS_PASSED+=("Docker bypass check (Docker not installed)")
        return 0
    fi

    printf '\n'
    section "Docker + ufw Warning"
    warn "Docker bypasses ufw for published ports."
    plain "When a Docker container uses 'ports: [\"8080:8080\"]', Docker injects"
    plain "iptables rules directly, completely bypassing ufw. The port becomes"
    plain "accessible from the network even if ufw has no rule for it."
    plain ""
    plain "The correct mitigation:"
    plain "  Use 'ports: [\"127.0.0.1:8080:8080\"]' instead."
    plain "  This binds the port to localhost only. Your reverse proxy (Caddy,"
    plain "  cloudflared, newt) can still reach it, but external hosts cannot."
    plain ""
    plain "This script cannot automatically fix docker-compose.yml files."
    plain "Use manage-firewall.sh option 'h' on the Docker topic for full details."

    # This is always a warn/info, not a fixable check — mark as passed (informational)
    CHECKS_PASSED+=("Docker bypass warning displayed")
}

# ── Show current state ─────────────────────────────────────────────────────────

show_state() {
    printf '\n'
    if ! is_pkg_installed "ufw"; then
        printf "  ${RED}ufw:${NC} not installed\n"
        return
    fi

    if ufw_active; then
        printf "  ${GREEN}ufw:${NC} active\n"
    else
        printf "  ${RED}ufw:${NC} inactive\n"
    fi

    printf '\n'
    show_ufw_rules
}

# ── All-pass detection ─────────────────────────────────────────────────────────

all_checks_pass() {
    is_pkg_installed "ufw"    || return 1
    ufw_active                || return 1
    ufw_default_deny_in       || return 1
    ufw_default_allow_out     || return 1
    local ssh_port
    ssh_port=$(detect_ssh_port)
    ufw status 2>/dev/null | grep -qE "^${ssh_port}[/[:space:]].*ALLOW" || return 1
    return 0
}

# ── main ───────────────────────────────────────────────────────────────────────

main() {
    CHECKS_PASSED=()
    CHECKS_FIXED=()
    CHECKS_DECLINED=()

    preflight_checks

    # ── Status-only path ──────────────────────────────────────────────────────
    if [[ "$STATUS_MODE" == "true" ]]; then
        check_ufw_installed
        check_ufw_active
        check_default_policies
        check_ssh_rule
        check_no_wide_open_rules
        check_tunnel_exposure
        check_docker_bypass
        _emit_status
        [[ ${#STATUS_FAIL[@]} -eq 0 ]] && exit 0 || exit 1
    fi

    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              harden-firewall.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    # ── All-pass early exit ───────────────────────────────────────────────────
    if all_checks_pass; then
        header "Current Firewall State"
        show_state
        ok "All hardening checks pass. No action needed."
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

    section "Current Firewall State"
    show_state

    section "Checks"
    check_ufw_installed
    check_ufw_active
    check_default_policies
    check_ssh_rule
    check_no_wide_open_rules
    check_tunnel_exposure
    check_docker_bypass

    # ── Final state + summary ──────────────────────────────────────────────────
    header "Hardening State"
    show_state

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
        ok   "All accepted fixes applied. Re-run $(basename "$0") to confirm."
    fi
}

main