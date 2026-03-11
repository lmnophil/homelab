#!/usr/bin/env bash
# ==============================================================================
# harden-crowdsec.sh — Audit and harden CrowdSec IPS configuration
# ==============================================================================
# Checks whether CrowdSec is installed and correctly configured for your
# Proxmox LXC / homelab deployment. Guides you through remediation for every
# failed check. Safe to re-run — idempotent.
#
# Usage:
#   sudo ./harden-crowdsec.sh [--dry-run] [--status]
#   ./harden-crowdsec.sh --help
#
# Options:
#   --dry-run   Print commands without executing them (no root required)
#   --status    Machine-readable PASS/FAIL output, exits 0 or 1 (no prompts)
#   --help/-h   Show this help and exit
#
# Environment variables:
#   DRY_RUN          true|false           (default: false)
#   STATUS_MODE      true|false           (default: false)
#   EXPOSURE_METHOD  cloudflare|pangolin|lan|vpn|direct|mixed
#                    Auto-detected when unset; prompted if detection fails.
#
# ── Best-practice summary ─────────────────────────────────────────────────────
#
#  INSTALL CrowdSec when:
#    • Any port is reachable from the internet (direct, Cloudflare, Pangolin)
#    • SSH is on the LAN — the community blocklist is cheap insurance
#    • You run a reverse proxy (Caddy, NginxPM) — parse its access logs
#
#  SKIP CrowdSec when:
#    • This is a minimal internal service LXC with no exposed ports
#    • The reverse proxy already runs CrowdSec in its own LXC
#      (avoid double-agents on the same traffic)
#
#  CLOUDFLARE TUNNEL users — read this before anything else:
#    The nftables bouncer blocks by network IP. All web traffic arrives from
#    Cloudflare's own IPs, not the real visitor. Without whitelisting CF IPs,
#    CrowdSec will eventually ban a Cloudflare range and cut off ALL tunnel
#    traffic. This script enforces that whitelist. HTTP-layer blocking (banning
#    the real visitor IP) requires the caddy-crowdsec-bouncer module or the
#    crowdsec-nginx-bouncer — this script checks for that too.
#
#  PANGOLIN users:
#    Similar to Cloudflare: traffic arrives via your VPS WireGuard tunnel IP.
#    Whitelist the Pangolin VPS WireGuard IP. For HTTP-layer blocking install
#    the Traefik CrowdSec plugin on the Pangolin VPS itself.
#
# ==============================================================================

set -euo pipefail

DRY_RUN="${DRY_RUN:-false}"
STATUS_MODE="${STATUS_MODE:-false}"
EXPOSURE_METHOD="${EXPOSURE_METHOD:-}"

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

# ── Status helpers (--status mode) ───────────────────────────────────────────

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

# ── OS detection globals ──────────────────────────────────────────────────────

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
}

# ── State query helpers ───────────────────────────────────────────────────────

is_pkg_installed()     { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
is_service_active()    { systemctl is-active  "$1" &>/dev/null; }
is_service_enabled()   { systemctl is-enabled "$1" &>/dev/null; }
is_crowdsec_installed(){ command -v cscli &>/dev/null && is_pkg_installed "crowdsec"; }

is_bouncer_installed() {
    is_pkg_installed "crowdsec-firewall-bouncer-nftables" || \
    is_pkg_installed "crowdsec-firewall-bouncer-iptables"
}

is_capi_registered() {
    [[ -f /etc/crowdsec/online_api_credentials.yaml ]] && \
        grep -q "login:" /etc/crowdsec/online_api_credentials.yaml 2>/dev/null
}

is_collection_installed() {
    cscli collections list -o raw 2>/dev/null | grep -q "^$1,"
}

# Check if CF IPs appear in any CrowdSec whitelist file
cf_ips_whitelisted() {
    grep -rl "173.245.48.0" /etc/crowdsec/ 2>/dev/null | grep -q .
}

# Check if any nftables/iptables CrowdSec chain exists (bouncer applied rules)
bouncer_rules_active() {
    nft list tables 2>/dev/null | grep -q "crowdsec" || \
    iptables -L crowdsec-blacklists 2>/dev/null | grep -q "Chain"
}

# ── Exposure detection ────────────────────────────────────────────────────────

_detect_exposure() {
    # Cloudflare tunnel
    if systemctl is-active cloudflared &>/dev/null || command -v cloudflared &>/dev/null; then
        printf 'cloudflare'; return
    fi
    # Pangolin newt client
    if systemctl is-active newt &>/dev/null || command -v newt &>/dev/null || \
       systemctl is-active pangolin &>/dev/null; then
        printf 'pangolin'; return
    fi
    # WireGuard interfaces suggest VPN
    if ip link show type wireguard 2>/dev/null | grep -q .; then
        printf 'vpn'; return
    fi
    printf 'unknown'
}

_ask_exposure() {
    printf '\n'
    info "How are your services exposed to the internet?"
    plain "This determines which CrowdSec checks apply."
    plain ""
    plain "  1) LAN-only       — no ports exposed to internet"
    plain "  2) Cloudflare     — Cloudflare Tunnel (cloudflared)"
    plain "  3) Pangolin       — self-hosted tunnel (newt/gerbil)"
    plain "  4) VPN            — WireGuard/Tailscale/ZeroTier only"
    plain "  5) Direct/public  — ports open directly on a public IP"
    plain "  6) Mixed          — some services via CF/VPN, some direct"
    plain ""
    local choice
    while true; do
        choice=$(ask_val "Exposure method (1-6)" "1")
        case "$choice" in
            1) EXPOSURE_METHOD="lan";        break ;;
            2) EXPOSURE_METHOD="cloudflare"; break ;;
            3) EXPOSURE_METHOD="pangolin";   break ;;
            4) EXPOSURE_METHOD="vpn";        break ;;
            5) EXPOSURE_METHOD="direct";     break ;;
            6) EXPOSURE_METHOD="mixed";      break ;;
            *) warn "Enter 1-6." ;;
        esac
    done
}

# ── Install helper ────────────────────────────────────────────────────────────

_do_install_crowdsec() {
    section "Installing CrowdSec"
    info "Adding CrowdSec repository..."
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" \
            "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
        printf "    ${DIM}[dry-run]${NC} %s\n" \
            "apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables"
    else
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
        apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables
    fi
    ok "CrowdSec and nftables bouncer installed."
}

_write_cf_whitelist() {
    local wl_dir="/etc/crowdsec/parsers/s02-enrich"
    local wl_file="${wl_dir}/whitelists-cloudflare.yaml"
    local bak="${wl_file}.bak.$(date +%Y%m%d%H%M%S)"

    run mkdir -p "$wl_dir"
    [[ -f "$wl_file" ]] && run cp "$wl_file" "$bak" && info "Backed up to ${bak}"

    if [[ "$DRY_RUN" != "true" ]]; then
        cat > "$wl_file" << 'YAML'
name: local/whitelists-cloudflare
description: "Cloudflare egress IPs — managed by harden-crowdsec.sh"
whitelist:
  reason: "Cloudflare infrastructure — banning these IPs kills all tunnel traffic"
  cidr:
    # IPv4 — https://www.cloudflare.com/ips-v4
    - "173.245.48.0/20"
    - "103.21.244.0/22"
    - "103.22.200.0/22"
    - "103.31.4.0/22"
    - "141.101.64.0/18"
    - "108.162.192.0/18"
    - "190.93.240.0/20"
    - "188.114.96.0/20"
    - "197.234.240.0/22"
    - "198.41.128.0/17"
    - "162.158.0.0/15"
    - "104.16.0.0/13"
    - "104.24.0.0/14"
    - "172.64.0.0/13"
    - "131.0.72.0/22"
    # IPv6 — https://www.cloudflare.com/ips-v6
    - "2400:cb00::/32"
    - "2606:4700::/32"
    - "2803:f800::/32"
    - "2405:b500::/32"
    - "2405:8100::/32"
    - "2a06:98c0::/29"
    - "2c0f:f248::/32"
YAML
        ok "Whitelist written to ${wl_file}"
    else
        printf "    ${DIM}[dry-run]${NC} %s\n" "write ${wl_file} (CF IPv4+IPv6 ranges)"
    fi
}

# ── Check functions ───────────────────────────────────────────────────────────

check_installation() {
    # ── STATUS MODE ──
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_crowdsec_installed; then
            local ver; ver=$(cscli version 2>/dev/null | awk '/version:/{print $2}' || printf 'unknown')
            status_pass "crowdsec_installed" "version ${ver}"
        else
            status_fail "crowdsec_installed" "crowdsec is not installed"
        fi
        return 0
    fi

    if is_crowdsec_installed; then
        local ver; ver=$(cscli version 2>/dev/null | awk '/version:/{print $2}' || printf 'unknown')
        ok "CrowdSec is installed (${ver})."
        CHECKS_PASSED+=("CrowdSec installed (${ver})")
        return 0
    fi

    printf '\n'
    warn "CrowdSec is not installed."
    plain ""
    plain "CrowdSec is a collaborative intrusion prevention system. It does two things:"
    plain "  1. Watches your logs for attack patterns (brute-force, scans, CVE exploits)"
    plain "     and bans offending IPs via nftables — in near real-time."
    plain "  2. Pulls a community blocklist of ~500 k known-bad IPs maintained by"
    plain "     millions of CrowdSec instances worldwide. These IPs are blocked before"
    plain "     they even make a first request to your services."
    plain ""
    plain "When to install it:"
    plain "  • Any port reachable from the internet — value is immediate and measurable"
    plain "  • LAN-only setups — cheap insurance against accidental port-forwards"
    plain "  • Reverse proxy LXCs (Caddy, NginxPM) — parse access logs for HTTP attacks"
    plain ""
    plain "When to skip it:"
    plain "  • A backend service LXC with zero exposed ports and no logs worth parsing"
    plain "  • An LXC behind a reverse proxy that already runs CrowdSec"
    plain "    (two agents watching the same traffic is redundant, not additive)"

    if ask "Install CrowdSec now?" "y"; then
        _do_install_crowdsec
        if is_crowdsec_installed; then
            ok "CrowdSec is now installed."
            CHECKS_FIXED+=("CrowdSec installed")
        else
            warn "Installation did not succeed. Check output above."
            CHECKS_DECLINED+=("CrowdSec installation failed")
        fi
    else
        warn "Skipped — CrowdSec not installed. Most remaining checks will be skipped."
        CHECKS_DECLINED+=("CrowdSec not installed (skipped by operator)")
    fi
}

check_bouncer() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_bouncer_installed && is_service_active "crowdsec-firewall-bouncer"; then
            status_pass "bouncer_running"
        elif is_bouncer_installed; then
            status_fail "bouncer_running" "bouncer installed but not active"
        else
            status_fail "bouncer_running" "crowdsec-firewall-bouncer-nftables not installed"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    if is_bouncer_installed && is_service_active "crowdsec-firewall-bouncer"; then
        ok "nftables bouncer is installed and running."
        CHECKS_PASSED+=("nftables bouncer active")
        return 0
    fi

    printf '\n'
    if ! is_bouncer_installed; then
        warn "nftables bouncer is not installed."
        plain "The bouncer enforces CrowdSec's ban decisions in nftables. Without it,"
        plain "CrowdSec detects attacks and records decisions — but nothing is blocked."
        if ask "Install crowdsec-firewall-bouncer-nftables?" "y"; then
            run apt-get install -y crowdsec-firewall-bouncer-nftables
            run systemctl enable --now crowdsec-firewall-bouncer
            ok "Bouncer installed and started."
            CHECKS_FIXED+=("nftables bouncer installed and started")
        else
            warn "Skipped — CrowdSec will detect attacks but not block them."
            CHECKS_DECLINED+=("nftables bouncer not installed (risk accepted)")
        fi
    else
        warn "nftables bouncer is installed but not running."
        plain "Decisions are being made but not enforced in nftables."
        if ask "Enable and start crowdsec-firewall-bouncer?" "y"; then
            run systemctl enable --now crowdsec-firewall-bouncer
            ok "Bouncer started."
            CHECKS_FIXED+=("nftables bouncer started")
        else
            warn "Skipped — bouncer remains stopped."
            CHECKS_DECLINED+=("nftables bouncer not started (risk accepted)")
        fi
    fi
}

check_services_running() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_service_active "crowdsec" && is_service_enabled "crowdsec"; then
            status_pass "crowdsec_service"
        else
            status_fail "crowdsec_service" \
                "crowdsec service is $(systemctl is-active crowdsec 2>/dev/null || printf 'unknown')"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    local active; active=$(systemctl is-active crowdsec 2>/dev/null || printf 'inactive')
    local enabled; enabled=$(systemctl is-enabled crowdsec 2>/dev/null || printf 'disabled')

    if [[ "$active" == "active" && "$enabled" == "enabled" ]]; then
        ok "crowdsec service is active and enabled."
        CHECKS_PASSED+=("crowdsec service active and enabled")
        return 0
    fi

    printf '\n'
    warn "crowdsec service: active=${active}, enabled=${enabled}"
    plain "CrowdSec is not watching logs. No new bans are being issued."

    if ask "Enable and start crowdsec now?" "y"; then
        run systemctl enable --now crowdsec
        ok "crowdsec service enabled and started."
        CHECKS_FIXED+=("crowdsec service enabled and started")
    else
        warn "Skipped — crowdsec remains ${active}."
        CHECKS_DECLINED+=("crowdsec service not started (risk accepted)")
    fi
}

check_capi_registered() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if is_capi_registered; then
            status_pass "capi_registered"
        else
            status_fail "capi_registered" "not registered with CrowdSec Central API"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    if is_capi_registered; then
        ok "Registered with CrowdSec Central API (community blocklist active)."
        CHECKS_PASSED+=("CAPI registered")
        return 0
    fi

    printf '\n'
    warn "Not registered with CrowdSec Central API."
    plain ""
    plain "The Central API gives you access to the community blocklist — roughly 500 k"
    plain "IPs with a history of attacks, maintained by CrowdSec's global network."
    plain "Without registration you only have local detection; you lose the community"
    plain "intelligence that makes CrowdSec substantially more effective than fail2ban."
    plain ""
    plain "Registration is free, anonymous, and does not require an account. You share"
    plain "your signals (anonymised attacker IPs + patterns) and receive the global feed."

    if ask "Register with CrowdSec Central API now?" "y"; then
        run cscli capi register
        run systemctl restart crowdsec
        ok "Registered. Community blocklist will be active after the first sync (~1 min)."
        CHECKS_FIXED+=("CAPI registration complete")
    else
        warn "Skipped — community blocklist not available."
        CHECKS_DECLINED+=("CAPI not registered (community blocklist missing)")
    fi
}

check_base_collections() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        local missing=()
        is_crowdsec_installed || { status_fail "base_collections" "crowdsec not installed"; return 0; }
        is_collection_installed "crowdsecurity/linux" || missing+=("crowdsecurity/linux")
        is_collection_installed "crowdsecurity/sshd"  || missing+=("crowdsecurity/sshd")
        if [[ ${#missing[@]} -eq 0 ]]; then
            status_pass "base_collections"
        else
            status_fail "base_collections" "missing: ${missing[*]}"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    local missing=()
    is_collection_installed "crowdsecurity/linux" || missing+=("crowdsecurity/linux")
    is_collection_installed "crowdsecurity/sshd"  || missing+=("crowdsecurity/sshd")

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "Base collections installed (linux, sshd)."
        CHECKS_PASSED+=("Base collections present")
        return 0
    fi

    printf '\n'
    warn "Missing base collections: ${missing[*]}"
    plain ""
    plain "crowdsecurity/linux — OS-level log parsing (auth, kernel, systemd)."
    plain "crowdsecurity/sshd  — SSH brute-force detection and banning."
    plain "These are the minimum recommended baseline for every Linux server."

    if ask "Install missing base collections?" "y"; then
        run cscli collections install "${missing[@]}"
        run systemctl restart crowdsec
        ok "Base collections installed."
        CHECKS_FIXED+=("Base collections installed: ${missing[*]}")
    else
        warn "Skipped — some attack patterns will not be detected."
        CHECKS_DECLINED+=("Base collections not installed: ${missing[*]}")
    fi
}

check_cloudflare_whitelist() {
    # Only applies to Cloudflare Tunnel users.
    [[ "$EXPOSURE_METHOD" == "cloudflare" || "$EXPOSURE_METHOD" == "mixed" ]] || return 0

    if [[ "$STATUS_MODE" == "true" ]]; then
        if ! is_crowdsec_installed; then return 0; fi
        if cf_ips_whitelisted; then
            status_pass "cloudflare_whitelist"
        else
            status_fail "cloudflare_whitelist" \
                "Cloudflare IPs not whitelisted — CrowdSec could ban your tunnel"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    if cf_ips_whitelisted; then
        ok "Cloudflare IPs are whitelisted."
        CHECKS_PASSED+=("Cloudflare IPs whitelisted")
        return 0
    fi

    printf '\n'
    warn "CRITICAL: Cloudflare IPs are not whitelisted."
    plain ""
    plain "This is the highest-priority fix for Cloudflare Tunnel users."
    plain ""
    plain "All web traffic through your tunnel arrives from Cloudflare's own IPs,"
    plain "not from your real visitors. If CrowdSec triggers on HTTP traffic (e.g.,"
    plain "a scanner reaching your services via the tunnel), it will ban a Cloudflare"
    plain "IP range. This instantly cuts off ALL your tunnel traffic — every service"
    plain "behind the tunnel goes offline. It can happen within minutes of first setup."
    plain ""
    plain "The whitelist tells CrowdSec: 'never take action on these IPs regardless"
    plain "of what their traffic looks like.' It does not prevent HTTP-level detection"
    plain "(the alerts still appear) — it just prevents the nftables block."

    if ask "Write Cloudflare IP whitelist now? (strongly recommended)" "y"; then
        _write_cf_whitelist
        run systemctl restart crowdsec
        ok "Cloudflare whitelist written and crowdsec restarted."
        CHECKS_FIXED+=("Cloudflare IP whitelist written")
    else
        warn "DECLINED — your tunnel is at risk of a self-inflicted outage."
        CHECKS_DECLINED+=("Cloudflare whitelist not written (HIGH RISK)")
    fi
}

check_pangolin_whitelist() {
    [[ "$EXPOSURE_METHOD" == "pangolin" ]] || return 0

    if [[ "$STATUS_MODE" == "true" ]]; then
        is_crowdsec_installed || return 0
        # We can only check if a whitelist file exists; we don't know the VPS IP
        if [[ -f /etc/crowdsec/parsers/s02-enrich/whitelists-pangolin.yaml ]]; then
            status_pass "pangolin_whitelist"
        else
            status_fail "pangolin_whitelist" "no Pangolin tunnel IP whitelist found"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    if [[ -f /etc/crowdsec/parsers/s02-enrich/whitelists-pangolin.yaml ]]; then
        ok "Pangolin tunnel whitelist file exists."
        CHECKS_PASSED+=("Pangolin whitelist file present")
        return 0
    fi

    printf '\n'
    warn "No Pangolin tunnel whitelist found."
    plain ""
    plain "Pangolin routes all traffic through your VPS via a WireGuard tunnel."
    plain "From CrowdSec's perspective, HTTP requests arrive from the WireGuard"
    plain "tunnel IP (not the real visitor IP). Without whitelisting that IP,"
    plain "CrowdSec could ban your VPS IP and cut off all Pangolin traffic."
    plain ""
    plain "You need to add your Pangolin VPS's WireGuard IP (the peer address"
    plain "in your wg0.conf or similar) to a CrowdSec whitelist."
    plain ""
    plain "For HTTP-layer blocking (real visitor IPs), install the Traefik"
    plain "CrowdSec bouncer plugin on the Pangolin VPS itself — that is where"
    plain "the real IPs are visible."

    if ask "Enter your Pangolin VPS/tunnel IP or CIDR to whitelist now?" "y"; then
        local vps_ip
        while true; do
            vps_ip=$(ask_val "Pangolin VPS IP or CIDR (e.g. 10.10.0.1 or 10.10.0.0/24)")
            [[ -z "$vps_ip" ]] && { info "Cancelled."; return 0; }
            # Basic validation
            if [[ "$vps_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
                break
            fi
            warn "Does not look like an IPv4 address or CIDR. Try again."
        done

        local wl_dir="/etc/crowdsec/parsers/s02-enrich"
        local wl_file="${wl_dir}/whitelists-pangolin.yaml"
        run mkdir -p "$wl_dir"

        if [[ "$DRY_RUN" != "true" ]]; then
            cat > "$wl_file" << YAML
name: local/whitelists-pangolin
description: "Pangolin VPS tunnel IP — managed by harden-crowdsec.sh"
whitelist:
  reason: "Pangolin WireGuard tunnel endpoint — real visitor IPs not visible here"
  cidr:
    - "${vps_ip}"
YAML
            ok "Pangolin whitelist written to ${wl_file}"
        else
            printf "    ${DIM}[dry-run]${NC} %s\n" "write ${wl_dir}/whitelists-pangolin.yaml (${vps_ip})"
        fi

        run systemctl restart crowdsec
        CHECKS_FIXED+=("Pangolin tunnel whitelist written (${vps_ip})")
    else
        warn "Skipped — Pangolin traffic could trigger incorrect bans."
        CHECKS_DECLINED+=("Pangolin whitelist not written (risk accepted)")
    fi
}

check_http_layer_protection() {
    # For CF Tunnel and Pangolin, the nftables bouncer cannot see real visitor IPs.
    # An HTTP-layer bouncer is needed for actual per-visitor blocking.
    [[ "$EXPOSURE_METHOD" == "cloudflare" || "$EXPOSURE_METHOD" == "pangolin" || \
       "$EXPOSURE_METHOD" == "mixed" ]] || return 0

    if [[ "$STATUS_MODE" == "true" ]]; then
        is_crowdsec_installed || return 0
        local has_http=false
        # Caddy bouncer: check Caddyfile or caddy module list
        grep -r "crowdsec" /etc/caddy/ 2>/dev/null | grep -q . && has_http=true
        # NginxPM bouncer
        is_pkg_installed "crowdsec-nginx-bouncer" && has_http=true
        [[ -f /etc/nginx/conf.d/crowdsec_nginx.conf ]] && has_http=true

        if [[ "$has_http" == "true" ]]; then
            status_pass "http_layer_bouncer"
        else
            status_fail "http_layer_bouncer" \
                "no HTTP-layer bouncer detected; nftables bouncer cannot see real visitor IPs"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0

    local has_http=false
    grep -r "crowdsec" /etc/caddy/ 2>/dev/null | grep -q . && has_http=true
    is_pkg_installed "crowdsec-nginx-bouncer" && has_http=true
    [[ -f /etc/nginx/conf.d/crowdsec_nginx.conf ]] && has_http=true

    if [[ "$has_http" == "true" ]]; then
        ok "HTTP-layer bouncer is configured."
        CHECKS_PASSED+=("HTTP-layer bouncer detected")
        return 0
    fi

    printf '\n'
    warn "No HTTP-layer bouncer detected."
    plain ""

    if [[ "$EXPOSURE_METHOD" == "cloudflare" ]]; then
        plain "With Cloudflare Tunnel all HTTP requests arrive from Cloudflare IPs."
        plain "The nftables bouncer blocks by network IP, so banning the 'attacker'"
        plain "would actually ban Cloudflare — that's why CF IPs are whitelisted."
        plain "Real visitor banning requires an HTTP-layer bouncer that reads the"
        plain "CF-Connecting-IP header to get the actual visitor IP."
    else
        plain "With Pangolin all requests arrive from your VPS WireGuard IP."
        plain "The nftables bouncer cannot see individual visitor IPs. Real visitor"
        plain "banning must happen at the Traefik layer on the Pangolin VPS itself."
    fi

    plain ""
    plain "Options:"
    if command -v caddy &>/dev/null || is_service_active "caddy"; then
        plain "  Caddy:    Install caddy-crowdsec-bouncer (requires a custom Caddy build)"
        plain "            https://github.com/hslatman/caddy-crowdsec-bouncer"
        plain "            Build with: xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer"
    fi
    if command -v nginx &>/dev/null || is_service_active "nginx"; then
        plain "  NginxPM:  Install crowdsec-nginx-bouncer"
        plain "            apt install crowdsec-nginx-bouncer"
        plain "            Ensure the NginxPM LXC has CrowdSec installed (see manage script)."
    fi
    plain ""
    plain "  Note: if your reverse proxy runs in a SEPARATE LXC from CrowdSec, you"
    plain "  must install CrowdSec (agent + bouncer) in the proxy LXC so it can read"
    plain "  the real headers. The manage script has a proxy integration wizard."

    warn "HTTP-layer bouncer not configured — visitor-level blocking not active."
    CHECKS_DECLINED+=("HTTP-layer bouncer not configured (informational)")
}

check_fail2ban_conflict() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        is_crowdsec_installed || return 0
        if is_pkg_installed "fail2ban" && \
           fail2ban-client status sshd &>/dev/null 2>&1; then
            status_fail "fail2ban_conflict" \
                "fail2ban sshd jail and CrowdSec sshd collection both active — duplicate coverage"
        else
            status_pass "fail2ban_conflict" "no fail2ban/crowdsec SSH conflict"
        fi
        return 0
    fi

    is_crowdsec_installed || return 0
    is_pkg_installed "fail2ban" || return 0

    if ! fail2ban-client status sshd &>/dev/null 2>&1; then
        ok "No fail2ban/CrowdSec SSH conflict (fail2ban sshd jail not active)."
        CHECKS_PASSED+=("No fail2ban/CrowdSec conflict")
        return 0
    fi

    printf '\n'
    warn "fail2ban sshd jail and CrowdSec sshd collection are both active."
    plain ""
    plain "Both tools are watching /var/log/auth.log and will ban the same IPs."
    plain "This is not dangerous, but it is redundant: each ban is enforced twice"
    plain "(once by fail2ban via iptables, once by CrowdSec via nftables)."
    plain "It also means SSH bans may not be cleared cleanly if you manage one tool"
    plain "without knowing about the other."
    plain ""
    plain "Best practice: use CrowdSec for SSH. Disable fail2ban's sshd jail"
    plain "(you can keep fail2ban active for other jails if you have them)."

    if ask "Disable fail2ban sshd jail?" "y"; then
        local f2b_local="/etc/fail2ban/jail.local"
        local bak="${f2b_local}.bak.$(date +%Y%m%d%H%M%S)"
        if [[ -f "$f2b_local" ]]; then
            run cp "$f2b_local" "$bak"
            info "Backed up to ${bak}"
        fi
        if [[ "$DRY_RUN" != "true" ]]; then
            # Add or update [sshd] enabled = false
            if grep -q "^\[sshd\]" "$f2b_local" 2>/dev/null; then
                sed -i '/^\[sshd\]/,/^\[/ { /^enabled/d }' "$f2b_local"
                sed -i '/^\[sshd\]/a enabled = false' "$f2b_local"
            else
                printf '\n[sshd]\nenabled = false\n' >> "$f2b_local"
            fi
        else
            printf "    ${DIM}[dry-run]${NC} %s\n" "add [sshd] enabled = false to ${f2b_local}"
        fi
        run systemctl restart fail2ban
        ok "fail2ban sshd jail disabled."
        CHECKS_FIXED+=("fail2ban sshd jail disabled")
    else
        warn "Skipped — duplicate SSH banning remains in place."
        CHECKS_DECLINED+=("fail2ban sshd conflict not resolved (redundant but safe)")
    fi
}

# ── State display ─────────────────────────────────────────────────────────────

show_state() {
    local cs_status bouncer_status capi_status
    if is_crowdsec_installed; then
        cs_status="${GREEN}installed${NC}"
    else
        cs_status="${RED}not installed${NC}"
    fi

    if is_service_active "crowdsec"; then
        cs_status+=" ${GREEN}(active)${NC}"
    elif is_crowdsec_installed; then
        cs_status+=" ${RED}(stopped)${NC}"
    fi

    if is_bouncer_installed && is_service_active "crowdsec-firewall-bouncer"; then
        bouncer_status="${GREEN}active${NC}"
    elif is_bouncer_installed; then
        bouncer_status="${YELLOW}installed, stopped${NC}"
    else
        bouncer_status="${RED}not installed${NC}"
    fi

    if is_capi_registered; then
        capi_status="${GREEN}registered${NC}"
    else
        capi_status="${RED}not registered${NC}"
    fi

    local div; printf -v div '%*s' 52 ''; div="${div// /─}"
    printf "  %-24s %s\n"  "crowdsec agent:"    "$(printf "${cs_status}")"
    printf "  %-24s %s\n"  "nftables bouncer:"  "$(printf "${bouncer_status}")"
    printf "  %-24s %s\n"  "CAPI (blocklist):"  "$(printf "${capi_status}")"
    printf "  %-24s %s\n"  "exposure:"          "${BOLD}${EXPOSURE_METHOD:-unknown}${NC}"
    printf '\n'

    if is_crowdsec_installed; then
        printf "  %-28s %s\n" "Collections:" ""
        local col
        for col in "crowdsecurity/linux" "crowdsecurity/sshd" \
                   "crowdsecurity/caddy" "crowdsecurity/nginx" \
                   "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios"; do
            if is_collection_installed "$col"; then
                printf "    ${GREEN}✓${NC}  %s\n" "$col"
            fi
        done
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
    preflight_checks

    # ── Detect exposure method ───────────────────────────────────────────────
    if [[ -z "$EXPOSURE_METHOD" ]]; then
        EXPOSURE_METHOD=$(_detect_exposure)
        if [[ "$EXPOSURE_METHOD" == "unknown" && "$STATUS_MODE" != "true" ]]; then
            _ask_exposure
        fi
    fi

    # ── Status mode: run all checks silently then emit ───────────────────────
    if [[ "$STATUS_MODE" == "true" ]]; then
        check_installation
        check_bouncer
        check_services_running
        check_capi_registered
        check_base_collections
        check_cloudflare_whitelist
        check_pangolin_whitelist
        check_http_layer_protection
        check_fail2ban_conflict
        _emit_status
        [[ ${#STATUS_FAIL[@]} -eq 0 ]] && exit 0 || exit 1
    fi

    # ── Banner ───────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              harden-crowdsec.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"           "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"  "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n"          "$DRY_RUN"
    printf "  Exposure: ${BOLD}%s${NC}\n\n"        "${EXPOSURE_METHOD:-detecting...}"

    # ── All-pass check ───────────────────────────────────────────────────────
    local all_pass=true
    if ! is_crowdsec_installed; then all_pass=false; fi
    if ! is_bouncer_installed || ! is_service_active "crowdsec-firewall-bouncer"; then all_pass=false; fi
    if ! is_service_active "crowdsec"; then all_pass=false; fi
    if ! is_capi_registered; then all_pass=false; fi
    if [[ "$EXPOSURE_METHOD" == "cloudflare" || "$EXPOSURE_METHOD" == "mixed" ]]; then
        cf_ips_whitelisted || all_pass=false
    fi

    if [[ "$all_pass" == "true" ]]; then
        show_state
        ok "All CrowdSec hardening checks pass. No action needed."
        exit 0
    fi

    # ── Run checks ───────────────────────────────────────────────────────────
    CHECKS_PASSED=()
    CHECKS_FIXED=()
    CHECKS_DECLINED=()

    section "Installation"
    check_installation

    section "Bouncer"
    check_bouncer

    section "Service"
    check_services_running

    section "Central API (community blocklist)"
    check_capi_registered

    section "Collections"
    check_base_collections

    if [[ "$EXPOSURE_METHOD" == "cloudflare" || "$EXPOSURE_METHOD" == "mixed" ]]; then
        section "Cloudflare Whitelist"
        check_cloudflare_whitelist
    fi

    if [[ "$EXPOSURE_METHOD" == "pangolin" ]]; then
        section "Pangolin Tunnel Whitelist"
        check_pangolin_whitelist
    fi

    if [[ "$EXPOSURE_METHOD" == "cloudflare" || "$EXPOSURE_METHOD" == "pangolin" || \
          "$EXPOSURE_METHOD" == "mixed" ]]; then
        section "HTTP-layer Bouncer"
        check_http_layer_protection
    fi

    section "fail2ban Conflict"
    check_fail2ban_conflict

    # ── Final state + summary ────────────────────────────────────────────────
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
    if (( ${#CHECKS_DECLINED[@]} > 0 )); then
        warn "Some checks were skipped. Re-run $(basename "$0") to address them."
    elif (( ${#CHECKS_FIXED[@]} > 0 )); then
        ok "All accepted fixes applied. Re-run $(basename "$0") to confirm."
    fi
}

main "$@"