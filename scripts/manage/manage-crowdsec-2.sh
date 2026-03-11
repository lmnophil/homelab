#!/usr/bin/env bash
# ==============================================================================
# manage-crowdsec.sh — Full lifecycle management for CrowdSec IPS
# ==============================================================================
# Interactive menu for managing CrowdSec: installation, decisions, collections,
# whitelists, bouncers, reverse-proxy integration, and service control.
#
# Usage:
#   sudo ./manage-crowdsec.sh [--dry-run]
#   ./manage-crowdsec.sh --help
#
# Options:
#   --dry-run   Print commands without executing them (no root required)
#   --help/-h   Show this help and exit
#
# At any menu prompt, type h<N> (e.g. h3) for detailed help on option 3.
# Type h for a general overview of CrowdSec concepts.
#
# Environment variables:
#   DRY_RUN          true|false  (default: false)
#
# ── CrowdSec component overview ───────────────────────────────────────────────
#
#  crowdsec (agent)
#    Reads log acquisition config, parses logs with installed collections,
#    issues ban decisions, and syncs with the Central API (community blocklist).
#
#  bouncer (crowdsec-firewall-bouncer-nftables)
#    Queries the agent for active decisions and enforces them in nftables.
#    The agent decides; the bouncer acts. No bouncer = detection only, no blocks.
#
#  collections
#    Bundles of parsers + scenarios for a specific service (sshd, caddy, nginx).
#    Install the collection for every service whose logs you want CrowdSec to read.
#
#  CAPI (Central API)
#    Crowdsec's cloud service. Provides the community blocklist (~500k known-bad
#    IPs). You share anonymised signals; you receive the global feed. Free.
#
#  Console (app.crowdsec.net)
#    Optional dashboard. Links this agent so you can view decisions and metrics
#    in a web UI. Separate from CAPI — you can have one without the other.
#
# ==============================================================================

set -euo pipefail

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

# ── OS detection globals ──────────────────────────────────────────────────────

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

is_console_enrolled() {
    cscli console status 2>/dev/null | grep -qi "enrolled\|active"
}

is_collection_installed() {
    cscli collections list -o raw 2>/dev/null | grep -q "^$1,"
}

cf_ips_whitelisted() {
    grep -rl "173.245.48.0" /etc/crowdsec/ 2>/dev/null | grep -q .
}

crowdsec_version() {
    cscli version 2>/dev/null | awk '/version:/{print $2}' || printf 'unknown'
}

decision_count() {
    cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || printf '0'
}

# ── Module-level globals ──────────────────────────────────────────────────────

_MENU_MAX=0
MENU_DEFAULT=''

# ── Install helper ────────────────────────────────────────────────────────────

_do_install_crowdsec() {
    info "Adding CrowdSec package repository..."
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" \
            "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
        printf "    ${DIM}[dry-run]${NC} %s\n" \
            "apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables"
    else
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
        apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables
    fi
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
description: "Cloudflare egress IPs — managed by manage-crowdsec.sh"
whitelist:
  reason: "Cloudflare infrastructure — banning these IPs kills all tunnel traffic"
  cidr:
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
    - "2400:cb00::/32"
    - "2606:4700::/32"
    - "2803:f800::/32"
    - "2405:b500::/32"
    - "2405:8100::/32"
    - "2a06:98c0::/29"
    - "2c0f:f248::/32"
YAML
        ok "Cloudflare whitelist written to ${wl_file}"
    else
        printf "    ${DIM}[dry-run]${NC} %s\n" "write ${wl_file} (CF IPv4 + IPv6)"
    fi
}

# ── State table ───────────────────────────────────────────────────────────────

show_state() {
    local div; printf -v div '%*s' 54 ''; div="${div// /─}"
    printf "\n  ${BOLD}%-22s %-14s %s${NC}\n" "Component" "Status" "Info"
    printf "  %s\n" "$div"

    # CrowdSec agent
    if is_crowdsec_installed; then
        local ver; ver=$(crowdsec_version)
        if is_service_active "crowdsec"; then
            printf "  %-22s ${GREEN}%-14s${NC} %s\n" "crowdsec" "active" "v${ver}"
        else
            printf "  %-22s ${RED}%-14s${NC} %s\n" "crowdsec" "stopped" "v${ver}"
        fi
    else
        printf "  %-22s ${RED}%-14s${NC} %s\n" "crowdsec" "not installed" ""
    fi

    # nftables bouncer
    if is_bouncer_installed; then
        if is_service_active "crowdsec-firewall-bouncer"; then
            printf "  %-22s ${GREEN}%-14s${NC}\n" "nftables bouncer" "active"
        else
            printf "  %-22s ${YELLOW}%-14s${NC}\n" "nftables bouncer" "stopped"
        fi
    else
        printf "  %-22s ${RED}%-14s${NC}\n" "nftables bouncer" "not installed"
    fi

    printf "  %s\n" "$div"

    # CAPI + Console
    if is_capi_registered; then
        printf "  %-22s ${GREEN}%-14s${NC}\n" "CAPI (blocklist)" "registered"
    else
        printf "  %-22s ${RED}%-14s${NC}\n" "CAPI (blocklist)" "not registered"
    fi

    if is_crowdsec_installed; then
        if is_console_enrolled; then
            printf "  %-22s ${GREEN}%-14s${NC}\n" "Console" "enrolled"
        else
            printf "  %-22s ${DIM}%-14s${NC}\n" "Console" "not enrolled"
        fi

        # Active decisions
        local dcount; dcount=$(decision_count)
        printf "  %-22s ${BOLD}%-14s${NC}\n" "Active decisions" "${dcount}"

        # Whitelist status
        if cf_ips_whitelisted; then
            printf "  %-22s ${GREEN}%-14s${NC}\n" "CF IP whitelist" "present"
        else
            printf "  %-22s ${DIM}%-14s${NC}\n" "CF IP whitelist" "absent"
        fi

        printf "  %s\n" "$div"

        # Collections
        printf "  ${BOLD}Collections${NC}\n"
        local col found=false
        for col in "crowdsecurity/linux" "crowdsecurity/sshd" \
                   "crowdsecurity/caddy" "crowdsecurity/nginx" \
                   "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios" \
                   "crowdsecurity/nginx-proxy-manager"; do
            if is_collection_installed "$col"; then
                printf "    ${GREEN}✓${NC}  %s\n" "$col"
                found=true
            fi
        done
        [[ "$found" == "false" ]] && printf "    ${DIM}(none installed)${NC}\n"
    fi

    printf '\n'
}

# ── Help texts ────────────────────────────────────────────────────────────────

show_help_general() {
    printf '\n'
    section "CrowdSec Overview"
    plain "CrowdSec has two independent layers:"
    plain ""
    plain "  AGENT (crowdsec)"
    plain "    Reads logs → matches attack patterns → records ban decisions locally."
    plain "    Also pulls the global community blocklist via the Central API (CAPI)."
    plain "    Decisions live in a local SQLite database."
    plain ""
    plain "  BOUNCER (crowdsec-firewall-bouncer-nftables)"
    plain "    Reads the agent's decisions and enforces them in nftables."
    plain "    No bouncer = detection only, nothing is actually blocked."
    plain ""
    plain "  COLLECTIONS"
    plain "    Bundles of parsers + scenarios per service. You need the collection"
    plain "    for every service whose logs you want analysed."
    plain ""
    plain "  PROXY INTEGRATION"
    plain "    For Cloudflare Tunnel and Pangolin, the nftables bouncer cannot see"
    plain "    real visitor IPs — all traffic arrives from the proxy IP. You need"
    plain "    an HTTP-layer bouncer (caddy-crowdsec-bouncer, crowdsec-nginx-bouncer)"
    plain "    to do per-visitor blocking. See option: Reverse Proxy Integration."
}

show_help_for() {
    local opt="$1"
    printf '\n'
    case "$opt" in
        1)
            section "Help: Install CrowdSec"
            plain "Installs the crowdsec agent and nftables bouncer from the official"
            plain "packagecloud repository. Also installs base collections (linux + sshd)"
            plain "and registers with the Central API for the community blocklist."
            plain ""
            plain "After installation run harden-crowdsec.sh to audit the full setup."
            ;;
        2)
            section "Help: View Active Decisions"
            plain "Shows the current ban list: IPs that CrowdSec has decided to block."
            plain "Each entry includes the IP, the reason (scenario that triggered it),"
            plain "the ban duration, and whether it came from local detection or the"
            plain "community blocklist."
            plain ""
            plain "A large decision list is normal — the community blocklist can bring"
            plain "in hundreds of thousands of known-bad IPs immediately after CAPI"
            plain "registration."
            ;;
        3)
            section "Help: Unban an IP"
            plain "Removes a specific IP from the active decision list. Use this when:"
            plain "  • You or a trusted user has been accidentally banned"
            plain "  • A service IP (monitoring, CDN, VPN exit node) got flagged"
            plain "  • You are debugging and need a clean slate for a specific IP"
            plain ""
            plain "Note: if the IP is in the community blocklist it will be re-banned"
            plain "on the next CAPI sync (~15 min). To permanently allow an IP, add it"
            plain "to a whitelist instead (option: Manage Whitelists)."
            ;;
        4)
            section "Help: Flush All Decisions (Debug Mode)"
            plain "Removes ALL active ban decisions — both local and community blocklist."
            plain "This is a debugging / emergency tool."
            plain ""
            plain "Use it when:"
            plain "  • Something is blocked that shouldn't be and you can't identify it"
            plain "  • You need to test that a service is reachable without bans in the way"
            plain "  • A misconfiguration caused a mass-ban event"
            plain ""
            plain "WARNING: After flushing, ALL previously banned IPs can reach you again."
            plain "CrowdSec will rebuild the community blocklist automatically on the next"
            plain "CAPI sync (~15 min). Local decisions are gone until re-triggered."
            plain ""
            plain "This option does NOT disable CrowdSec — it just clears the ban list."
            plain "To stop CrowdSec entirely, use: Toggle Service On/Off."
            ;;
        5)
            section "Help: Whitelist an IP"
            plain "Adds an IP or CIDR range to a CrowdSec whitelist parser. Whitelisted"
            plain "IPs are NEVER banned regardless of what their traffic looks like."
            plain ""
            plain "Use for:"
            plain "  • Your own static IP (home/office)"
            plain "  • Cloudflare egress IPs (use the CF option — it's pre-configured)"
            plain "  • Pangolin VPS WireGuard IP"
            plain "  • Monitoring services (Uptime Kuma, UptimeRobot, etc.)"
            plain "  • Internal LAN subnets"
            plain ""
            plain "Unlike unbanning (option 3), a whitelist survives reboots and CAPI"
            plain "syncs — the IP will never be banned again until you remove it."
            ;;
        6)
            section "Help: Manage Collections"
            plain "Collections are the rule sets that tell CrowdSec what to look for"
            plain "in your logs and which attack patterns to detect."
            plain ""
            plain "Key collections:"
            plain "  crowdsecurity/linux      — base OS log parsing (always install)"
            plain "  crowdsecurity/sshd       — SSH brute-force (always install)"
            plain "  crowdsecurity/caddy      — Caddy access log parsing"
            plain "  crowdsecurity/nginx      — Nginx access log parsing"
            plain "  crowdsecurity/nginx-proxy-manager — NginxPM log format variant"
            plain "  crowdsecurity/http-cve   — known CVE exploit detection in HTTP"
            plain "  crowdsecurity/base-http-scenarios — generic HTTP attack patterns"
            plain ""
            plain "Only install collections for services running on THIS LXC."
            plain "If your reverse proxy is in a separate LXC, install those collections"
            plain "on that LXC's CrowdSec instance, not this one."
            ;;
        7)
            section "Help: Reverse Proxy Integration"
            plain "Configures CrowdSec to work correctly with your reverse proxy setup."
            plain "This wizard covers: Cloudflare Tunnel, NginxPM, Caddy, Pangolin."
            plain ""
            plain "CLOUDFLARE TUNNEL"
            plain "  All traffic arrives from Cloudflare IPs → whitelisting is mandatory."
            plain "  The nftables bouncer cannot ban real visitors. For HTTP-layer banning"
            plain "  you need caddy-crowdsec-bouncer or crowdsec-nginx-bouncer which read"
            plain "  the CF-Connecting-IP header."
            plain ""
            plain "SAME LXC vs SEPARATE LXC:"
            plain "  If your reverse proxy (Caddy/NginxPM) runs in the SAME LXC as"
            plain "  CrowdSec: direct log access works, install the proxy's collection."
            plain ""
            plain "  If the reverse proxy runs in a DIFFERENT LXC: CrowdSec in this LXC"
            plain "  cannot read the proxy's logs. Options:"
            plain "    a) Install CrowdSec in the proxy LXC (recommended)"
            plain "    b) Forward logs via syslog from the proxy LXC to this one"
            plain "    c) Use only the HTTP-layer bouncer plugin in the proxy LXC"
            plain "       (this doesn't need CrowdSec in the proxy LXC, just the bouncer)"
            plain ""
            plain "PANGOLIN"
            plain "  Pangolin uses Traefik as its internal reverse proxy on the VPS."
            plain "  The best place for CrowdSec is on the Pangolin VPS itself."
            plain "  Install: https://docs.crowdsec.net/docs/getting_started/install_crowdsec"
            plain "  Traefik bouncer: https://github.com/fbonalair/traefik-crowdsec-bouncer"
            ;;
        8)
            section "Help: Log Acquisition"
            plain "CrowdSec needs to know which log files to read. Acquisition configs"
            plain "live in /etc/crowdsec/acquis.d/ (one YAML file per source)."
            plain ""
            plain "Common sources:"
            plain "  /var/log/auth.log        — SSH, sudo (covered by linux/sshd collections)"
            plain "  /var/log/caddy/access.log — Caddy access logs (JSON format)"
            plain "  /var/log/nginx/           — Nginx access logs"
            plain "  Docker socket            — all container logs via the Docker socket"
            plain ""
            plain "If a service's log path isn't in acquis.d, CrowdSec is blind to it"
            plain "even if the correct collection is installed."
            ;;
        9)
            section "Help: Console Enrollment"
            plain "The CrowdSec console (app.crowdsec.net) is an optional web dashboard."
            plain "Enrollment links this agent to your account so you can:"
            plain "  • View active decisions and alerts in a UI"
            plain "  • See detection metrics and trends over time"
            plain "  • Manage multiple agents from one place"
            plain ""
            plain "Enrollment is separate from CAPI registration. You can have the"
            plain "community blocklist (CAPI) without the console, and vice versa."
            plain ""
            plain "To get an enrollment key: sign up at https://app.crowdsec.net,"
            plain "go to Security Engines → Add, and copy the enrollment key."
            ;;
        10)
            section "Help: Toggle CrowdSec On/Off"
            plain "Stops or starts both the crowdsec agent and the nftables bouncer."
            plain ""
            plain "Stopping CrowdSec:"
            plain "  • Immediately removes all nftables ban rules"
            plain "  • No new bans will be issued"
            plain "  • All traffic is allowed through again"
            plain "  • Useful for debugging connectivity issues"
            plain ""
            plain "Starting CrowdSec:"
            plain "  • Bouncer re-reads decisions from the local DB and re-applies rules"
            plain "  • Community blocklist is restored from local cache"
            plain "  • Log watching resumes"
            plain ""
            plain "This is the recommended tool for debugging 'why can't X connect?'"
            plain "before resorting to a full decision flush."
            ;;
        11)
            section "Help: Remove CrowdSec Entirely"
            plain "Purges CrowdSec and the bouncer from this system."
            plain ""
            plain "This removes:"
            plain "  • crowdsec package and all nftables rules"
            plain "  • crowdsec-firewall-bouncer-nftables"
            plain "  • All ban decisions (local DB is deleted)"
            plain "  • Acquisition configs in /etc/crowdsec/acquis.d/"
            plain ""
            plain "This does NOT remove:"
            plain "  • Custom whitelist files in /etc/crowdsec/parsers/"
            plain "  • Your console enrollment (deregister at app.crowdsec.net)"
            plain ""
            plain "This is irreversible. Re-running manage-crowdsec.sh or"
            plain "harden-crowdsec.sh will offer to reinstall."
            ;;
        *)
            plain "No help available for option ${opt}."
            ;;
    esac
}

# ── Action: Install ───────────────────────────────────────────────────────────

action_install() {
    if is_crowdsec_installed; then
        ok "CrowdSec is already installed ($(crowdsec_version))."
        return 0
    fi

    section "Install CrowdSec"
    info "This will install:"
    plain "  • crowdsec (IPS agent)"
    plain "  • crowdsec-firewall-bouncer-nftables (enforcement layer)"
    plain "  • Base collections: crowdsecurity/linux + crowdsecurity/sshd"
    plain ""
    info "After install, you should also:"
    plain "  • Register with CAPI for the community blocklist"
    plain "  • Run harden-crowdsec.sh for a full audit"
    plain "  • Configure proxy integration if behind Cloudflare/Pangolin"
    printf '\n'

    ask "Proceed with installation?" "y" || { info "Cancelled."; return 0; }

    _do_install_crowdsec

    if ! is_crowdsec_installed; then
        warn "Installation appears to have failed. Check output above."
        return 0
    fi

    ok "CrowdSec installed. Installing base collections..."
    run cscli collections install crowdsecurity/linux crowdsecurity/sshd
    run systemctl enable --now crowdsec
    run systemctl enable --now crowdsec-firewall-bouncer

    printf '\n'
    info "Register with the Central API now to activate the community blocklist?"
    plain "(Recommended — provides ~500k known-bad IP blocks immediately)"
    if ask "Register with CAPI?" "y"; then
        run cscli capi register
        run systemctl restart crowdsec
        ok "CAPI registration complete."
    fi

    ok "CrowdSec is installed and running."
    info "Run harden-crowdsec.sh for a full audit of your configuration."
}

# ── Action: View decisions ────────────────────────────────────────────────────

action_view_decisions() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi
    section "Active Decisions"
    local dcount; dcount=$(decision_count)
    info "Total active decisions: ${dcount}"
    plain ""
    if (( dcount > 200 )); then
        info "Large list — showing first 50. Use 'cscli decisions list' for full output."
        cscli decisions list 2>/dev/null | head -55 || true
    else
        cscli decisions list 2>/dev/null || true
    fi
    printf '\n'
}

# ── Action: Unban an IP ───────────────────────────────────────────────────────

action_unban_ip() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi

    section "Unban an IP"
    info "This removes a single IP from the active decision list."
    plain "Note: IPs from the community blocklist will be re-banned on the next"
    plain "CAPI sync (~15 min). To permanently allow an IP, use Manage Whitelists."
    printf '\n'

    local target_ip
    while true; do
        target_ip=$(ask_val "IP to unban (Enter to cancel)")
        [[ -z "$target_ip" ]] && { info "Cancelled."; return 0; }
        if [[ "$target_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || \
           [[ "$target_ip" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
            break
        fi
        warn "Does not look like a valid IP or CIDR. Try again (Enter to cancel)."
    done

    if ! cscli decisions list -i "$target_ip" 2>/dev/null | grep -q "$target_ip"; then
        warn "${target_ip} does not appear to have an active decision."
        return 0
    fi

    info "Removing decision for ${target_ip}..."
    run cscli decisions delete --ip "$target_ip"
    ok "Decision for ${target_ip} removed."
}

# ── Action: Flush all decisions ───────────────────────────────────────────────

action_flush_decisions() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi

    section "Flush All Decisions — DEBUG / EMERGENCY"
    printf '\n'
    warn "This removes ALL active ban decisions. Consequences:"
    plain "  • Every currently-banned IP can reach your services immediately"
    plain "  • Community blocklist (~500k IPs) will be gone until CAPI re-syncs"
    plain "  • Local bans will not return until re-triggered by attack traffic"
    plain "  • The CAPI sync takes ~15 minutes to restore the community list"
    plain ""
    warn "This is a debugging tool. Do not use in production unless necessary."
    plain "To stop banning without clearing the list, use: Toggle Service On/Off."
    printf '\n'

    ask "Flush ALL decisions? This is a destructive operation." "n" \
        || { info "Cancelled."; return 0; }

    # Require typing confirmation for destructive ops
    warn "Type 'flush' to confirm, or Enter to cancel:"
    local confirm; confirm=$(ask_val "Confirm")
    if [[ "$confirm" != "flush" ]]; then
        info "Cancelled — confirmation did not match."
        return 0
    fi

    run cscli decisions delete --all
    run systemctl restart crowdsec
    ok "All decisions flushed. CrowdSec is running and will re-detect attacks."
    info "Community blocklist will be restored by CAPI sync in ~15 minutes."

    # Offer to also whitelist current IP as a debugging measure
    local my_ip
    my_ip=$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1{print $7}' || printf '')
    if [[ -n "$my_ip" ]]; then
        info "Would you like to whitelist your current IP (${my_ip}) to prevent"
        plain "accidental self-banning during debugging?"
        if ask "Add ${my_ip} to CrowdSec whitelist?" "y"; then
            _write_ip_whitelist "$my_ip" "local-admin"
        fi
    fi
}

_write_ip_whitelist() {
    local ip="$1" label="${2:-custom}"
    local wl_dir="/etc/crowdsec/parsers/s02-enrich"
    local wl_file="${wl_dir}/whitelist-${label}.yaml"
    run mkdir -p "$wl_dir"

    if [[ "$DRY_RUN" != "true" ]]; then
        cat > "$wl_file" << YAML
name: local/whitelist-${label}
description: "Whitelist added by manage-crowdsec.sh"
whitelist:
  reason: "Trusted IP — managed by manage-crowdsec.sh"
  cidr:
    - "${ip}"
YAML
        ok "Whitelist written to ${wl_file}"
    else
        printf "    ${DIM}[dry-run]${NC} %s\n" "write whitelist for ${ip} to ${wl_file}"
    fi
    run systemctl restart crowdsec
}

# ── Action: Whitelist management ──────────────────────────────────────────────

action_whitelist() {
    section "Manage Whitelists"
    printf '\n'
    info "Whitelist options:"
    plain "  1) Add Cloudflare IPs (required for Cloudflare Tunnel users)"
    plain "  2) Add a custom IP or CIDR"
    plain "  3) View existing whitelist files"
    plain "  4) Cancel"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Option (1-4)" "4")
        case "$choice" in
            1) _action_whitelist_cloudflare; break ;;
            2) _action_whitelist_custom;     break ;;
            3) _action_whitelist_view;       break ;;
            4) info "Cancelled."; return 0  ;;
            *) warn "Enter 1-4." ;;
        esac
    done
}

_action_whitelist_cloudflare() {
    if cf_ips_whitelisted; then
        ok "Cloudflare IPs are already whitelisted."
        return 0
    fi

    warn "Cloudflare IPs are NOT whitelisted."
    plain "If you use Cloudflare Tunnel, this is a critical safety measure."
    plain "CrowdSec could ban a Cloudflare IP range and take all tunnel services offline."
    printf '\n'

    ask "Write Cloudflare IP whitelist now?" "y" || { info "Cancelled."; return 0; }
    _write_cf_whitelist
    run systemctl restart crowdsec
}

_action_whitelist_custom() {
    info "Adding a custom IP or CIDR to a whitelist."
    plain "Use this for your own IP, monitoring services, LAN subnets, or any IP"
    plain "that should never be banned regardless of what its traffic looks like."
    printf '\n'

    local ip
    while true; do
        ip=$(ask_val "IP or CIDR to whitelist (Enter to cancel)")
        [[ -z "$ip" ]] && { info "Cancelled."; return 0; }
        if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || \
           [[ "$ip" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
            break
        fi
        warn "Does not look like a valid IP or CIDR. Try again."
    done

    local label
    label=$(ask_val "Label for this whitelist (letters/numbers, no spaces)" "custom")
    label="${label//[^a-zA-Z0-9_-]/}"
    label="${label:-custom}"

    _write_ip_whitelist "$ip" "$label"
}

_action_whitelist_view() {
    section "Existing Whitelist Files"
    local wl_dir="/etc/crowdsec/parsers/s02-enrich"
    if [[ ! -d "$wl_dir" ]]; then
        info "No whitelist directory found (${wl_dir})."
        return 0
    fi
    local found=false
    local f
    for f in "${wl_dir}"/*.yaml; do
        [[ -f "$f" ]] || continue
        printf "\n  ${BOLD}%s${NC}\n" "$(basename "$f")"
        # Show the CIDR list if present
        grep -E "^\s+-\s+" "$f" 2>/dev/null || grep "cidr\|ip:" "$f" 2>/dev/null || true
        found=true
    done
    [[ "$found" == "false" ]] && info "No whitelist files found in ${wl_dir}."
}

# ── Action: Collections ───────────────────────────────────────────────────────

action_manage_collections() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi

    section "Manage Collections"
    printf '\n'
    info "Options:"
    plain "  1) Install a collection"
    plain "  2) Remove a collection"
    plain "  3) Update all collections (hub upgrade)"
    plain "  4) Cancel"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Option (1-4)" "4")
        case "$choice" in
            1) _action_collection_install; break ;;
            2) _action_collection_remove;  break ;;
            3) _action_collection_update;  break ;;
            4) info "Cancelled."; return 0 ;;
            *) warn "Enter 1-4." ;;
        esac
    done
}

_action_collection_install() {
    printf '\n'
    info "Available collections (commonly used):"
    plain "  crowdsecurity/linux              — base OS log parsing (recommended: always)"
    plain "  crowdsecurity/sshd               — SSH brute-force (recommended: always)"
    plain "  crowdsecurity/caddy              — Caddy reverse proxy logs"
    plain "  crowdsecurity/nginx              — Nginx logs"
    plain "  crowdsecurity/nginx-proxy-manager — NginxPM log format"
    plain "  crowdsecurity/http-cve           — CVE exploit detection in HTTP"
    plain "  crowdsecurity/base-http-scenarios — generic HTTP attack patterns"
    plain ""
    plain "Note: only install collections for services running on THIS LXC."
    plain "If your reverse proxy is in a separate LXC, install those collections"
    plain "in that LXC's CrowdSec instance."
    printf '\n'

    local col
    while true; do
        col=$(ask_val "Collection name (e.g. crowdsecurity/nginx, Enter to cancel)")
        [[ -z "$col" ]] && { info "Cancelled."; return 0; }
        [[ "$col" == *"/"* ]] && break
        warn "Collection names contain a slash, e.g. crowdsecurity/nginx"
    done

    if is_collection_installed "$col"; then
        ok "${col} is already installed."
        return 0
    fi

    run cscli collections install "$col"
    run systemctl restart crowdsec
    ok "${col} installed."
}

_action_collection_remove() {
    printf '\n'
    warn "Removing a collection removes the parsers and scenarios it provides."
    plain "CrowdSec will stop detecting the attack patterns that collection covers."
    printf '\n'

    local col
    while true; do
        col=$(ask_val "Collection to remove (Enter to cancel)")
        [[ -z "$col" ]] && { info "Cancelled."; return 0; }
        [[ "$col" == *"/"* ]] && break
        warn "Collection names contain a slash, e.g. crowdsecurity/nginx"
    done

    if ! is_collection_installed "$col"; then
        warn "${col} is not currently installed."
        return 0
    fi

    ask "Remove ${col}? Detection for this service will stop." "n" \
        || { info "Cancelled."; return 0; }

    run cscli collections remove "$col"
    run systemctl restart crowdsec
    ok "${col} removed."
}

_action_collection_update() {
    info "Updating CrowdSec hub and upgrading all installed items..."
    run cscli hub update
    run cscli hub upgrade
    run systemctl restart crowdsec
    ok "Collections and parsers updated."
}

# ── Action: Proxy integration wizard ─────────────────────────────────────────

action_proxy_wizard() {
    section "Reverse Proxy Integration Wizard"
    printf '\n'
    info "Which reverse proxy are you configuring?"
    plain "  1) Cloudflare Tunnel (cloudflared)"
    plain "  2) Nginx Proxy Manager (NginxPM)"
    plain "  3) Caddy"
    plain "  4) Pangolin (self-hosted VPS tunnel)"
    plain "  5) Cancel"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Select (1-5)" "5")
        case "$choice" in
            1) _proxy_cloudflare; break ;;
            2) _proxy_nginxpm;    break ;;
            3) _proxy_caddy;      break ;;
            4) _proxy_pangolin;   break ;;
            5) info "Cancelled."; return 0 ;;
            *) warn "Enter 1-5." ;;
        esac
    done
}

_proxy_cloudflare() {
    section "Cloudflare Tunnel Integration"
    printf '\n'
    info "Cloudflare Tunnel: what CrowdSec can and cannot do"
    plain ""
    plain "  WHAT WORKS:"
    plain "    • Community blocklist (CAPI) — blocks known-bad IPs at network level"
    plain "    • SSH log watching — protects SSH regardless of how web is exposed"
    plain "    • nftables bouncer — enforces bans for non-HTTP traffic"
    plain ""
    plain "  WHAT DOESN'T WORK without HTTP-layer bouncer:"
    plain "    • All web traffic arrives from Cloudflare's own IPs (not real visitors)"
    plain "    • If CrowdSec bans 'the attacker', it actually bans a Cloudflare range"
    plain "    • This can take ALL your tunnel services offline"
    plain ""
    plain "  THE FIX — two steps:"
    plain "    1. Whitelist CF IPs so they are never banned (prevents outages)"
    plain "    2. Install an HTTP-layer bouncer that reads CF-Connecting-IP header"
    plain "       to get the real visitor IP for per-visitor blocking"
    printf '\n'

    # Step 1: Whitelist
    if cf_ips_whitelisted; then
        ok "Step 1: Cloudflare IPs already whitelisted."
    else
        warn "Step 1: Cloudflare IPs are NOT whitelisted — this is urgent."
        if ask "Write Cloudflare IP whitelist now?" "y"; then
            _write_cf_whitelist
            run systemctl restart crowdsec
        fi
    fi

    # Step 2: HTTP-layer bouncer guidance
    printf '\n'
    section "Step 2: HTTP-Layer Bouncer (per-visitor blocking)"

    # Detect which reverse proxy is on this LXC
    local proxy_type="none"
    command -v caddy &>/dev/null || is_service_active "caddy" && proxy_type="caddy"
    command -v nginx &>/dev/null || is_service_active "nginx" && proxy_type="nginx"

    if [[ "$proxy_type" == "caddy" ]]; then
        info "Caddy detected on this LXC."
        plain ""
        plain "For HTTP-layer banning with Caddy you need a custom Caddy build that"
        plain "includes the caddy-crowdsec-bouncer module."
        plain ""
        plain "Build it with xcaddy:"
        plain "  xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer"
        plain ""
        plain "Then in your Caddyfile, add to each site block:"
        plain "  crowdsec {"
        plain "    api_url http://localhost:8080"
        plain "    api_key <bouncer-api-key from cscli bouncers add caddy>"
        plain "  }"
        plain ""
        info "This handles Caddy-on-same-LXC. For a separate Caddy LXC, see h7."

    elif [[ "$proxy_type" == "nginx" ]]; then
        info "Nginx/NginxPM detected on this LXC."
        plain ""
        plain "Install the nginx bouncer:"
        plain "  apt install crowdsec-nginx-bouncer"
        plain ""
        plain "The bouncer reads /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf"
        plain "and maps CF-Connecting-IP (or X-Real-IP) to real visitor IPs."
        plain ""
        info "This handles Nginx on same LXC. For a separate NginxPM LXC, see h7."

    else
        info "No reverse proxy detected on this LXC."
        plain ""
        plain "If your reverse proxy (Caddy or NginxPM) runs in a SEPARATE LXC:"
        plain ""
        plain "  Option A (recommended): Install CrowdSec in the proxy LXC"
        plain "    Run manage-crowdsec.sh in the proxy LXC and install there."
        plain "    Each LXC runs its own CrowdSec agent — this is the simplest setup."
        plain ""
        plain "  Option B: Install only the HTTP bouncer in the proxy LXC"
        plain "    Install crowdsec-nginx-bouncer or caddy-crowdsec-bouncer"
        plain "    Point its API URL to this LXC's CrowdSec agent (requires network"
        plain "    access and a bouncer API key from: cscli bouncers add <name>)."
        plain ""
        plain "  Option C: Forward logs via syslog"
        plain "    rsyslog can forward the proxy LXC's access logs to this LXC."
        plain "    Complex to maintain — Option A is usually easier."
    fi
}

_proxy_nginxpm() {
    section "Nginx Proxy Manager Integration"
    printf '\n'
    info "Is NginxPM running on this LXC or a separate LXC?"
    plain "  1) Same LXC as CrowdSec (or will be)"
    plain "  2) Separate LXC"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Option (1-2)" "1")
        case "$choice" in
            1|2) break ;;
            *) warn "Enter 1 or 2." ;;
        esac
    done

    printf '\n'

    if [[ "$choice" == "1" ]]; then
        info "Same-LXC setup: NginxPM + CrowdSec"
        plain ""
        plain "1. Install the NginxPM collection:"
        plain "   cscli collections install crowdsecurity/nginx-proxy-manager"
        plain "   (or crowdsecurity/nginx if using standard Nginx)"
        plain ""
        plain "2. Add log acquisition so CrowdSec reads NginxPM's logs."
        plain "   NginxPM stores access logs in /data/logs/ (Docker volume path)."
        plain "   A typical acquis.d entry:"
        plain ""
        plain "   # /etc/crowdsec/acquis.d/nginxpm.yaml"
        plain "   filenames:"
        plain "     - /data/logs/proxy-host-*_access.log"
        plain "   labels:"
        plain "     type: nginx"
        plain ""
        plain "   (Adjust path to match your NginxPM data directory.)"
        plain ""
        plain "3. If you use Cloudflare Tunnel in front of NginxPM:"
        plain "   Ensure CF IPs are whitelisted (Cloudflare Tunnel option in this wizard)."
        plain "   Install crowdsec-nginx-bouncer for HTTP-layer blocking."
        printf '\n'

        if ask "Install crowdsecurity/nginx-proxy-manager collection now?" "y"; then
            run cscli collections install crowdsecurity/nginx-proxy-manager
            run systemctl restart crowdsec
            ok "Collection installed."
        fi

        if ask "Open log acquisition config now?" "y"; then
            action_acquisition
        fi

    else
        info "Separate-LXC setup: NginxPM in its own LXC"
        plain ""
        plain "CrowdSec in THIS LXC cannot read NginxPM's logs from another LXC."
        plain ""
        plain "Recommended approach:"
        plain "  Install CrowdSec in the NginxPM LXC:"
        plain "    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
        plain "    apt install crowdsec crowdsec-nginx-bouncer"
        plain "    cscli collections install crowdsecurity/nginx-proxy-manager"
        plain ""
        plain "  Each LXC runs its own CrowdSec agent. The community blocklist"
        plain "  covers both — there is no downside to running two agents."
        plain ""
        plain "Alternative (remote bouncer only):"
        plain "  Install crowdsec-nginx-bouncer in the NginxPM LXC."
        plain "  Edit /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf:"
        plain "    api_url: http://<this-lxc-ip>:8080/"
        plain "    api_key: <key from: cscli bouncers add nginxpm>"
        plain "  The bouncer enforces decisions from THIS agent. No log analysis"
        plain "  in the NginxPM LXC — only community blocklist + this LXC's bans."
        printf '\n'
        info "Generate a bouncer API key for the remote NginxPM LXC?"
        if ask "Run: cscli bouncers add nginxpm-remote?" "n"; then
            run cscli bouncers add nginxpm-remote
            ok "API key generated. Copy it to the NginxPM LXC's bouncer config."
        fi
    fi
}

_proxy_caddy() {
    section "Caddy Integration"
    printf '\n'
    info "Is Caddy running on this LXC or a separate LXC?"
    plain "  1) Same LXC as CrowdSec (or will be)"
    plain "  2) Separate LXC"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Option (1-2)" "1")
        case "$choice" in
            1|2) break ;;
            *) warn "Enter 1 or 2." ;;
        esac
    done

    printf '\n'

    if [[ "$choice" == "1" ]]; then
        info "Same-LXC setup: Caddy + CrowdSec"
        plain ""
        plain "nftables bouncer (already managed by this script):"
        plain "  Blocks at the network layer. Works automatically. If you are behind"
        plain "  Cloudflare Tunnel, this cannot see real visitor IPs — see CF wizard."
        plain ""
        plain "caddy-crowdsec-bouncer (HTTP layer — optional but recommended for CF):"
        plain "  Requires a custom Caddy binary with the bouncer module compiled in."
        plain "  1. Install xcaddy:"
        plain "     apt install golang-go"
        plain "     go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
        plain "  2. Build Caddy with the module:"
        plain "     xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer"
        plain "     mv caddy /usr/local/bin/caddy"
        plain "  3. Create a bouncer API key:"
        plain "     cscli bouncers add caddy-http"
        plain "  4. Add to each site in your Caddyfile:"
        plain "     crowdsec {"
        plain "       api_url http://localhost:8080"
        plain "       api_key <key from step 3>"
        plain "     }"
        plain ""
        plain "Log acquisition for Caddy JSON logs:"
        plain "  Add /etc/crowdsec/acquis.d/caddy.yaml:"
        plain "    filenames:"
        plain "      - /var/log/caddy/*.log"
        plain "    labels:"
        plain "      type: caddy"
        printf '\n'

        if ask "Install crowdsecurity/caddy + http-cve collections?" "y"; then
            run cscli collections install crowdsecurity/caddy crowdsecurity/http-cve
            run systemctl restart crowdsec
            ok "Collections installed."
        fi

        if ask "Generate a bouncer API key for caddy-crowdsec-bouncer?" "n"; then
            run cscli bouncers add caddy-http
        fi

    else
        info "Separate-LXC setup: Caddy in its own LXC"
        plain ""
        plain "Recommended: Install CrowdSec in the Caddy LXC."
        plain "  This gives full log access and HTTP-layer banning."
        plain "  Run manage-crowdsec.sh in the Caddy LXC."
        plain ""
        plain "Alternative (remote bouncer only — same as NginxPM remote setup):"
        plain "  Install caddy-crowdsec-bouncer in the Caddy LXC."
        plain "  Point api_url at this LXC's CrowdSec agent."
        plain "  Generate an API key below and add it to the bouncer config."
        printf '\n'

        if ask "Generate a bouncer API key for a remote Caddy LXC?" "n"; then
            run cscli bouncers add caddy-remote
            ok "API key generated. Use it in the Caddy LXC bouncer config."
        fi
    fi
}

_proxy_pangolin() {
    section "Pangolin (Self-Hosted Tunnel) Integration"
    printf '\n'
    info "Pangolin routes traffic through your VPS via a WireGuard tunnel."
    plain ""
    plain "How the traffic flow works:"
    plain "  Visitor → Pangolin VPS (Traefik) → WireGuard tunnel → your LXC"
    plain ""
    plain "What CrowdSec sees on your LXC:"
    plain "  The request appears to come from the WireGuard tunnel IP of the Pangolin VPS."
    plain "  Real visitor IPs are in X-Forwarded-For headers."
    plain ""
    plain "Critical: whitelist your Pangolin VPS's WireGuard IP to prevent"
    plain "CrowdSec from banning the tunnel IP and cutting off all Pangolin traffic."
    printf '\n'

    # Step 1: whitelist the VPS WireGuard IP
    info "Step 1: Whitelist the Pangolin VPS tunnel IP"
    plain ""
    if [[ -f /etc/crowdsec/parsers/s02-enrich/whitelists-pangolin.yaml ]]; then
        ok "Pangolin whitelist file already exists."
        plain "  $(cat /etc/crowdsec/parsers/s02-enrich/whitelists-pangolin.yaml 2>/dev/null | grep -E "^\s+-" | head -5 || true)"
    else
        local vps_ip
        while true; do
            vps_ip=$(ask_val "Pangolin VPS WireGuard IP or CIDR (Enter to skip)")
            [[ -z "$vps_ip" ]] && { info "Skipped whitelist setup."; break; }
            if [[ "$vps_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
                _write_ip_whitelist "$vps_ip" "pangolin"
                break
            fi
            warn "Does not look like a valid IPv4 address/CIDR. Try again."
        done
    fi

    # Step 2: Guidance on where to put CrowdSec for best coverage
    printf '\n'
    section "Step 2: Where to run CrowdSec for HTTP-layer protection"
    plain ""
    plain "Option A — CrowdSec on the Pangolin VPS (BEST for visitor-level blocking)"
    plain "  Install CrowdSec on the VPS where Pangolin (Traefik) runs."
    plain "  Install the Traefik CrowdSec bouncer plugin:"
    plain "    https://github.com/fbonalair/traefik-crowdsec-bouncer"
    plain "  This is where real visitor IPs are visible — it is the ideal placement."
    plain ""
    plain "Option B — CrowdSec here (on your home LXC)"
    plain "  CrowdSec here only sees the WireGuard tunnel IP for HTTP traffic."
    plain "  Useful for SSH protection and the community blocklist."
    plain "  Cannot do per-visitor HTTP banning without the Traefik bouncer on the VPS."
    plain ""
    plain "Recommended: run CrowdSec on BOTH the VPS and here."
    plain "  VPS CrowdSec handles HTTP-layer banning for Pangolin traffic."
    plain "  LXC CrowdSec handles SSH and the community blocklist locally."
}

# ── Action: Log acquisition ───────────────────────────────────────────────────

action_acquisition() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi

    section "Log Acquisition Sources"
    printf '\n'
    info "Current acquisition configs:"
    local acq_dir="/etc/crowdsec/acquis.d"
    if [[ -d "$acq_dir" ]] && ls "${acq_dir}"/*.yaml &>/dev/null 2>&1; then
        for f in "${acq_dir}"/*.yaml; do
            printf "  ${CYAN}%s${NC}\n" "$(basename "$f")"
            grep -E "(filename|filenames|docker_host|labels):" "$f" 2>/dev/null \
                | head -5 | sed 's/^/    /'
        done
    else
        info "No acquisition configs found in ${acq_dir}."
    fi

    printf '\n'
    info "Add a new acquisition source:"
    plain "  1) Caddy log file"
    plain "  2) Nginx / NginxPM log file"
    plain "  3) Docker socket (all containers)"
    plain "  4) Custom file path"
    plain "  5) Cancel"
    printf '\n'

    local choice
    while true; do
        choice=$(ask_val "Option (1-5)" "5")
        case "$choice" in
            1) _add_acquis "caddy"  "/var/log/caddy/access.log" "caddy";  break ;;
            2) _add_acquis "nginx"  "/var/log/nginx/access.log" "nginx";  break ;;
            3) _add_acquis_docker;                                          break ;;
            4) _add_acquis_custom;                                          break ;;
            5) info "Cancelled."; return 0 ;;
            *) warn "Enter 1-5." ;;
        esac
    done
}

_add_acquis() {
    local name="$1" default_path="$2" log_type="$3"
    local acq_dir="/etc/crowdsec/acquis.d"
    local acq_file="${acq_dir}/${name}.yaml"

    [[ -f "$acq_file" ]] && { ok "${acq_file} already exists."; return 0; }

    local log_path
    log_path=$(ask_val "Log file path" "$default_path")
    [[ -z "$log_path" ]] && { info "Cancelled."; return 0; }

    run mkdir -p "$acq_dir"

    if [[ "$DRY_RUN" != "true" ]]; then
        cat > "$acq_file" << YAML
# CrowdSec acquisition — ${name} — managed by manage-crowdsec.sh
filenames:
  - ${log_path}
labels:
  type: ${log_type}
YAML
        ok "Acquisition config written to ${acq_file}"
    else
        printf "    ${DIM}[dry-run]${NC} %s\n" "write ${acq_file} (${log_path} → ${log_type})"
    fi

    run systemctl restart crowdsec
}

_add_acquis_docker() {
    local acq_file="/etc/crowdsec/acquis.d/docker.yaml"
    [[ -f "$acq_file" ]] && { ok "${acq_file} already exists."; return 0; }

    run mkdir -p "$(dirname "$acq_file")"

    if [[ "$DRY_RUN" != "true" ]]; then
        cat > "$acq_file" << 'YAML'
# CrowdSec Docker acquisition — managed by manage-crowdsec.sh
# Reads logs from all running containers via the Docker socket.
# Tag individual containers in docker-compose.yml:
#   labels:
#     crowdsec.enable: "true"
#     crowdsec.log_type: "caddy"   # nginx, apache2, syslog, etc.
source: docker
docker_host: unix:///var/run/docker.sock
labels:
  type: syslog
YAML
        ok "Docker acquisition config written to ${acq_file}"
    else
        printf "    ${DIM}[dry-run]${NC} %s\n" "write ${acq_file} (Docker socket)"
    fi

    run systemctl restart crowdsec
}

_add_acquis_custom() {
    local log_path
    log_path=$(ask_val "Log file path (Enter to cancel)")
    [[ -z "$log_path" ]] && { info "Cancelled."; return 0; }

    local log_type
    log_type=$(ask_val "Log type (caddy/nginx/syslog/apache2)" "syslog")

    local name
    name=$(ask_val "Config file name (no extension)" "custom")
    name="${name//[^a-zA-Z0-9_-]/}"
    name="${name:-custom}"

    _add_acquis "$name" "$log_path" "$log_type"
}

# ── Action: Console enrollment ────────────────────────────────────────────────

action_console_enroll() {
    if ! is_crowdsec_installed; then
        warn "CrowdSec is not installed."
        return 0
    fi

    section "CrowdSec Console Enrollment"
    printf '\n'

    if is_console_enrolled; then
        ok "This agent appears to be enrolled in the CrowdSec console."
        if ask "Re-enroll with a new key?" "n"; then
            : # fall through
        else
            return 0
        fi
    fi

    info "The CrowdSec console (app.crowdsec.net) is an optional web dashboard."
    plain "It lets you view decisions, alerts, and metrics across your agents."
    plain "It is separate from CAPI — you can have one without the other."
    plain ""
    info "To get your enrollment key:"
    plain "  1. Sign up / log in at https://app.crowdsec.net"
    plain "  2. Go to Security Engines → Add a security engine"
    plain "  3. Copy the enrollment key shown"
    printf '\n'

    local key
    key=$(ask_val "Enrollment key (Enter to cancel)")
    [[ -z "$key" ]] && { info "Cancelled."; return 0; }

    run cscli console enroll "$key"
    run systemctl restart crowdsec
    ok "Enrollment command sent. Check app.crowdsec.net to confirm."
}

# ── Action: Toggle service ────────────────────────────────────────────────────

action_toggle_service() {
    section "Toggle CrowdSec On/Off"
    printf '\n'

    local cs_active; cs_active=$(systemctl is-active crowdsec 2>/dev/null || printf 'inactive')
    local bouncer_active; bouncer_active=$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null || printf 'inactive')

    if [[ "$cs_active" == "active" ]]; then
        info "CrowdSec is currently ACTIVE."
        plain ""
        plain "Stopping CrowdSec will:"
        plain "  • Remove all nftables ban rules immediately"
        plain "  • Allow all currently-banned IPs to connect"
        plain "  • Stop monitoring logs for new attacks"
        plain ""
        plain "Use this to debug 'why can't X connect?' before resorting to a full flush."
        warn "All active blocks will be removed until you restart CrowdSec."

        if ask "Stop CrowdSec (agent + bouncer)?" "n"; then
            run systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
            run systemctl stop crowdsec
            ok "CrowdSec stopped. All nftables rules removed."
            info "To restart: run this option again, or: systemctl start crowdsec crowdsec-firewall-bouncer"
        else
            info "Cancelled — CrowdSec remains active."
        fi
    else
        info "CrowdSec is currently STOPPED."
        plain ""
        plain "Starting CrowdSec will:"
        plain "  • Re-read decisions from the local database"
        plain "  • Re-apply nftables ban rules"
        plain "  • Resume log monitoring"

        if ask "Start CrowdSec (agent + bouncer)?" "y"; then
            run systemctl start crowdsec
            run systemctl start crowdsec-firewall-bouncer 2>/dev/null || true
            ok "CrowdSec started. Ban rules are now active."
        else
            info "Cancelled."
        fi
    fi
}

# ── Action: Remove CrowdSec ───────────────────────────────────────────────────

action_remove_crowdsec() {
    section "Remove CrowdSec Entirely"
    printf '\n'
    warn "This is a destructive, largely irreversible action."
    plain ""
    plain "What will be removed:"
    plain "  • crowdsec package"
    plain "  • crowdsec-firewall-bouncer-nftables"
    plain "  • All nftables ban rules"
    plain "  • Local decisions database"
    plain "  • Acquisition configs in /etc/crowdsec/acquis.d/"
    plain ""
    plain "What will NOT be removed:"
    plain "  • Custom whitelist files in /etc/crowdsec/parsers/"
    plain "  • Your console enrollment (deregister manually at app.crowdsec.net)"
    plain ""
    warn "All currently-banned IPs will be able to connect immediately."

    ask "Remove CrowdSec? (default No)" "n" \
        || { info "Cancelled."; return 0; }

    warn "Type 'remove' to confirm, or Enter to cancel:"
    local confirm; confirm=$(ask_val "Confirm")
    if [[ "$confirm" != "remove" ]]; then
        info "Cancelled — confirmation did not match."
        return 0
    fi

    run systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl stop crowdsec 2>/dev/null || true
    run systemctl disable crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl disable crowdsec 2>/dev/null || true
    run apt-get purge -y crowdsec crowdsec-firewall-bouncer-nftables \
        crowdsec-firewall-bouncer-iptables 2>/dev/null || true
    run apt-get autoremove -y

    ok "CrowdSec removed. All ban rules cleared."
    info "Run manage-crowdsec.sh or harden-crowdsec.sh at any time to reinstall."
}

# ── Menu ──────────────────────────────────────────────────────────────────────

_show_menu() {
    local cs_installed=false
    is_crowdsec_installed && cs_installed=true

    printf "\n  ${BOLD}Actions${NC}\n"
    local div; printf -v div '%*s' 44 ''; div="${div// /─}"
    printf "  %s\n" "$div"

    local n=1

    if [[ "$cs_installed" == "false" ]]; then
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Install CrowdSec"; (( n++ ))
    fi

    if [[ "$cs_installed" == "true" ]]; then
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "View active decisions"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Unban an IP"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Flush all decisions  ${YELLOW}[debug]${NC}"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Whitelist an IP or CIDR"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Manage collections"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Reverse proxy integration wizard"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Log acquisition sources"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Console enrollment (app.crowdsec.net)"; (( n++ ))
        printf "  ${CYAN}%2d)${NC}  %s\n" $n "Toggle CrowdSec on/off"; (( n++ ))
        printf "  ${RED}%2d)${NC}  %s\n" $n "Remove CrowdSec entirely  ${RED}[destructive]${NC}"; (( n++ ))
    fi

    printf "  ${CYAN}%2d)${NC}  %s\n" $n "Exit"
    _MENU_MAX=$(( n ))

    printf "\n  ${DIM}Type h for overview, h<N> for help on an option (e.g. h3)${NC}\n"
}

_menu_default() {
    if ! is_crowdsec_installed; then
        printf '1'; return
    fi
    is_capi_registered || { printf '8'; return; }
    cf_ips_whitelisted || {
        # Only nudge toward proxy wizard if cloudflared is present
        command -v cloudflared &>/dev/null && { printf '6'; return; }
    }
    printf ''
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    preflight_checks

    # ── Banner ───────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              manage-crowdsec.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:    ${BOLD}%s${NC}\n"           "$(hostname)"
    printf "  OS:      ${BOLD}%s %s (%s)${NC}\n"  "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run: ${BOLD}%s${NC}\n\n"        "$DRY_RUN"

    show_state

    # ── Menu loop ────────────────────────────────────────────────────────────
    local cs_installed=false

    while true; do
        is_crowdsec_installed && cs_installed=true || cs_installed=false
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

        # Help commands: h, h1, h2, ...
        if [[ "$choice" == "h" ]]; then
            show_help_general
            printf '\n'
            show_state
            continue
        fi
        if [[ "$choice" =~ ^h([0-9]+)$ ]]; then
            show_help_for "${BASH_REMATCH[1]}"
            printf '\n'
            show_state
            continue
        fi

        if [[ "$cs_installed" == "false" ]]; then
            # Minimal menu: install + exit
            case "$choice" in
                1) action_install ;;
                2) info "Exiting."; break ;;
                *) warn "Please enter 1-${_MENU_MAX}." ; continue ;;
            esac
        else
            case "$choice" in
                1)  action_view_decisions ;;
                2)  action_unban_ip ;;
                3)  action_flush_decisions ;;
                4)  action_whitelist ;;
                5)  action_manage_collections ;;
                6)  action_proxy_wizard ;;
                7)  action_acquisition ;;
                8)  action_console_enroll ;;
                9)  action_toggle_service ;;
                10) action_remove_crowdsec ;;
                11) info "Exiting."; break ;;
                *)  warn "Please enter 1-${_MENU_MAX}." ; continue ;;
            esac
        fi

        printf '\n'
        show_state
    done
}

main "$@"