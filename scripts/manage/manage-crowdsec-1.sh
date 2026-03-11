#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# manage-crowdsec.sh — CrowdSec full lifecycle management
# ==============================================================================
# Interactive management for CrowdSec: install, configure for your topology
# (Cloudflare Tunnel, Caddy, NginxProxyManager, Nginx, Pangolin/VPS), manage
# collections, whitelists, log acquisition, bans, bouncers, and service state.
#
# Usage:
#   sudo ./manage-crowdsec.sh [--dry-run]
#
# Options:
#   --dry-run   Print what would be changed; make no changes. No root needed.
#   --help/-h   Show this help.
#
# Environment variables:
#   DRY_RUN=true    Same as --dry-run.
#
# ── Architecture quick reference ─────────────────────────────────────────────
# CrowdSec has two runtime components:
#   Agent   (crowdsec)                    Parses logs → makes ban decisions
#   Bouncer (crowdsec-firewall-bouncer)   Enforces decisions in nftables
#
# ── WHERE to install CrowdSec ─────────────────────────────────────────────────
# Install on the host that receives public traffic. CrowdSec reads log files
# directly — it cannot monitor logs on a remote machine.
#
#   Direct / LAN-only:         install here.
#   Cloudflare Tunnel:         install on the reverse proxy LXC (Caddy / NginxPM).
#   Caddy in THIS LXC:         install here. Run setup wizard → Caddy.
#   Caddy in ANOTHER LXC:      install in that LXC too. Run this script there.
#   NginxPM (Docker, this LXC):install here. Run setup wizard → NginxPM.
#   NginxPM in another LXC:    install there. Run this script there.
#   Pangolin/Traefik on VPS:   run this script ON the VPS (Oracle, etc.) for
#                              Traefik-specific guidance. Also run here for
#                              SSH / system-level protection on the homelab side.
#
# ── Cloudflare Tunnel critical note ──────────────────────────────────────────
# All tunnel traffic arrives from Cloudflare IP ranges. Without whitelisting CF
# IPs, a single false positive can trigger an nftables ban on a CF range and
# instantly kill ALL tunnel traffic. The setup wizard handles this automatically.
# ==============================================================================

DRY_RUN="${DRY_RUN:-false}"

for _arg in "$@"; do
    case "$_arg" in
        --dry-run) DRY_RUN=true ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ====/p' "$0" | sed 's/^# \{0,3\}//'
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

# ── OS globals ────────────────────────────────────────────────────────────────
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0

# ── Menu globals ──────────────────────────────────────────────────────────────
_MENU_ACTIONS=()
_MENU_MAX=0
MENU_DEFAULT=''

# ── Result globals ────────────────────────────────────────────────────────────
_PICK_RESULT=''

# ── Cloudflare IP ranges (refresh from https://www.cloudflare.com/ips/) ──────
CF_IPS_V4=(
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
    "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
    "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15"  "104.16.0.0/13"
    "104.24.0.0/14"   "172.64.0.0/13"   "131.0.72.0/22"
)
CF_IPS_V6=(
    "2400:cb00::/32" "2606:4700::/32" "2803:f800::/32" "2405:b500::/32"
    "2405:8100::/32" "2a06:98c0::/29" "2c0f:f248::/32"
)

# ── Pre-flight ────────────────────────────────────────────────────────────────
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

# ── State query helpers (read-only, never wrapped in run()) ───────────────────
is_pkg_installed()  { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
is_svc_active()     { systemctl is-active "$1" &>/dev/null; }
is_svc_enabled()    { systemctl is-enabled "$1" &>/dev/null; }

is_cs_installed()   { command -v cscli &>/dev/null; }
is_cs_running()     { is_svc_active crowdsec; }
is_bouncer_running(){ is_svc_active crowdsec-firewall-bouncer; }
is_bouncer_installed() { is_pkg_installed crowdsec-firewall-bouncer-nftables; }

is_cf_active() {
    is_svc_active cloudflared 2>/dev/null \
    || pgrep -x cloudflared &>/dev/null \
    || { command -v cloudflared &>/dev/null; }
}

is_cf_whitelisted() {
    grep -rq "173.245.48.0\|104.16.0.0\|162.158.0.0" \
        /etc/crowdsec/parsers/s02-enrich/ 2>/dev/null
}

is_capi_ok() {
    cscli capi status 2>/dev/null | grep -qi "connected\|registered"
}

_detect_proxy() {
    if command -v docker &>/dev/null && docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "nginx-proxy-manager\|jc21"; then
        printf 'npm'; return
    fi
    is_svc_active caddy 2>/dev/null && printf 'caddy' && return
    { is_svc_active nginx 2>/dev/null || is_pkg_installed nginx; } && printf 'nginx' && return
    printf 'none'
}

# ── State display ─────────────────────────────────────────────────────────────
_show_state() {
    local w=58 div; printf -v div '%*s' "$w" ''; div="${div// /─}"

    section "Current State"
    printf "\n  ${BOLD}%-26s  %-28s${NC}\n" "Component" "Status"
    printf "  %s\n" "$div"

    # Agent
    if is_cs_installed; then
        local ver; ver=$(cscli version 2>/dev/null | grep -i "version:" | awk '{print $2}' || printf "?")
        if is_cs_running; then
            printf "  %-26s  ${GREEN}● running${NC} ${DIM}%s${NC}\n" "Agent (crowdsec)" "$ver"
        elif is_svc_enabled crowdsec 2>/dev/null; then
            printf "  %-26s  ${RED}● stopped${NC} ${DIM}(enabled)${NC}\n" "Agent (crowdsec)"
        else
            printf "  %-26s  ${RED}● disabled${NC}\n" "Agent (crowdsec)"
        fi
    else
        printf "  %-26s  ${RED}not installed${NC}\n" "Agent (crowdsec)"
    fi

    # Bouncer
    if is_bouncer_installed; then
        if is_bouncer_running; then
            printf "  %-26s  ${GREEN}● running${NC}\n" "Bouncer (nftables)"
        else
            printf "  %-26s  ${YELLOW}● stopped${NC}\n" "Bouncer (nftables)"
        fi
    else
        printf "  %-26s  ${RED}not installed${NC}\n" "Bouncer (nftables)"
    fi

    # CAPI + Console (only if installed)
    if is_cs_installed; then
        if is_capi_ok; then
            printf "  %-26s  ${GREEN}connected${NC}\n" "CAPI (community list)"
        else
            printf "  %-26s  ${YELLOW}not registered${NC}\n" "CAPI (community list)"
        fi

        # Collections count
        local col_count; col_count=$(cscli collections list 2>/dev/null | grep -c "✔\|enabled" || printf "0")
        printf "  %-26s  ${DIM}%s installed${NC}\n" "Collections" "$col_count"

        # Active decisions
        local ban_count; ban_count=$(cscli decisions list 2>/dev/null | grep -c "ban" || printf "0")
        if (( ban_count > 0 )); then
            printf "  %-26s  ${YELLOW}%s active bans${NC}\n" "Decisions" "$ban_count"
        else
            printf "  %-26s  ${DIM}none${NC}\n" "Decisions"
        fi

        # Whitelist
        if [[ -f /etc/crowdsec/parsers/s02-enrich/99-whitelists.yaml ]]; then
            local cidr_count; cidr_count=$(grep -c "^\s*- " /etc/crowdsec/parsers/s02-enrich/99-whitelists.yaml 2>/dev/null || printf "?")
            printf "  %-26s  ${GREEN}present${NC} ${DIM}(%s CIDRs)${NC}\n" "Whitelist" "$cidr_count"
        else
            printf "  %-26s  ${DIM}none${NC}\n" "Whitelist"
        fi

        # Acquis sources
        local acquis_count=0
        [[ -d /etc/crowdsec/acquis.d ]] && \
            acquis_count=$(find /etc/crowdsec/acquis.d -name "*.yaml" -size +0 2>/dev/null | wc -l)
        printf "  %-26s  ${DIM}%s custom file(s)${NC}\n" "Log sources" "$acquis_count"
    fi

    # Cloudflare tunnel
    if is_cf_active; then
        if is_cf_whitelisted; then
            printf "  %-26s  ${GREEN}● active — IPs whitelisted${NC}\n" "Cloudflare Tunnel"
        else
            printf "  %-26s  ${RED}● active — IPs NOT whitelisted${NC}\n" "Cloudflare Tunnel"
        fi
    fi

    # Reverse proxy
    local proxy; proxy=$(_detect_proxy)
    [[ "$proxy" != "none" ]] && \
        printf "  %-26s  ${DIM}%s${NC}\n" "Reverse proxy" "$proxy"

    printf "  %s\n\n" "$div"
}

# ── Menu ──────────────────────────────────────────────────────────────────────
_show_menu() {
    _MENU_ACTIONS=()
    local n=0

    section "Actions"
    printf '\n'

    if ! is_cs_installed; then
        (( n++ )); printf "  %2d)  Install CrowdSec\n" "$n";           _MENU_ACTIONS+=("install")
    else
        if ! is_cs_running; then
            (( n++ ))
            printf "  %2d)  ${GREEN}Enable / start CrowdSec${NC}\n" "$n"
            _MENU_ACTIONS+=("enable")
        fi

        (( n++ )); printf "  %2d)  Setup wizard  (configure for my topology)\n" "$n"
        _MENU_ACTIONS+=("wizard")

        (( n++ )); printf "  %2d)  Manage collections\n" "$n"
        _MENU_ACTIONS+=("collections")

        (( n++ )); printf "  %2d)  Manage whitelists\n" "$n"
        _MENU_ACTIONS+=("whitelists")

        (( n++ )); printf "  %2d)  Manage log acquisition\n" "$n"
        _MENU_ACTIONS+=("log_sources")

        (( n++ )); printf "  %2d)  View and manage bans\n" "$n"
        _MENU_ACTIONS+=("decisions")

        (( n++ )); printf "  %2d)  Manage bouncers\n" "$n"
        _MENU_ACTIONS+=("bouncers")

        (( n++ )); printf "  %2d)  CAPI and Console enrollment\n" "$n"
        _MENU_ACTIONS+=("enrollment")

        if is_cs_running; then
            (( n++ ))
            printf "  %2d)  ${YELLOW}Disable CrowdSec${NC}  (stop all protection, keep installed)\n" "$n"
            _MENU_ACTIONS+=("disable")
        fi

        (( n++ ))
        printf "  %2d)  ${YELLOW}Debug: flush ALL active bans${NC}  (emergency access restore)\n" "$n"
        _MENU_ACTIONS+=("flush")

        (( n++ ))
        printf "  %2d)  ${RED}Uninstall CrowdSec${NC}\n" "$n"
        _MENU_ACTIONS+=("uninstall")
    fi

    printf "   h)  Help: architecture and best practices\n"
    printf "   0)  Exit\n"

    _MENU_MAX=$n
}

_menu_default() {
    ! is_cs_installed         && printf '1' && return
    ! is_cs_running           && printf '1' && return
    ! is_cf_whitelisted 2>/dev/null && is_cf_active && printf '' && return
    printf ''
}

# ==============================================================================
# ── Action functions ──────────────────────────────────────────────────────────
# ==============================================================================

action_install() {
    section "Install CrowdSec"
    printf '\n'
    info "CrowdSec will be installed with:"
    plain "  • crowdsec           — the detection agent"
    plain "  • crowdsec-firewall-bouncer-nftables — enforces bans in nftables"
    plain "  • crowdsecurity/linux + crowdsecurity/sshd — base collections"
    printf '\n'
    info "After install, use the Setup Wizard to configure for your topology."
    printf '\n'
    warn "Best-practice reminder: run CrowdSec on the SAME LXC as your reverse"
    plain "proxy. If Caddy or NginxPM is in another LXC, run this script there too."

    ask "Proceed with installation?" "y" || { info "Cancelled."; return 0; }

    info "Adding CrowdSec repository..."
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash\n"
    else
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    fi
    run apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables
    run cscli collections install crowdsecurity/linux crowdsecurity/sshd
    run systemctl enable --now crowdsec
    run systemctl enable --now crowdsec-firewall-bouncer
    ok "CrowdSec installed and running."
    info "Next: run the Setup Wizard (option 1 on the next menu) to configure"
    info "for your specific topology."
}

action_enable() {
    section "Enable CrowdSec"
    printf '\n'
    info "This will start and enable the crowdsec agent and nftables bouncer."
    info "CrowdSec will immediately begin enforcing any existing ban decisions."

    ask "Enable and start CrowdSec now?" "y" || { info "Cancelled."; return 0; }
    run systemctl enable --now crowdsec
    is_bouncer_installed && run systemctl enable --now crowdsec-firewall-bouncer
    ok "CrowdSec enabled and running."
}

action_wizard() {
    section "Setup Wizard"
    printf '\n'
    info "This wizard configures CrowdSec for your specific network topology."
    info "It will add collections, whitelists, and log acquisition sources."
    printf '\n'

    # ── Step 1: exposure method ───────────────────────────────────────────────
    info "Step 1: How are your services exposed to the internet?"
    plain "  1) Cloudflare Tunnel      (cloudflared, services behind CF)"
    plain "  2) Direct / public IP     (port-forwarded or public server)"
    plain "  3) LAN-only               (no public exposure)"
    plain "  4) VPN-only               (Tailscale, WireGuard, etc.)"
    plain "  5) Pangolin / self-hosted tunnel  (Traefik on Oracle/VPS)"
    plain "  6) Mixed                  (some services public, some behind CF)"

    local exp; exp=$(ask_val "Exposure method (1-6)" "1")
    local exposure
    case "$exp" in
        1) exposure="cloudflare" ;;
        2) exposure="direct"     ;;
        3) exposure="lan"        ;;
        4) exposure="vpn"        ;;
        5) exposure="pangolin"   ;;
        *) exposure="mixed"      ;;
    esac

    # ── Step 2: reverse proxy ─────────────────────────────────────────────────
    local proxy="none"
    if [[ "$exposure" != "lan" && "$exposure" != "vpn" ]]; then
        printf '\n'
        info "Step 2: What reverse proxy are you using on THIS host?"
        plain "  1) Caddy                   (native systemd service)"
        plain "  2) NginxProxyManager       (Docker container)"
        plain "  3) Nginx                   (native, not NPM)"
        plain "  4) None / other"

        local rp; rp=$(ask_val "Reverse proxy (1-4)" "4")
        case "$rp" in
            1) proxy="caddy" ;;
            2) proxy="npm"   ;;
            3) proxy="nginx" ;;
            *) proxy="none"  ;;
        esac

        if [[ "$proxy" != "none" ]]; then
            printf '\n'
            if ! ask "Is the reverse proxy running IN THIS LXC?" "y"; then
                printf '\n'
                warn "Cross-LXC configuration: CrowdSec cannot read another LXC's logs."
                plain ""
                plain "CrowdSec reads log files directly from the filesystem. It cannot"
                plain "inspect logs that live in a different LXC without either:"
                plain ""
                plain "  Option A (recommended): Install CrowdSec in the reverse proxy LXC."
                plain "    Run manage-crowdsec.sh from that LXC for full configuration."
                plain "    CrowdSec here on this LXC still protects SSH and system logs."
                plain ""
                plain "  Option B (advanced): CrowdSec LAPI federation — run CrowdSec as"
                plain "    an agent in the proxy LXC, reporting to this host as the LAPI"
                plain "    server. This requires manual configuration beyond this script."
                plain "    See: https://docs.crowdsec.net/docs/concepts"
                printf '\n'
                info "Configuring this host for SSH and system-level protection only."
                proxy="none"
            fi
        fi
    fi

    # ── Step 3: apply configuration ───────────────────────────────────────────
    printf '\n'
    info "Step 3: Applying configuration..."

    # Collections
    local cols=("crowdsecurity/linux" "crowdsecurity/sshd")
    case "$proxy" in
        caddy) cols+=("crowdsecurity/caddy" "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios") ;;
        npm|nginx) cols+=("crowdsecurity/nginx" "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios") ;;
    esac

    info "Installing collections: ${cols[*]}"
    run cscli collections install "${cols[@]}"

    # Cloudflare whitelist
    if [[ "$exposure" == "cloudflare" || "$exposure" == "mixed" ]]; then
        printf '\n'
        if is_cf_whitelisted; then
            ok "Cloudflare IP whitelist already present."
        else
            info "Writing Cloudflare IP whitelist..."
            warn "IMPORTANT: all tunnel traffic arrives from CF IPs. Without this"
            plain "whitelist, a false positive will ban a CF range and kill ALL traffic."
            _write_cf_whitelist_action
        fi
    fi

    # Log acquisition
    if [[ "$proxy" != "none" ]]; then
        printf '\n'
        info "Configuring log acquisition for ${proxy}..."
        _add_log_source_for_proxy "$proxy"
    fi

    # Pangolin / VPS guidance
    if [[ "$exposure" == "pangolin" ]]; then
        printf '\n'
        warn "Pangolin (self-hosted tunnel) setup requires action on your VPS:"
        plain ""
        plain "  Pangolin uses Traefik as its reverse proxy on the VPS side."
        plain "  CrowdSec should run on the VPS alongside Pangolin/Traefik."
        plain ""
        plain "  On the VPS (run manage-crowdsec.sh there):"
        plain "    1. Install CrowdSec (option: Install CrowdSec)"
        plain "    2. Install Traefik collections:"
        plain "         cscli collections install crowdsecurity/traefik"
        plain "         cscli collections install crowdsecurity/http-cve"
        plain "    3. Add Traefik middleware bouncer:"
        plain "         https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
        plain "         (add as a Traefik plugin in your docker-compose.yml)"
        plain ""
        plain "  On this homelab LXC (here):"
        plain "    CrowdSec will protect SSH and system-level access."
        plain "    Pangolin tunnel traffic is protected on the VPS side."
    fi

    # CAPI registration
    printf '\n'
    if is_capi_ok; then
        ok "CAPI already registered — community blocklist active."
    else
        info "Registering with CrowdSec Central API (community blocklist)..."
        run cscli capi register
    fi

    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
    ok "Setup wizard complete."

    # Summary advice for CF tunnel + HTTP layer
    if [[ "$exposure" == "cloudflare" ]] && [[ "$proxy" != "none" ]]; then
        printf '\n'
        warn "Next step for full HTTP-layer protection behind Cloudflare Tunnel:"
        plain "  The nftables bouncer can only block by network IP. Since all CF"
        plain "  tunnel traffic arrives from CF IPs (which are whitelisted), HTTP"
        plain "  attackers cannot be blocked at the network layer."
        plain ""
        case "$proxy" in
            caddy)
                plain "  Add the Caddy CrowdSec middleware (reads CF-Connecting-IP header):"
                plain "    https://github.com/hslatman/caddy-crowdsec-bouncer"
                plain "  This requires a custom Caddy build or the official CS+Caddy image."
                ;;
            npm|nginx)
                plain "  Add the NginxPM/Nginx CrowdSec bouncer:"
                plain "    apt-get install crowdsec-nginx-bouncer"
                plain "  Configure nginx to trust CF real-IP headers:"
                plain "    real_ip_header CF-Connecting-IP;"
                plain "    set_real_ip_from 173.245.48.0/20; (and other CF ranges)"
                ;;
        esac
    fi
}

_add_log_source_for_proxy() {
    # $1 = proxy type: caddy | npm | nginx
    local proxy="$1"
    local acquis_dir="/etc/crowdsec/acquis.d"
    run mkdir -p "$acquis_dir"

    case "$proxy" in
        caddy)
            local log_path="/var/log/caddy"
            if [[ "$DRY_RUN" == "false" ]] && [[ ! -d "$log_path" ]]; then
                warn "Caddy log directory ${log_path} not found."
                log_path=$(ask_val "Caddy log directory" "/var/log/caddy")
            fi
            if [[ "$DRY_RUN" == "true" ]]; then
                printf "    ${DIM}[dry-run]${NC} Would write %s/caddy.yaml\n" "$acquis_dir"
            else
                cat > "${acquis_dir}/caddy.yaml" << YAML
# CrowdSec log acquisition — Caddy — written by manage-crowdsec.sh
source: file
filenames:
  - ${log_path}/*.log
  - ${log_path}/*.json
labels:
  type: caddy
YAML
                ok "Caddy log acquisition written to ${acquis_dir}/caddy.yaml"
            fi
            ;;
        npm)
            warn "NginxProxyManager runs in Docker. CrowdSec will use the Docker socket."
            plain "All NPM container logs will be read via Docker's log API."
            if [[ "$DRY_RUN" == "true" ]]; then
                printf "    ${DIM}[dry-run]${NC} Would write %s/docker-npm.yaml\n" "$acquis_dir"
            else
                cat > "${acquis_dir}/docker-npm.yaml" << YAML
# CrowdSec log acquisition — NginxProxyManager (Docker) — written by manage-crowdsec.sh
source: docker
docker_host: unix:///var/run/docker.sock
labels:
  type: nginx
# To restrict to NPM containers only, uncomment and set container name:
# container_name:
#   - "nginx-proxy-manager"
YAML
                ok "Docker log acquisition written to ${acquis_dir}/docker-npm.yaml"
            fi
            ;;
        nginx)
            if [[ "$DRY_RUN" == "true" ]]; then
                printf "    ${DIM}[dry-run]${NC} Would write %s/nginx.yaml\n" "$acquis_dir"
            else
                cat > "${acquis_dir}/nginx.yaml" << YAML
# CrowdSec log acquisition — Nginx — written by manage-crowdsec.sh
source: file
filenames:
  - /var/log/nginx/*.log
labels:
  type: nginx
YAML
                ok "Nginx log acquisition written to ${acquis_dir}/nginx.yaml"
            fi
            ;;
    esac
}

_write_cf_whitelist_action() {
    local wl_dir="/etc/crowdsec/parsers/s02-enrich"
    local wl_file="${wl_dir}/99-whitelists.yaml"
    run mkdir -p "$wl_dir"
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} Would write CF whitelist to %s\n" "$wl_file"
        return
    fi
    {
        printf 'name: local/whitelists\n'
        printf 'description: "CF Tunnel IPs — written by manage-crowdsec.sh on %s"\n' "$(date +%Y-%m-%d)"
        printf 'whitelist:\n'
        printf '  reason: "Cloudflare Tunnel egress IPs — never block CF infrastructure"\n'
        printf '  cidr:\n'
        printf '    - "127.0.0.0/8"\n'
        printf '    - "::1/128"\n'
        for cidr in "${CF_IPS_V4[@]}"; do printf '    - "%s"\n' "$cidr"; done
        for cidr in "${CF_IPS_V6[@]}"; do printf '    - "%s"\n' "$cidr"; done
        printf '# Refresh IP list from: https://www.cloudflare.com/ips/\n'
    } > "$wl_file"
    ok "Cloudflare whitelist written to ${wl_file}"
}

action_collections() {
    while true; do
        section "Manage Collections"
        printf '\n'
        info "Installed collections:"
        cscli collections list 2>/dev/null || warn "Could not list collections."
        printf '\n'
        plain "  1) Install a collection by name"
        plain "  2) Remove a collection by name"
        plain "  3) Update all collections (hub upgrade)"
        plain "  4) List available collections (from hub)"
        plain "  0) Back"
        printf '\n'
        local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-4]: " choice || true
        case "${choice:-0}" in
            0) break ;;
            1)
                local name; name=$(ask_val "Collection name (e.g. crowdsecurity/nginx)")
                [[ -z "$name" ]] && { info "Cancelled."; continue; }
                run cscli collections install "$name"
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "Collection ${name} installed."
                ;;
            2)
                local name; name=$(ask_val "Collection name to remove")
                [[ -z "$name" ]] && { info "Cancelled."; continue; }
                warn "Removing '${name}' means attacks targeted by that collection will no longer be detected."
                ask "Remove ${name}?" "n" || { info "Cancelled."; continue; }
                run cscli collections remove "$name"
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "Collection ${name} removed."
                ;;
            3)
                info "Updating hub and upgrading all collections..."
                run cscli hub update
                run cscli hub upgrade
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "Collections updated."
                ;;
            4)
                cscli collections list -a 2>/dev/null | head -60 || warn "Could not list hub."
                plain "(showing first 60 lines — use 'cscli collections list -a' for full list)"
                ;;
            *) warn "Please enter 0–4." ;;
        esac
    done
}

action_whitelists() {
    while true; do
        section "Manage Whitelists"
        local wl_file="/etc/crowdsec/parsers/s02-enrich/99-whitelists.yaml"
        printf '\n'

        if [[ -f "$wl_file" ]]; then
            info "Current whitelist (${wl_file}):"
            cat "$wl_file"
        else
            warn "No whitelist file found at ${wl_file}"
            plain "A whitelist prevents CrowdSec from ever banning trusted IPs."
        fi

        printf '\n'
        plain "  1) Write Cloudflare Tunnel IP whitelist  (recommended if using CF)"
        plain "  2) Add a custom CIDR to whitelist"
        plain "  3) View / edit whitelist file manually"
        plain "  4) Remove whitelist file entirely"
        printf '\n'
        warn "Note: removing the whitelist when using Cloudflare Tunnel can cause"
        plain "  CrowdSec to ban CF IP ranges, killing all tunnel traffic."
        printf '\n'
        plain "  0) Back"
        printf '\n'
        local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-4]: " choice || true
        case "${choice:-0}" in
            0) break ;;
            1)
                if is_cf_whitelisted; then
                    warn "Cloudflare IPs already appear to be whitelisted."
                    ask "Overwrite with fresh CF IP list?" "n" || { info "Cancelled."; continue; }
                fi
                _write_cf_whitelist_action
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ;;
            2)
                local cidr; cidr=$(ask_val "CIDR to add (e.g. 192.168.1.0/24)")
                [[ -z "$cidr" ]] && { info "Cancelled."; continue; }
                if [[ "$DRY_RUN" == "true" ]]; then
                    printf "    ${DIM}[dry-run]${NC} Would add %s to whitelist\n" "$cidr"
                else
                    if [[ ! -f "$wl_file" ]]; then
                        run mkdir -p "$(dirname "$wl_file")"
                        {
                            printf 'name: local/whitelists\n'
                            printf 'description: "Custom whitelists — manage-crowdsec.sh"\n'
                            printf 'whitelist:\n'
                            printf '  reason: "Trusted local CIDRs"\n'
                            printf '  cidr:\n'
                            printf '    - "127.0.0.0/8"\n'
                        } > "$wl_file"
                    fi
                    printf '    - "%s"\n' "$cidr" >> "$wl_file"
                    ok "Added ${cidr} to whitelist."
                    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                fi
                ;;
            3)
                if [[ -z "${EDITOR:-}" ]]; then EDITOR="nano"; fi
                info "Opening ${wl_file} in ${EDITOR}..."
                if [[ "$DRY_RUN" == "true" ]]; then
                    printf "    ${DIM}[dry-run]${NC} Would open %s in %s\n" "$wl_file" "$EDITOR"
                else
                    "${EDITOR}" "$wl_file"
                    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                fi
                ;;
            4)
                warn "Removing the whitelist means CrowdSec may ban ANY IP, including"
                plain "your own LAN, Cloudflare infrastructure, or trusted services."
                if is_cf_active; then
                    warn "DANGER: Cloudflare Tunnel is active. Removing the CF whitelist"
                    plain "will allow CrowdSec to ban Cloudflare IP ranges, taking down"
                    plain "ALL tunnel traffic. Only do this for debugging; re-add immediately."
                fi
                ask "Remove whitelist file? (not recommended)" "n" || { info "Cancelled."; continue; }
                local confirm; confirm=$(ask_val "Type 'remove' to confirm")
                [[ "$confirm" == "remove" ]] || { info "Cancelled."; continue; }
                run rm -f "$wl_file"
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "Whitelist removed."
                ;;
            *) warn "Please enter 0–4." ;;
        esac
    done
}

action_log_sources() {
    while true; do
        section "Manage Log Acquisition"
        local acquis_dir="/etc/crowdsec/acquis.d"
        printf '\n'
        info "CrowdSec can only detect attacks in log files it is watching."
        plain "System defaults (auth.log, syslog) are always active."
        plain "Add sources here for reverse proxy and container logs."
        printf '\n'

        if [[ -d "$acquis_dir" ]]; then
            local files; files=$(find "$acquis_dir" -name "*.yaml" 2>/dev/null)
            if [[ -n "$files" ]]; then
                info "Custom acquisition files:"
                while IFS= read -r f; do
                    printf "    ${DIM}%s${NC}\n" "$(basename "$f")"
                done <<< "$files"
            else
                info "No custom acquisition files configured."
            fi
        fi

        printf '\n'
        plain "  1) Add Caddy log source          (local native Caddy service)"
        plain "  2) Add NginxPM log source        (Docker container via socket)"
        plain "  3) Add Nginx log source          (native nginx service)"
        plain "  4) Add custom file source        (specify path manually)"
        plain "  5) Add Docker socket source      (all containers — generic)"
        plain "  6) Remove an acquisition file"
        plain "  7) View a file"
        plain "  0) Back"
        printf '\n'
        warn "If your proxy is in a different LXC, you cannot read its logs from here."
        plain "  Install and run manage-crowdsec.sh in the proxy LXC instead."
        printf '\n'
        local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-7]: " choice || true
        case "${choice:-0}" in
            0) break ;;
            1) _add_log_source_for_proxy caddy
               run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec ;;
            2) _add_log_source_for_proxy npm
               run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec ;;
            3) _add_log_source_for_proxy nginx
               run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec ;;
            4)
                local path; path=$(ask_val "Log file path or glob (e.g. /var/log/myapp/*.log)")
                [[ -z "$path" ]] && { info "Cancelled."; continue; }
                local ltype; ltype=$(ask_val "Log type label (e.g. nginx, caddy, syslog)" "syslog")
                local fname; fname=$(ask_val "Acquisition file name (no .yaml)" "custom")
                if [[ "$DRY_RUN" == "true" ]]; then
                    printf "    ${DIM}[dry-run]${NC} Would write %s/%s.yaml\n" "$acquis_dir" "$fname"
                else
                    run mkdir -p "$acquis_dir"
                    cat > "${acquis_dir}/${fname}.yaml" << YAML
# CrowdSec log acquisition — written by manage-crowdsec.sh
source: file
filenames:
  - ${path}
labels:
  type: ${ltype}
YAML
                    ok "Acquisition file written: ${acquis_dir}/${fname}.yaml"
                    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                fi
                ;;
            5)
                if [[ "$DRY_RUN" == "true" ]]; then
                    printf "    ${DIM}[dry-run]${NC} Would write %s/docker-all.yaml\n" "$acquis_dir"
                else
                    run mkdir -p "$acquis_dir"
                    cat > "${acquis_dir}/docker-all.yaml" << YAML
# CrowdSec log acquisition — all Docker containers — written by manage-crowdsec.sh
source: docker
docker_host: unix:///var/run/docker.sock
labels:
  type: syslog
YAML
                    ok "Docker acquisition written to ${acquis_dir}/docker-all.yaml"
                    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                fi
                ;;
            6)
                if [[ ! -d "$acquis_dir" ]]; then warn "No acquis.d directory."; continue; fi
                local files_list=()
                while IFS= read -r f; do files_list+=("$(basename "$f")"); done \
                    < <(find "$acquis_dir" -name "*.yaml" 2>/dev/null)
                if [[ ${#files_list[@]} -eq 0 ]]; then warn "No files to remove."; continue; fi
                printf '\n'
                local i=1
                for f in "${files_list[@]}"; do printf "    %d) %s\n" "$i" "$f"; (( i++ )); done
                local sel; sel=$(ask_val "File number to remove (Enter to cancel)")
                [[ -z "$sel" || ! "$sel" =~ ^[0-9]+$ ]] && { info "Cancelled."; continue; }
                (( sel >= 1 && sel <= ${#files_list[@]} )) || { warn "Invalid selection."; continue; }
                local target="${acquis_dir}/${files_list[$(( sel - 1 ))]}"
                ask "Remove ${target}?" "n" || { info "Cancelled."; continue; }
                run rm -f "$target"
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "Removed ${target}."
                ;;
            7)
                if [[ ! -d "$acquis_dir" ]]; then warn "No acquis.d directory."; continue; fi
                local files_list=()
                while IFS= read -r f; do files_list+=("$f"); done \
                    < <(find "$acquis_dir" -name "*.yaml" 2>/dev/null)
                if [[ ${#files_list[@]} -eq 0 ]]; then warn "No files to view."; continue; fi
                local i=1
                for f in "${files_list[@]}"; do printf "    %d) %s\n" "$i" "$(basename "$f")"; (( i++ )); done
                local sel; sel=$(ask_val "File number to view")
                [[ -z "$sel" || ! "$sel" =~ ^[0-9]+$ ]] && { info "Cancelled."; continue; }
                (( sel >= 1 && sel <= ${#files_list[@]} )) || { warn "Invalid selection."; continue; }
                printf '\n'; cat "${files_list[$(( sel - 1 ))]}"; printf '\n'
                ;;
            *) warn "Please enter 0–7." ;;
        esac
    done
}

action_decisions() {
    while true; do
        section "Active Bans and Decisions"
        printf '\n'
        info "Active decisions:"
        cscli decisions list 2>/dev/null || warn "Could not list decisions."
        printf '\n'
        plain "  1) Add a manual ban (IP or CIDR)"
        plain "  2) Remove a ban by IP"
        plain "  3) Remove a ban by decision ID"
        plain "  4) View recent alerts (what triggered bans)"
        plain "  0) Back"
        printf '\n'
        local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-4]: " choice || true
        case "${choice:-0}" in
            0) break ;;
            1)
                local ip; ip=$(ask_val "IP or CIDR to ban (e.g. 1.2.3.4 or 10.0.0.0/8)")
                [[ -z "$ip" ]] && { info "Cancelled."; continue; }
                local dur; dur=$(ask_val "Duration (e.g. 4h, 24h, 7d)" "24h")
                local reason; reason=$(ask_val "Reason / label" "manual-ban")
                warn "Adding manual ban for ${ip} (${dur})."
                plain "This will block all connections from that IP/range via nftables."
                ask "Confirm ban?" "n" || { info "Cancelled."; continue; }
                run cscli decisions add --ip "$ip" --duration "$dur" --reason "$reason" --type ban
                ok "Ban added for ${ip}."
                ;;
            2)
                local ip; ip=$(ask_val "IP to remove ban for")
                [[ -z "$ip" ]] && { info "Cancelled."; continue; }
                run cscli decisions delete --ip "$ip"
                ok "Ban removed for ${ip}."
                ;;
            3)
                local did; did=$(ask_val "Decision ID to remove")
                [[ -z "$did" ]] && { info "Cancelled."; continue; }
                run cscli decisions delete --id "$did"
                ok "Decision ${did} removed."
                ;;
            4)
                info "Recent alerts:"
                cscli alerts list 2>/dev/null || warn "Could not list alerts."
                ;;
            *) warn "Please enter 0–4." ;;
        esac
    done
}

action_bouncers() {
    section "Manage Bouncers"
    printf '\n'
    info "Registered bouncers:"
    cscli bouncers list 2>/dev/null || warn "Could not list bouncers."
    printf '\n'
    info "A bouncer enforces CrowdSec's ban decisions. Without one, bans are"
    plain "issued by the agent but never actually applied."
    printf '\n'

    local proxy; proxy=$(_detect_proxy)

    printf "  Available bouncers:\n\n"
    printf "  ${BOLD}nftables bouncer${NC} (installed: "
    is_bouncer_installed \
        && printf "${GREEN}yes${NC})\n" \
        || printf "${RED}no${NC})\n"
    plain "    Blocks at network layer. Works for SSH, all services."
    plain "    Limitation with Cloudflare Tunnel: cannot block real HTTP attackers"
    plain "    (all traffic arrives from CF IPs, which must be whitelisted)."

    if [[ "$proxy" == "caddy" ]]; then
        printf '\n'
        printf "  ${BOLD}Caddy CrowdSec middleware${NC}\n"
        plain "    Blocks at HTTP layer. Reads CF-Connecting-IP for real attacker IP."
        plain "    Requires a custom Caddy build — not installable via apt."
        plain "    See: https://github.com/hslatman/caddy-crowdsec-bouncer"
    fi

    if [[ "$proxy" == "npm" || "$proxy" == "nginx" ]]; then
        printf '\n'
        printf "  ${BOLD}crowdsec-nginx-bouncer${NC} (installed: "
        is_pkg_installed crowdsec-nginx-bouncer \
            && printf "${GREEN}yes${NC})\n" \
            || printf "${RED}no${NC})\n"
        plain "    Blocks at HTTP layer inside Nginx. Works with real-IP header from CF."
        plain "    Install: apt-get install crowdsec-nginx-bouncer"
    fi

    printf '\n'
    plain "  1) Install nftables bouncer"
    plain "  2) Restart nftables bouncer"
    if [[ "$proxy" == "npm" || "$proxy" == "nginx" ]]; then
        plain "  3) Install nginx bouncer"
    fi
    plain "  4) Remove a registered bouncer (by name)"
    plain "  0) Back"
    printf '\n'
    local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-4]: " choice || true
    case "${choice:-0}" in
        0) return ;;
        1)
            is_bouncer_installed && { ok "nftables bouncer already installed."; return; }
            run apt-get install -y crowdsec-firewall-bouncer-nftables
            run systemctl enable --now crowdsec-firewall-bouncer
            ok "nftables bouncer installed and running."
            ;;
        2)
            run systemctl restart crowdsec-firewall-bouncer
            ok "Bouncer restarted."
            ;;
        3)
            if [[ "$proxy" == "npm" || "$proxy" == "nginx" ]]; then
                warn "The nginx bouncer is installed as a system service."
                plain "For NginxPM (Docker), the bouncer must run INSIDE the NPM container"
                plain "or as a sidecar — not as a host service. This is advanced; see:"
                plain "  https://docs.crowdsec.net/docs/bouncers/nginx"
                ask "Install crowdsec-nginx-bouncer?" "n" || return
                run apt-get install -y crowdsec-nginx-bouncer
                ok "nginx bouncer installed."
            fi
            ;;
        4)
            local name; name=$(ask_val "Bouncer name to remove")
            [[ -z "$name" ]] && { info "Cancelled."; return; }
            ask "Remove bouncer '${name}'?" "n" || { info "Cancelled."; return; }
            run cscli bouncers delete "$name"
            ok "Bouncer ${name} removed."
            ;;
        *) warn "Invalid choice." ;;
    esac
}

action_enrollment() {
    section "CAPI and Console Enrollment"
    printf '\n'
    info "CrowdSec has two separate cloud integrations:"
    plain ""
    plain "  ${BOLD}Central API (CAPI)${NC}"
    plain "    Downloads the global community blocklist (~500k known-bad IPs)."
    plain "    Also shares anonymised attack data back to the community."
    plain "    Free and anonymous. Strongly recommended."
    if is_capi_ok; then
        plain "    Status: ${GREEN}connected${NC}"
    else
        plain "    Status: ${YELLOW}not registered${NC}"
    fi
    plain ""
    plain "  ${BOLD}CrowdSec Console${NC}  (app.crowdsec.net)"
    plain "    Dashboard to view decisions, alerts, and metrics visually."
    plain "    Free tier available. Optional but useful for monitoring."
    printf '\n'
    plain "  1) Register with CAPI"
    plain "  2) Enroll in CrowdSec Console"
    plain "  0) Back"
    printf '\n'
    local choice; read -rp "    ${YELLOW}>  ${NC}Choice [0-2]: " choice || true
    case "${choice:-0}" in
        0) return ;;
        1)
            if is_capi_ok; then
                ok "Already registered with CAPI."
            else
                run cscli capi register
                run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
                ok "CAPI registration complete. Blocklist will sync within minutes."
            fi
            ;;
        2)
            info "To get your enrollment key:"
            plain "  1. Sign up / log in at https://app.crowdsec.net"
            plain "  2. Go to Security Engines → Add a security engine"
            plain "  3. Copy the enrollment key"
            printf '\n'
            local key; key=$(ask_val "Enrollment key (Enter to cancel)")
            [[ -z "$key" ]] && { info "Cancelled."; return; }
            run cscli console enroll "$key"
            ok "Agent enrolled in CrowdSec Console."
            ;;
        *) warn "Invalid choice." ;;
    esac
}

action_disable() {
    section "Disable CrowdSec"
    printf '\n'
    warn "Disabling CrowdSec will:"
    plain "  • Stop the crowdsec agent — no more log parsing or ban decisions"
    plain "  • Stop the nftables bouncer — all active bans are immediately lifted"
    plain "  • All services become accessible to previously-banned IPs"
    plain ""
    plain "CrowdSec remains installed. Re-enable at any time from this menu."
    plain "This is useful for debugging or when CrowdSec is suspected of blocking"
    plain "legitimate traffic."

    if is_cf_active; then
        printf '\n'
        warn "Cloudflare Tunnel is active. Disabling CrowdSec removes the only"
        plain "network-layer protection against attacks coming through the tunnel."
    fi

    printf '\n'
    ask "Disable CrowdSec and lift all active bans?" "n" || { info "Cancelled."; return 0; }
    local confirm; confirm=$(ask_val "Type 'disable' to confirm")
    [[ "$confirm" == "disable" ]] || { info "Cancelled."; return 0; }

    run systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl disable crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl stop crowdsec
    run systemctl disable crowdsec
    ok "CrowdSec disabled. All bans lifted."
    plain "To re-enable: select 'Enable CrowdSec' from the menu."
}

action_flush() {
    section "Debug: Flush All Active Bans"
    printf '\n'
    warn "This is an emergency / debug operation."
    plain ""
    plain "Flushing all bans will:"
    plain "  • Immediately unblock ALL currently-banned IPs"
    plain "  • Allow previously-blocked attackers to reconnect"
    plain "  • Leave CrowdSec running — new attacks will be re-detected and re-banned"
    plain ""
    plain "Use this when:"
    plain "  • You have been accidentally locked out (your IP was mistakenly banned)"
    plain "  • A legitimate service was blocked (e.g. a monitoring agent's IP)"
    plain "  • You want a clean slate to verify CrowdSec is working correctly"
    plain ""
    plain "Do NOT leave this state for long on a directly-exposed server."

    ask "Flush all active bans now?" "n" || { info "Cancelled."; return 0; }

    local count; count=$(cscli decisions list 2>/dev/null | grep -c "ban" || printf "0")
    info "Removing ${count} active ban(s)..."
    run cscli decisions delete --all
    ok "All bans flushed. CrowdSec is still running and will re-detect attacks."
    plain "To re-add the community blocklist: systemctl reload crowdsec"
    plain "(CAPI-sourced bans will resync automatically within a few minutes)"
}

action_uninstall() {
    section "Uninstall CrowdSec"
    printf '\n'
    warn "Uninstalling CrowdSec will:"
    plain "  • Remove crowdsec, cscli, and all bouncers"
    plain "  • Lift all active bans immediately"
    plain "  • Remove all collections, decisions, and enrollment state"
    plain "  • Your whitelist and acquis.d configs are preserved under /etc/crowdsec"
    plain "    (config directory remains; remove manually if desired)"
    plain ""
    plain "After uninstall, no IP-based threat detection or blocking will be active."

    ask "Uninstall CrowdSec?" "n" || { info "Cancelled."; return 0; }
    local confirm; confirm=$(ask_val "Type 'uninstall' to confirm")
    [[ "$confirm" == "uninstall" ]] || { info "Cancelled."; return 0; }

    run systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl disable crowdsec-firewall-bouncer 2>/dev/null || true
    run systemctl stop crowdsec 2>/dev/null || true
    run apt-get remove -y crowdsec crowdsec-firewall-bouncer-nftables crowdsec-nginx-bouncer 2>/dev/null || true
    ok "CrowdSec uninstalled."
    plain "Config files remain in /etc/crowdsec — remove with: rm -rf /etc/crowdsec"
}

action_help() {
    header "CrowdSec Architecture and Best Practices"
    printf '\n'
    printf "${BOLD}  What is CrowdSec?${NC}\n\n"
    plain "CrowdSec is a collaborative intrusion prevention system (IPS). It has"
    plain "two components that work together:"
    plain ""
    plain "  ${BOLD}Agent (crowdsec)${NC}"
    plain "    Reads your log files, matches patterns against installed 'collections',"
    plain "    and creates ban decisions when attacks are detected. Also downloads a"
    plain "    global community blocklist of ~500k known-bad IPs contributed by"
    plain "    millions of CrowdSec nodes worldwide."
    plain ""
    plain "  ${BOLD}Bouncer (crowdsec-firewall-bouncer)${NC}"
    plain "    Reads the agent's decisions and enforces them — blocking IPs in"
    plain "    nftables before any traffic reaches your services."
    printf '\n'
    printf "${BOLD}  WHERE should CrowdSec run?${NC}\n\n"
    plain "Run CrowdSec on the host that handles public traffic. It reads log"
    plain "files directly — it cannot see logs on a different machine."
    plain ""
    plain "  ${BOLD}Homelab LXC (standard):${NC}"
    plain "    If Caddy or NginxPM runs here → install and run here."
    plain "    CrowdSec watches reverse proxy logs + SSH logs on this LXC."
    plain ""
    plain "  ${BOLD}Caddy or NginxPM in another LXC:${NC}"
    plain "    Install CrowdSec in THAT LXC too. Run this script there."
    plain "    CrowdSec here still protects SSH and system access."
    plain ""
    plain "  ${BOLD}Cloudflare Tunnel:${NC}"
    plain "    Install on the reverse proxy LXC. Whitelist CF IPs (wizard does this)."
    plain "    The nftables bouncer protects SSH and blocks at the network level."
    plain "    For HTTP-layer blocking (real attacker IP), add a middleware bouncer"
    plain "    in Caddy or NginxPM — the nftables bouncer cannot see behind CF."
    plain ""
    plain "  ${BOLD}Pangolin / self-hosted VPS tunnel:${NC}"
    plain "    Pangolin uses Traefik on the VPS side. Run CrowdSec ON the VPS."
    plain "    Use this script on the VPS for Traefik guidance."
    plain "    Traefik plugin: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
    plain "    CrowdSec here (homelab) protects SSH."
    printf '\n'
    printf "${BOLD}  Cloudflare Tunnel — critical warning${NC}\n\n"
    plain "All CF Tunnel traffic arrives from Cloudflare IP ranges. Without"
    plain "whitelisting those ranges, a false positive CAN and WILL ban a CF IP"
    plain "block and instantly kill ALL your tunnel services. Always whitelist"
    plain "CF IPs when using a tunnel. The setup wizard does this automatically."
    plain ""
    plain "The nftables bouncer cannot block real HTTP attackers behind CF Tunnel"
    plain "because all HTTP arrives from CF IPs (whitelisted). To block by real IP:"
    plain "  Caddy:  https://github.com/hslatman/caddy-crowdsec-bouncer"
    plain "  Nginx:  crowdsec-nginx-bouncer + real_ip_header CF-Connecting-IP"
    printf '\n'
    printf "${BOLD}  CrowdSec vs fail2ban${NC}\n\n"
    plain "Both can watch SSH logs and ban IPs. Running both on SSH is redundant."
    plain "CrowdSec is preferred: it has the community blocklist and cross-service"
    plain "detection that fail2ban lacks. Disable fail2ban's sshd jail if both run."
    printf '\n'
    printf "${BOLD}  Useful commands${NC}\n\n"
    plain "  cscli decisions list              Active bans"
    plain "  cscli alerts list                 What triggered bans"
    plain "  cscli metrics                     Detection stats"
    plain "  cscli collections list            Installed rule sets"
    plain "  cscli hub update && hub upgrade   Update all collections"
    plain "  cscli capi status                 Community blocklist connection"
    plain "  journalctl -u crowdsec -f         Live agent log"
    printf '\n'
    read -rp "    Press Enter to return to menu..." _ || true
}

# ==============================================================================
# ── main ──────────────────────────────────────────────────────────────────────
# ==============================================================================
main() {
    preflight_checks

    # ── Banner ────────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              manage-crowdsec.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    if ! is_cs_installed; then
        warn "CrowdSec is not installed on this host."
        plain "Use option 1 to install, or type 'h' for architecture guidance."
        plain "See the header of this script for WHERE to install CrowdSec."
    fi

    # ── Menu loop ─────────────────────────────────────────────────────────────
    while true; do
        _show_state
        _show_menu

        MENU_DEFAULT=$(_menu_default)
        local choice
        if [[ -n "$MENU_DEFAULT" ]]; then
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [0-${_MENU_MAX}, h for help, default ${MENU_DEFAULT}]: " \
                choice || true
            choice="${choice:-$MENU_DEFAULT}"
        else
            read -rp $'\n'"    ${YELLOW}>  ${NC}Choice [0-${_MENU_MAX}, h for help]: " choice || true
            choice="${choice:-0}"
        fi

        case "$choice" in
            0) info "Exiting."; break ;;
            h|H|'?') action_help ;;
            [1-9]|[1-9][0-9])
                if (( choice >= 1 && choice <= _MENU_MAX )) 2>/dev/null; then
                    local action="${_MENU_ACTIONS[$(( choice - 1 ))]}"
                    "action_${action}"
                else
                    warn "Please enter 0–${_MENU_MAX} or h."
                fi
                ;;
            *) warn "Please enter 0–${_MENU_MAX} or h." ;;
        esac
        printf '\n'
    done
}

main "$@"