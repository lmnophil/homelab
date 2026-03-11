#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# harden-crowdsec.sh — Audit and harden CrowdSec IPS configuration
# ==============================================================================
# Checks CrowdSec installation, service health, bouncer, CAPI registration,
# collections, Cloudflare Tunnel whitelist, HTTP proxy collections, log
# acquisition, and fail2ban overlap. Detects Cloudflare Tunnel, Caddy,
# NginxProxyManager, and Nginx automatically.
#
# Usage:
#   sudo ./harden-crowdsec.sh [--dry-run] [--status]
#
# Options:
#   --dry-run    Print what would be changed; make no changes. No root needed.
#   --status     Machine-readable PASS/FAIL. No prompts. Exit 1 if any FAIL.
#   --help/-h    Show this help.
#
# Environment variables:
#   DRY_RUN=true     Same as --dry-run.
#   STATUS_MODE=true Same as --status.
#
# ── Architecture overview ─────────────────────────────────────────────────────
# CrowdSec has two layers:
#   • Agent (crowdsec)         Parses logs, detects attacks, makes ban decisions
#   • Bouncer (nftables/etc.)  Enforces those decisions (blocks IPs in firewall)
#
# ── WHERE to run CrowdSec ─────────────────────────────────────────────────────
# Run CrowdSec on the same LXC as your reverse proxy. CrowdSec reads log files
# directly — remote log collection is fragile and not officially supported.
#
#   Caddy or NginxPM in this LXC:  install and run here.
#   Caddy or NginxPM in another LXC: run THIS script in that LXC too. CrowdSec
#     on THIS LXC still protects SSH and system-level access.
#
# ── Cloudflare Tunnel ─────────────────────────────────────────────────────────
# All tunnel traffic arrives from Cloudflare IPs. The nftables bouncer blocks
# by network IP, so if CrowdSec triggers on HTTP traffic without CF IPs
# whitelisted, it bans a Cloudflare range and takes down ALL tunnel services.
# Whitelist CF IPs first. For real HTTP-layer blocking (real attacker IP):
#   • Caddy: use https://github.com/hslatman/caddy-crowdsec-bouncer
#   • NginxPM / Nginx: use crowdsec-nginx-bouncer
#
# ── Pangolin (self-hosted tunnel, e.g. Oracle VPS) ────────────────────────────
# Run CrowdSec on the VPS alongside Traefik/Pangolin. Use manage-crowdsec.sh
# there for Traefik-specific setup guidance.
#
# ── For full lifecycle management (enable/disable, flush bans, wizard) ─────────
#   use manage-crowdsec.sh
# ==============================================================================

DRY_RUN="${DRY_RUN:-false}"
STATUS_MODE="${STATUS_MODE:-false}"

for _arg in "$@"; do
    case "$_arg" in
        --dry-run) DRY_RUN=true ;;
        --status)  STATUS_MODE=true ;;
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

# ── run() — dry-run wrapper ───────────────────────────────────────────────────
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

# ── Status helpers (--status mode) ────────────────────────────────────────────
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

# ── OS globals (required by set -u) ───────────────────────────────────────────
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0

# ── State globals ─────────────────────────────────────────────────────────────
CS_INSTALLED=false
CS_VERSION=''
CS_RUNNING=false
CS_BOUNCER_INSTALLED=false
CS_BOUNCER_RUNNING=false
CS_CAPI_OK=false
CS_HAS_LINUX=false
CS_HAS_SSHD=false
CF_ACTIVE=false
CF_WHITELISTED=false
PROXY_TYPE=''          # caddy | nginx | npm | none
CS_HAS_HTTP_COLS=false
DOCKER_PRESENT=false
CS_HAS_ACQUIS=false
F2B_SSHD_ACTIVE=false

# ── Cloudflare IP ranges (as of 2025; refresh from https://www.cloudflare.com/ips/) ──
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

# ── Detection helpers (read-only) ─────────────────────────────────────────────
is_pkg_installed()    { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
is_svc_active()       { systemctl is-active "$1" &>/dev/null; }

_detect_cloudflared() {
    is_svc_active cloudflared 2>/dev/null \
    || pgrep -x cloudflared &>/dev/null \
    || { command -v cloudflared &>/dev/null && true; }
}

_detect_proxy() {
    # Returns the most specific proxy type detected on this host.
    command -v docker &>/dev/null && DOCKER_PRESENT=true
    if $DOCKER_PRESENT && docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "nginx-proxy-manager\|jc21/nginx"; then
        printf 'npm'; return
    fi
    if is_svc_active caddy 2>/dev/null || command -v caddy &>/dev/null; then
        printf 'caddy'; return
    fi
    if is_svc_active nginx 2>/dev/null || is_pkg_installed nginx; then
        printf 'nginx'; return
    fi
    printf 'none'
}

_cf_ips_whitelisted() {
    # True if at least one known CF range appears in any crowdsec whitelist file
    grep -rq "173.245.48.0\|104.16.0.0\|162.158.0.0" \
        /etc/crowdsec/parsers/s02-enrich/ 2>/dev/null
}

_collection_installed() {
    # $1 = collection name e.g. "crowdsecurity/sshd"
    cscli collections list 2>/dev/null | grep -q "$1"
}

_capi_ok() {
    cscli capi status 2>/dev/null | grep -qi "connected\|registered"
}

_has_http_collections() {
    cscli collections list 2>/dev/null | grep -qE "crowdsecurity/(caddy|nginx|http-cve|base-http)"
}

_has_acquis_sources() {
    # True if any non-default acquisition file exists, or acquis.yaml has entries
    [[ -d /etc/crowdsec/acquis.d ]] && \
        find /etc/crowdsec/acquis.d -name "*.yaml" -size +0 2>/dev/null | grep -q . && return 0
    # Also check the main acquis.yaml beyond defaults
    grep -q "^filenames\|^source:" /etc/crowdsec/acquis.yaml 2>/dev/null
}

# ── State computation ─────────────────────────────────────────────────────────
_compute_state() {
    command -v cscli &>/dev/null && CS_INSTALLED=true || CS_INSTALLED=false
    if $CS_INSTALLED; then
        CS_VERSION=$(cscli version 2>/dev/null | grep -i "version:" | awk '{print $2}' || echo "unknown")
        is_svc_active crowdsec && CS_RUNNING=true || CS_RUNNING=false
        is_pkg_installed crowdsec-firewall-bouncer-nftables && CS_BOUNCER_INSTALLED=true || CS_BOUNCER_INSTALLED=false
        is_svc_active crowdsec-firewall-bouncer && CS_BOUNCER_RUNNING=true || CS_BOUNCER_RUNNING=false
        _capi_ok && CS_CAPI_OK=true || CS_CAPI_OK=false
        _collection_installed "crowdsecurity/linux" && CS_HAS_LINUX=true || CS_HAS_LINUX=false
        _collection_installed "crowdsecurity/sshd"  && CS_HAS_SSHD=true  || CS_HAS_SSHD=false
        _has_http_collections && CS_HAS_HTTP_COLS=true || CS_HAS_HTTP_COLS=false
        _has_acquis_sources   && CS_HAS_ACQUIS=true    || CS_HAS_ACQUIS=false
    fi
    _detect_cloudflared && CF_ACTIVE=true || CF_ACTIVE=false
    $CF_ACTIVE && { _cf_ips_whitelisted && CF_WHITELISTED=true || CF_WHITELISTED=false; }
    PROXY_TYPE=$(_detect_proxy)
    command -v docker &>/dev/null && DOCKER_PRESENT=true || true
    if command -v fail2ban-client &>/dev/null && is_svc_active fail2ban 2>/dev/null; then
        fail2ban-client status sshd 2>/dev/null | grep -q "Status for" && F2B_SSHD_ACTIVE=true || true
    fi
}

# ── State display ─────────────────────────────────────────────────────────────
_show_state() {
    local w=56 div; printf -v div '%*s' "$w" ''; div="${div// /─}"
    printf "\n${BOLD}  %-24s  %-28s${NC}\n" "Component" "Status"
    printf "  %s\n" "$div"

    local cs_status cf_status bouncer_status
    if $CS_INSTALLED; then
        cs_status="${GREEN}installed${NC} ${DIM}(${CS_VERSION})${NC}"
    else
        cs_status="${RED}not installed${NC}"
    fi

    if $CS_RUNNING;          then local ag="${GREEN}● running${NC}"
    elif $CS_INSTALLED;      then local ag="${RED}● stopped${NC}"
    else                          local ag="${DIM}n/a${NC}"; fi

    if $CS_BOUNCER_INSTALLED && $CS_BOUNCER_RUNNING; then
        bouncer_status="${GREEN}● running${NC}"
    elif $CS_BOUNCER_INSTALLED; then
        bouncer_status="${YELLOW}● stopped${NC}"
    else
        bouncer_status="${RED}not installed${NC}"
    fi

    printf "  ${BOLD}%-24s${NC}  " "Agent (crowdsec)"
    printf "${cs_status}\n"
    printf "  ${BOLD}%-24s${NC}  ${ag}\n" ""
    printf "  ${BOLD}%-24s${NC}  ${bouncer_status}\n" "Bouncer (nftables)"
    $CS_INSTALLED && {
        local capi_s; $CS_CAPI_OK && capi_s="${GREEN}connected${NC}" || capi_s="${YELLOW}not registered${NC}"
        printf "  ${BOLD}%-24s${NC}  ${capi_s}\n" "CAPI (community list)"
        local col_s; ( $CS_HAS_LINUX && $CS_HAS_SSHD ) \
            && col_s="${GREEN}base collections OK${NC}" \
            || col_s="${YELLOW}missing base collections${NC}"
        $CS_HAS_HTTP_COLS && col_s="${col_s} ${DIM}+http${NC}"
        printf "  ${BOLD}%-24s${NC}  ${col_s}\n" "Collections"
    }
    if $CF_ACTIVE; then
        local cf_s; $CF_WHITELISTED \
            && cf_s="${GREEN}CF IPs whitelisted${NC}" \
            || cf_s="${RED}CF IPs NOT whitelisted${NC}"
        printf "  ${BOLD}%-24s${NC}  ${cf_s}\n" "Cloudflare Tunnel"
    fi
    [[ "$PROXY_TYPE" != "none" ]] && \
        printf "  ${BOLD}%-24s${NC}  ${DIM}%s${NC} detected\n" "Reverse proxy" "$PROXY_TYPE"
    printf "  %s\n" "$div"
}

# ── Quick all-pass check ──────────────────────────────────────────────────────
_quick_pass() {
    $CS_INSTALLED         || return 1
    $CS_RUNNING           || return 1
    $CS_BOUNCER_INSTALLED || return 1
    $CS_BOUNCER_RUNNING   || return 1
    $CS_CAPI_OK           || return 1
    $CS_HAS_LINUX         || return 1
    $CS_HAS_SSHD          || return 1
    $CF_ACTIVE && ! $CF_WHITELISTED && return 1
    $F2B_SSHD_ACTIVE && $CS_HAS_SSHD && return 1
    return 0
}

# ── Install helper (used by check_crowdsec_installed) ─────────────────────────
_install_crowdsec() {
    info "Adding CrowdSec package repository..."
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
        printf "    ${DIM}[dry-run]${NC} %s\n" "apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables"
        printf "    ${DIM}[dry-run]${NC} %s\n" "cscli collections install crowdsecurity/linux crowdsecurity/sshd"
        return
    fi
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    run apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables
    run cscli collections install crowdsecurity/linux crowdsecurity/sshd
    run systemctl enable --now crowdsec
    run systemctl enable --now crowdsec-firewall-bouncer
    ok "CrowdSec installed with nftables bouncer and base collections."
    info "Run manage-crowdsec.sh to configure for your reverse proxy / tunnel topology."
    CS_INSTALLED=true
    CS_VERSION=$(cscli version 2>/dev/null | grep -i "version:" | awk '{print $2}' || echo "unknown")
}

# ── Write CF whitelist helper ─────────────────────────────────────────────────
_write_cf_whitelist() {
    local wl_dir="/etc/crowdsec/parsers/s02-enrich"
    local wl_file="${wl_dir}/99-whitelists.yaml"
    run mkdir -p "$wl_dir"
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} Would write %s with %d CF CIDR entries\n" \
            "$wl_file" "$(( ${#CF_IPS_V4[@]} + ${#CF_IPS_V6[@]} ))"
        return
    fi
    {
        printf 'name: local/whitelists\n'
        printf 'description: "Trusted IPs — written by harden-crowdsec.sh on %s"\n' "$(date +%Y-%m-%d)"
        printf 'whitelist:\n'
        printf '  reason: "Cloudflare Tunnel egress IPs and loopback — never block infrastructure"\n'
        printf '  cidr:\n'
        printf '    - "127.0.0.0/8"\n'
        printf '    - "::1/128"\n'
        for cidr in "${CF_IPS_V4[@]}"; do printf '    - "%s"\n' "$cidr"; done
        for cidr in "${CF_IPS_V6[@]}"; do printf '    - "%s"\n' "$cidr"; done
        printf '# Refresh IPs from: https://www.cloudflare.com/ips/\n'
    } > "$wl_file"
    ok "Whitelist written to ${wl_file}"
    run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
    CF_WHITELISTED=true
}

# ==============================================================================
# ── Check functions ────────────────────────────────────────────────────────────
# ==============================================================================

check_crowdsec_installed() {
    # ── STATUS mode ───────────────────────────────────────────────────────────
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_INSTALLED \
            && status_pass "crowdsec_installed" "${CS_VERSION}" \
            || status_fail "crowdsec_installed" "CrowdSec is not installed"
        return 0
    fi

    if $CS_INSTALLED; then
        ok "CrowdSec is installed (${CS_VERSION})."
        CHECKS_PASSED+=("CrowdSec installed")
        return 0
    fi

    printf '\n'
    warn "CrowdSec is not installed."
    plain "CrowdSec provides two layers of protection:"
    plain "  1. Community blocklist (~500k known-bad IPs blocked on arrival)"
    plain "  2. Log-based detection — bans IPs that attack your services in real time"
    plain ""
    plain "Without CrowdSec, you have no automated IP threat detection or blocking."
    printf '\n'
    warn "Best-practice placement: run CrowdSec on the same LXC as your reverse"
    plain "proxy (Caddy / NginxPM). It reads log files directly — it cannot inspect"
    plain "logs on a different host without a complex forwarding setup."
    plain ""
    plain "If your reverse proxy is in another LXC, install CrowdSec THERE too."
    plain "Running it here still protects SSH and system-level access on this host."

    if ask "Install CrowdSec + nftables bouncer + base collections now?" "y"; then
        _install_crowdsec
        CHECKS_FIXED+=("CrowdSec installed")
    else
        warn "CrowdSec not installed. All remaining checks will be skipped."
        CHECKS_DECLINED+=("CrowdSec not installed (skipped)")
    fi
}

check_agent_running() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_RUNNING \
            && status_pass "agent_running" "crowdsec.service active" \
            || status_fail "agent_running" "crowdsec.service is not running"
        return 0
    fi

    if $CS_RUNNING; then
        ok "CrowdSec agent is running."
        CHECKS_PASSED+=("CrowdSec agent running")
        return 0
    fi

    printf '\n'
    warn "CrowdSec agent (crowdsec.service) is not running."
    plain "Without the agent, no logs are parsed, no bans are issued, and the"
    plain "community blocklist is not fetched. Protection is completely inactive."

    if ask "Start and enable crowdsec.service now?" "y"; then
        run systemctl enable --now crowdsec
        ok "crowdsec.service started and enabled."
        CS_RUNNING=true
        CHECKS_FIXED+=("CrowdSec agent started")
    else
        warn "Agent left stopped. CrowdSec is inactive."
        CHECKS_DECLINED+=("CrowdSec agent not started (risk accepted)")
    fi
}

check_bouncer_installed() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_BOUNCER_INSTALLED \
            && status_pass "bouncer_installed" "crowdsec-firewall-bouncer-nftables" \
            || status_fail "bouncer_installed" "No nftables bouncer installed — decisions are not enforced"
        return 0
    fi

    if $CS_BOUNCER_INSTALLED; then
        ok "nftables bouncer (crowdsec-firewall-bouncer-nftables) is installed."
        CHECKS_PASSED+=("nftables bouncer installed")
        return 0
    fi

    printf '\n'
    warn "No nftables bouncer is installed."
    plain "The CrowdSec agent detects attacks and makes ban decisions, but those"
    plain "decisions are never enforced without a bouncer. Attackers are not blocked."
    plain "The nftables bouncer blocks IPs at the network layer before they can"
    plain "reach any service on this host."
    plain ""
    plain "Note: if using Cloudflare Tunnel, the nftables bouncer works for SSH and"
    plain "system traffic, but cannot block HTTP attackers by their real IP (all"
    plain "HTTP traffic arrives from Cloudflare IPs). For HTTP-layer blocking behind"
    plain "CF Tunnel, add a middleware bouncer in Caddy or NginxPM instead."

    if ask "Install crowdsec-firewall-bouncer-nftables now?" "y"; then
        run apt-get install -y crowdsec-firewall-bouncer-nftables
        ok "nftables bouncer installed."
        CS_BOUNCER_INSTALLED=true
        CHECKS_FIXED+=("nftables bouncer installed")
    else
        warn "Bouncer not installed. Ban decisions will not be enforced."
        CHECKS_DECLINED+=("nftables bouncer not installed (risk accepted)")
    fi
}

check_bouncer_running() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_BOUNCER_RUNNING \
            && status_pass "bouncer_running" "crowdsec-firewall-bouncer active" \
            || status_fail "bouncer_running" "crowdsec-firewall-bouncer is not running"
        return 0
    fi

    if $CS_BOUNCER_RUNNING; then
        ok "nftables bouncer is running."
        CHECKS_PASSED+=("nftables bouncer running")
        return 0
    fi

    if ! $CS_BOUNCER_INSTALLED; then
        return 0  # install check already handled/declined this
    fi

    printf '\n'
    warn "nftables bouncer (crowdsec-firewall-bouncer) is installed but not running."
    plain "Bans are being issued by the agent but are not being applied to the firewall."

    if ask "Start and enable crowdsec-firewall-bouncer now?" "y"; then
        run systemctl enable --now crowdsec-firewall-bouncer
        ok "Bouncer started and enabled."
        CS_BOUNCER_RUNNING=true
        CHECKS_FIXED+=("nftables bouncer started")
    else
        warn "Bouncer left stopped. Bans will not be enforced."
        CHECKS_DECLINED+=("nftables bouncer not started (risk accepted)")
    fi
}

check_capi_registered() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_CAPI_OK \
            && status_pass "capi_registered" "connected to Central API" \
            || status_fail "capi_registered" "not registered — community blocklist inactive"
        return 0
    fi

    if $CS_CAPI_OK; then
        ok "CrowdSec Central API (CAPI) is connected."
        CHECKS_PASSED+=("CAPI registered — community blocklist active")
        return 0
    fi

    printf '\n'
    warn "CrowdSec is not registered with the Central API (CAPI)."
    plain "CAPI is the community threat feed. Without it, CrowdSec cannot download"
    plain "the shared global blocklist (~500k known-bad IPs contributed by millions"
    plain "of other CrowdSec nodes worldwide). Your node also won't share back."
    plain ""
    plain "CAPI registration is anonymous and free. It shares only attack metadata"
    plain "(attacker IP, scenario triggered, timestamp) — not your server's IP."

    if ask "Register with CAPI now?" "y"; then
        run cscli capi register
        run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
        ok "Registered with CrowdSec CAPI."
        CHECKS_FIXED+=("CAPI registered")
    else
        warn "CAPI not registered. Global blocklist will not be fetched."
        plain "Register later with: cscli capi register"
        CHECKS_DECLINED+=("CAPI not registered (community blocklist inactive)")
    fi
}

check_base_collections() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        ( $CS_HAS_LINUX && $CS_HAS_SSHD ) \
            && status_pass "base_collections" "linux + sshd collections present" \
            || status_fail "base_collections" "missing crowdsecurity/linux and/or crowdsecurity/sshd"
        return 0
    fi

    if $CS_HAS_LINUX && $CS_HAS_SSHD; then
        ok "Base collections installed (crowdsecurity/linux + crowdsecurity/sshd)."
        CHECKS_PASSED+=("Base collections present")
        return 0
    fi

    printf '\n'
    warn "One or both base collections are missing."
    plain "  crowdsecurity/linux  — detects generic Linux log attack patterns"
    plain "  crowdsecurity/sshd   — detects SSH brute-force attacks (watches auth.log)"
    plain ""
    plain "These are the minimum collections for any server. Without sshd, repeated"
    plain "failed SSH logins will never trigger a ban."

    local install_list=()
    $CS_HAS_LINUX || install_list+=("crowdsecurity/linux")
    $CS_HAS_SSHD  || install_list+=("crowdsecurity/sshd")

    if ask "Install missing base collections (${install_list[*]})?" "y"; then
        run cscli collections install "${install_list[@]}"
        run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
        ok "Base collections installed."
        CHECKS_FIXED+=("Base collections installed")
    else
        warn "Base collections not installed. SSH brute-force will not be detected."
        CHECKS_DECLINED+=("Base collections not installed (risk accepted)")
    fi
}

check_cloudflare_whitelist() {
    # Only called when CF_ACTIVE=true
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CF_WHITELISTED \
            && status_pass "cf_whitelist" "Cloudflare IPs whitelisted" \
            || status_fail "cf_whitelist" "cloudflared detected — CF IPs not whitelisted (risk of self-ban)"
        return 0
    fi

    if $CF_WHITELISTED; then
        ok "Cloudflare Tunnel IPs are whitelisted."
        CHECKS_PASSED+=("Cloudflare IP whitelist present")
        return 0
    fi

    printf '\n'
    warn "Cloudflare Tunnel is running, but Cloudflare IPs are NOT whitelisted."
    plain ""
    plain "  ╔═══════════════════════════════════════════════════════════════╗"
    plain "  ║  RISK: accidental self-ban of ALL tunnel traffic              ║"
    plain "  ╚═══════════════════════════════════════════════════════════════╝"
    plain ""
    plain "All tunnel traffic arrives from Cloudflare's IP ranges. If CrowdSec"
    plain "triggers on an HTTP attack signature — even a false positive — it will"
    plain "ban a Cloudflare IP block via nftables, immediately killing ALL traffic"
    plain "through your tunnel until you manually remove the ban."
    plain ""
    plain "Whitelisting CF IPs is the correct fix. CrowdSec will still detect"
    plain "attacks in application logs; it just won't block at the network layer"
    plain "for CF IPs. To block real attackers by their actual IP behind CF Tunnel,"
    plain "use a middleware bouncer in Caddy or NginxPM (see manage-crowdsec.sh)."
    plain ""
    plain "The IP list will be written to:"
    plain "  /etc/crowdsec/parsers/s02-enrich/99-whitelists.yaml"

    if ask "Write Cloudflare IP whitelist now? (strongly recommended)" "y"; then
        _write_cf_whitelist
        CHECKS_FIXED+=("Cloudflare IP whitelist written")
    else
        warn "CF IPs remain unwhitelisted. Risk of accidental self-ban is HIGH."
        CHECKS_DECLINED+=("Cloudflare IP whitelist declined (self-ban risk accepted)")
    fi
}

check_http_collections() {
    # Only called when PROXY_TYPE != none
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_HAS_HTTP_COLS \
            && status_pass "http_collections" "HTTP collections present for ${PROXY_TYPE}" \
            || status_fail "http_collections" "${PROXY_TYPE} detected — no HTTP collections installed"
        return 0
    fi

    if $CS_HAS_HTTP_COLS; then
        ok "HTTP collections are installed for ${PROXY_TYPE}."
        CHECKS_PASSED+=("HTTP collections present")
        return 0
    fi

    printf '\n'
    warn "Reverse proxy (${PROXY_TYPE}) detected but no HTTP collections are installed."
    plain "HTTP collections let CrowdSec detect web attacks: exploit scanners,"
    plain "credential stuffing, CVE-based probes, and bad-bot behaviour."
    plain ""
    plain "Without HTTP collections, CrowdSec is blind to web-layer attacks even"
    plain "though it is running. Your SSH and system logs are still watched."

    local suggest=()
    case "$PROXY_TYPE" in
        caddy)      suggest=("crowdsecurity/caddy" "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios") ;;
        nginx|npm)  suggest=("crowdsecurity/nginx" "crowdsecurity/http-cve" "crowdsecurity/base-http-scenarios") ;;
    esac

    printf '\n'
    info "Suggested collections for ${PROXY_TYPE}: ${suggest[*]}"

    if $CF_ACTIVE; then
        printf '\n'
        warn "Cloudflare Tunnel + nftables bouncer limitation:"
        plain "  The nftables bouncer blocks by network IP. All HTTP traffic arrives from"
        plain "  Cloudflare IPs (which are whitelisted), so the bouncer cannot block real"
        plain "  attackers by IP for web traffic. HTTP collections will detect attacks in"
        plain "  your logs, but blocking the actual offender requires a middleware bouncer:"
        plain "    Caddy:    https://github.com/hslatman/caddy-crowdsec-bouncer"
        plain "    NginxPM:  crowdsec-nginx-bouncer (configure real_ip from CF headers)"
        plain "  manage-crowdsec.sh → Setup wizard → provides setup instructions."
    fi

    if [[ "${#suggest[@]}" -gt 0 ]] && ask "Install HTTP collections for ${PROXY_TYPE} now?" "y"; then
        run cscli collections install "${suggest[@]}"
        run systemctl reload crowdsec 2>/dev/null || run systemctl restart crowdsec
        ok "HTTP collections installed."
        CHECKS_FIXED+=("HTTP collections installed for ${PROXY_TYPE}")
    else
        warn "HTTP collections not installed. Web-layer attacks will not be detected."
        CHECKS_DECLINED+=("HTTP collections not installed (risk accepted)")
    fi
}

check_log_acquisition() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        $CS_HAS_ACQUIS \
            && status_pass "log_acquisition" "custom acquisition sources configured" \
            || status_fail "log_acquisition" "no custom log acquisition — proxy logs may not be watched"
        return 0
    fi

    if $CS_HAS_ACQUIS; then
        ok "Custom log acquisition sources are configured."
        CHECKS_PASSED+=("Log acquisition configured")
        return 0
    fi

    if [[ "$PROXY_TYPE" == "none" ]] && ! $DOCKER_PRESENT; then
        ok "No proxy detected — default log sources (auth.log, syslog) are sufficient."
        CHECKS_PASSED+=("Log acquisition: default sources sufficient")
        return 0
    fi

    printf '\n'
    warn "No custom log acquisition is configured."
    plain "CrowdSec defaults to watching system logs (auth.log, syslog). It will"
    plain "NOT watch your reverse proxy logs unless you add an acquisition source."

    if [[ "$PROXY_TYPE" == "npm" ]] || $DOCKER_PRESENT; then
        plain ""
        plain "Docker containers (including NginxPM) require a docker acquisition"
        plain "source. Without it, CrowdSec cannot see any container log output."
    fi

    local proxy_log=""
    case "$PROXY_TYPE" in
        caddy)  proxy_log="/var/log/caddy/*.log" ;;
        nginx)  proxy_log="/var/log/nginx/*.log" ;;
        npm)    proxy_log="(docker acquisition — see manage-crowdsec.sh)" ;;
    esac
    [[ -n "$proxy_log" ]] && plain "Expected log path: ${proxy_log}"

    plain ""
    plain "Use manage-crowdsec.sh → Manage log acquisition to add sources"
    plain "appropriate for your topology (native logs or Docker socket)."

    warn "Log acquisition not auto-configured here to avoid wrong paths."
    plain "Run manage-crowdsec.sh for the full setup wizard."
    CHECKS_DECLINED+=("Log acquisition not configured — run manage-crowdsec.sh")
}

check_fail2ban_overlap() {
    if [[ "$STATUS_MODE" == "true" ]]; then
        if $F2B_SSHD_ACTIVE && $CS_HAS_SSHD; then
            status_fail "fail2ban_overlap" "fail2ban sshd jail + CrowdSec sshd collection both active (redundant)"
        else
            status_pass "fail2ban_overlap" "no redundant fail2ban/CrowdSec overlap"
        fi
        return 0
    fi

    if ! ( $F2B_SSHD_ACTIVE && $CS_HAS_SSHD ); then
        ok "No fail2ban / CrowdSec SSH overlap detected."
        CHECKS_PASSED+=("No fail2ban/CrowdSec SSH overlap")
        return 0
    fi

    printf '\n'
    warn "fail2ban sshd jail AND CrowdSec sshd collection are both active."
    plain "Both tools are watching the same SSH logs and can issue bans for the"
    plain "same attack. This is redundant, not dangerous — but it wastes resources"
    plain "and produces duplicate ban entries that are harder to audit."
    plain "Recommendation: disable fail2ban's sshd jail and let CrowdSec handle SSH."

    if ask "Disable fail2ban sshd jail (keep fail2ban running for other jails)?" "y"; then
        run fail2ban-client stop sshd
        ok "fail2ban sshd jail stopped."
        plain "To make permanent, add 'enabled = false' to the [sshd] section in"
        plain "/etc/fail2ban/jail.local (or jail.conf), then restart fail2ban."
        CHECKS_FIXED+=("fail2ban sshd jail disabled")
    else
        warn "Leaving overlap in place."
        CHECKS_DECLINED+=("fail2ban/CrowdSec SSH overlap left (redundancy accepted)")
    fi
}

# ==============================================================================
# ── main ──────────────────────────────────────────────────────────────────────
# ==============================================================================
main() {
    preflight_checks
    _compute_state

    # ── --status mode: silent pass/fail, no prompts ───────────────────────────
    if [[ "$STATUS_MODE" == "true" ]]; then
        check_crowdsec_installed
        if $CS_INSTALLED; then
            check_agent_running
            check_bouncer_installed
            check_bouncer_running
            check_capi_registered
            check_base_collections
            $CF_ACTIVE    && check_cloudflare_whitelist
            [[ "$PROXY_TYPE" != "none" ]] && check_http_collections
            check_log_acquisition
            check_fail2ban_overlap
        fi
        _emit_status
        [[ ${#STATUS_FAIL[@]} -eq 0 ]] && exit 0 || exit 1
    fi

    # ── Banner ────────────────────────────────────────────────────────────────
    printf '\n'
    printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
    printf "${BLUE}${BOLD}  │              harden-crowdsec.sh                     │${NC}\n"
    printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
    printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
    printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
    printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"

    _show_state

    # ── All-pass early exit ───────────────────────────────────────────────────
    if _quick_pass; then
        ok "All CrowdSec hardening checks pass. No action needed."
        exit 0
    fi

    # ── Per-check functions ───────────────────────────────────────────────────
    CHECKS_PASSED=()
    CHECKS_FIXED=()
    CHECKS_DECLINED=()

    section "1 — Installation"
    check_crowdsec_installed

    if $CS_INSTALLED; then
        section "2 — Agent service"
        check_agent_running

        section "3 — nftables bouncer"
        check_bouncer_installed
        check_bouncer_running

        section "4 — Community blocklist"
        check_capi_registered

        section "5 — Base collections"
        check_base_collections

        if $CF_ACTIVE; then
            section "6 — Cloudflare Tunnel whitelist"
            check_cloudflare_whitelist
        fi

        if [[ "$PROXY_TYPE" != "none" ]]; then
            section "7 — HTTP collections (${PROXY_TYPE})"
            check_http_collections
        fi

        section "8 — Log acquisition"
        check_log_acquisition

        section "9 — fail2ban overlap"
        check_fail2ban_overlap
    fi

    # ── Final state and summary ───────────────────────────────────────────────
    _compute_state
    header "CrowdSec Hardening State"
    _show_state

    printf "  ${BOLD}Summary${NC}\n\n"
    for msg in "${CHECKS_PASSED[@]+"${CHECKS_PASSED[@]}"}";   do printf "  ${GREEN}  ✓${NC}  %s\n" "$msg"; done
    for msg in "${CHECKS_FIXED[@]+"${CHECKS_FIXED[@]}"}";     do printf "  ${CYAN}  ~${NC}  %s\n" "$msg"; done
    for msg in "${CHECKS_DECLINED[@]+"${CHECKS_DECLINED[@]}"}"; do printf "  ${YELLOW}  !${NC}  %s\n" "$msg"; done

    printf '\n'
    if   (( ${#CHECKS_DECLINED[@]} > 0 )); then
        warn "Some checks were skipped. Re-run $(basename "$0") to address them."
    elif (( ${#CHECKS_FIXED[@]}   > 0 )); then
        ok   "All accepted fixes applied. Re-run $(basename "$0") to confirm."
    fi
}

main "$@"