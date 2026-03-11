# Script Family Context — `harden-*` and `manage-*`

This document is a reference for Claude when writing new scripts in this family.
Paste it at the start of a new session before requesting a script.

Covered domains (current and planned):
`users` · `packages` · `docker` · `firewall` · `unattended-upgrades` · `crowdsec`
`msmtp` · `aliases` · `services` · `ssh` · `apparmor` · `fail2ban` · `sysctl`

---

## Philosophy

- **Each script is a single, self-contained file.** No shared libraries, no
  sourced helpers. Anyone can receive one file and run it. Never suggest
  extracting shared code into a separate file.
- Scripts target **Debian 11+ and Ubuntu 22.04+**, with Proxmox LXC containers
  as the primary environment.
- All scripts require `sudo` (or root) to run. `--dry-run` is an exception:
  it prints commands without executing them and does not require root.
- Every action is **idempotent** — re-running when already in the correct state
  reports all-clear and exits cleanly without prompting.
- **Show state before asking for action.** The operator should always be able
  to see what is currently true before being asked to change anything.
- **Declining is always allowed.** Skipped checks and cancelled actions are
  recorded and surfaced in the summary — never silently dropped.

---

## Script Families

### `harden-*.sh`

Focused, opinionated audit tools. Each script checks a specific domain for
security or correctness, reports pass/fail for every check, and walks the
operator through remediation interactively.

- Exits cleanly with no prompts when everything is already correct.
- Each check function is responsible for its own state query, output, and
  remediation flow. Never intermix two checks inside one function.
- Operator can decline any fix. Declined items are recorded and the summary
  advises re-running.

```
preflight → banner → fast all-pass check → per-check functions → final state + summary
```

All of the above runs inside a `main()` function called at the bottom of the
script. Function definitions (helpers, check functions) come before `main()`.

### `manage-*.sh`

Full lifecycle management menus for a specific domain. Presents an interactive
numbered menu. After every action the relevant state table is refreshed so the
operator always sees current state.

- Dynamically adjusts menu options based on system state (e.g., hide an option
  when a required package or group doesn't exist yet, and explain why).
- Always interactive — they do not support unattended execution. If automation
  is needed for a domain, write a dedicated idempotent script for that task.

```
preflight → banner → state table → menu loop → action functions
```

All of the above runs inside a `main()` function called at the bottom of the
script. `_show_menu()`, `_menu_default()`, and action functions are defined
before `main()`. Any globals read by action functions must be declared at
module level (not only inside `main()`) to satisfy `set -u`.

---

## Universal Boilerplate

The following blocks are included **verbatim** in every script. Do not
paraphrase, restructure, or abbreviate them.

### Shebang and safety flags

```bash
#!/usr/bin/env bash
set -euo pipefail
```

### Section comment style

Use the `──` dash style for all in-script section headings. Never use `===`
fences. The style mirrors the `section()` output helper and works cleanly in
both light and dark terminals.

```bash
# ── Label ─────────────────────────────────────────────────────────────────────

# ── Label with extra note ─────────────────────────────────────────────────────
# Continuation comment lines are fine directly beneath a section header.
```

Aim to fill to approximately column 80. For short labels the right-hand
dashes pad the line; for very long labels just end naturally.

The file-level header (top of script) uses `=` borders and the `==...==`
fences because it acts as a document header, not a section separator:

```bash
# ==============================================================================
# script-name.sh — One-line description
# ==============================================================================
```

### Argument parsing

`DRY_RUN` is always present. Add domain-specific environment variables on the
lines immediately below, following the same `VAR="${VAR:-default}"` pattern.
Document them in the script header under `# Environment variables:`.

`STATUS_MODE` is always present in `harden-*` scripts. When true, the script
runs all check functions (each records pass/fail silently into STATUS_PASS /
STATUS_FAIL arrays instead of prompting), then calls `_emit_status` and exits
0 (all pass) or 1 (any fail) — no prompts, no mutations. `--status` does not
require root (state queries are read-only).

```bash
DRY_RUN="${DRY_RUN:-false}"
STATUS_MODE="${STATUS_MODE:-false}"
# domain-specific env vars go here, e.g.:\r
# SOME_VAR="${SOME_VAR:-}"

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
```

### Colors

Colors degrade to empty strings when stdout is not a terminal (pipes, logs,
CI output). Never assume a terminal.

```bash
if [[ -t 1 ]]; then
    RED=$'\e[0;31m';  GREEN=$'\e[0;32m';  YELLOW=$'\e[1;33m'
    BLUE=$'\e[0;34m'; CYAN=$'\e[0;36m';   BOLD=$'\e[1m'
    DIM=$'\e[2m';     NC=$'\e[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi
```

### Output helpers

```bash
info()    { printf "${CYAN}  >>>  ${NC}%s\n"   "$1"; }
ok()      { printf "${GREEN}  [+]  ${NC}%s\n"  "$1"; }
warn()    { printf "${YELLOW}  [!]  ${NC}%s\n" "$1"; }
err()     { printf "${RED}  [x]  ${NC}%s\n"    "$1" >&2; }
plain()   { printf "        %s\n"              "$1"; }
die()     { err "$1"; exit 1; }
section() { printf "\n${BOLD}  ── %s${NC}\n"   "$1"; }
```

Intended use:
- `ok`      — something succeeded, or is already correct
- `info`    — neutral status, next steps, or instructions
- `warn`    — needs attention, was skipped, or has a risk worth noting
- `err`     — non-fatal stderr; always paired with `die` for fatal errors
- `plain`   — continuation lines under an `ok`/`info`/`warn`; no prefix icon
- `die`     — print error to stderr and `exit 1`
- `section` — named heading before a logical group of work

### Status helpers — `harden-*` scripts only

Used to record per-check outcomes in `--status` mode. Each entry is stored as
`"id|detail"`. Detail is printed inline for PASS and indented below for FAIL.
Declare the arrays at module level (required by `set -u`).

```bash
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
```

Output format (machine-parseable, one script per invocation):

```
harden-ssh
  PASS  pubkey_auth
  PASS  idle_timeout  ~10min (300s × 2)
  FAIL  password_auth
        PasswordAuthentication is 'yes'  expected: no
```

### `header()` — section title with ruled border

Used in `harden-*` scripts for the final state display. Pure-bash, no subshells.

```bash
header() {
    local title=" $1 " w=60
    local pad=$(( (w - ${#title}) / 2 ))
    local line; printf -v line '%*s' "$w" ''; line="${line// /─}"
    printf "\n${BLUE}${BOLD}%s\n" "$line"
    printf "%${pad}s%s\n" "" "$title"
    printf "%s${NC}\n\n" "$line"
}
```

### `run()` — dry-run wrapper

Wrap every state-mutating command in `run`. Do **not** wrap read-only queries
(`systemctl is-active`, `grep`, `stat`, `ss`, etc.).

```bash
run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf "    ${DIM}[dry-run]${NC} %s\n" "$*"
    else
        "$@"
    fi
}
```

### Prompt helpers

```bash
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
```

`ask_secret` can be omitted from scripts that have no secret inputs.

### Pre-flight checks

Declare the OS globals at module level (required by `set -u`) immediately
before the function definition. Add any domain-specific globals that
`preflight_checks` sets on the same lines. Any count or state globals read by
helper functions (e.g. `HUMAN_COUNT`, `SUDO_COUNT`, `MENU_DEFAULT`) must also
be declared at module level even if they are first assigned inside `main()`.

```bash
OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0
```

Sets globals `OS_ID`, `OS_CODENAME`, `OS_VERSION_ID`, `OS_MAJOR`. Add any
domain-specific assertions (required binaries, kernel features, etc.) inside
this function after the OS checks.

```bash
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
```

### Banner

Replace the script name on the centre line. The inner box content is 53 chars
wide — pad the title with spaces to fill the line exactly. For odd-length
titles, place the extra space on the right side.

```bash
printf '\n'
printf "${BLUE}${BOLD}  ┌─────────────────────────────────────────────────────┐${NC}\n"
printf "${BLUE}${BOLD}  │                 harden-foo.sh                       │${NC}\n"
printf "${BLUE}${BOLD}  └─────────────────────────────────────────────────────┘${NC}\n"
printf "  Host:     ${BOLD}%s${NC}\n"            "$(hostname)"
printf "  OS:       ${BOLD}%s %s (%s)${NC}\n"   "$OS_ID" "$OS_CODENAME" "$OS_VERSION_ID"
printf "  Dry-run:  ${BOLD}%s${NC}\n\n"         "$DRY_RUN"
```

Centring guide (inner width = 53, formula: left = (53 - len) / 2, right = 53 - len - left):

| Script           | len | left | right | Inner line                                      |
|------------------|-----|------|-------|-------------------------------------------------|
| harden-ssh.sh    |  13 |  20  |  20   | `                    harden-ssh.sh                    ` |
| harden-users.sh  |  15 |  19  |  19   | `                   harden-users.sh                   ` |
| manage-ssh.sh    |  13 |  20  |  20   | `                    manage-ssh.sh                    ` |
| manage-users.sh  |  15 |  19  |  19   | `                   manage-users.sh                   ` |

### Divider lines — pure bash

Never use `seq` or any subshell to produce divider lines.

```bash
# Fixed-width
local line; printf -v line '%*s' 60 ''; printf "%s\n" "${line// /─}"

# Variable-width with indent
local w=50 div; printf -v div '%*s' "$w" ''; printf "    %s\n" "${div// /─}"
```

---

## `harden-*` Conventions

### Summary arrays

Declare at the top of `main`, before any check function is called. Each check
function appends to exactly one array.

```bash
CHECKS_PASSED=()    # already correct — no action needed
CHECKS_FIXED=()     # operator chose to fix it
CHECKS_DECLINED=()  # operator skipped (risk accepted)
```

Do **not** declare these at module level — they are only meaningful within a
single run of `main()` and declaring them in `main()` makes that scope
explicit. Because check functions are always called from inside `main()`, and
bash arrays without `local` are global, all check functions see the same
arrays.

### Check function structure

Every check follows this shape. Query state first (never use `run()` here),
return early if passing, then explain the problem, then offer remediation.

```bash
check_something() {
    if <already_correct>; then
        ok "Thing is already correctly configured."
        CHECKS_PASSED+=("Thing is correctly configured")
        return 0
    fi

    printf '\n'
    warn "Thing is not configured correctly."
    plain "This matters because..."

    if ask "Fix this now?" "y"; then
        run <fix_command>
        ok "Thing fixed."
        CHECKS_FIXED+=("Thing fixed")
    else
        warn "Skipped — thing remains misconfigured."
        CHECKS_DECLINED+=("Thing not fixed (risk accepted)")
    fi
}
```

### All-pass early exit

Before running any checks, test whether everything already passes. If so,
display the current state and exit without prompting.

```bash
compute_state   # populate whatever globals the state display needs
if <all_checks_pass>; then
    show_state
    ok "All hardening checks pass. No action needed."
    exit 0
fi
```

### Final state display and summary

```bash
header "Hardening State"
show_state

printf "  ${BOLD}Summary${NC}\n\n"
for msg in "${CHECKS_PASSED[@]+"${CHECKS_PASSED[@]}"}";     do
    printf "  ${GREEN}  ✓${NC}  %s\n" "$msg"
done
for msg in "${CHECKS_FIXED[@]+"${CHECKS_FIXED[@]}"}";       do
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
```

---

## `manage-*` Conventions

### Menu loop

```bash
_MENU_MAX=10   # updated by _show_menu when option count varies

while true; do
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

    case "$choice" in
        1)  action_one   ;;
        # ...
        N)  info "Exiting."; break ;;
        *)  warn "Please enter 1–${_MENU_MAX}." ;;
    esac

    printf '\n'
    show_state   # refresh after every action
done
```

### `_show_menu()`

- Prints the numbered action list.
- Conditionally includes options whose prerequisites may not yet exist. When an
  option is hidden, update `_MENU_MAX` and keep the `case` statement in sync.
- The exit option is always the last numbered item.

### `_menu_default()`

Returns the number of the most helpful action given current system state.
Prints nothing (empty string) when no obvious nudge applies. The caller omits
the default hint from the prompt when this is empty.

```bash
_menu_default() {
    <condition_A> && printf '1' && return
    <condition_B> && printf '3' && return
    printf ''
}
```

### State table

Every `manage-*` script opens with a state table and reprints it after every
action. The table shows all managed entities and their relevant attributes.

Design rules:
- Column widths are fixed constants — not computed at runtime.
- A divider row immediately follows the header row; use pure-bash dividers.
- Colour-code status values consistently: GREEN = good/active/enabled,
  YELLOW = warning/partial/degraded, RED = bad/missing/disabled, DIM = absent
  or not applicable.
- Only include a column when it's meaningful for the domain. If a column only
  applies when certain infrastructure exists, show it conditionally and adjust
  the divider width to match.

---

## Domain-Specific Patterns

The sections below describe **patterns**, not prescriptive implementations.
The exact helpers, state queries, and table columns will differ per domain.
The user-management scripts (`harden-users.sh`, `manage-users.sh`) are a
worked example of all of these patterns applied together.

### State query helpers

Write small, focused query functions that return a boolean or a status string.
Never mutate state inside them. Never wrap them in `run()`.

```bash
# Boolean presence / membership check
is_<thing>_<condition>() { <read-only test>; }

# Examples from the users domain:
is_sudo_member()      { getent group sudo 2>/dev/null | grep -qw "$1"; }

# Examples for other domains:
is_service_enabled()  { systemctl is-enabled "$1" &>/dev/null; }
is_service_active()   { systemctl is-active  "$1" &>/dev/null; }
is_pkg_installed()    { dpkg-query -W -f='${Status}' "$1" 2>/dev/null \
                            | grep -q "install ok installed"; }
is_port_open()        { ss -tlnp | grep -q ":${1} "; }
is_rule_present()     { grep -qF "$1" /etc/some/config 2>/dev/null; }
```

### Count / aggregate helpers

When a script needs to branch on how many items satisfy a condition, compute
counts into clearly named globals. Call before any logic that reads them, and
again after mutations to keep them fresh.

```bash
compute_<domain>_state() {
    THING_TOTAL=0
    THING_ENABLED=0
    # ... populate from read-only queries
}
```

### Selection helpers — `pick_<entity>()`

When an action targets one entity from a list (a service, a rule, a package),
follow this pattern:

1. Build an array of eligible items from a read-only query.
2. If empty, `warn` and `return 1`. Callers do `|| return 0` to go back to the
   menu cleanly.
3. Print the current state table (or a focused subset) for context.
4. Loop with `ask_val` until the operator gives a valid choice.
   **Always retry on bad input — never accept it and return an error code.**

**Return convention — use result globals in ALL script families:**

Command substitution `$()` cannot be used for pick or prompt helpers that
print display output (warn/info/plain/list tables), because `$()` captures
stdout — all that output would be silently swallowed instead of shown to the
operator. Use a result global instead, declared at module level.

- **All script families**: Use a result global (e.g. `_PICK_RESULT`). Set the
  global inside the function and read it at the call site.
- **Exception**: A pick helper that prints *nothing* (no state table, no
  warn/info calls) may use `printf '%s' "$chosen"` and `$()` capture — but
  this is rare. When in doubt, use a global.

```bash
# All families — result global pattern
_PICK_RESULT=''   # declare at module level

pick_<entity>() {
    local prompt="$1" items=() item
    _PICK_RESULT=''
    # populate items array
    if [[ ${#items[@]} -eq 0 ]]; then
        warn "No eligible items found."
        return 1
    fi
    printf '\n'
    show_state
    printf '\n'
    local chosen found
    while true; do
        chosen=$(ask_val "$prompt (Enter to cancel)")
        [[ -z "$chosen" ]] && { info "Cancelled."; return 1; }
        found=false
        for item in "${items[@]}"; do
            [[ "$item" == "$chosen" ]] && found=true && break
        done
        [[ "$found" == "true" ]] && { _PICK_RESULT="$chosen"; return 0; }
        warn "'${chosen}' is not valid — please try again."
    done
}

# Caller:
pick_<entity> "Prompt text" || return 0
local target="$_PICK_RESULT"
```

**`harden-*` pick helpers**: Because check functions call pick helpers before
any state table is shown, it can be tempting to embed `list_state` inside the
pick function. **Do not do this.** Display the state table explicitly in the
calling code before invoking the pick helper; the pick helper itself should
only validate and return a value. This keeps the pick helper reusable and
avoids the `$()` swallowing problem entirely.

### Input validation helpers — `_prompt_<thing>()`

For any freeform input that must satisfy constraints (a path, an IP, a port, a
key, a cron expression):

1. Use a result global (e.g. `_USERNAME_RESULT`, `_PASSWORD_RESULT`) declared
   at module level — same reason as pick helpers: validation warnings use
   `warn`/`plain` which write to stdout, and `$()` capture would swallow them.
2. Return 1 on blank input (blank = "cancel") with `info "Cancelled."`.
3. Loop until input satisfies all constraints.
4. Validate with a concrete regex or command; print rejection messages that
   explain exactly what the rule is.

```bash
_USERNAME_RESULT=''   # declare at module level

_prompt_<thing>() {
    _<THING>_RESULT=''
    local candidate
    while true; do
        candidate=$(ask_val "Prompt text (Enter to cancel)")
        if [[ -z "$candidate" ]]; then
            info "Cancelled."
            return 1
        fi
        if ! <validation_test "$candidate">; then
            warn "Invalid — explain the rule."; continue
        fi
        _<THING>_RESULT="$candidate"
        return 0
    done
}

# Caller:
_prompt_<thing> || return 0
local value="$_<THING>_RESULT"
```

### Destructive action confirmation

Any action that is difficult or impossible to undo requires explicit
confirmation before proceeding.

```bash
# Minimum bar — prompt defaults to No
ask "Remove the thing permanently?" "n" || { info "Cancelled."; return 0; }

# High-stakes — require typing the target name back
warn "Type the name to confirm, or Enter to cancel:"
local confirm; confirm=$(ask_val "Confirm")
if [[ "$confirm" != "$target" ]]; then
    info "Cancelled — did not match."
    return 0
fi
```

### Prerequisite / dependency checks

If an action requires a package, service, kernel module, or other
infrastructure that may not exist, check at the top of the action function and
explain clearly what is needed.

```bash
action_something() {
    if ! is_pkg_installed "some-package"; then
        printf '\n'
        warn "some-package is not installed."
        plain "Install it first: apt install some-package"
        return 0
    fi
    # ...
}
```

For `manage-*` scripts, conditionally hide the menu option entirely rather than
letting the operator select it only to hit this error.

### Multi-step rollback — ERR trap

When an action involves several mutating steps that form one logical operation,
trap ERR to undo partial work on failure. Name the cleanup function after the
specific action so traps don't collide.

```bash
local _ref="$target"
_<action>_cleanup() {
    [[ "$DRY_RUN" == "true" ]] && return
    warn "Error — rolling back..."
    <undo_steps> 2>/dev/null || true
}
trap _<action>_cleanup ERR

run step_one
run step_two
run step_three

trap - ERR
```

### Config file backup before editing

When an action modifies a system config file, back it up with a timestamped
`.bak` suffix before touching it. Show the backup path.

```bash
local cfg="/etc/some/config"
local bak="${cfg}.bak.$(date +%Y%m%d%H%M%S)"
run cp "$cfg" "$bak"
info "Backed up to ${bak}"
run sed -i '...' "$cfg"   # or tee, awk, etc.
```

---

### Home directory lookup

Whenever an action needs the home directory of a target user, look it up from
`/etc/passwd` via `getent` rather than constructing `/home/${username}`. This
is correct even on systems where some home dirs live outside `/home`.

```bash
local target_home; target_home=$(getent passwd "$target" | cut -d: -f6)
local auth_keys="${target_home}/.ssh/authorized_keys"
```

---

## SSH Domain Patterns

The SSH scripts write configuration exclusively through a drop-in file rather
than modifying the base `sshd_config`. This keeps the base config pristine and
makes all managed settings visible in one place.

### Drop-in file convention

All SSH configuration changes go to:
```
/etc/ssh/sshd_config.d/99-hardened.conf
```

The base `/etc/ssh/sshd_config` is never modified. The `99-` prefix ensures
this drop-in is read last, giving it precedence over all other drop-ins.

### Reading effective values

To read the effective value of a directive (drop-in overrides base):

```bash
sshd_eff_val() {
    local key="$1" val=""
    val=$(grep -ih "^${key}[[:space:]]" "$SSHD_DROP_IN" 2>/dev/null \
        | tail -1 | awk '{print $2}' || true)
    if [[ -z "$val" ]]; then
        val=$(grep -ih "^${key}[[:space:]]" "$SSHD_CONFIG" 2>/dev/null \
            | tail -1 | awk '{print $2}' || true)
    fi
    printf '%s' "$val"
}
```

### Writing and validating the drop-in

1. Back up the existing drop-in with a timestamped `.bak` suffix.
2. Write the new drop-in via `cat > "$SSHD_DROP_IN" << DROPIN`.
3. Validate with `sshd -t`. On failure, restore the backup and reload.
4. On success, reload sshd:
   `systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true`

### Authorized keys management

- Keys are appended idempotently: check for duplicate `type blob` before
  writing; skip if already present.
- Write a labelled comment header before each source block so re-runs are
  idempotent even if the file is edited externally.
- Always set `chmod 700 ~/.ssh` and `chmod 600 ~/.ssh/authorized_keys`.
- Use `chown -R user:user ~/.ssh` (with a fallback to `chown -R user` for
  systems where the group name differs from the username).

### Colour-coding SSH config values

Use a `_conf_color()` helper that maps directive/value pairs to ANSI colours.
This helper is called from both the state table and the edit-config table. Keep
the logic in one place and call it from both display paths.

---

## Conventions Checklist

Use this for every new script, regardless of domain.

**Structure**
- [ ] `#!/usr/bin/env bash` and `set -euo pipefail` at the top
- [ ] Argument parsing block verbatim; domain env vars declared below `DRY_RUN`
- [ ] `OS_ID=''; OS_CODENAME=''; OS_VERSION_ID=''; OS_MAJOR=0` declared before `preflight_checks()`
- [ ] All domain count/state globals read by helpers declared at module level (e.g. `HUMAN_COUNT=0; SUDO_COUNT=0`)
- [ ] All result globals for pick/prompt helpers declared at module level (e.g. `_PICK_RESULT=''`, `_USERNAME_RESULT=''`, `_PASSWORD_RESULT=''`)
- [ ] Color block verbatim
- [ ] All output helpers verbatim (`info` `ok` `warn` `err` `plain` `die` `section` `header`)
- [ ] `run()` verbatim
- [ ] Prompt helpers verbatim (`ask` `ask_val`; `ask_secret` only if needed)
- [ ] `preflight_checks()` verbatim; domain-specific assertions added inside it
- [ ] Banner present; script name centred and padded to fill the 53-char box
- [ ] All execution wrapped in `main()`; `main` called at the bottom of the file
- [ ] Section headings use `# ── Label ──────` style throughout; `===` fences only in the file header

**Behaviour**
- [ ] `run()` wraps every mutating command; read-only queries are not wrapped
- [ ] No `seq` calls anywhere — use `printf -v` for all dividers
- [ ] State is shown before any action is requested
- [ ] Every check/action is idempotent — re-running a correct state produces no prompts
- [ ] Declining any fix is always possible; declined items appear in the final summary

**`harden-*` specific**
- [ ] `CHECKS_PASSED`, `CHECKS_FIXED`, `CHECKS_DECLINED` declared at the top of `main()` (not at module level), before the banner
- [ ] `STATUS_MODE` flag declared alongside `DRY_RUN`; `--status` case present in argument parsing
- [ ] `STATUS_PASS=()`, `STATUS_FAIL=()`, `status_pass()`, `status_fail()`, `_emit_status()` declared at module level
- [ ] `--status` path in `main()` is **before the banner**: runs all check functions (each calls `status_pass`/`status_fail` and returns immediately), calls `_emit_status`, exits 0 if `${#STATUS_FAIL[@]} -eq 0` else exits 1 — no prompts, no mutations
- [ ] Every check function has a `STATUS_MODE` branch at the top: calls `status_pass`/`status_fail` with a stable `snake_case` id and a human-readable detail string, then `return 0`
- [ ] Every check function appends to exactly one of the three summary arrays in its interactive path
- [ ] All-pass early exit present before check functions run; prints full summary loop before `exit 0`
- [ ] Final state display uses `header()` followed by the summary loop with ✓ / ~ / ! symbols
- [ ] Closing message matches outcome: all-pass / some-fixed / some-declined

**`manage-*` specific**
- [ ] State table printed on entry and refreshed after every action
- [ ] `_show_menu()` and `_menu_default()` functions present
- [ ] Dynamic options hidden (not just disabled) when prerequisites are absent
- [ ] Menu numbering in `_show_menu()` and the `case` statement are kept in sync
- [ ] Exit is always the last numbered option
- [ ] `_MENU_MAX` and `MENU_DEFAULT` declared at module level

**Domain-specific**
- [ ] State query helpers are read-only and never wrapped in `run()`
- [ ] Pick helpers use result globals (`_PICK_RESULT`) — never `$()` capture when the function prints output
- [ ] Pick helpers do NOT call display functions (list tables, show_state) internally; the caller shows state before invoking the pick helper
- [ ] Prompt helpers (`_prompt_*`) use result globals and return 1 on blank/cancel input
- [ ] Selection helpers use a retry loop — never single-attempt with return-on-bad-input
- [ ] Input validation helpers loop until valid
- [ ] Destructive actions have at minimum an `ask` with default `n`; high-stakes actions require typing a confirmation string
- [ ] Actions that modify config files back them up with a timestamped `.bak` suffix first
- [ ] Multi-step operations use a named ERR trap for rollback
- [ ] Prerequisite checks are at the top of any action that needs them, with a clear install hint
- [ ] Home directory obtained from `getent passwd "$user" | cut -d: -f6`, never constructed as `/home/${user}`