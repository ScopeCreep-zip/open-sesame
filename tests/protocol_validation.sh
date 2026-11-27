#!/usr/bin/env bash
# tests/protocol_validation.sh — lifecycle validation of an Open Sesame build.
#
# Runs this tree's daemons and CLI through their whole lifecycle under an
# isolated root: first-run `sesame init`, every daemon's request, the lock
# and activation protocol (V-001 through V-011), sandbox containment, and
# shutdown. The installation of the user running it is not touched: no
# config, vault, unit, running daemon, or keyring item of theirs is read or
# changed.
#
# Usage:
#   cargo build --workspace --bins
#   bash tests/protocol_validation.sh [--bin DIR] [--keep] [--clipboard]
#
#   --bin DIR    the binaries to validate (default: target/debug of this tree)
#   --keep       keep the isolated root (logs, config, vault) for inspection
#   --clipboard  also check clipboard capture: copies a token with wl-copy,
#                replacing the session clipboard, and restores the text
#                selection it replaced afterwards (a non-text selection is
#                not restored)
#
# Requirements:
#   - Any Linux kernel: the daemons run under what its Landlock enforces
#     (no `[global.sandbox] require` floor is configured). L-01 records it
#     (doctor `platform.kernel`, whose value names the enforcement), and
#     L-04 expects every daemon to report that enforcement.
#   - A Wayland session of the same user (`$WAYLAND_DISPLAY`, or a
#     `wayland-*` socket in `/run/user/$UID`): daemon-wm and daemon-clipboard
#     connect to the compositor.
#   - `journalctl -k` readable by the user (the `systemd-journal` or `adm`
#     group): a seccomp kill is read from the kernel's audit record.
#   - `jq`: the doctor's report is JSON.
#   - The user's systemd service manager (`systemd-run --user`): each
#     daemon runs as a transient service under its shipped unit's
#     sandboxing.
#
# How it isolates:
#   - Every location the layout derives (`core_layout::Environment`) is set
#     beneath a temporary root; the runtime directory is
#     `/run/user/$UID/pds-lifecycle-<pid>`, short enough for a socket path
#     (108 bytes) and apart from the user's `pds/`.
#   - `sesame init` starts the daemons with `systemctl --user`: a stand-in
#     `systemctl` first on `PATH` answers exactly those calls, and fails on
#     any other. It starts each daemon as a transient user service
#     (`systemd-run --user`) under the `[Service]` settings of its unit in
#     `contrib/systemd`, the units the packages ship: `ProtectSystem`,
#     `ProtectHome`, `ReadWritePaths`, `InaccessiblePaths`, the address
#     families, limits, `Type=notify` readiness, and the rest, with `%t`,
#     `%E`, `%C`, and `%h` as the isolated runtime, configuration, cache,
#     and home directories (any other specifier fails). Left out are
#     `ExecStart` (this tree's binary runs) and `Restart`/`RestartSec` (a
#     crash fails the check rather than restarting). The `*Directory=`
#     settings would resolve to the user's own XDG directories; the
#     stand-in creates their isolated equivalents as systemd would (mode
#     0755) and grants them writable in the service's namespace
#     (`ReadWritePaths`), as systemd does. systemd returns from a start
#     once the daemon has sent `READY=1`; a daemon that exits first fails
#     the start. Its output goes to the journal.
#   - Passwords are piped: every `sesame` prompt reads piped stdin.
#   - daemon-clipboard connects to the session's compositor and records
#     the selection current at its start into the isolated history, which
#     is removed with the root.
#
# Exit status: 0 when every check passes, 1 when one fails, 2 when a
# requirement is missing.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BIN="$SCRIPT_DIR/../target/debug"
KEEP=0
CLIPBOARD=0
while (($#)); do
    case "$1" in
    --bin)
        BIN=$2
        shift 2
        ;;
    --keep)
        KEEP=1
        shift
        ;;
    --clipboard)
        CLIPBOARD=1
        shift
        ;;
    -h | --help)
        sed -n '2,/^[^#]/{/^#/p;}' "${BASH_SOURCE[0]}"
        exit 0
        ;;
    *)
        echo "unknown argument: $1 (see --help)" >&2
        exit 2
        ;;
    esac
done
BIN=$(cd -- "$BIN" && pwd)

DAEMONS_HEADLESS=(daemon-profile daemon-secrets daemon-launcher daemon-snippets)
DAEMONS_DESKTOP=(daemon-wm daemon-clipboard daemon-input)
SANDBOXED=(daemon-profile daemon-secrets daemon-snippets daemon-wm daemon-clipboard daemon-input)
PASSWORD="lifecycle-$RANDOM-$RANDOM"
PROFILE=default

PASS=0
FAIL=0

# -- Requirements -------------------------------------------------------------

require() {
    echo "requirement: $*" >&2
    exit 2
}

for binary in sesame "${DAEMONS_HEADLESS[@]}" "${DAEMONS_DESKTOP[@]}"; do
    [[ -x "$BIN/$binary" ]] || require "$BIN/$binary is missing (cargo build --workspace --bins)"
done
command -v jq >/dev/null || require "jq is not on PATH"
UNITS=$(cd -- "$SCRIPT_DIR/../contrib/systemd" && pwd)

HOST_RUNTIME=/run/user/$(id -u)
[[ -d "$HOST_RUNTIME" ]] || require "no session runtime directory $HOST_RUNTIME"
case "${WAYLAND_DISPLAY:-}" in
/*) WAYLAND_SOCKET=$WAYLAND_DISPLAY ;;
"") WAYLAND_SOCKET=$(find "$HOST_RUNTIME" -maxdepth 1 -type s -name 'wayland-*' -print -quit) ;;
*) WAYLAND_SOCKET=$HOST_RUNTIME/$WAYLAND_DISPLAY ;;
esac
[[ -S "${WAYLAND_SOCKET:-}" ]] || require "no Wayland compositor socket in $HOST_RUNTIME"

# Host tools run without a development shell's library path.
host() { env -u LD_LIBRARY_PATH "$@"; }
host journalctl -k -n 1 --no-pager >/dev/null 2>&1 || require "journalctl -k is not readable"
# The host's own systemctl and systemd-run, before the stand-in shadows
# systemctl on PATH.
HOST_SYSTEMCTL=$(command -v systemctl) || require "systemctl is not on PATH"
HOST_SYSTEMD_RUN=$(command -v systemd-run) || require "systemd-run is not on PATH"
host "$HOST_SYSTEMCTL" --user show-environment >/dev/null 2>&1 \
    || require "no user service manager (systemctl --user)"
if ((CLIPBOARD)); then
    for tool in wl-copy wl-paste; do
        host sh -c "command -v $tool" >/dev/null || require "--clipboard needs $tool (wl-clipboard)"
    done
fi

# -- Isolated root ------------------------------------------------------------

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sesame-lifecycle.XXXXXX")
RUNTIME=$HOST_RUNTIME/pds-lifecycle-$$
mkdir -p "$ROOT"/{home,config,cache,data,log,pids,units,bin} "$RUNTIME"
chmod 700 "$RUNTIME"
STARTED=$(date '+%Y-%m-%d %H:%M:%S')

# Stop the daemons in systemd's order: the bus clients (After=
# open-sesame-profile.service) first, then daemon-profile once they have
# exited, so no client loses the bus while stopping.
stop_daemons() {
    local pidfile pid clients=()
    for pidfile in "$ROOT"/pids/*; do
        [[ -e "$pidfile" && "$(basename "$pidfile")" != daemon-profile ]] || continue
        pid=$(<"$pidfile")
        kill -TERM "$pid" 2>/dev/null && clients+=("$pid")
    done
    local alive
    for _ in $(seq 20); do
        alive=0
        for pid in "${clients[@]}"; do
            kill -0 "$pid" 2>/dev/null && alive=1
        done
        ((alive)) || break
        sleep 0.5
    done
    [[ -e "$ROOT/pids/daemon-profile" ]] && kill -TERM "$(<"$ROOT/pids/daemon-profile")" 2>/dev/null || true
}

cleanup() {
    stop_daemons
    # Every transient service of this run, stopped and its journal kept
    # with the root.
    local units daemon
    for units in "$ROOT"/units/*; do
        [[ -e "$units" ]] || continue
        daemon=$(basename "$units")
        log_of "$daemon" >"$ROOT/log/$daemon.log" || true
        xargs -r env -u LD_LIBRARY_PATH "$HOST_SYSTEMCTL" --user stop <"$units" 2>/dev/null || true
    done
    rm -rf "$RUNTIME"
    if ((KEEP)); then
        echo "kept: $ROOT"
    else
        rm -rf "$ROOT"
    fi
}
trap cleanup EXIT

export HOME=$ROOT/home
export XDG_CONFIG_HOME=$ROOT/config
export XDG_CACHE_HOME=$ROOT/cache
export XDG_DATA_HOME=$ROOT/data
export XDG_RUNTIME_DIR=$RUNTIME
export WAYLAND_DISPLAY=$WAYLAND_SOCKET
export XDG_SESSION_TYPE=wayland
export PDS_LOG_FORMAT=pretty
unset NOTIFY_SOCKET DBUS_SYSTEM_BUS_ADDRESS
export LIFECYCLE_ROOT=$ROOT LIFECYCLE_BIN=$BIN LIFECYCLE_UNITS=$UNITS LIFECYCLE_ID=$$
export LIFECYCLE_LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
export HOST_SYSTEMCTL HOST_SYSTEMD_RUN
export PATH="$ROOT/bin:$BIN:$PATH"

# The systemctl stand-in: the calls `sesame init` makes, answered by
# starting this tree's daemons as transient user services under their
# shipped units' sandboxing. A target is active while every one of its
# daemons runs; starting an active target is a no-op.
cat >"$ROOT/bin/systemctl" <<'STANDIN'
#!/usr/bin/env bash
set -euo pipefail
HEADLESS=(daemon-profile daemon-secrets daemon-launcher daemon-snippets)
DESKTOP=(daemon-wm daemon-clipboard daemon-input)
host() { env -u LD_LIBRARY_PATH "$@"; }
fail() { echo "systemctl stand-in: $*" >&2; exit 1; }
running() {
  local pidfile=$LIFECYCLE_ROOT/pids/$1
  [[ -e "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}
active() {
  local daemon
  for daemon in "$@"; do running "$daemon" || return 1; done
}
# The [Service] settings of daemon $1's shipped unit as systemd-run
# --property arguments, one per line, with the specifiers %t, %E, %C, and
# %h as the isolated runtime, configuration, cache, and home directories.
# The *Directory= settings are created here instead, under the isolated
# XDG directories, as systemd creates them (0755), and granted writable
# inside the service's namespace, as systemd grants them.
properties() {
  local unit=$LIFECYCLE_UNITS/open-sesame-${1#daemon-}.service line key value section=""
  [[ -f "$unit" ]] || fail "no unit $unit"
  while IFS= read -r line || [[ -n "$line" ]]; do
    case $line in
    "" | "#"*) continue ;;
    "["*) section=$line; continue ;;
    esac
    [[ $section == "[Service]" ]] || continue
    key=${line%%=*}
    value=${line#*=}
    value=${value//%t/$XDG_RUNTIME_DIR}
    value=${value//%E/$XDG_CONFIG_HOME}
    value=${value//%C/$XDG_CACHE_HOME}
    value=${value//%h/$HOME}
    [[ $value != *%* ]] || fail "unknown specifier in $unit: $line"
    case $key in
    ExecStart | Restart | RestartSec) continue ;;
    ConfigurationDirectory) value=$XDG_CONFIG_HOME/$value ;;
    CacheDirectory) value=$XDG_CACHE_HOME/$value ;;
    RuntimeDirectory) value=$XDG_RUNTIME_DIR/$value ;;
    *Directory) fail "unhandled $key in $unit" ;;
    esac
    case $key in
    ConfigurationDirectory | CacheDirectory | RuntimeDirectory)
      install -d -m 0755 "$value"
      key=ReadWritePaths
      ;;
    esac
    printf -- '--property=%s=%s\n' "$key" "$value"
  done <"$unit"
}
# Start daemon $1 as a transient user service and record its pid. systemd
# returns once the service is ready (Type=notify) or has failed.
spawn() {
  local daemon=$1 unit="sesame-lifecycle-$LIFECYCLE_ID-$1-$RANDOM" settings pid
  local props=()
  settings=$(properties "$daemon") || exit 1
  mapfile -t props <<<"$settings"
  # A development shell's build loads its libraries (libwayland-client)
  # through the shell's library path; a packaged binary finds the system's.
  if [[ -n "$LIFECYCLE_LD_LIBRARY_PATH" ]]; then
    props+=("--setenv=LD_LIBRARY_PATH=$LIFECYCLE_LD_LIBRARY_PATH")
  fi
  echo "$unit" >>"$LIFECYCLE_ROOT/units/$daemon"
  host "$HOST_SYSTEMD_RUN" --user --quiet --collect --unit="$unit" "${props[@]}" \
    --setenv=HOME="$HOME" --setenv=XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    --setenv=XDG_CACHE_HOME="$XDG_CACHE_HOME" --setenv=XDG_DATA_HOME="$XDG_DATA_HOME" \
    --setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" --setenv=WAYLAND_DISPLAY="$WAYLAND_DISPLAY" \
    --setenv=XDG_SESSION_TYPE="$XDG_SESSION_TYPE" --setenv=PDS_LOG_FORMAT="$PDS_LOG_FORMAT" \
    "$LIFECYCLE_BIN/$daemon" || fail "$daemon did not start (journalctl --user -u $unit)"
  pid=$(host "$HOST_SYSTEMCTL" --user show --property=MainPID --value "$unit")
  [[ "$pid" != 0 ]] || fail "$daemon is not running (journalctl --user -u $unit)"
  echo "$pid" >"$LIFECYCLE_ROOT/pids/$daemon"
}
start() {
  local daemon
  for daemon in "$@"; do
    running "$daemon" || spawn "$daemon"
  done
}
case "$*" in
  "--user is-active --quiet open-sesame-headless.target") active "${HEADLESS[@]}" ;;
  "--user daemon-reload") exit 0 ;;
  "--user list-unit-files open-sesame-desktop.target --no-pager --no-legend")
    echo "open-sesame-desktop.target static" ;;
  "--user reset-failed "*) exit 0 ;;
  "--user start open-sesame-headless.target")
    # The other daemons are After=open-sesame-profile.service: they start
    # once daemon-profile, which issues their keys, is ready.
    start daemon-profile
    start "${HEADLESS[@]:1}" ;;
  "--user start open-sesame-desktop.target") start "${DESKTOP[@]}" ;;
  *) echo "systemctl stand-in: unexpected call: $*" >&2; exit 1 ;;
esac
STANDIN
chmod 755 "$ROOT/bin/systemctl"

# -- Checks -------------------------------------------------------------------

pass() {
    echo "PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "FAIL: $1"
    shift
    local line
    for line in "$@"; do echo "  $line"; done
    FAIL=$((FAIL + 1))
}

# Standard input with terminal color codes removed. A stream filter: bash
# pattern substitution over a whole daemon log takes minutes.
uncolor() { sed 's/\x1b\[[0-9;]*m//g'; }

# A daemon's log, from the journal of every service it ran as, colors
# removed. Callers search it as a here-string: under pipefail a `grep -q`
# that stops at its first match fails the pipeline it reads (SIGPIPE).
log_of() {
    local unit
    [[ -e "$ROOT/units/$1" ]] || return 0
    while read -r unit; do
        host journalctl --user --unit="$unit" --output=cat --no-pager
    done <"$ROOT/units/$1" | uncolor
}

# The last 20 lines of a daemon's log, colors removed.
log_tail() { log_of "$1" | tail -n 20; }

# Run `sesame "$@"`, with `$INPUT` (when set) as one piped line: its output,
# colors removed, in $OUT and its exit status in $STATUS. Called directly,
# not in a command substitution, so both reach the caller.
OUT=""
STATUS=0
INPUT=""
sesame_run() {
    local raw
    STATUS=0
    if [[ -n "$INPUT" ]]; then
        raw=$(printf '%s\n' "$INPUT" | sesame "$@" 2>&1) || STATUS=$?
    else
        raw=$(sesame "$@" 2>&1 </dev/null) || STATUS=$?
    fi
    INPUT=""
    OUT=$(uncolor <<<"$raw")
}

# The same with `$1` piped.
sesame_with() {
    INPUT=$1
    shift
    sesame_run "$@"
}

# Pass when $OUT matches the extended regular expression `$2` and $STATUS
# is `$3` (default 0).
expect_match() {
    local name=$1 pattern=$2 status=${3:-0}
    if [[ "$STATUS" -eq "$status" ]] && grep -Eq -- "$pattern" <<<"$OUT"; then
        pass "$name"
    else
        fail "$name" "expected exit $status and /$pattern/" "exit $STATUS: $OUT"
    fi
}

expect_no_match() {
    local name=$1 pattern=$2
    if ! grep -Eq -- "$pattern" <<<"$OUT"; then
        pass "$name"
    else
        fail "$name" "unexpected /$pattern/" "$OUT"
    fi
}

alive() { [[ -e "$ROOT/pids/$1" ]] && kill -0 "$(<"$ROOT/pids/$1")" 2>/dev/null; }

# Run `sesame "${@:3}"` until $OUT matches `$1`, for up to `$2` seconds.
wait_for() {
    local pattern=$1 seconds=$2
    shift 2
    for _ in $(seq $((seconds * 2))); do
        sesame_run "$@"
        grep -Eq -- "$pattern" <<<"$OUT" && return 0
        sleep 0.5
    done
}

# -- Lifecycle ----------------------------------------------------------------

echo "========================================"
echo " Open Sesame lifecycle validation"
echo " binaries: $BIN"
echo " root:     $ROOT"
echo "========================================"

sesame_run status --doctor platform --output json
kernel=$(jq -r '.checks[] | select(.id == "platform.kernel") | "\(.status) \(.value)"' <<<"$OUT" 2>&1 || true)
OUT=$kernel
expect_match "L-01: the doctor reports the kernel's Landlock coverage (platform.kernel)" '^(pass|warn) .*, Landlock (fully|partially|not) enforced$'
case "$kernel" in
*", Landlock fully enforced") ENFORCEMENT=FullyEnforced ;;
*", Landlock partially enforced") ENFORCEMENT=PartiallyEnforced ;;
*) ENFORCEMENT=NotEnforced ;;
esac

sesame_with "$PASSWORD" init --no-keybinding
expect_match "L-02: sesame init sets up config, daemons, and the vault" 'Setup complete'

for daemon in "${DAEMONS_HEADLESS[@]}" "${DAEMONS_DESKTOP[@]}"; do
    if alive "$daemon"; then
        pass "L-03: $daemon is running"
    else
        fail "L-03: $daemon is running" "$(log_tail "$daemon")"
    fi
done

for daemon in "${SANDBOXED[@]}"; do
    if grep -q "sandbox applied status=$ENFORCEMENT" <<<"$(log_of "$daemon")"; then
        pass "L-04: $daemon is sandboxed as the kernel enforces ($ENFORCEMENT)"
    else
        fail "L-04: $daemon is sandboxed as the kernel enforces ($ENFORCEMENT)" "$(log_tail "$daemon")"
    fi
done

sesame_run status
expect_match "L-05: the vault is unlocked after init" "$PROFILE +unlocked"

sesame_with "lifecycle-value" secret set -p "$PROFILE" lifecycle-key
expect_match "L-06: daemon-secrets stores a secret" "stored"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "L-06: daemon-secrets returns it" "^lifecycle-value$"

sesame_run wm list
expect_match "L-07: daemon-wm lists the compositor's windows" "ID"
sesame_run launch search a
expect_match "L-07: daemon-launcher searches desktop entries" "Name|No "
sesame_run clipboard history -p "$PROFILE"
expect_match "L-07: daemon-clipboard answers history" "."
sesame_run input status
expect_match "L-07: daemon-input answers status" "Active layer"
sesame_run snippet list -p "$PROFILE"
expect_match "L-07: daemon-snippets answers list" "."

if ((CLIPBOARD)); then
    # The text selection replaced, restored below; empty when there is none.
    saved=$(host wl-paste --no-newline --type text 2>/dev/null || true)
    token="lifecycle-clipboard-$RANDOM$RANDOM"
    host wl-copy -- "$token"
    wait_for "$token" 10 clipboard history -p "$PROFILE"
    expect_match "L-08: daemon-clipboard captures a copied selection" "$token"
    entry=""
    [[ $(grep -F -- "$token" <<<"$OUT" || true) =~ (clip-[0-9a-f-]{36}) ]] && entry=${BASH_REMATCH[1]}
    if [[ -n "$entry" ]]; then
        sesame_run clipboard get "$entry"
        expect_match "L-08: the captured entry's content is served" "^$token$"
    else
        fail "L-08: the captured entry's content is served" "no entry ID listed for the token"
    fi
    if [[ -n "$saved" ]]; then
        host wl-copy -- "$saved"
    else
        host wl-copy --clear
    fi
fi

# -- Lock and activation protocol ---------------------------------------------

sesame_run lock -p "$PROFILE"
expect_match "V-002: lock zeroizes the vault key" "locked"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "V-002: a locked vault denies the secret" "vault locked" 1
sesame_run status
expect_match "V-006: status after lock reports locked" "$PROFILE +locked"

sesame_with "$PASSWORD" unlock -p "$PROFILE"
expect_match "V-003: unlock with the password" "unlocked via password"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "V-003: unlock without activate denies the secret" "is not active" 1

sesame_with "$PASSWORD" unlock -p "$PROFILE"
expect_match "V-008: unlock of an unlocked vault is reported, not repeated" "already unlocked"

sesame_run profile activate "$PROFILE"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "V-004: lock, unlock, activate, then the secret is served" "^lifecycle-value$"

sesame_run profile deactivate "$PROFILE"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "V-001: deactivate denies the secret" "is not active" 1
sesame_run status
expect_no_match "V-007: status after deactivate lists no active profile" "- $PROFILE"

sesame_run profile activate "$PROFILE"
sesame_run secret get -p "$PROFILE" lifecycle-key
expect_match "V-005/V-010: deactivate, activate, then the secret is served" "^lifecycle-value$"

sesame_with "$PASSWORD" init --no-keybinding
expect_match "V-011: sesame init re-run completes" "Setup complete"

alive daemon-secrets && kill -TERM "$(<"$ROOT/pids/daemon-secrets")"
wait_for "treated as locked" 40 status
expect_match "V-009: with daemon-secrets gone, status reports every vault locked" "daemon-secrets is not answering; every vault is treated as locked"

# -- Containment and shutdown -------------------------------------------------

stop_daemons
running=0
for _ in $(seq 20); do
    running=0
    for pidfile in "$ROOT"/pids/*; do
        kill -0 "$(cat "$pidfile")" 2>/dev/null && running=1
    done
    ((running)) || break
    sleep 0.5
done
if ((running)); then
    fail "S-01: every daemon stops on SIGTERM within 10 s" "$(for p in "$ROOT"/pids/*; do kill -0 "$(cat "$p")" 2>/dev/null && basename "$p"; done)"
else
    pass "S-01: every daemon stops on SIGTERM within 10 s"
fi

# The audit record names the executable the kernel ran: the binaries'
# resolved directories (a --bin of symlinks into the Nix store, and a
# wrapper's wrapped binary beside it).
exe_dirs=()
for daemon in "${DAEMONS_HEADLESS[@]}" "${DAEMONS_DESKTOP[@]}"; do
    exe_dirs+=(-e "exe=\"$(dirname -- "$(readlink -f -- "$BIN/$daemon")")/")
done
kills=$(host journalctl -k --no-pager --since "$STARTED" | grep 'type=1326' | grep -F "${exe_dirs[@]}" || true)
if [[ -z "$kills" ]]; then
    pass "S-02: no daemon was killed by its seccomp filter"
else
    fail "S-02: no daemon was killed by its seccomp filter" "$kills"
fi

for daemon in "${DAEMONS_HEADLESS[@]}" "${DAEMONS_DESKTOP[@]}"; do
    errors=$(grep -E ' ERROR |^Error:' <<<"$(log_of "$daemon")" || true)
    if [[ -z "$errors" ]]; then
        pass "S-03: $daemon logged no error"
    else
        fail "S-03: $daemon logged no error" "$errors"
    fi
done

echo "========================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "========================================"
((FAIL == 0)) || exit 1
