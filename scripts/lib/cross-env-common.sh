#!/usr/bin/env bash
# Shared helpers for the cross-environment ant-quic test harness.
# Sourced by scripts/run-cross-env-matrix.sh and scripts/lib/scenarios/*.sh.
#
# These helpers wrap SSH / local execution and log capture in a uniform way so
# the per-scenario scripts only have to express what they want to verify, not
# how to start/stop nodes or collect logs.
#
# Required env (set by the orchestrator):
#   ANT_QUIC_BIN_LOCAL    Path to the macOS ant-quic binary on this MacBook.
#   ANT_QUIC_BIN_LINUX    Path to the cross-compiled Linux binary on VPS hosts.
#   LOG_DIR               Per-run log directory (created by orchestrator).
#   SSH_OPTS              Array of ssh options shared with run-connectivity-matrix.sh.

set -euo pipefail

: "${LOG_DIR:?LOG_DIR must be set by the orchestrator}"

# SSH options. Bash arrays cannot be exported across subshells, so we define
# them here in the sourced common helper rather than relying on the orchestrator
# to export. Scenario subshells get the same options for free.
SSH_OPTS=(
    -4
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o ControlMaster=no
    -o ControlPath=none
    -o StrictHostKeyChecking=accept-new
)

# Color helpers (safe when stdout is not a TTY).
_supports_color() { [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; }
_red()    { _supports_color && printf '\033[31m%s\033[0m\n' "$*" || printf '%s\n' "$*"; }
_green()  { _supports_color && printf '\033[32m%s\033[0m\n' "$*" || printf '%s\n' "$*"; }
_yellow() { _supports_color && printf '\033[33m%s\033[0m\n' "$*" || printf '%s\n' "$*"; }

log_info()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
log_warn()  { _yellow "[WARN] $(date +%H:%M:%S) $*"; }
log_error() { _red    "[ERR ] $(date +%H:%M:%S) $*" >&2; }
log_ok()    { _green  "[ OK ] $(date +%H:%M:%S) $*"; }

# Run a command on a remote host and stream its output to a per-host logfile.
# Usage: ssh_run_log <host_label> <ssh_target> <remote_cmd>
# Returns the local PID of the ssh process so the caller can stop it later.
ssh_run_log() {
    local label="$1"; shift
    local target="$1"; shift
    local logfile="${LOG_DIR}/${label}.log"
    log_info "ssh ${target}: ${*}  → ${logfile}"
    # shellcheck disable=SC2029  # we want client-side expansion of $@
    ssh "${SSH_OPTS[@]:-}" "${target}" "$@" \
        >"${logfile}" 2>&1 &
    echo $!
}

# Run a command locally with output redirected to a per-host logfile.
# Usage: local_run_log <label> <cmd> [args...]
# Returns the PID.
local_run_log() {
    local label="$1"; shift
    local logfile="${LOG_DIR}/${label}.log"
    log_info "local: $* → ${logfile}"
    "$@" >"${logfile}" 2>&1 &
    echo $!
}

# Wait until a peer-id line appears in a node's log, or until timeout.
# Usage: wait_for_peer_id <label> <timeout_seconds>
# Echoes the discovered peer ID hex (32 bytes / 64 hex chars) on success.
wait_for_peer_id() {
    local label="$1"
    local timeout="${2:-30}"
    local logfile="${LOG_DIR}/${label}.log"
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        # Match the binary's "Peer ID: <hex>" line emitted at startup.
        local peer
        peer=$(grep -Eo 'Peer ID:[[:space:]]*[0-9a-f]{64}' "$logfile" 2>/dev/null \
            | head -n1 | awk '{print $NF}')
        if [ -n "$peer" ]; then
            echo "$peer"
            return 0
        fi
        sleep 1
    done
    log_error "wait_for_peer_id(${label}): no peer id in ${timeout}s"
    return 1
}

# Count occurrences of a literal pattern across all logs in LOG_DIR.
# Usage: count_log_pattern <pattern>
count_log_pattern() {
    local pattern="$1"
    grep -hF "$pattern" "$LOG_DIR"/*.log 2>/dev/null | wc -l | tr -d ' '
}

# Assert a count of silent-drop events across all logs is zero.
# Returns 0 on success, 1 on any drops detected (with a log message).
assert_no_silent_drops() {
    local n
    n=$(count_log_pattern 'target=ant_quic::silent_drop')
    if [ "$n" -gt 0 ]; then
        log_error "silent drops detected: ${n} occurrences across ${LOG_DIR}"
        grep -h 'target=ant_quic::silent_drop' "$LOG_DIR"/*.log \
            | awk -F'kind=' '{print $2}' | awk '{print $1}' \
            | sort | uniq -c | sort -rn >&2
        return 1
    fi
    log_ok "no silent drops detected"
    return 0
}

# Stop a list of pids (typically background ssh / local node processes).
# Usage: stop_pids "${PIDS[@]}"
stop_pids() {
    for pid in "$@"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Give them a chance to clean up before SIGKILL.
    sleep 1
    for pid in "$@"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
}

# Convenience: trap to ensure cleanup on EXIT for the calling script.
register_cleanup() {
    local cleanup_fn="$1"
    trap "${cleanup_fn}" EXIT INT TERM
}

# Extract a node's full 64-char hex peer ID from its startup log.
# Reads the `{"event":"local_identity","peer_id":"..."}` JSON line which
# contains the full 32-byte (64-hex-char) peer id needed by --send-to and
# --connect-peer-id. The plain "Peer ID:" INFO line shows only the first
# 16 chars and is NOT what we want.
#
# `label` is the c1_<node> prefix (e.g. "c1_L1"); the function strips the
# leading "c1_" if present so callers can pass either form.
extract_peer_id_from_log() {
    local label="$1"
    local logfile="${LOG_DIR}/${label}.log"
    [ -f "$logfile" ] || return 1
    grep -m1 '"event":"local_identity"' "$logfile" 2>/dev/null \
        | sed -E 's/.*"peer_id":"([0-9a-f]{64})".*/\1/'
}

# Run a command with a wall-clock timeout, portable across BSD (macOS)
# and GNU. macOS has no `timeout` binary by default; this helper picks
# `gtimeout` if available, else falls back to a backgrounded watchdog.
# Usage: portable_timeout <secs> <cmd> [args...]
portable_timeout() {
    local secs="$1"; shift
    local bin
    bin=$(command -v gtimeout 2>/dev/null || command -v timeout 2>/dev/null || true)
    if [ -n "$bin" ]; then
        "$bin" "$secs" "$@"
        return $?
    fi
    # Watchdog fallback. Keep PID isolated so we don't kill the parent.
    "$@" &
    local cmd_pid=$!
    ( sleep "$secs"; kill -TERM "$cmd_pid" 2>/dev/null; sleep 2; kill -KILL "$cmd_pid" 2>/dev/null ) &
    local wd_pid=$!
    wait "$cmd_pid" 2>/dev/null
    local rc=$?
    kill "$wd_pid" 2>/dev/null
    wait "$wd_pid" 2>/dev/null
    return $rc
}

# Install a pfctl rule on this MacBook that drops UDP between localhost and
# the given remote IP/port pair. Used by the forced-relay scenario to
# guarantee the direct path fails so the relay path engages.
#
# Requires sudo. Anchor name "com.saorsa/cross-env" so we can flush cleanly.
block_direct_path_pfctl() {
    local remote_ip="$1"
    local remote_port="${2:-${ANT_QUIC_PORT:-10000}}"
    log_warn "installing pfctl block: udp ↔ ${remote_ip}:${remote_port} (sudo)"
    sudo pfctl -a com.saorsa/cross-env -f - <<EOF
block drop quick proto udp from any to ${remote_ip} port ${remote_port}
block drop quick proto udp from ${remote_ip} to any port ${remote_port}
EOF
}

unblock_direct_path_pfctl() {
    log_info "flushing pfctl anchor com.saorsa/cross-env (sudo)"
    sudo pfctl -a com.saorsa/cross-env -F all 2>/dev/null || true
}
