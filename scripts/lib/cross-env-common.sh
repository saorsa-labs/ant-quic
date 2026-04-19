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
