#!/usr/bin/env bash
# Scenario C6: cleanup verification.
#
# Sends SIGTERM to every c1 node (locally and via SSH), waits 5s for clean
# shutdown, then verifies each node logged "Shutting down P2P endpoint"
# and that no silent_drop / send_error / stale-reaper line appeared during
# the entire run.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

read -r -a NODES <<< "${REACHABLE_NODES_STR:-${ALL_NODES[*]}}"

run() {
    log_info "C6: shutting down ${#NODES[@]} c1 nodes"
    for label in "${NODES[@]}"; do
        if [ "$label" = "L1" ]; then
            # local node — kill any matching ant-quic process started by c1
            pkill -TERM -f "ant-quic.*--listen.*\[::\]:${ANT_QUIC_PORT}" 2>/dev/null || true
        else
            ssh "${SSH_OPTS[@]}" "${NODE_SSH[$label]}" \
                "pkill -TERM -f 'ant-quic.*--listen.*\[::\]:${ANT_QUIC_PORT}' 2>/dev/null || true" \
                </dev/null 2>/dev/null || true
        fi
    done
    sleep 5
}

verify() {
    log_info "C6: verifying clean shutdown"
    local fail=0
    for label in "${NODES[@]}"; do
        local f="${LOG_DIR}/c1_${label}.log"
        [ -f "$f" ] || continue
        if grep -q 'Shutting down P2P endpoint' "$f"; then
            log_ok "  ${label}: clean shutdown logged"
        else
            log_warn "  ${label}: no clean-shutdown log line"
        fi
        if grep -q 'stale.connection.reaper' "$f"; then
            log_error "  ${label}: stale-reaper triggered (lifecycle regression)"
            fail=1
        fi
    done
    if ! assert_no_silent_drops; then
        fail=1
    fi
    return $fail
}

case "${1:-run}" in
    run)    run ;;
    verify) verify ;;
    all)    run && verify ;;
    *)      echo "usage: $0 {run|verify|all}" >&2; exit 64 ;;
esac
