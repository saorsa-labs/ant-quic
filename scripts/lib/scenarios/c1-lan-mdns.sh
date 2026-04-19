#!/usr/bin/env bash
# Scenario C1: LAN-mesh-mdns
#
# Verifies that 3 LAN-only nodes (this MacBook + 2 Studios) discover each other
# via mDNS without any internet access and form a full mesh.
#
# Run via the orchestrator: scripts/run-cross-env-matrix.sh --scenario c1-lan-mdns
# Direct invocation is supported for debugging.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"

: "${ANT_QUIC_BIN_LOCAL:?must be set}"
: "${LOG_DIR:?must be set}"

PIDS=()
cleanup() { stop_pids "${PIDS[@]:-}"; }
register_cleanup cleanup

run() {
    log_info "C1: starting LAN-mesh-mdns scenario"

    # Local MacBook node — mDNS enabled, no default bootstrap.
    local pid_l1
    pid_l1=$(local_run_log "c1_macbook" \
        "${ANT_QUIC_BIN_LOCAL}" \
        --listen "[::]:0" \
        --no-default-bootstrap \
        --mdns \
        --mdns-mode Both \
        --mdns-auto-connect Enabled \
        --stats --stats-interval 2)
    PIDS+=("$pid_l1")

    # Remote Studios — same args. Studio binary path is provided by
    # ANT_QUIC_BIN_STUDIO (set by the orchestrator after cross-env-deploy).
    if [ -n "${STUDIO1_TARGET:-}" ]; then
        local pid_l2
        pid_l2=$(ssh_run_log "c1_studio1" "${STUDIO1_TARGET}" \
            "${ANT_QUIC_BIN_STUDIO:-ant-quic} --listen '[::]:0' --no-default-bootstrap --mdns --mdns-mode Both --mdns-auto-connect Enabled --stats --stats-interval 2")
        PIDS+=("$pid_l2")
    fi
    if [ -n "${STUDIO2_TARGET:-}" ]; then
        local pid_l3
        pid_l3=$(ssh_run_log "c1_studio2" "${STUDIO2_TARGET}" \
            "${ANT_QUIC_BIN_STUDIO:-ant-quic} --listen '[::]:0' --no-default-bootstrap --mdns --mdns-mode Both --mdns-auto-connect Enabled --stats --stats-interval 2")
        PIDS+=("$pid_l3")
    fi

    # Allow startup + mDNS resolution.
    log_info "C1: waiting 25s for mDNS discovery and mesh formation"
    sleep 25

    log_info "C1: stopping nodes"
    stop_pids "${PIDS[@]}"
    PIDS=()

    log_info "C1: scenario data captured to ${LOG_DIR}"
}

verify() {
    log_info "C1: verifying acceptance criteria"
    local fail=0

    # Each LAN node should have observed at least one MdnsPeerDiscovered.
    for label in c1_macbook c1_studio1 c1_studio2; do
        local logfile="${LOG_DIR}/${label}.log"
        [ -f "$logfile" ] || continue
        if ! grep -q 'MdnsPeerDiscovered' "$logfile"; then
            log_error "${label}: no MdnsPeerDiscovered observed"
            fail=1
        else
            log_ok "${label}: mDNS discovery confirmed"
        fi
    done

    # No silent drops should appear during the mesh formation window.
    if ! assert_no_silent_drops; then
        fail=1
    fi

    return $fail
}

# Allow direct invocation: ./scripts/lib/scenarios/c1-lan-mdns.sh run
case "${1:-run}" in
    run)    run ;;
    verify) verify ;;
    all)    run && verify ;;
    *)      echo "usage: $0 {run|verify|all}" >&2; exit 64 ;;
esac
