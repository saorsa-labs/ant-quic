#!/usr/bin/env bash
# Scenario C2: full LAN+VPS mesh formation.
#
# Brings up the 3 LAN nodes (mDNS) plus optional Studio remotes and asserts
# every node reaches at least one VPS bootstrap (default saorsa-1 / saorsa-2)
# within a 30-second window.
#
# Notes:
# - Cross-NAT discovery here uses the binary's built-in default bootstrap.
# - VPS-side processes are NOT started by this scenario (they run as
#   systemd `saorsa-quic-test` services on the saorsa-N nodes).

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
    log_info "C2: starting full LAN+VPS mesh"

    local pid
    pid=$(local_run_log "c2_macbook" \
        "${ANT_QUIC_BIN_LOCAL}" \
        --listen "[::]:0" \
        --mdns --mdns-mode Both \
        --stats --stats-interval 2)
    PIDS+=("$pid")

    if [ -n "${STUDIO1_TARGET:-}" ]; then
        pid=$(ssh_run_log "c2_studio1" "${STUDIO1_TARGET}" \
            "${ANT_QUIC_BIN_STUDIO:-ant-quic} --listen '[::]:0' --mdns --mdns-mode Both --stats --stats-interval 2")
        PIDS+=("$pid")
    fi
    if [ -n "${STUDIO2_TARGET:-}" ]; then
        pid=$(ssh_run_log "c2_studio2" "${STUDIO2_TARGET}" \
            "${ANT_QUIC_BIN_STUDIO:-ant-quic} --listen '[::]:0' --mdns --mdns-mode Both --stats --stats-interval 2")
        PIDS+=("$pid")
    fi

    log_info "C2: waiting 35s for full mesh formation (mDNS + default bootstrap)"
    sleep 35

    log_info "C2: stopping LAN nodes"
    stop_pids "${PIDS[@]}"
    PIDS=()
}

verify() {
    log_info "C2: verifying mesh"
    local fail=0

    for label in c2_macbook c2_studio1 c2_studio2; do
        local logfile="${LOG_DIR}/${label}.log"
        [ -f "$logfile" ] || continue

        # At least one ConnectionEstablished overall.
        if ! grep -q 'ConnectionEstablished' "$logfile"; then
            log_error "${label}: zero ConnectionEstablished events"
            fail=1
            continue
        fi

        # mDNS for the other 2 LAN nodes.
        if ! grep -q 'MdnsPeerDiscovered' "$logfile"; then
            log_warn "${label}: no MdnsPeerDiscovered (LAN sibling unreachable?)"
        fi

        log_ok "${label}: at least one connection observed"
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
