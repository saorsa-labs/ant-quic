#!/usr/bin/env bash
# Scenario C5: forced-relay evidence.
#
# Pick one specific LAN-VPS pair (default L1 ↔ V_HEL) where direct should
# normally win. Install a pfctl block on this MacBook so all UDP between
# us and that VPS:port is dropped. Then re-run the C3 transfer for that
# pair. Verify:
#
#   1. Sender logs `connection_type:"relayed"` in peer_connected event.
#   2. Some VPS emits `target=ant_quic::relay_traffic` with
#      bytes_forwarded > 0 during the test window.
#   3. Recipient (V_HEL) logs `data_received` with `sha_match: true`.
#
# Tear-down: flush the pfctl anchor.
#
# REQUIRES sudo on this MacBook.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

: "${LOG_DIR:?must be set}"
: "${ANT_QUIC_PORT:?must be set}"

FORCED_PAIR_SENDER="${FORCED_PAIR_SENDER:-L1}"
FORCED_PAIR_RECIPIENT="${FORCED_PAIR_RECIPIENT:-V_HEL}"
TRANSFER_BYTES="${C5_TRANSFER_BYTES:-67108864}"
TRANSFER_TIMEOUT="${C5_TRANSFER_TIMEOUT:-90}"

declare -A PEER_ID
load_peer_ids() {
    [ -f "${LOG_DIR}/peer_ids.tsv" ] || { log_error "C5: peer_ids.tsv missing"; return 1; }
    while IFS=$'\t' read -r label pid; do
        PEER_ID[$label]="$pid"
    done < "${LOG_DIR}/peer_ids.tsv"
}

cleanup() {
    unblock_direct_path_pfctl || true
}
register_cleanup cleanup

run() {
    load_peer_ids
    local s="${FORCED_PAIR_SENDER}"
    local r="${FORCED_PAIR_RECIPIENT}"
    local rid="${PEER_ID[$r]:-}"
    if [ -z "$rid" ]; then
        log_error "C5: no peer-id known for recipient ${r}"
        return 1
    fi
    if [ "$s" != "L1" ]; then
        log_error "C5: only supports FORCED_PAIR_SENDER=L1 (pfctl runs locally)"
        return 1
    fi

    local rip="${NODE_HOST[$r]}"
    local rport="${ANT_QUIC_PORT}"
    local logfile_label="c5_send_${s}_to_${r}_relay"

    log_warn "C5: blocking direct UDP to ${rip}:${rport} (sudo)"
    if ! block_direct_path_pfctl "${rip}" "${rport}"; then
        log_error "C5: pfctl block failed (need sudo)"
        return 1
    fi

    log_info "C5: ${s} -> ${r}: ${TRANSFER_BYTES} bytes via relay"
    local kp; kp=$(known_peers_csv)
    timeout "${TRANSFER_TIMEOUT}" "${NODE_BIN[$s]}" \
        --listen "[::]:0" \
        --no-default-bootstrap \
        --known-peers "${kp}" \
        --json --duration $((TRANSFER_TIMEOUT - 5)) \
        --send-to "${rid}" \
        --send-to-timeout 45 \
        --generate-data "${TRANSFER_BYTES}" \
        > "${LOG_DIR}/${logfile_label}.log" 2>&1 || true
}

verify() {
    local s="${FORCED_PAIR_SENDER}"
    local r="${FORCED_PAIR_RECIPIENT}"
    local sender_log="${LOG_DIR}/c5_send_${s}_to_${r}_relay.log"
    local recipient_log="${LOG_DIR}/c1_${r}.log"

    local fail=0
    if [ -f "$sender_log" ]; then
        if grep -q '"connection_type":"relayed"' "$sender_log"; then
            log_ok "  sender saw connection_type=relayed"
        else
            log_error "  sender did NOT see connection_type=relayed"
            fail=1
        fi
        if grep -q '"event":"send_to_complete".*"sha_ok":true' "$sender_log"; then
            log_ok "  sender completed transfer (sha_ok=true)"
        else
            log_warn "  sender did not complete transfer; full data may not have flowed"
            fail=1
        fi
    else
        log_error "  no sender log: ${sender_log}"
        fail=1
    fi

    # Look for relay_traffic warns across ALL nodes (any node could have relayed).
    local total_relay_lines=0
    for f in "${LOG_DIR}"/c1_*.log; do
        [ -f "$f" ] || continue
        local n
        n=$(grep -c 'target=ant_quic::relay_traffic' "$f" 2>/dev/null || true)
        total_relay_lines=$((total_relay_lines + n))
    done
    if [ "$total_relay_lines" -gt 0 ]; then
        log_ok "  observed ${total_relay_lines} relay_traffic log line(s) across nodes"
    else
        log_error "  no relay_traffic log lines anywhere"
        fail=1
    fi

    if [ -f "$recipient_log" ]; then
        if grep -q '"event":"data_received".*"sha_match":true' "$recipient_log"; then
            log_ok "  recipient verified ≥1 chunk via SHA"
        else
            log_warn "  recipient log has no sha-verified data_received events"
            fail=1
        fi
    fi

    return $fail
}

case "${1:-run}" in
    run)    run ;;
    verify) verify ;;
    all)    run && verify ;;
    *)      echo "usage: $0 {run|verify|all}" >&2; exit 64 ;;
esac
