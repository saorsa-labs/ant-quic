#!/usr/bin/env bash
# Scenario C3: pairwise large-data transfer matrix.
#
# For every directed pair (sender, recipient) with sender != recipient:
#   1. SSH into sender (or run locally for L1).
#   2. Invoke `ant-quic --send-to <recipient_peer_id> --generate-data 67108864`
#      with --known-peers so the sender can find the recipient via the mesh.
#   3. Block until sender logs send_to_complete OR per-pair timeout.
#   4. Aggregator greps recipient's c1_<recipient>.log for matching
#      data_received events with sha_match: true.
#
# Note: the recipient node is the c1_<recipient> instance (still running).
# Sender is a fresh short-lived ant-quic process (not a c1 node), so its
# log goes to LOG_DIR/c3_send_<sender>_to_<recipient>.log.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

: "${LOG_DIR:?must be set}"
: "${ANT_QUIC_PORT:?must be set}"
TRANSFER_BYTES="${TRANSFER_BYTES:-67108864}"     # 64 MiB
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-90}"       # wall timeout per pair (tight; send-to-timeout=30 means fail-fast at 30s)
SEND_TO_TIMEOUT="${SEND_TO_TIMEOUT:-30}"
CHUNK_SIZE="${CHUNK_SIZE:-65536}"
PAR_SENDERS="${PAR_SENDERS:-1}"                  # if 1, run sender rows concurrently; 0 keeps legacy serial behavior

read -r -a NODES <<< "${REACHABLE_NODES_STR:-${ALL_NODES[*]}}"
KNOWN_CSV=$(known_peers_csv)

declare -A PEER_ID
load_peer_ids() {
    if [ ! -f "${LOG_DIR}/peer_ids.tsv" ]; then
        log_error "C3: ${LOG_DIR}/peer_ids.tsv not found — did C1 run?"
        return 1
    fi
    while IFS=$'\t' read -r label pid; do
        PEER_ID[$label]="$pid"
    done < "${LOG_DIR}/peer_ids.tsv"
}

# Sender invocation. Note we re-use the same listen port as the c1 node
# would conflict, so the sender uses a random port.
send_one() {
    local sender="$1"
    local recipient="$2"
    local rid="${PEER_ID[$recipient]:-}"
    if [ -z "$rid" ]; then
        log_warn "  ${sender} -> ${recipient}: no recipient peer-id, skipping"
        return 0
    fi
    local logfile_label="c3_send_${sender}_to_${recipient}"
    log_info "  ${sender} -> ${recipient}: ${TRANSFER_BYTES} bytes (rid=${rid})"

    local cmd
    if [ "$sender" = "L1" ]; then
        # shellcheck disable=SC2086
        portable_timeout "${TRANSFER_TIMEOUT}" "${NODE_BIN[$sender]}" \
            --listen "[::]:0" \
            --no-default-bootstrap \
            --known-peers "${KNOWN_CSV}" \
            --json --duration $((TRANSFER_TIMEOUT - 5)) \
            --send-to "${rid}" \
            --send-to-timeout "${SEND_TO_TIMEOUT}" \
            --generate-data "${TRANSFER_BYTES}" \
            --chunk-size "${CHUNK_SIZE}" \
            > "${LOG_DIR}/${logfile_label}.log" 2>&1 || true
    else
        cmd="${NODE_BIN[$sender]} \
            --listen '[::]:0' \
            --no-default-bootstrap \
            --known-peers '${KNOWN_CSV}' \
            --json --duration $((TRANSFER_TIMEOUT - 5)) \
            --send-to '${rid}' \
            --send-to-timeout ${SEND_TO_TIMEOUT} \
            --generate-data ${TRANSFER_BYTES} \
            --chunk-size ${CHUNK_SIZE}"
        # Prefer `gtimeout` (coreutils on macOS) or `timeout` (GNU on Linux);
        # fall back to a shell watchdog so Darwin studios without either still work.
        local remote_wrap="if command -v gtimeout >/dev/null 2>&1; then gtimeout ${TRANSFER_TIMEOUT} ${cmd}; elif command -v timeout >/dev/null 2>&1; then timeout ${TRANSFER_TIMEOUT} ${cmd}; else ${cmd} & pid=\$!; (sleep ${TRANSFER_TIMEOUT}; kill -TERM \$pid 2>/dev/null; sleep 2; kill -KILL \$pid 2>/dev/null) & wd=\$!; wait \$pid 2>/dev/null; rc=\$?; kill \$wd 2>/dev/null; exit \$rc; fi"
        ssh "${SSH_OPTS[@]}" "${NODE_SSH[$sender]}" "$remote_wrap" \
            > "${LOG_DIR}/${logfile_label}.log" 2>&1 || true
    fi
}

send_row() {
    local s="$1"
    for r in "${NODES[@]}"; do
        [ "$s" = "$r" ] && continue
        send_one "$s" "$r"
    done
}

run() {
    load_peer_ids
    log_info "C3: starting pairwise transfers (${#NODES[@]} nodes, ${TRANSFER_BYTES} B each, PAR_SENDERS=${PAR_SENDERS})"
    local count=$(( ${#NODES[@]} * (${#NODES[@]} - 1) ))
    if [ "${PAR_SENDERS}" = "1" ]; then
        local pids=()
        for s in "${NODES[@]}"; do
            send_row "$s" &
            pids+=($!)
        done
        wait "${pids[@]}"
    else
        for s in "${NODES[@]}"; do
            send_row "$s"
        done
    fi
    log_ok "C3: ${count} pairwise transfers attempted"
}

verify() {
    log_info "C3: counting send_to_complete + data_received events"
    local sent=0 verified=0
    for f in "${LOG_DIR}"/c3_send_*.log; do
        [ -f "$f" ] || continue
        if grep -q '"event":"send_to_complete"' "$f"; then
            sent=$((sent+1))
        fi
    done
    # Recipients log to c1_<recipient>.log (since they're the c1 nodes)
    for f in "${LOG_DIR}"/c1_*.log; do
        [ -f "$f" ] || continue
        local n
        n=$(grep -c '"event":"data_received".*"sha_match":true' "$f" 2>/dev/null || true)
        verified=$((verified+n))
    done
    log_info "C3: ${sent} sender completions, ${verified} verified-chunk receptions"
    if ! assert_no_silent_drops; then
        return 1
    fi
    return 0
}

case "${1:-run}" in
    run)    run ;;
    verify) verify ;;
    all)    run && verify ;;
    *)      echo "usage: $0 {run|verify|all}" >&2; exit 64 ;;
esac
