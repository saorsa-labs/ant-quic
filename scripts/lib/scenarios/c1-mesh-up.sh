#!/usr/bin/env bash
# Scenario C1: bring every reachable node up and prove they form a mesh.
#
# - Each LAN node uses mDNS + --known-peers (the VPS list).
# - Each VPS node uses --known-peers only.
# - Wait MESH_TIMEOUT seconds.
# - For every reachable pair, assert at least one peer_connected event in
#   the sender's log mentioning the recipient's short peer ID.
#
# Side effect: populates LOG_DIR/peer_ids.tsv (label → 16-char short id)
# so subsequent scenarios can address peers by id.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

: "${LOG_DIR:?must be set}"
: "${ANT_QUIC_PORT:?must be set}"
MESH_TIMEOUT="${MESH_TIMEOUT:-60}"

PIDS=()
cleanup() { stop_pids "${PIDS[@]:-}"; }
register_cleanup cleanup

# Resolve which nodes the orchestrator says are reachable.
read -r -a NODES <<< "${REACHABLE_NODES_STR:-${ALL_NODES[*]}}"
KNOWN_CSV=$(known_peers_csv)

start_node() {
    local label="$1"
    local logfile_label="c1_${label}"
    local listen="[::]:${ANT_QUIC_PORT}"
    local mdns_args=()
    if [[ "$label" =~ ^L ]]; then
        mdns_args=(--mdns --mdns-mode both --mdns-auto-connect enabled)
    fi
    local cmd="${NODE_BIN[$label]} \
        --listen '${listen}' \
        --no-default-bootstrap \
        --known-peers '${KNOWN_CSV}' \
        --json --stats --stats-interval 5 \
        --verify-data \
        ${mdns_args[*]}"

    if [ "$label" = "L1" ]; then
        # shellcheck disable=SC2086
        local pid; pid=$(local_run_log "${logfile_label}" \
            "${NODE_BIN[$label]}" \
            --listen "${listen}" \
            --no-default-bootstrap \
            --known-peers "${KNOWN_CSV}" \
            --json --stats --stats-interval 5 \
            --verify-data \
            "${mdns_args[@]}")
        PIDS+=("$pid")
    else
        local pid; pid=$(ssh_run_log "${logfile_label}" "${NODE_SSH[$label]}" "${cmd}")
        PIDS+=("$pid")
    fi
}

run() {
    log_info "C1: starting ${#NODES[@]} nodes"
    for label in "${NODES[@]}"; do
        start_node "$label"
    done

    log_info "C1: waiting up to ${MESH_TIMEOUT}s for mesh formation"
    sleep "${MESH_TIMEOUT}"

    log_info "C1: capturing peer ids"
    : > "${LOG_DIR}/peer_ids.tsv"
    for label in "${NODES[@]}"; do
        local pid
        pid=$(extract_peer_id_from_log "c1_${label}" || true)
        if [ -n "${pid:-}" ]; then
            printf '%s\t%s\n' "$label" "$pid" >> "${LOG_DIR}/peer_ids.tsv"
            log_ok "  ${label}: ${pid}"
        else
            log_warn "  ${label}: could not extract peer id"
        fi
    done
}

verify() {
    log_info "C1: verifying every reachable pair connected"
    local fail=0
    declare -A short_id
    while IFS=$'\t' read -r label pid; do
        short_id[$label]="$pid"
    done < "${LOG_DIR}/peer_ids.tsv"

    for sender in "${NODES[@]}"; do
        local logfile="${LOG_DIR}/c1_${sender}.log"
        [ -f "$logfile" ] || { log_warn "  ${sender}: no log"; fail=1; continue; }
        for recipient in "${NODES[@]}"; do
            [ "$sender" = "$recipient" ] && continue
            local rid="${short_id[$recipient]:-}"
            if [ -z "$rid" ]; then
                continue
            fi
            # Match the binary's JSON peer_connected event referencing the
            # recipient's short id (first 16 hex chars).
            if grep -q "\"event\":\"peer_connected\".*\"peer_id\":\"${rid}\"" "$logfile" 2>/dev/null; then
                : # ok
            else
                log_warn "  ${sender} -> ${recipient}: no peer_connected for ${rid}"
                fail=1
            fi
        done
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
