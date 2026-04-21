#!/usr/bin/env bash
# Scenario C4: stream evidence per pair via --counter-test.
#
# For every directed pair, run a sender process for STREAM_DURATION seconds
# with --counter-test --counter-interval 100ms. Each counter is one new
# uni-stream, so the counter rate is a proxy for stream open/close health.
#
# Recipient is the c1_<recipient> node (still running with --echo if its
# c1 args included it — otherwise we just count counter_sent events from
# the sender side).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

: "${LOG_DIR:?must be set}"
STREAM_DURATION="${STREAM_DURATION:-30}"
COUNTER_INTERVAL_MS="${COUNTER_INTERVAL_MS:-100}"

read -r -a NODES <<< "${REACHABLE_NODES_STR:-${ALL_NODES[*]}}"
KNOWN_CSV=$(known_peers_csv)

declare -A PEER_ID
load_peer_ids() {
    [ -f "${LOG_DIR}/peer_ids.tsv" ] || { log_error "C4: peer_ids.tsv missing"; return 1; }
    while IFS=$'\t' read -r label pid; do
        PEER_ID[$label]="$pid"
    done < "${LOG_DIR}/peer_ids.tsv"
}

stream_one() {
    local sender="$1" recipient="$2"
    local rid="${PEER_ID[$recipient]:-}"
    [ -z "$rid" ] && return 0
    local logfile_label="c4_stream_${sender}_to_${recipient}"
    log_info "  ${sender} -> ${recipient}: ${STREAM_DURATION}s @ ${COUNTER_INTERVAL_MS}ms"

    if [ "$sender" = "L1" ]; then
        portable_timeout $((STREAM_DURATION + 10)) "${NODE_BIN[$sender]}" \
            --listen "[::]:0" \
            --no-default-bootstrap \
            --known-peers "${KNOWN_CSV}" \
            --json --duration "${STREAM_DURATION}" \
            --connect-peer-id "${rid}" \
            --counter-test --counter-interval "${COUNTER_INTERVAL_MS}" \
            > "${LOG_DIR}/${logfile_label}.log" 2>&1 || true
    else
        local cmd="${NODE_BIN[$sender]} \
            --listen '[::]:0' \
            --no-default-bootstrap \
            --known-peers '${KNOWN_CSV}' \
            --json --duration ${STREAM_DURATION} \
            --connect-peer-id '${rid}' \
            --counter-test --counter-interval ${COUNTER_INTERVAL_MS}"
        local wall=$((STREAM_DURATION + 10))
        # Prefer `gtimeout` (coreutils on macOS) or `timeout` (GNU on Linux);
        # fall back to a shell watchdog so Darwin studios without either still work.
        local remote_wrap="if command -v gtimeout >/dev/null 2>&1; then gtimeout ${wall} ${cmd}; elif command -v timeout >/dev/null 2>&1; then timeout ${wall} ${cmd}; else ${cmd} & pid=\$!; (sleep ${wall}; kill -TERM \$pid 2>/dev/null; sleep 2; kill -KILL \$pid 2>/dev/null) & wd=\$!; wait \$pid 2>/dev/null; rc=\$?; kill \$wd 2>/dev/null; exit \$rc; fi"
        ssh "${SSH_OPTS[@]}" "${NODE_SSH[$sender]}" "$remote_wrap" \
            > "${LOG_DIR}/${logfile_label}.log" 2>&1 || true
    fi
}

run() {
    load_peer_ids
    log_info "C4: stream tests across ${#NODES[@]} nodes"
    local count=0
    for s in "${NODES[@]}"; do
        for r in "${NODES[@]}"; do
            [ "$s" = "$r" ] && continue
            stream_one "$s" "$r"
            count=$((count+1))
        done
    done
    log_ok "C4: ${count} stream tests attempted"
}

verify() {
    local total=0
    for f in "${LOG_DIR}"/c4_stream_*.log; do
        [ -f "$f" ] || continue
        local n
        n=$(grep -c '"event":"counter_sent"' "$f" 2>/dev/null || true)
        total=$((total+n))
    done
    log_info "C4: ${total} counter_sent events across all pairs"
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
