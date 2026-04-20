#!/usr/bin/env bash
# Scenario C2: per-pair path-type matrix.
#
# Re-uses the mesh from C1 (its nodes are still running). Reads each node's
# log for `direct_path_status` events and folds them into a per-pair cell
# (direct-v4 / direct-v6 / nat_traversed / relayed / pending).
#
# Pure log-mining — does not start or stop any node. Aggregator builds the
# matrix into SUMMARY.md.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

run() {
    log_info "C2: extracting direct_path_status events from c1 logs"
    : > "${LOG_DIR}/path_types.tsv"
    for f in "${LOG_DIR}"/c1_*.log; do
        [ -f "$f" ] || continue
        local sender_label
        sender_label=$(basename "$f" .log | sed 's/^c1_//')
        # Each direct_path_status JSON line: {"event":"direct_path_status","peer_id":"<short>","status":"<repr>"}
        grep '"event":"direct_path_status"' "$f" 2>/dev/null \
            | sed -E 's/.*"peer_id":"([^"]+)".*"status":"([^"]+)".*/\1\t\2/' \
            | while IFS=$'\t' read -r peer status; do
                printf '%s\t%s\t%s\n' "$sender_label" "$peer" "$status" >> "${LOG_DIR}/path_types.tsv"
            done
    done
    local n; n=$(wc -l < "${LOG_DIR}/path_types.tsv" | tr -d ' ')
    log_ok "C2: ${n} direct_path_status events captured"
}

verify() {
    # Always passes — pure data capture. Aggregator reports the matrix in
    # SUMMARY.md and flags pairs with no path-status info.
    return 0
}

case "${1:-run}" in
    run)    run ;;
    verify) verify ;;
    all)    run && verify ;;
    *)      echo "usage: $0 {run|verify|all}" >&2; exit 64 ;;
esac
