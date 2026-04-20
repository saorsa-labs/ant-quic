#!/usr/bin/env bash
# Top-level orchestrator for the comprehensive cross-environment ant-quic
# test matrix.
#
# Topology comes from scripts/lib/topology.sh — 3 LAN Macs + 6 x0x bootstrap
# VPS, all on port 10000. Registry is dropped.
#
# Usage:
#   scripts/run-cross-env-matrix.sh                        # all scenarios
#   scripts/run-cross-env-matrix.sh --scenario c1-mesh-up
#   scripts/run-cross-env-matrix.sh --list
#   scripts/run-cross-env-matrix.sh --no-preflight
#
# Env knobs:
#   ANT_QUIC_BIN_LOCAL   macOS binary on this MacBook (default target/debug/ant-quic)
#   ANT_QUIC_PORT        test mesh port (default 10000)
#   LOG_DIR              override default log directory
#   STUDIO1_TARGET / STUDIO2_TARGET   override SSH targets for L2/L3
#
# Exits non-zero if any scenario verify() fails OR aggregate.py reports FAIL.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
LIB_DIR="${SCRIPT_DIR}/lib"
SCENARIOS_DIR="${LIB_DIR}/scenarios"

export LOG_DIR="${LOG_DIR:-${REPO_DIR}/target/cross-env/$(date +%Y%m%d-%H%M%S)}"
export ANT_QUIC_BIN_LOCAL="${ANT_QUIC_BIN_LOCAL:-${REPO_DIR}/target/debug/ant-quic}"
export ANT_QUIC_PORT="${ANT_QUIC_PORT:-10000}"

mkdir -p "${LOG_DIR}"

# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"
# shellcheck disable=SC1091
source "${LIB_DIR}/topology.sh"

# Apply env-var overrides for studio targets so users can swap hostnames
# without editing topology.sh.
[ -n "${STUDIO1_TARGET:-}" ] && NODE_SSH[L2]="${STUDIO1_TARGET}"
[ -n "${STUDIO2_TARGET:-}" ] && NODE_SSH[L3]="${STUDIO2_TARGET}"

# Subset of nodes to actually use this run. preflight() prunes unreachable
# ones. Default = ALL_NODES.
REACHABLE_NODES=("${ALL_NODES[@]}")

print_help() {
    sed -n '2,18p' "$0"
}

list_scenarios() {
    log_info "Available scenarios:"
    for s in "${SCENARIOS_DIR}"/*.sh; do
        [ -f "$s" ] || continue
        printf '  %s\n' "$(basename "${s%.sh}")"
    done
}

# Probe each node's port; remove unreachable ones from REACHABLE_NODES
# and record them in skipped.txt for the aggregator.
preflight() {
    log_info "preflight: ant-quic local binary"
    if [ ! -x "${ANT_QUIC_BIN_LOCAL}" ]; then
        log_error "ANT_QUIC_BIN_LOCAL not found or not executable: ${ANT_QUIC_BIN_LOCAL}"
        log_error "  build with: cargo build --release --bin ant-quic"
        return 1
    fi

    log_info "preflight: probing ${#ALL_NODES[@]} nodes on port ${ANT_QUIC_PORT}"
    local kept=()
    : > "${LOG_DIR}/skipped.txt"
    for label in "${ALL_NODES[@]}"; do
        local host="${NODE_HOST[$label]}"
        if [ "$label" = "L1" ]; then
            kept+=("$label")
            continue
        fi
        # For non-L1 nodes, probe SSH reachability. (Node may not have a
        # process listening on ${ANT_QUIC_PORT} until C1 starts it; SSH is
        # the only reliable pre-startup probe.)
        local target="${NODE_SSH[$label]}"
        if ssh "${SSH_OPTS[@]}" "${target}" true 2>/dev/null; then
            log_ok "  ${label}: reachable via ssh ${target}"
            kept+=("$label")
        else
            log_warn "  ${label}: ssh ${target} failed — SKIPPED"
            printf '%s\t%s\n' "$label" "ssh-unreachable" >> "${LOG_DIR}/skipped.txt"
        fi
    done
    REACHABLE_NODES=("${kept[@]}")
    export REACHABLE_NODES_STR="${kept[*]}"

    if [ "${#REACHABLE_NODES[@]}" -lt 2 ]; then
        log_error "fewer than 2 reachable nodes; cannot form a mesh"
        return 1
    fi
    log_ok "preflight: ${#REACHABLE_NODES[@]} reachable nodes (${REACHABLE_NODES[*]})"
}

run_scenario() {
    local name="$1"
    local script="${SCENARIOS_DIR}/${name}.sh"
    if [ ! -x "$script" ]; then
        log_error "no executable scenario: ${script}"
        return 64
    fi
    log_info "=== Scenario: ${name} ==="
    if ! "$script" all; then
        log_error "scenario ${name} failed"
        return 1
    fi
    log_ok "scenario ${name} passed"
}

aggregate() {
    log_info "Aggregating logs into SUMMARY.md"
    if ! python3 "${LIB_DIR}/aggregate.py" "${LOG_DIR}"; then
        log_error "aggregator reported FAIL — see ${LOG_DIR}/SUMMARY.md"
        return 1
    fi
    log_ok "SUMMARY.md written"
}

main() {
    local scenarios=()
    local skip_preflight=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --scenario) scenarios+=("$2"); shift 2 ;;
            --list)     list_scenarios; exit 0 ;;
            --no-preflight) skip_preflight=1; shift ;;
            --help|-h)  print_help; exit 0 ;;
            *)          log_error "unknown arg: $1"; print_help; exit 64 ;;
        esac
    done

    if [ ${#scenarios[@]} -eq 0 ]; then
        for s in "${SCENARIOS_DIR}"/*.sh; do
            [ -f "$s" ] || continue
            scenarios+=("$(basename "${s%.sh}")")
        done
    fi

    log_info "Log dir: ${LOG_DIR}"
    log_info "Topology port: ${ANT_QUIC_PORT}"
    [ "$skip_preflight" -eq 0 ] && preflight

    local fail=0
    for name in "${scenarios[@]}"; do
        run_scenario "$name" || fail=1
    done

    aggregate || fail=1

    [ "$fail" -eq 0 ] && log_ok "ALL SCENARIOS PASSED" || log_error "ONE OR MORE SCENARIOS FAILED"
    return $fail
}

main "$@"
