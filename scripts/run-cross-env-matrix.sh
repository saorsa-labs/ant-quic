#!/usr/bin/env bash
# Top-level orchestrator for the cross-environment ant-quic test.
#
# Runs one or more scenarios under scripts/lib/scenarios/ against a mixed
# topology (this MacBook + 2 Mac Studios on the local LAN, plus the
# saorsa-N.saorsalabs.com VPS fleet). Aggregates per-node logs into
# SUMMARY.md via scripts/lib/aggregate.py.
#
# Usage:
#   scripts/run-cross-env-matrix.sh                       # run all scenarios
#   scripts/run-cross-env-matrix.sh --scenario c1-lan-mdns
#   scripts/run-cross-env-matrix.sh --list                # list scenarios
#   scripts/run-cross-env-matrix.sh --no-deploy           # skip VPS deploy step
#
# Env knobs:
#   ANT_QUIC_BIN_LOCAL    macOS ant-quic binary (default: target/release/ant-quic)
#   STUDIO1_TARGET        SSH target for studio 1 (e.g. studio1@studio1.local)
#   STUDIO2_TARGET        SSH target for studio 2
#   REGISTRY_HEALTH_URL   Default https://saorsa-1.saorsalabs.com/health
#   LOG_DIR               Override default log dir
#
# Exits non-zero if any scenario's verify() fails OR aggregate.py reports FAIL.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
LIB_DIR="${SCRIPT_DIR}/lib"
SCENARIOS_DIR="${LIB_DIR}/scenarios"

export LOG_DIR="${LOG_DIR:-${REPO_DIR}/target/cross-env/$(date +%Y%m%d-%H%M%S)}"
export ANT_QUIC_BIN_LOCAL="${ANT_QUIC_BIN_LOCAL:-${REPO_DIR}/target/release/ant-quic}"
export REGISTRY_HEALTH_URL="${REGISTRY_HEALTH_URL:-https://saorsa-1.saorsalabs.com/health}"
# Reuse the SSH options shape from run-connectivity-matrix.sh.
export SSH_OPTS=(
    -4
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o ControlMaster=no
    -o ControlPath=none
    -o StrictHostKeyChecking=accept-new
)

# shellcheck disable=SC1091
source "${LIB_DIR}/cross-env-common.sh"

mkdir -p "${LOG_DIR}"

print_help() {
    sed -n '2,25p' "$0"
}

list_scenarios() {
    log_info "Available scenarios:"
    for s in "${SCENARIOS_DIR}"/*.sh; do
        [ -f "$s" ] || continue
        printf '  %s\n' "$(basename "${s%.sh}")"
    done
}

preflight() {
    log_info "preflight: ant-quic local binary"
    if [ ! -x "${ANT_QUIC_BIN_LOCAL}" ]; then
        log_error "ANT_QUIC_BIN_LOCAL not found or not executable: ${ANT_QUIC_BIN_LOCAL}"
        log_error "  build with: cargo build --release --bin ant-quic"
        return 1
    fi

    log_info "preflight: registry health"
    if ! curl -fsSm 5 "${REGISTRY_HEALTH_URL}" >/dev/null 2>&1; then
        log_warn "registry health probe failed (${REGISTRY_HEALTH_URL}); LAN-only scenarios will still run"
    else
        log_ok "registry healthy"
    fi

    log_info "preflight: studio reachability"
    for target in "${STUDIO1_TARGET:-}" "${STUDIO2_TARGET:-}"; do
        [ -n "$target" ] || continue
        if ! ssh "${SSH_OPTS[@]}" "$target" true 2>/dev/null; then
            log_warn "studio ${target} unreachable; scenarios needing it will skip"
        else
            log_ok "studio ${target} reachable"
        fi
    done
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
