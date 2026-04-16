#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat <<'EOF'
Usage:
  scripts/vps-test-orchestrator.sh run nat_matrix

Environment:
  MATRIX_LOOPS        Number of matrix loops (default: 3)
  BASE_DURATION       Seconds each base node stays up per loop
  PROBE_DURATION      Seconds for reverse NAT probes
  IPV6_PROBE_DURATION Seconds for IPv6 probes
EOF
}

if [[ "${1:-}" != "run" ]]; then
    usage
    exit 1
fi

case "${2:-}" in
    nat_matrix)
        exec "${SCRIPT_DIR}/run-connectivity-matrix.sh"
        ;;
    *)
        usage
        exit 1
        ;;
esac
