#!/usr/bin/env bash
set -euo pipefail

# Local NAT traversal test runner used by tests/nat_local.rs.
# Usage:
#   scripts/run-local-nat-tests.sh [smoke|nat|all]

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
SUITE="${1:-nat}"

cd "${REPO_DIR}"

case "${SUITE}" in
    smoke)
        cargo test --test simple_nat_traversal_tests
        ;;
    nat)
        cargo test --test nat_traversal_simulation
        ;;
    all)
        cargo test --test simple_nat_traversal_tests
        cargo test --test nat_traversal_simulation
        cargo test --test address_discovery_nat_traversal
        ;;
    *)
        echo "Unknown suite: ${SUITE}" >&2
        echo "Usage: $0 [smoke|nat|all]" >&2
        exit 2
        ;;
esac
