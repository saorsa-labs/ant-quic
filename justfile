# ant-quic development recipes
# Use `just --list` to see available commands.

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Show available recipes
default:
    just --list

# Format all Rust code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Run clippy with the repository's zero-warning policy
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Fast compile check for all targets/features
check:
    cargo check --all-targets --all-features

# Run library tests
unit-test:
    cargo test --lib --all-features -- --test-threads=2

# Run documentation tests
doc-test:
    cargo test --doc --all-features

# Run quick integration suite
quick-test:
    cargo test --test quick --all-features -- --test-threads=2 --skip auto_binding --skip binding_stream --skip kem_group_is_restricted_with_provider

# Run standard integration suite
standard-test:
    cargo test --test standard --all-features -- --test-threads=2

# Run property tests in release mode
property-test:
    cargo test --test property_tests --release --all-features -- --test-threads=4

# Compile all benchmarks without running them
bench-check:
    cargo bench --all-features --no-run

# Full PR-style validation: format, lint, library/doc/quick/standard/property tests, benchmark compile
full-test: fmt-check lint unit-test doc-test quick-test standard-test property-test bench-check

# Integration coverage report including tests; requires cargo-llvm-cov
coverage-integration:
    cargo llvm-cov --all-features --workspace --tests --ignore-filename-regex '(benches/|examples/|build\.rs)'

# Heavy/manual NAT Docker tests; requires Docker/network namespace support
heavy-nat:
    cargo test --test docker_nat_integration --all-features -- --ignored --test-threads=1 --nocapture
    cargo test --test nat_docker_integration --all-features -- --ignored --test-threads=1 --nocapture

# Heavy/manual long and stress tests; intended for scheduled/local runs, not normal PR CI
heavy-long:
    cargo test --test long --all-features --release -- --ignored --test-threads=1 --nocapture
    cargo test --lib --all-features --release -- --ignored stress --test-threads=1 --nocapture

# Heavy/manual live mDNS smoke tests; requires ANT_QUIC_LIVE_MDNS=1 and LAN multicast support
heavy-mdns:
    test "${ANT_QUIC_LIVE_MDNS:-}" = "1"
    cargo test mdns --all-features -- --ignored --test-threads=1 --nocapture

# Heavy/manual live UPnP smoke tests; requires ANT_QUIC_LIVE_UPNP=1 and a real IGD/UPnP gateway
heavy-upnp:
    test "${ANT_QUIC_LIVE_UPNP:-}" = "1"
    cargo test upnp --all-features -- --ignored --test-threads=1 --nocapture

# Heavy/manual scheduled benchmark run for currently wired Criterion benches
heavy-bench:
    cargo bench --all-features --bench quic_benchmarks
    cargo bench --all-features --bench nat_traversal_performance
    cargo bench --all-features --bench connection_management

# Full manual validation including PR suite plus heavy/manual suites where environment supports them
manual-full-test: full-test heavy-nat heavy-long heavy-bench
