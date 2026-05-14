#!/usr/bin/env bash
set -euo pipefail

# Measure VarInt + Codec round-trip performance using criterion benchmarks
# Outputs a METRIC line with the mean round-trip time in nanoseconds.

cd "$(dirname "$0")/.."

# Build and run only the quic_benchmarks, filtering for varint benchmarks
# We limit iterations with --sample-size to keep things fast
# Remove old criterion data to avoid change comparison analysis
cargo bench --bench quic_benchmarks -- "varint" --sample-size 10 --measurement-time 1 2>&1 | tee /tmp/ant-quic-bench.out

# Parse the criterion output for mean times
# Format: varint/create_small     time:   [406.29 ps 407.86 ps 409.29 ps]
SMALL=$(grep 'create_small' /tmp/ant-quic-bench.out | sed -n 's/.*\[\([0-9.]*\) [np]s.*/\1/p' | head -1)
MEDIUM=$(grep 'create_medium' /tmp/ant-quic-bench.out | sed -n 's/.*\[\([0-9.]*\) [np]s.*/\1/p' | head -1)
LARGE=$(grep 'create_large' /tmp/ant-quic-bench.out | sed -n 's/.*\[\([0-9.]*\) [np]s.*/\1/p' | head -1)
COMPARE=$(grep 'compare' /tmp/ant-quic-bench.out | sed -n 's/.*\[\([0-9.]*\) [np]s.*/\1/p' | head -1)

# If values are in ps, convert to ns
to_ns() {
    local val=$1
    local unit=$2
    if [ "$unit" = "ps" ]; then
        echo "scale=3; $val / 1000" | bc
    else
        echo "$val"
    fi
}

SMALL_NS=$(echo "$SMALL" | awk '{print $1/1000}')
MEDIUM_NS=$(echo "$MEDIUM" | awk '{print $1/1000}')
LARGE_NS=$(echo "$LARGE" | awk '{print $1/1000}')
COMPARE_NS=$(echo "$COMPARE" | awk '{print $1/1000}')

# Calculate mean as a simple average  
MEAN=$(echo "($SMALL_NS + $MEDIUM_NS + $LARGE_NS + $COMPARE_NS) / 4" | bc -l)

echo ""
echo "=== VarInt Benchmark Results (ns) ==="
echo "create_small:  ${SMALL_NS} ns"
echo "create_medium: ${MEDIUM_NS} ns"
echo "create_large:  ${LARGE_NS} ns"
echo "compare:       ${COMPARE_NS} ns"
echo "mean:          ${MEAN} ns"
echo ""
echo "METRIC roundtrip_mean_ns=${MEAN}"
