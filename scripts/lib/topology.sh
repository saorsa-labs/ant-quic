#!/usr/bin/env bash
# Single source of truth for the cross-env mesh topology.
#
# Sourced by the orchestrator AND every scenario, so they all agree on
# which nodes exist, where they live, and which port they speak on.
#
# Borrows the VPS list from x0x's DEFAULT_BOOTSTRAP_PEERS
# (../x0x/src/network.rs:64-98) but uses port 10000 instead of x0x's 5483
# so we don't collide with running x0xd instances.
#
# After C1 mesh-up runs, NODE_PEER_ID[label] gets populated by the harness
# from each node's startup log.

# Default port for ant-quic test mesh on every node (LAN + VPS).
ANT_QUIC_PORT="${ANT_QUIC_PORT:-10000}"

# Labels — preserve insertion order via a parallel ordered array.
LAN_NODES=(L1 L2 L3)
VPS_NODES=(V_NYC V_SFO V_HEL V_NUE V_SGP V_TYO)
ALL_NODES=("${LAN_NODES[@]}" "${VPS_NODES[@]}")

# Per-node host (IP for VPS, hostname for LAN).
declare -A NODE_HOST
NODE_HOST[L1]="127.0.0.1"          # this MacBook (local exec)
NODE_HOST[L2]="studio1.local"      # mDNS hostname
NODE_HOST[L3]="studio2.local"
NODE_HOST[V_NYC]="142.93.199.50"
NODE_HOST[V_SFO]="147.182.234.192"
NODE_HOST[V_HEL]="65.21.157.229"
NODE_HOST[V_NUE]="116.203.101.172"
NODE_HOST[V_SGP]="149.28.156.231"
NODE_HOST[V_TYO]="45.77.176.184"

# IPv6 — populated where known, empty otherwise.
declare -A NODE_IPV6
NODE_IPV6[V_NYC]="2604:a880:400:d1:0:3:7db3:f001"
NODE_IPV6[V_SFO]="2604:a880:4:1d0:0:1:6ba1:f000"
NODE_IPV6[V_HEL]="2a01:4f9:c012:684b::1"
NODE_IPV6[V_NUE]="2a01:4f8:1c1a:31e6::1"
NODE_IPV6[V_SGP]="2001:19f0:4401:346:5400:5ff:fed9:9735"
NODE_IPV6[V_TYO]="2401:c080:1000:4c32:5400:5ff:fed9:9737"

# SSH target — empty for L1 (run locally), set for L2/L3/VPS.
declare -A NODE_SSH
NODE_SSH[L1]=""
NODE_SSH[L2]="studio1@studio1.local"
NODE_SSH[L3]="studio2@studio2.local"
for v in "${VPS_NODES[@]}"; do
    NODE_SSH[$v]="root@${NODE_HOST[$v]}"
done

# Per-node remote binary path. Macs use ~/ant-quic-matrix/bin/ant-quic;
# VPS use /opt/ant-quic-test/bin/ant-quic (deploy-vps.sh writes there).
declare -A NODE_BIN
NODE_BIN[L1]="${ANT_QUIC_BIN_LOCAL:-target/debug/ant-quic}"
NODE_BIN[L2]='$HOME/ant-quic-matrix/bin/ant-quic'
NODE_BIN[L3]='$HOME/ant-quic-matrix/bin/ant-quic'
for v in "${VPS_NODES[@]}"; do
    NODE_BIN[$v]="/opt/ant-quic-test/bin/ant-quic"
done

# Will be filled in after C1 mesh-up parses each node's startup log.
declare -A NODE_PEER_ID

# Comma-separated --known-peers list of VPS IPv4 addresses on the test
# port. By default returns ALL VPS, but if REACHABLE_NODES_STR is set
# (preflight populates it) the unreachable ones are excluded — otherwise
# every short-lived sender process pays the SSH-timeout cost trying to
# connect to dead nodes.
known_peers_csv() {
    local reachable="${REACHABLE_NODES_STR:-${ALL_NODES[*]}}"
    local out=""
    for v in "${VPS_NODES[@]}"; do
        # Include only if this VPS is in the reachable list.
        case " ${reachable} " in
            *" ${v} "*) : ;;
            *) continue ;;
        esac
        [ -n "$out" ] && out+=","
        out+="${NODE_HOST[$v]}:${ANT_QUIC_PORT}"
    done
    printf '%s' "$out"
}

# Pretty label for a node, e.g. "L1 (studio1.local:10000)".
pretty_node() {
    local label="$1"
    printf '%s (%s:%s)' "$label" "${NODE_HOST[$label]}" "${ANT_QUIC_PORT}"
}

# Iterate over nodes, calling a callback with each label.
# Usage: for_each_node my_callback
for_each_node() {
    local cb="$1"
    for label in "${ALL_NODES[@]}"; do
        "$cb" "$label"
    done
}

# Iterate over directed pairs (sender, recipient) where sender != recipient.
# Usage: for_each_directed_pair my_callback
for_each_directed_pair() {
    local cb="$1"
    for s in "${ALL_NODES[@]}"; do
        for r in "${ALL_NODES[@]}"; do
            [ "$s" = "$r" ] && continue
            "$cb" "$s" "$r"
        done
    done
}
