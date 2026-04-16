#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-linux-gnu}"
MATRIX_LOOPS="${MATRIX_LOOPS:-3}"
BASE_DURATION="${BASE_DURATION:-900}"
PUBLIC_BOOT_WAIT_SECS="${PUBLIC_BOOT_WAIT_SECS:-25}"
MDNS_WAIT_SECS="${MDNS_WAIT_SECS:-25}"
PROBE_DURATION="${PROBE_DURATION:-45}"
IPV6_PROBE_DURATION="${IPV6_PROBE_DURATION:-20}"
PROBE_WALL_TIMEOUT_SECS="${PROBE_WALL_TIMEOUT_SECS:-120}"
IPV6_PROBE_WALL_TIMEOUT_SECS="${IPV6_PROBE_WALL_TIMEOUT_SECS:-60}"
PUBLIC_PORT="${PUBLIC_PORT:-10000}"
SKIP_DEPLOY="${SKIP_DEPLOY:-0}"
SSH_RETRIES="${SSH_RETRIES:-5}"
SSH_RETRY_DELAY_SECS="${SSH_RETRY_DELAY_SECS:-2}"
LOG_DIR="${LOG_DIR:-${REPO_DIR}/target/connectivity-matrix/$(date +%Y%m%d-%H%M%S)}"

SSH_OPTS=(
    -4
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o ControlMaster=no
    -o ControlPath=none
    -o StrictHostKeyChecking=accept-new
)

PUBLIC_NAMES=("saorsa1" "saorsa2" "vultr1" "vultr2")
PUBLIC_TARGETS=(
    "root@77.42.75.115"
    "root@142.93.199.50"
    "root@149.28.156.231"
    "root@45.77.176.184"
)
PUBLIC_IPV4S=(
    "77.42.75.115"
    "142.93.199.50"
    "149.28.156.231"
    "45.77.176.184"
)

LOCAL_NAMES=("macbook" "studio1" "studio2")
LOCAL_TARGETS=("LOCAL" "studio1@studio1.local" "studio2@studio2.local")

REMOTE_LINUX_BINARY_PATH="/root/ant-quic-matrix/bin/ant-quic"
REMOTE_STUDIO_BINARY_PATH="ant-quic-matrix/bin/ant-quic"

LOCAL_MATRIX_BINARY="${REPO_DIR}/target/release/ant-quic"
LINUX_RELEASE_BINARY="${REPO_DIR}/target/${TARGET_TRIPLE}/release/ant-quic"

mkdir -p "${LOG_DIR}"

LOCAL_BASE_PID=""
LOCAL_BASE_LOG=""
PUBLIC_REMOTE_LOGS=()
PUBLIC_REMOTE_PIDS=()
PUBLIC_PEER_IDS=()
PUBLIC_IPV6S=()
LOCAL_REMOTE_LOGS=()
LOCAL_REMOTE_PIDS=()
LOCAL_PEER_IDS=()
LOCAL_IPV4S=()
LOCAL_EXTERNAL_ADDRS=()

print_header() {
    echo
    echo "== $1 =="
}

print_step() {
    echo "-- $1"
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

if [[ -n "${PUBLIC_NAMES_CSV:-}" ]]; then
    IFS=',' read -r -a PUBLIC_NAMES <<< "${PUBLIC_NAMES_CSV}"
fi

if [[ -n "${PUBLIC_TARGETS_CSV:-}" ]]; then
    IFS=',' read -r -a PUBLIC_TARGETS <<< "${PUBLIC_TARGETS_CSV}"
fi

if [[ -n "${PUBLIC_IPV4S_CSV:-}" ]]; then
    IFS=',' read -r -a PUBLIC_IPV4S <<< "${PUBLIC_IPV4S_CSV}"
fi

if [[ -n "${LOCAL_NAMES_CSV:-}" ]]; then
    IFS=',' read -r -a LOCAL_NAMES <<< "${LOCAL_NAMES_CSV}"
fi

if [[ -n "${LOCAL_TARGETS_CSV:-}" ]]; then
    IFS=',' read -r -a LOCAL_TARGETS <<< "${LOCAL_TARGETS_CSV}"
fi

if [[ ${#PUBLIC_NAMES[@]} -ne ${#PUBLIC_TARGETS[@]} ]]; then
    fail "PUBLIC_NAMES and PUBLIC_TARGETS length mismatch"
fi

if [[ ${#PUBLIC_IPV4S[@]} -ne ${#PUBLIC_TARGETS[@]} ]]; then
    fail "PUBLIC_IPV4S and PUBLIC_TARGETS length mismatch"
fi

if [[ ${#LOCAL_NAMES[@]} -ne ${#LOCAL_TARGETS[@]} ]]; then
    fail "LOCAL_NAMES and LOCAL_TARGETS length mismatch"
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

ssh_run() {
    local target="$1"
    shift
    local attempt=1
    local status=0

    while true; do
        if ssh "${SSH_OPTS[@]}" "${target}" "$@"; then
            return 0
        fi
        status=$?
        if (( attempt >= SSH_RETRIES )); then
            return "${status}"
        fi
        sleep "${SSH_RETRY_DELAY_SECS}"
        attempt=$((attempt + 1))
    done
}

scp_copy() {
    local source="$1"
    local destination="$2"
    local attempt=1
    local status=0

    while true; do
        if scp "${SSH_OPTS[@]}" "${source}" "${destination}"; then
            return 0
        fi
        status=$?
        if (( attempt >= SSH_RETRIES )); then
            return "${status}"
        fi
        sleep "${SSH_RETRY_DELAY_SECS}"
        attempt=$((attempt + 1))
    done
}

local_ipv4() {
    ipconfig getifaddr en0 2>/dev/null \
        || ipconfig getifaddr en1 2>/dev/null \
        || ifconfig 2>/dev/null \
            | sed -nE 's/^[[:space:]]*inet ([0-9.]+) netmask .*/\1/p' \
            | grep -v '^127\.' \
            | head -n1
}

remote_ipv4() {
    local target="$1"
    ssh_run "${target}" \
        "ipconfig getifaddr en0 2>/dev/null \
        || ipconfig getifaddr en1 2>/dev/null \
        || hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -n1 \
        || ip -o -4 addr show scope global 2>/dev/null | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1 | head -n1"
}

remote_ipv6() {
    local target="$1"
    ssh_run "${target}" \
        "ip -o -6 addr show scope global 2>/dev/null | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1 | head -n1 \
        || ifconfig 2>/dev/null | sed -nE 's/^[[:space:]]*inet6 ([0-9a-f:]+)%?.*/\1/p' | grep -vi '^fe80:' | head -n1"
}

public_known_peers_csv_except() {
    local exclude_index="${1:--1}"
    local peers=()
    local i

    for i in "${!PUBLIC_IPV4S[@]}"; do
        if [[ "${i}" != "${exclude_index}" ]]; then
            peers+=("${PUBLIC_IPV4S[$i]}:${PUBLIC_PORT}")
        fi
    done

    local joined=""
    local peer
    for peer in "${peers[@]}"; do
        if [[ -n "${joined}" ]]; then
            joined+=","
        fi
        joined+="${peer}"
    done

    printf '%s\n' "${joined}"
}

single_public_known_peer_except() {
    local exclude_index="$1"
    local i

    for i in "${!PUBLIC_IPV4S[@]}"; do
        if [[ "${i}" != "${exclude_index}" ]]; then
            printf '%s:%s\n' "${PUBLIC_IPV4S[$i]}" "${PUBLIC_PORT}"
            return 0
        fi
    done

    fail "unable to choose a public known peer excluding index ${exclude_index}"
}

wait_local_log_pattern() {
    local log_file="$1"
    local pattern="$2"
    local timeout_secs="${3:-30}"
    local elapsed=0

    while (( elapsed < timeout_secs )); do
        if [[ -f "${log_file}" ]] && grep -q -- "${pattern}" "${log_file}"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    fail "timed out waiting for pattern '${pattern}' in ${log_file}"
}

wait_remote_log_pattern() {
    local target="$1"
    local remote_log="$2"
    local pattern="$3"
    local timeout_secs="${4:-30}"
    local elapsed=0

    while (( elapsed < timeout_secs )); do
        if ssh_run "${target}" "test -f '${remote_log}' && grep -q -- '${pattern}' '${remote_log}'"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    fail "timed out waiting for pattern '${pattern}' in ${remote_log} on ${target}"
}

extract_peer_id_from_log() {
    local log_file="$1"
    grep -m1 '"event":"local_identity"' "${log_file}" \
        | sed -E 's/.*"peer_id":"([^"]+)".*/\1/'
}

extract_remote_peer_id_from_log() {
    local target="$1"
    local remote_log="$2"
    ssh_run "${target}" \
        "grep -m1 '\"event\":\"local_identity\"' '${remote_log}' | sed -E 's/.*\"peer_id\":\"([^\"]+)\".*/\1/'"
}

extract_external_addr_from_log() {
    local log_file="$1"
    grep -m1 '"event":"external_address_discovered"' "${log_file}" \
        | sed -E 's/.*"addr":"udp:\/\/([^"]+)".*/\1/'
}

copy_remote_log() {
    local target="$1"
    local remote_log="$2"
    local local_log="$3"
    ssh_run "${target}" "cat '${remote_log}'" >"${local_log}"
}

assert_grep() {
    local pattern="$1"
    local file="$2"
    local message="$3"

    grep -Eq -- "${pattern}" "${file}" || fail "${message} (${file})"
}

assert_no_grep() {
    local pattern="$1"
    local file="$2"
    local message="$3"

    if grep -Eq -- "${pattern}" "${file}"; then
        fail "${message} (${file})"
    fi
}

analyze_log_for_bugs() {
    local file="$1"
    assert_no_grep 'panicked at|thread .+ panicked|stack backtrace|Segmentation fault' "${file}" \
        "bug signature detected"
    assert_no_grep '(^|[[:space:]])ERROR[[:space:]]' "${file}" "error log detected"
}

build_binaries() {
    print_header "Build"

    require_command cargo
    require_command cargo-zigbuild
    require_command zig
    require_command ssh
    require_command scp
    require_command python3

    print_step "Building local release binary"
    (
        cd "${REPO_DIR}"
        cargo build --release --bin ant-quic
    )

    print_step "Building ${TARGET_TRIPLE} release binary"
    (
        cd "${REPO_DIR}"
        cargo zigbuild --release --bin ant-quic --target "${TARGET_TRIPLE}"
    )

    [[ -x "${LOCAL_MATRIX_BINARY}" ]] || fail "local matrix binary not found"
    [[ -x "${LINUX_RELEASE_BINARY}" ]] || fail "linux release binary not found"
}

deploy_public_hosts() {
    if [[ "${SKIP_DEPLOY}" == "1" ]]; then
        print_header "Deploy Public Hosts"
        print_step "Skipping public deploy"
        return
    fi

    print_header "Deploy Public Hosts"

    local i
    for i in "${!PUBLIC_TARGETS[@]}"; do
        local name="${PUBLIC_NAMES[$i]}"
        local target="${PUBLIC_TARGETS[$i]}"
        print_step "Deploying to ${name} (${target})"
        ssh_run "${target}" "mkdir -p /root/ant-quic-matrix/bin"
        scp_copy "${LINUX_RELEASE_BINARY}" "${target}:${REMOTE_LINUX_BINARY_PATH}.new"
        ssh_run "${target}" \
            "chmod +x '${REMOTE_LINUX_BINARY_PATH}.new' \
            && mv '${REMOTE_LINUX_BINARY_PATH}.new' '${REMOTE_LINUX_BINARY_PATH}' \
            && '${REMOTE_LINUX_BINARY_PATH}' --version"
    done
}

deploy_local_hosts() {
    if [[ "${SKIP_DEPLOY}" == "1" ]]; then
        print_header "Deploy Local Hosts"
        print_step "Skipping local deploy"
        return
    fi

    print_header "Deploy Local Hosts"

    local i
    for i in "${!LOCAL_TARGETS[@]}"; do
        if [[ "${i}" == "0" ]]; then
            continue
        fi
        local name="${LOCAL_NAMES[$i]}"
        local target="${LOCAL_TARGETS[$i]}"
        print_step "Deploying to ${name} (${target})"
        ssh_run "${target}" "mkdir -p '${REMOTE_STUDIO_BINARY_PATH%/*}'"
        scp_copy "${LOCAL_MATRIX_BINARY}" "${target}:${REMOTE_STUDIO_BINARY_PATH}.new"
        ssh_run "${target}" \
            "chmod +x '${REMOTE_STUDIO_BINARY_PATH}.new' \
            && mv '${REMOTE_STUDIO_BINARY_PATH}.new' '${REMOTE_STUDIO_BINARY_PATH}' \
            && '${REMOTE_STUDIO_BINARY_PATH}' --version"
    done
}

kill_public_base_nodes() {
    local i
    for i in "${!PUBLIC_TARGETS[@]}"; do
        local pid="${PUBLIC_REMOTE_PIDS[$i]:-}"
        if [[ -n "${pid}" ]]; then
            ssh_run "${PUBLIC_TARGETS[$i]}" "kill '${pid}' >/dev/null 2>&1 || true" || true
        fi
    done
}

kill_local_base_nodes() {
    if [[ -n "${LOCAL_BASE_PID}" ]]; then
        kill "${LOCAL_BASE_PID}" >/dev/null 2>&1 || true
    fi

    local i
    for i in "${!LOCAL_TARGETS[@]}"; do
        if [[ "${i}" == "0" ]]; then
            continue
        fi
        local pid="${LOCAL_REMOTE_PIDS[$i]:-}"
        if [[ -n "${pid}" ]]; then
            kill "${pid}" >/dev/null 2>&1 || true
        fi
    done
}

cleanup() {
    kill_local_base_nodes
    kill_public_base_nodes
}

trap cleanup EXIT INT TERM

start_public_base_nodes() {
    local loop="$1"
    local i
    local j

    print_header "Loop ${loop}: Public Base Nodes"
    for i in "${!PUBLIC_TARGETS[@]}"; do
        local name="${PUBLIC_NAMES[$i]}"
        local target="${PUBLIC_TARGETS[$i]}"
        local known_peers
        local known_peers_flag=""
        local remote_log
        known_peers=""
        for ((j = 0; j < i; j++)); do
            if [[ -n "${known_peers}" ]]; then
                known_peers+=","
            fi
            known_peers+="${PUBLIC_IPV4S[$j]}:${PUBLIC_PORT}"
        done
        if [[ -n "${known_peers}" ]]; then
            known_peers_flag="--known-peers \"${known_peers}\""
        fi
        remote_log="/tmp/ant-quic-matrix-${name}-loop${loop}.log"
        PUBLIC_REMOTE_LOGS[$i]="${remote_log}"

        print_step "Starting ${name}"
        PUBLIC_REMOTE_PIDS[$i]=$(ssh_run "${target}" "sh -lc '
            pkill -f \"^${REMOTE_LINUX_BINARY_PATH}( |$)\" >/dev/null 2>&1 || true
            rm -f \"${remote_log}\"
            nohup \"${REMOTE_LINUX_BINARY_PATH}\" \
                --listen \"[::]:${PUBLIC_PORT}\" \
                --json \
                --duration \"${BASE_DURATION}\" \
                --no-default-bootstrap \
                --no-port-mapping \
                --no-mdns \
                ${known_peers_flag} \
                --counter-test \
                --counter-interval 1000 \
                --echo \
                >\"${remote_log}\" 2>&1 </dev/null &
            printf \"%s\n\" \$!
        '")

        wait_remote_log_pattern "${target}" "${remote_log}" "local_identity" 30
        PUBLIC_PEER_IDS[$i]=$(extract_remote_peer_id_from_log "${target}" "${remote_log}")
        PUBLIC_IPV6S[$i]=$(remote_ipv6 "${target}" || true)
    done
}

start_local_base_nodes() {
    local loop="$1"
    local namespace="matrix-${loop}-$(date +%s)"
    local public_known_peers
    local macbook_ip
    local i

    print_header "Loop ${loop}: Local Base Nodes"
    public_known_peers=$(public_known_peers_csv_except -1)
    macbook_ip=$(local_ipv4)
    [[ -n "${macbook_ip}" ]] || fail "could not determine MacBook LAN IPv4 address"
    LOCAL_IPV4S[0]="${macbook_ip}"
    LOCAL_BASE_LOG="${LOG_DIR}/macbook-loop${loop}.log"

        print_step "Starting macbook (${macbook_ip})"
    pkill -f "^${LOCAL_MATRIX_BINARY}( |$).*--mdns-service ant-quic-matrix" >/dev/null 2>&1 || true
    (
        cd "${REPO_DIR}"
        "${LOCAL_MATRIX_BINARY}" \
            --listen "${macbook_ip}:0" \
            --json \
            --duration "${BASE_DURATION}" \
            --known-peers "${public_known_peers}" \
            --no-port-mapping \
            --mdns \
            --mdns-service ant-quic-matrix \
            --mdns-namespace "${namespace}" \
            --counter-test \
            --counter-interval 1000 \
            >"${LOCAL_BASE_LOG}" 2>&1
    ) &
    LOCAL_BASE_PID=$!
    wait_local_log_pattern "${LOCAL_BASE_LOG}" "local_identity" 30
    LOCAL_PEER_IDS[0]=$(extract_peer_id_from_log "${LOCAL_BASE_LOG}")

    for i in "${!LOCAL_TARGETS[@]}"; do
        if [[ "${i}" == "0" ]]; then
            continue
        fi
        local name="${LOCAL_NAMES[$i]}"
        local target="${LOCAL_TARGETS[$i]}"
        local lan_ip
        local local_log

        lan_ip=$(remote_ipv4 "${target}")
        [[ -n "${lan_ip}" ]] || fail "could not determine ${name} LAN IPv4 address"
        LOCAL_IPV4S[$i]="${lan_ip}"
        local_log="${LOG_DIR}/${name}-loop${loop}.log"
        LOCAL_REMOTE_LOGS[$i]="${local_log}"

        print_step "Starting ${name} (${lan_ip})"
        ssh_run "${target}" "pkill -f '^${REMOTE_STUDIO_BINARY_PATH}( |$)' >/dev/null 2>&1 || true"
        rm -f "${local_log}"
        ssh "${SSH_OPTS[@]}" "${target}" \
            "'${REMOTE_STUDIO_BINARY_PATH}' \
                --listen '${lan_ip}:0' \
                --json \
                --duration '${BASE_DURATION}' \
                --known-peers '${public_known_peers}' \
                --no-port-mapping \
                --mdns \
                --mdns-service ant-quic-matrix \
                --mdns-namespace '${namespace}' \
                --counter-test \
                --counter-interval 1000" \
            >"${local_log}" 2>&1 &
        LOCAL_REMOTE_PIDS[$i]=$!

        wait_local_log_pattern "${local_log}" "local_identity" 30
        LOCAL_PEER_IDS[$i]=$(extract_peer_id_from_log "${local_log}")
    done
}

collect_base_logs() {
    local loop="$1"
    local i

    for i in "${!PUBLIC_TARGETS[@]}"; do
        copy_remote_log \
            "${PUBLIC_TARGETS[$i]}" \
            "${PUBLIC_REMOTE_LOGS[$i]}" \
            "${LOG_DIR}/${PUBLIC_NAMES[$i]}-loop${loop}.log"
    done

    for i in "${!LOCAL_TARGETS[@]}"; do
        if [[ "${i}" == "0" ]]; then
            continue
        fi
        local log_file="${LOG_DIR}/${LOCAL_NAMES[$i]}-loop${loop}.log"
        [[ -f "${log_file}" ]] || fail "missing local studio log ${log_file}"
    done
}

assert_base_connectivity() {
    local loop="$1"
    local i

    print_header "Loop ${loop}: Base Connectivity"

    sleep "${PUBLIC_BOOT_WAIT_SECS}"
    collect_base_logs "${loop}"

    for i in "${!PUBLIC_TARGETS[@]}"; do
        local log_file="${LOG_DIR}/${PUBLIC_NAMES[$i]}-loop${loop}.log"
        assert_grep '"event":"peer_connected"' "${log_file}" \
            "${PUBLIC_NAMES[$i]} missing peer_connected events"
        assert_grep '"event":"counter_received"' "${log_file}" \
            "${PUBLIC_NAMES[$i]} missing counter round-trip"
        analyze_log_for_bugs "${log_file}"
    done

    sleep "${MDNS_WAIT_SECS}"
    if [[ "${LOCAL_BASE_LOG}" != "${LOG_DIR}/macbook-loop${loop}.log" ]]; then
        cp "${LOCAL_BASE_LOG}" "${LOG_DIR}/macbook-loop${loop}.log"
    fi
    for i in "${!LOCAL_TARGETS[@]}"; do
        if [[ "${i}" == "0" ]]; then
            continue
        fi
        local log_file="${LOG_DIR}/${LOCAL_NAMES[$i]}-loop${loop}.log"
        [[ -f "${log_file}" ]] || fail "missing local studio log ${log_file}"
    done

    for i in "${!LOCAL_TARGETS[@]}"; do
        local log_file="${LOG_DIR}/${LOCAL_NAMES[$i]}-loop${loop}.log"
        assert_grep '"event":"peer_connected"' "${log_file}" \
            "${LOCAL_NAMES[$i]} missing peer_connected events"
        assert_grep '"event":"counter_received"' "${log_file}" \
            "${LOCAL_NAMES[$i]} missing counter round-trip"
        assert_grep '"event":"mdns_service_advertised"' "${log_file}" \
            "${LOCAL_NAMES[$i]} missing mDNS advertise event"
        assert_grep '"event":"mdns_peer_discovered"' "${log_file}" \
            "${LOCAL_NAMES[$i]} missing mDNS discovery event"
        analyze_log_for_bugs "${log_file}"
        LOCAL_EXTERNAL_ADDRS[$i]=$(extract_external_addr_from_log "${log_file}")
        [[ -n "${LOCAL_EXTERNAL_ADDRS[$i]}" ]] || fail "${LOCAL_NAMES[$i]} missing discovered external address"
    done
}

run_public_to_local_probe() {
    local loop="$1"
    local public_index="$2"
    local local_index="$3"
    local public_name="${PUBLIC_NAMES[$public_index]}"
    local public_target="${PUBLIC_TARGETS[$public_index]}"
    local local_name="${LOCAL_NAMES[$local_index]}"
    local coordinator_known_peers
    local probe_peer_id
    local probe_short_peer_id
    local target_log_file="${LOG_DIR}/${local_name}-loop${loop}.log"
    local public_log_file="${LOG_DIR}/${public_name}-loop${loop}.log"
    local public_peer_id="${PUBLIC_PEER_IDS[$public_index]}"
    local public_short_peer_id="${public_peer_id:0:16}"
    local target_peer_id="${LOCAL_PEER_IDS[$local_index]}"
    local target_short_peer_id="${target_peer_id:0:16}"
    local log_file="${LOG_DIR}/loop${loop}-${public_name}-to-${local_name}.log"
    local probe_status=0

    coordinator_known_peers="${PUBLIC_IPV4S[$public_index]}:${PUBLIC_PORT}"

    if grep -Eq "\"event\":\"peer_connected\".*\"peer_id\":\"${target_short_peer_id}\".*\"connection_type\":\"(direct|nat_traversed)\"" "${public_log_file}" \
        && grep -Eq "\"event\":\"counter_(sent|received)\".*\"peer\":\"${target_short_peer_id}\"" "${public_log_file}" \
        && grep -Eq "\"event\":\"peer_connected\".*\"peer_id\":\"${public_short_peer_id}\".*\"connection_type\":\"(direct|nat_traversed)\"" "${target_log_file}" \
        && grep -Eq "\"event\":\"counter_(sent|received)\".*\"peer\":\"${public_short_peer_id}\"" "${target_log_file}"; then
        print_step "Probe ${public_name} -> ${local_name} satisfied by base node connectivity"
        return 0
    fi

    print_step "Probe ${public_name} -> ${local_name}"
    set +e
    ssh_run "${public_target}" \
        "timeout '${PROBE_WALL_TIMEOUT_SECS}' \
            '${REMOTE_LINUX_BINARY_PATH}' \
                --json \
                --duration '${PROBE_DURATION}' \
                --no-default-bootstrap \
                --no-port-mapping \
                --no-mdns \
                --known-peers '${coordinator_known_peers}' \
                --connect-peer-id '${target_peer_id}' \
                --counter-test \
                --counter-interval 1000" \
        >"${log_file}" 2>&1
    probe_status=$?
    set -e

    if [[ "${probe_status}" -ne 0 && "${probe_status}" -ne 124 ]]; then
        fail "${public_name} -> ${local_name} probe failed with exit ${probe_status}"
    fi

    probe_peer_id=$(extract_peer_id_from_log "${log_file}")
    [[ -n "${probe_peer_id}" ]] || fail "${public_name} -> ${local_name} missing probe peer identity"
    probe_short_peer_id="${probe_peer_id:0:16}"

    assert_grep "\"event\":\"peer_connected\".*\"peer_id\":\"${target_short_peer_id}\".*\"connection_type\":\"(direct|nat_traversed)\"" "${log_file}" \
        "${public_name} -> ${local_name} did not establish a direct or NAT-traversed path"
    assert_no_grep "\"event\":\"peer_connected\".*\"peer_id\":\"${target_short_peer_id}\".*\"connection_type\":\"relayed\"" "${log_file}" \
        "${public_name} -> ${local_name} fell back to relay"
    assert_grep "\"event\":\"direct_path_status\".*\"peer_id\":\"${target_short_peer_id}\".*Established" "${log_file}" \
        "${public_name} -> ${local_name} missing established direct-path status"
    assert_grep "\"event\":\"counter_sent\".*\"peer\":\"${target_short_peer_id}\"" "${log_file}" \
        "${public_name} -> ${local_name} did not send application data after connect"
    assert_grep "\"event\":\"peer_connected\".*\"peer_id\":\"${probe_short_peer_id}\".*\"connection_type\":\"(direct|nat_traversed)\"" "${target_log_file}" \
        "${local_name} did not observe inbound connectivity from ${public_name}"
    analyze_log_for_bugs "${log_file}"
}

run_reverse_nat_matrix() {
    local loop="$1"
    local i
    local j

    print_header "Loop ${loop}: Public To Local NAT Matrix"
    for i in "${!PUBLIC_TARGETS[@]}"; do
        for j in "${!LOCAL_TARGETS[@]}"; do
            run_public_to_local_probe "${loop}" "${i}" "${j}"
        done
    done
}

run_public_ipv6_probe() {
    local loop="$1"
    local source_index="$2"
    local target_index="$3"
    local source_name="${PUBLIC_NAMES[$source_index]}"
    local source_target="${PUBLIC_TARGETS[$source_index]}"
    local target_name="${PUBLIC_NAMES[$target_index]}"
    local target_ipv6="${PUBLIC_IPV6S[$target_index]}"
    local log_file="${LOG_DIR}/loop${loop}-${source_name}-to-${target_name}-ipv6.log"
    local probe_status=0

    set +e
    ssh_run "${source_target}" \
        "timeout '${IPV6_PROBE_WALL_TIMEOUT_SECS}' \
            '${REMOTE_LINUX_BINARY_PATH}' \
                --json \
                --duration '${IPV6_PROBE_DURATION}' \
                --no-default-bootstrap \
                --no-port-mapping \
                --no-mdns \
                --connect '[${target_ipv6}]:${PUBLIC_PORT}' \
                --counter-test \
                --counter-interval 1000" \
        >"${log_file}" 2>&1
    probe_status=$?
    set -e

    if [[ "${probe_status}" -ne 0 && "${probe_status}" -ne 124 ]]; then
        fail "${source_name} -> ${target_name} IPv6 probe failed with exit ${probe_status}"
    fi

    assert_grep '"event":"peer_connected".*"connection_type":"direct"' "${log_file}" \
        "${source_name} -> ${target_name} IPv6 did not connect directly"
    assert_grep "${target_ipv6}" "${log_file}" \
        "${source_name} -> ${target_name} IPv6 log missing target address"
    assert_grep '"event":"counter_received"' "${log_file}" \
        "${source_name} -> ${target_name} IPv6 missing counter echo"
    analyze_log_for_bugs "${log_file}"
}

run_ipv6_matrix() {
    local loop="$1"
    local i
    local j

    print_header "Loop ${loop}: Public IPv6 Matrix"
    for i in "${!PUBLIC_TARGETS[@]}"; do
        [[ -n "${PUBLIC_IPV6S[$i]}" ]] || fail "${PUBLIC_NAMES[$i]} is missing a global IPv6 address"
    done

    for i in "${!PUBLIC_TARGETS[@]}"; do
        for j in "${!PUBLIC_TARGETS[@]}"; do
            if [[ "${i}" != "${j}" ]]; then
                run_public_ipv6_probe "${loop}" "${i}" "${j}"
            fi
        done
    done
}

analyze_all_logs() {
    print_header "Log Analysis"

    local file
    while IFS= read -r file; do
        analyze_log_for_bugs "${file}"
    done < <(find "${LOG_DIR}" -type f -name '*.log' | sort)
}

run_loop() {
    local loop="$1"

    cleanup
    start_public_base_nodes "${loop}"
    start_local_base_nodes "${loop}"
    assert_base_connectivity "${loop}"
    run_reverse_nat_matrix "${loop}"
    run_ipv6_matrix "${loop}"
    cleanup
}

main() {
    build_binaries
    deploy_public_hosts
    deploy_local_hosts

    local loop
    for loop in $(seq 1 "${MATRIX_LOOPS}"); do
        run_loop "${loop}"
    done

    analyze_all_logs

    print_header "Success"
    echo "Connectivity matrix completed successfully"
    echo "Logs written to ${LOG_DIR}"
}

main "$@"
