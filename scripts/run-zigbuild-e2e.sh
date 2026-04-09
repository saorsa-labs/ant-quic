#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-linux-gnu}"
BUILD_PROFILE="${BUILD_PROFILE:-debug}"
LISTENER_PORT="${LISTENER_PORT:-9000}"
LISTENER_DURATION="${LISTENER_DURATION:-120}"
CLIENT_DURATION="${CLIENT_DURATION:-25}"
MDNS_DURATION="${MDNS_DURATION:-20}"
REMOTE_BINARY_PATH="${REMOTE_BINARY_PATH:-/root/ant-quic-bin}"
LOG_DIR="${LOG_DIR:-${REPO_DIR}/target/e2e-logs/$(date +%Y%m%d-%H%M%S)}"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=20)

HOST_NAMES=("saorsa1" "saorsa2" "saorsa3")
HOST_TARGETS=("root@saorsa-1.saorsalabs.com" "root@142.93.199.50" "root@147.182.234.192")
HOST_IPS=("77.42.75.115" "142.93.199.50" "147.182.234.192")
LISTENER_ACTIVE=(0 0 0)

mkdir -p "${LOG_DIR}"

LOCAL_BINARY="${REPO_DIR}/target/debug/ant-quic"
LINUX_BINARY="${REPO_DIR}/target/${TARGET_TRIPLE}/${BUILD_PROFILE}/ant-quic"
LINUX_BINARY_SHA256=""

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

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

ssh_run() {
    local target="$1"
    shift
    ssh "${SSH_OPTS[@]}" "${target}" "$@"
}

scp_copy() {
    local source="$1"
    local destination="$2"
    scp "${SSH_OPTS[@]}" "${source}" "${destination}"
}

local_ip() {
    ipconfig getifaddr en0 2>/dev/null \
        || ipconfig getifaddr en1 2>/dev/null \
        || ifconfig | awk '/inet / && $2 !~ /^127\./ { print $2; exit }'
}

log_path() {
    local name="$1"
    echo "${LOG_DIR}/${name}.log"
}

combined_log_path() {
    local name="$1"
    echo "${LOG_DIR}/${name}.combined.log"
}

cleanup() {
    for i in "${!HOST_NAMES[@]}"; do
        if [[ "${LISTENER_ACTIVE[$i]}" == "1" ]]; then
            ssh_run "${HOST_TARGETS[$i]}" \
                "pkill -f '${REMOTE_BINARY_PATH} --listen 0.0.0.0:${LISTENER_PORT}' || true" >/dev/null 2>&1 || true
        fi
    done
}

trap cleanup EXIT

build_binaries() {
    print_header "Build"

    require_command cargo
    require_command cargo-zigbuild
    require_command zig
    require_command shasum

    if [[ ! -x "${LOCAL_BINARY}" ]]; then
        print_step "Building local macOS binary"
        (cd "${REPO_DIR}" && cargo build --bin ant-quic)
    else
        print_step "Reusing existing local binary at ${LOCAL_BINARY}"
    fi

    print_step "Building ${TARGET_TRIPLE} binary with cargo zigbuild"
    local cargo_args=(zigbuild --bin ant-quic --target "${TARGET_TRIPLE}")
    if [[ "${BUILD_PROFILE}" == "release" ]]; then
        cargo_args+=(--release)
    fi
    (cd "${REPO_DIR}" && cargo "${cargo_args[@]}")

    [[ -x "${LINUX_BINARY}" ]] || fail "zigbuild output not found at ${LINUX_BINARY}"
    LINUX_BINARY_SHA256=$(shasum -a 256 "${LINUX_BINARY}" | awk '{print $1}')
}

deploy_host() {
    local index="$1"
    local name="${HOST_NAMES[$index]}"
    local target="${HOST_TARGETS[$index]}"
    local remote_tmp="${REMOTE_BINARY_PATH}.new.$$"
    local remote_hash=""

    remote_hash=$(ssh_run "${target}" \
        "sha256sum '${REMOTE_BINARY_PATH}' 2>/dev/null | awk '{print \$1}' || true")

    if [[ -n "${remote_hash}" && "${remote_hash}" == "${LINUX_BINARY_SHA256}" ]]; then
        print_step "Skipping deploy to ${name}: remote binary already matches local zigbuild output"
        return 0
    fi

    print_step "Deploying zigbuilt binary to ${name} (${target})"
    ssh_run "${target}" "rm -f '${remote_tmp}'" >/dev/null 2>&1 || true
    scp_copy "${LINUX_BINARY}" "${target}:${remote_tmp}"
    ssh_run "${target}" \
        "chmod +x '${remote_tmp}' \
        && mv '${remote_tmp}' '${REMOTE_BINARY_PATH}' \
        && '${REMOTE_BINARY_PATH}' --version" \
        >"$(log_path "deploy-${name}")"
}

deploy_all() {
    print_header "Deploy"

    require_command ssh
    require_command scp

    for i in "${!HOST_NAMES[@]}"; do
        deploy_host "${i}"
    done
}

listener_port_free() {
    local target="$1"
    if ssh_run "${target}" "ss -ulnp | grep -Eq ':${LISTENER_PORT}[[:space:]]'"; then
        return 1
    fi
    return 0
}

start_listener() {
    local index="$1"
    local name="${HOST_NAMES[$index]}"
    local target="${HOST_TARGETS[$index]}"
    local remote_log="/tmp/ant-quic-${name}-${LISTENER_PORT}.log"

    if ! listener_port_free "${target}"; then
        print_step "Skipping ${name} listener: UDP ${LISTENER_PORT} already in use"
        LISTENER_ACTIVE[$index]=0
        return 0
    fi

    print_step "Starting listener on ${name}:${LISTENER_PORT}"
    ssh_run "${target}" \
        "nohup '${REMOTE_BINARY_PATH}' \
            --listen 0.0.0.0:${LISTENER_PORT} \
            --json \
            --duration ${LISTENER_DURATION} \
            --no-default-bootstrap \
            --no-port-mapping \
            > '${remote_log}' 2>&1 < /dev/null &"
    sleep 2

    ssh_run "${target}" \
        "ss -ulnp | grep -Eq ':${LISTENER_PORT}[[:space:]].*ant-quic-bin'" \
        || fail "listener failed to bind on ${name}:${LISTENER_PORT}"

    LISTENER_ACTIVE[$index]=1
}

start_listeners() {
    print_header "Remote Listeners"

    for i in "${!HOST_NAMES[@]}"; do
        start_listener "${i}"
    done

    local active_count=0
    for flag in "${LISTENER_ACTIVE[@]}"; do
        if [[ "${flag}" == "1" ]]; then
            active_count=$((active_count + 1))
        fi
    done

    [[ "${active_count}" -gt 0 ]] || fail "no remote listeners were started"
}

active_known_peers_csv() {
    local exclude_index="${1:--1}"
    local peers=()

    for i in "${!HOST_NAMES[@]}"; do
        if [[ "${LISTENER_ACTIVE[$i]}" == "1" && "${i}" != "${exclude_index}" ]]; then
            peers+=("${HOST_IPS[$i]}:${LISTENER_PORT}")
        fi
    done

    if (( ${#peers[@]} == 0 )); then
        echo ""
        return 0
    fi

    local joined=""
    local peer
    for peer in "${peers[@]}"; do
        if [[ -n "${joined}" ]]; then
            joined+=","
        fi
        joined+="${peer}"
    done

    echo "${joined}"
}

assert_grep() {
    local pattern="$1"
    local file="$2"
    local message="$3"

    grep -Eq -- "${pattern}" "${file}" || fail "${message} (${file})"
}

assert_peer_count() {
    local file="$1"
    local minimum="$2"
    local count

    count=$(grep -c '"event":"peer_connected".*"direction":"outbound"' "${file}" || true)
    if (( count < minimum )); then
        fail "expected at least ${minimum} outbound peer_connected events in ${file}, found ${count}"
    fi
}

run_local_mdns() {
    print_header "Local mDNS"

    local lan_ip
    lan_ip=$(local_ip)
    [[ -n "${lan_ip}" ]] || fail "could not determine a non-loopback local IPv4 address"

    local namespace="zigbuild-e2e-$(date +%Y%m%d%H%M%S)"
    local log_a
    local log_b
    local combined
    log_a=$(log_path "local-mdns-a")
    log_b=$(log_path "local-mdns-b")
    combined=$(combined_log_path "local-mdns")

    print_step "Running isolated local mDNS test on ${lan_ip}"
    (
        cd "${REPO_DIR}"
        "${LOCAL_BINARY}" \
            --listen "${lan_ip}:0" \
            --json \
            --duration "${MDNS_DURATION}" \
            --no-default-bootstrap \
            --no-port-mapping \
            --mdns-service ant-quic-e2e \
            --mdns-namespace "${namespace}" \
            >"${log_a}" 2>&1 &
        local pid_a=$!
        sleep 1
        "${LOCAL_BINARY}" \
            --listen "${lan_ip}:0" \
            --json \
            --duration "${MDNS_DURATION}" \
            --no-default-bootstrap \
            --no-port-mapping \
            --mdns-service ant-quic-e2e \
            --mdns-namespace "${namespace}" \
            >"${log_b}" 2>&1 &
        local pid_b=$!

        wait "${pid_a}"
        wait "${pid_b}"
    )

    cat "${log_a}" "${log_b}" >"${combined}"

    assert_grep '"event":"mdns_service_advertised"' "${combined}" "mDNS advertise event missing"
    assert_grep '"event":"mdns_peer_discovered"' "${combined}" "mDNS peer discovery event missing"
    assert_grep '"event":"mdns_auto_connect_succeeded"' "${combined}" "mDNS auto-connect success missing"
    assert_grep '"event":"peer_connected"' "${combined}" "mDNS peer connection missing"
}

run_local_public() {
    print_header "Local To VPS"

    local known_peers
    known_peers=$(active_known_peers_csv)
    [[ -n "${known_peers}" ]] || fail "no active public listeners available for local test"

    local log_file
    log_file=$(log_path "local-public")

    print_step "Connecting local node to ${known_peers}"
    (
        cd "${REPO_DIR}"
        "${LOCAL_BINARY}" \
            --json \
            --duration "${CLIENT_DURATION}" \
            --no-default-bootstrap \
            --known-peers "${known_peers}" \
            >"${log_file}" 2>&1
    )

    local expected
    expected=$(awk -F',' '{print NF}' <<<"${known_peers}")

    assert_grep '"event":"port_mapping_(failed|established|renewed)"' "${log_file}" "local port mapping lifecycle event missing"
    assert_grep '"event":"external_address_discovered"' "${log_file}" "local external address discovery missing"
    assert_peer_count "${log_file}" "${expected}"
}

run_remote_client() {
    local index="$1"
    local name="${HOST_NAMES[$index]}"
    local target="${HOST_TARGETS[$index]}"
    local known_peers
    known_peers=$(active_known_peers_csv "${index}")

    if [[ -z "${known_peers}" ]]; then
        print_step "Skipping ${name} client run: no other active listeners"
        return 0
    fi

    local log_file
    log_file=$(log_path "${name}-public-client")

    print_step "Running ${name} client against ${known_peers}"
    ssh_run "${target}" \
        "'${REMOTE_BINARY_PATH}' \
            --json \
            --duration ${CLIENT_DURATION} \
            --no-default-bootstrap \
            --no-port-mapping \
            --known-peers '${known_peers}'" \
        >"${log_file}" 2>&1

    local expected
    expected=$(awk -F',' '{print NF}' <<<"${known_peers}")

    assert_grep '"event":"external_address_discovered"' "${log_file}" "${name} external address discovery missing"
    assert_peer_count "${log_file}" "${expected}"
}

run_remote_clients() {
    print_header "VPS To VPS"

    for i in "${!HOST_NAMES[@]}"; do
        run_remote_client "${i}"
    done
}

main() {
    build_binaries
    deploy_all
    run_local_mdns
    start_listeners
    run_local_public
    run_remote_clients

    print_header "Success"
    echo "Logs written to ${LOG_DIR}"
}

main "$@"
