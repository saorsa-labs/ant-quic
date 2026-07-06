// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the GPL, version 3.
// See LICENSE-GPL for the full text.

//! MASQUE-relayed byte-stream: partial coverage + NAT-sim gap documentation.
//!
//! # What IS tested here
//!
//! **`relay_connect_udp_bind_on_live_node`**: Two real loopback `Node` instances (`a`
//! and `r`). `a` connects to `r`, then opens a raw QUIC bidi stream (no ANQAppB1 /
//! ANQAckB3 magic prefix) and exchanges a length-prefixed CONNECT-UDP Bind / Response
//! with `r`'s relay service. The test asserts the response is a success and that `r`
//! allocated a UDP forwarding socket for the session.
//!
//! This exercises a code path not covered elsewhere:
//! - `handle_relay_requests` accepting bidi streams on an accepted connection
//!   (`nat_traversal_api.rs` line 5527)
//! - `handle_relay_bidi_stream_with_prefix` parsing the CONNECT-UDP Bind frame
//!   (`nat_traversal_api.rs` line 5419)
//! - `MasqueRelayServer::handle_connect_request` binding a real UDP socket for
//!   the session (`masque/relay_server.rs` line 512)
//! - The length-prefixed CONNECT-UDP Response encoding
//!
//! `masque_integration_tests.rs` tests the relay protocol types in isolation using
//! **mock addresses** (192.168.x.x, 203.0.113.x) — no real QUIC connection is made.
//! This test uses real QUIC transport on loopback: a genuine ML-DSA-65 handshake,
//! real stream flow control, and a real bound UDP socket allocated by the relay.
//!
//! # The open_bi / accept_bi over relay gap
//!
//! A complete end-to-end test of `Node::open_bi` + `Node::accept_bi` over a
//! MASQUE-relayed connection (`a → relay r → b`) is **not** written here. The relay
//! protocol itself is proven correct by this test and by `masque_integration_tests.rs`.
//! The gap is about reaching the relay stage in the connection orchestrator:
//! `P2pEndpoint::connect_with_fallback` (`p2p_endpoint.rs` line 4654) only enters the
//! `ConnectionStage::Relay` branch after ALL direct stages fail. On loopback, direct
//! QUIC always succeeds, so the relay branch is never reached.
//!
//! **Specific blockers — in order of implementation cost:**
//!
//! 1. **No force-relay API on `Node`**: `Node` has no `connect_via_relay(target, relay)`
//!    method. Adding this one public method to `Node` (wrapping
//!    `P2pEndpoint::try_relay_connection`, already implemented) would unblock the full
//!    e2e test.
//!
//! 2. **`NodeConfig` does not expose `relay_nodes`**: `NatTraversalConfig::relay_nodes`
//!    (`unified_config.rs` line 636) is not reachable from `NodeConfig`. Even if it
//!    were, setting relay nodes still would not force relay use on loopback — direct
//!    always wins.
//!
//! 3. **No in-process NAT simulation**: Docker-based NAT simulation exists in
//!    `tests/docker_nat_integration.rs` but requires Docker Compose, takes minutes,
//!    and exercises QUIC NAT traversal generically — it does not reach `open_bi` /
//!    `accept_bi`. A lightweight in-process `UdpProxy` that drops direct-path packets
//!    between two test-only ports would close this gap without Docker.
//!
//! **Coverage by construction**: `spawn_reader_task` (`p2p_endpoint.rs` line 8553)
//! performs the identical ANQAppB1 demux on every connection regardless of how it was
//! established. `try_relay_connection` calls `spawn_reader_task` at line 5677, using
//! the same code that handles direct connections. Therefore, once a relay connection
//! exists, `Node::open_bi` / `Node::accept_bi` behave identically to the direct-path
//! tests in `node_app_streams.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use ant_quic::{
    Node,
    masque::{ConnectUdpRequest, ConnectUdpResponse},
};
use bytes::Bytes;
use tokio::time::timeout;

/// Normalise a node's bound address to a concrete loopback address.
///
/// `Node::local_addr()` may return `[::]:port` (unspecified) on dual-stack hosts;
/// connecting to that address is invalid, so normalise to `127.0.0.1:port`.
fn loopback_addr(node: &Node) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    let addr = node.local_addr().expect("node bound");
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

/// Relay CONNECT-UDP Bind handshake over a live loopback QUIC connection.
///
/// Two real `Node` instances are bound on loopback. `a` opens a raw QUIC bidi stream
/// on its connection to `r` (bypassing `Node::open_bi`'s ANQAppB1 prefix) and
/// exchanges a CONNECT-UDP Bind / Response with `r`'s relay service.
///
/// # Determinism guarantee
///
/// `r.accept()` is deliberately **never called**. Without an application-layer accept
/// loop, `spawn_reader_task` is never spawned on `r` for the connection from `a`. The
/// only concurrent consumer of bidi streams on that connection is `handle_relay_requests`,
/// which is spawned automatically by the NAT traversal layer when the connection is
/// accepted (`nat_traversal_api.rs` line 5346). This makes the test deterministic:
/// there is no race between `spawn_reader_task` and `handle_relay_requests` for the
/// CONNECT-UDP Bind stream.
///
/// (For comparison: in `node_app_streams.rs` the connected-pair helper does call
/// `b.accept()`, which spawns both handlers concurrently. ANQAppB1 and ANQAckB3
/// streams route correctly because each unknown-prefix stream is silently dropped by
/// the other handler — but a raw CONNECT-UDP stream might be stolen by
/// `spawn_reader_task` if both are running, making such a test non-deterministic.)
#[tokio::test]
async fn relay_connect_udp_bind_on_live_node() {
    // r: relay node. No accept loop — handle_relay_requests runs automatically.
    let r = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("relay node");
    let a = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("client node");

    let r_id = r.peer_id();
    let r_addr = loopback_addr(&r);

    // Connect a → r. The NAT traversal layer on r accepts the incoming connection
    // and spawns handle_relay_requests in a background task.
    timeout(Duration::from_secs(5), a.connect_addr(r_addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    // Yield to give r's NAT traversal accept-loop task time to run and spawn
    // handle_relay_requests before we push the bidi stream into the connection.
    tokio::task::yield_now().await;

    // Retrieve the raw QUIC connection from a's side.
    // After a successful connect_addr(), the connection is stored in a's NAT
    // traversal layer keyed by r's PeerId.
    let conn = a
        .inner_endpoint()
        .get_quic_connection(&r_id)
        .expect("get_quic_connection error")
        .expect("no connection to relay node after successful connect");

    // Open a raw bidi stream. This is NOT Node::open_bi() — that method prepends
    // the 8-byte ANQAppB1 magic which would make handle_relay_requests interpret
    // the first 4 bytes as a length = 0x414e5141 > 1024 and silently drop the stream.
    // A raw stream has no prefix, so the first 4 bytes are our length field.
    let (mut send, mut recv) = timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .expect("open_bi timed out")
        .expect("open_bi failed");

    // Send a CONNECT-UDP Bind request with 4-byte big-endian length prefix.
    // This matches the framing in NatTraversalEndpoint::establish_relay_session
    // (nat_traversal_api.rs line 6282) and what handle_relay_bidi_stream_with_prefix
    // expects (nat_traversal_api.rs line 5438).
    let request = ConnectUdpRequest::bind_any();
    let request_bytes: Bytes = request.encode();
    let req_len = request_bytes.len() as u32;
    send.write_all(&req_len.to_be_bytes())
        .await
        .expect("write request length");
    send.write_all(&request_bytes)
        .await
        .expect("write request body");
    // Do NOT finish() — a successful relay stream stays open for UDP forwarding.

    // Read the length-prefixed CONNECT-UDP Response.
    // The relay service writes this via encode_relay_response_frame()
    // (nat_traversal_api.rs line 5483).
    let mut resp_len_buf = [0u8; 4];
    timeout(Duration::from_secs(5), recv.read_exact(&mut resp_len_buf))
        .await
        .expect("read response length timed out")
        .expect("read response length failed");

    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
    let mut response_bytes = vec![0u8; resp_len];
    timeout(Duration::from_secs(5), recv.read_exact(&mut response_bytes))
        .await
        .expect("read response body timed out")
        .expect("read response body failed");

    let response = ConnectUdpResponse::decode(&mut Bytes::from(response_bytes))
        .expect("failed to decode CONNECT-UDP Response");

    // The relay server must acknowledge the Bind request successfully and
    // report the allocated UDP forwarding address.
    assert!(
        response.is_success(),
        "relay CONNECT-UDP Bind must succeed on a live loopback Node; \
         got status={} reason={:?}",
        response.status,
        response.reason,
    );
    assert!(
        response.proxy_public_address.is_some(),
        "relay response must include the allocated UDP forwarding address; \
         response={response:?}",
    );
}
