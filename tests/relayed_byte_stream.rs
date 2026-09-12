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
//! This exercises a code path not covered elsewhere:
//! - the reader task's bidi demux forwarding a raw (unrecognised-prefix)
//!   stream to the relay service via `handle_relay_bidi_stream_from_app_reader`
//!   (`p2p_endpoint.rs`) — the single stream consumer on an accepted
//!   connection (#280: the former redundant per-connection relay accept task
//!   was removed)
//! - `handle_relay_bidi_stream_with_prefix` parsing the CONNECT-UDP Bind frame
//!   (`nat_traversal_api.rs`)
//! - `MasqueRelayServer::handle_connect_request` binding a real UDP socket for
//!   the session (`masque/relay_server.rs`)
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
/// # Determinism guarantee
///
/// `r` runs a normal application accept loop, so the connection from `a` gets
/// exactly one reader task — the single `accept_bi` consumer on that
/// connection (#280). The reader's prefix demux forwards the raw
/// length-prefixed CONNECT-UDP Bind stream to the relay service; there is no
/// second consumer to race with. (Pre-#280 this test deliberately never called
/// `r.accept()` because a redundant NAT-layer relay task raced the reader for
/// bidi streams; that task no longer exists.)
#[tokio::test]
async fn relay_connect_udp_bind_on_live_node() {
    // r: relay node, with a normal accept loop (single-consumer path, #280).
    let r = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("relay node");
    let a = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("client node");

    // r drains accepted connections so each gets its single reader task.
    let r_for_accept = r.clone();
    tokio::spawn(async move { while r_for_accept.accept().await.is_some() {} });

    let r_id = r.peer_id();
    let r_addr = loopback_addr(&r);

    // Connect a → r. r's accept loop registers the connection and spawns its
    // single reader task, whose prefix demux serves relay requests.
    timeout(Duration::from_secs(5), a.connect_addr(r_addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    // Retrieve the raw QUIC connection from a's side.
    // After a successful connect_addr(), the connection is stored in a's NAT
    // traversal layer keyed by r's PeerId.
    let conn = a
        .inner_endpoint()
        .get_quic_connection(&r_id)
        .expect("get_quic_connection error")
        .expect("no connection to relay node after successful connect");

    // Open a raw bidi stream. This is NOT Node::open_bi() — that method
    // prepends the 8-byte ANQAppB1 magic, which the reader's prefix demux
    // routes to the application queue instead of the relay service. A raw
    // stream has no magic, so the first 4 bytes are our length field.
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

/// #280 round 2: a live relay session must not wedge the peer's other
/// streams.
///
/// `establish_relay_session` deliberately REUSES the existing peer
/// connection, so the CONNECT-UDP forwarding loop shares the connection with
/// application bidi streams and uni datagrams. Pre-fix, the reader awaited
/// the relay branch inline, pinning the sole `accept_bi`/`accept_uni`
/// consumer inside `run_stream_forwarding_loop` for the whole session: every
/// app stream and uni from that peer went unaccepted until the session ended.
/// Post-fix the relay stream is served on its own task after prefix
/// classification, and both an app bidi stream and a uni datagram from the
/// same peer are still accepted while the session is live.
#[tokio::test]
async fn relay_session_does_not_wedge_peer_streams() {
    // b: relay node (relay server configured by default), with a normal
    // accept loop so the connection gets its single reader task.
    let b = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("relay node");
    let a = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("client node");

    let b_for_accept = b.clone();
    tokio::spawn(async move { while b_for_accept.accept().await.is_some() {} });

    let b_id = b.peer_id();
    let b_addr = loopback_addr(&b);

    timeout(Duration::from_secs(5), a.connect_addr(b_addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    // Open the relay session on the SAME connection the app streams will use.
    let conn = a
        .inner_endpoint()
        .get_quic_connection(&b_id)
        .expect("get_quic_connection error")
        .expect("no connection to relay node after successful connect");
    let (mut send, mut recv) = timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .expect("open_bi timed out")
        .expect("open_bi failed");

    let request = ConnectUdpRequest::bind_any();
    let request_bytes: Bytes = request.encode();
    let req_len = request_bytes.len() as u32;
    send.write_all(&req_len.to_be_bytes())
        .await
        .expect("write request length");
    send.write_all(&request_bytes)
        .await
        .expect("write request body");
    // Do NOT finish() — the relay stream stays open for UDP forwarding.

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
    assert!(
        response.is_success(),
        "relay session must be established before asserting peer-stream liveness"
    );

    // While the relay session is live on this connection: an application
    // bidi stream from the same peer must still be accepted.
    let (mut app_send, _app_recv) = timeout(Duration::from_secs(5), a.open_bi(&b_id))
        .await
        .expect("app open_bi timed out")
        .expect("app open_bi failed");
    app_send
        .write_all(b"app-during-relay")
        .await
        .expect("app write");
    app_send.finish().expect("app finish");
    let (_from, _send_half, mut app_stream) = timeout(Duration::from_secs(5), b.accept_bi())
        .await
        .expect("app stream must be accepted while the relay session is live")
        .expect("app stream handle");
    let app_payload = tokio::time::timeout(Duration::from_secs(5), app_stream.read_to_end(1024))
        .await
        .expect("app read timed out")
        .expect("app read");
    assert_eq!(app_payload, b"app-during-relay");

    // And a uni datagram from the same peer must still be delivered via
    // `recv()` (the reader's accept_uni path).
    a.send(&b_id, b"uni-during-relay")
        .await
        .expect("send uni datagram");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let uni_payload = loop {
        if let Ok(Ok((_peer, data))) = tokio::time::timeout(Duration::from_secs(2), b.recv()).await
        {
            break data;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "uni datagram must be delivered while the relay session is live"
        );
    };
    assert_eq!(uni_payload, b"uni-during-relay");

    a.shutdown().await;
    b.shutdown().await;
}
