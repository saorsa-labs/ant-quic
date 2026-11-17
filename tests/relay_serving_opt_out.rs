// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the GPL, version 3.
// See LICENSE-GPL for the full text.

//! ADR-019 relay-serving opt-out, through the public `Node` API.
//!
//! - Validation 1 (Node layer): `NodeConfigBuilder::relay_service_enabled`
//!   reaches the runtime and `NodeStatus.relay_service_enabled`.
//! - Validation 3 (wire): a serving-off node answers a CONNECT-UDP Bind with
//!   `403 "relay service disabled"` and a finished stream.
//! - Validation 5: a serving-off node still coordinates a peer-ID dial
//!   between two peers that only know it.
//! - Validation 7: a garbage stream to a serving-off node is dropped with no
//!   answer and no panic; the node keeps answering well-formed requests.
//!
//! All nodes bind loopback with ephemeral ports.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ant_quic::{
    Node, NodeConfig,
    masque::{ConnectUdpRequest, ConnectUdpResponse},
};
use bytes::Bytes;
use tokio::time::timeout;

fn loopback(node: &Node) -> SocketAddr {
    let addr = node.local_addr().expect("node bound");
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

async fn node(relay_serving: bool) -> Node {
    let config = NodeConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .port_mapping_enabled(false)
        .mdns_enabled(false)
        .relay_service_enabled(relay_serving)
        .build();
    Node::with_config(config).await.expect("node starts")
}

fn spawn_accept(node: &Node) -> tokio::task::JoinHandle<()> {
    let node = node.clone();
    tokio::spawn(async move { while node.accept().await.is_some() {} })
}

/// Open a raw (unprefixed) bidi stream from `client` to `relay`, the way
/// `establish_relay_session` does.
async fn raw_stream(
    client: &Node,
    relay: &Node,
) -> (
    ant_quic::high_level::SendStream,
    ant_quic::high_level::RecvStream,
) {
    let conn = client
        .inner_endpoint()
        .get_quic_connection(&relay.peer_id())
        .expect("get_quic_connection")
        .expect("connection to relay");
    timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .expect("open_bi timed out")
        .expect("open_bi")
}

async fn send_bind_request(client: &Node, relay: &Node) -> ConnectUdpResponse {
    let (mut send, mut recv) = raw_stream(client, relay).await;
    let request: Bytes = ConnectUdpRequest::bind_any().encode();
    send.write_all(&(request.len() as u32).to_be_bytes())
        .await
        .expect("write length");
    send.write_all(&request).await.expect("write request");

    let mut len = [0u8; 4];
    timeout(Duration::from_secs(5), recv.read_exact(&mut len))
        .await
        .expect("read length timed out")
        .expect("read length");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    timeout(Duration::from_secs(5), recv.read_exact(&mut body))
        .await
        .expect("read body timed out")
        .expect("read body");
    // The refusal finishes the stream: nothing follows the response.
    let rest = timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("stream end timed out")
        .expect("the refusal stream is finished, not reset");
    assert!(rest.is_empty(), "no bytes after the response");
    ConnectUdpResponse::decode(&mut Bytes::from(body)).expect("decode response")
}

/// ADR-019 Validation 1 (Node layer): the builder flag reaches the runtime,
/// and the default stays on.
#[tokio::test]
async fn adr019_node_config_relay_service_flag_reaches_status() {
    let off = node(false).await;
    assert!(!off.status().await.relay_service_enabled);
    assert!(!off.inner_endpoint().relay_service_enabled());

    let default = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("default node");
    assert!(default.status().await.relay_service_enabled);

    off.shutdown().await;
    default.shutdown().await;
}

/// ADR-019 Validation 3 (wire): a CONNECT-UDP Bind request to a serving-off
/// node is answered `403 "relay service disabled"` on a finished stream, and
/// the node holds no relay session.
#[tokio::test]
async fn adr019_serving_off_node_answers_bind_with_403() {
    let b = node(false).await;
    let a = node(true).await;
    let accept_b = spawn_accept(&b);
    timeout(Duration::from_secs(10), a.connect_addr(loopback(&b)))
        .await
        .expect("connect timed out")
        .expect("connect");

    let response = send_bind_request(&a, &b).await;
    assert_eq!(response.status, ConnectUdpResponse::STATUS_FORBIDDEN);
    assert_eq!(response.reason.as_deref(), Some("relay service disabled"));
    assert!(response.is_relay_service_disabled());

    let status = b.status().await;
    assert_eq!(status.relay_sessions, 0, "B holds no relay session");
    assert!(!status.is_relaying);
    assert_eq!(
        b.inner_endpoint()
            .stats()
            .await
            .relay_requests_refused_disabled,
        1
    );

    accept_b.abort();
    a.shutdown().await;
    b.shutdown().await;
}

/// ADR-019 Validation 5: B has relay serving off and still coordinates. A
/// and D only know B; A dials D by peer ID through B as coordinator.
#[tokio::test]
async fn adr019_serving_off_node_still_coordinates() {
    let b = node(false).await;
    let a = node(true).await;
    let d = node(true).await;
    let b_addr = loopback(&b);
    let (a_peer, d_peer) = (a.peer_id(), d.peer_id());
    a.add_peer(b_addr).await;
    d.add_peer(b_addr).await;
    let accept_b = spawn_accept(&b);

    let connected_a = timeout(Duration::from_secs(10), a.connect_known_peers())
        .await
        .expect("A connect_known_peers timed out")
        .expect("A connect_known_peers");
    let connected_d = timeout(Duration::from_secs(10), d.connect_known_peers())
        .await
        .expect("D connect_known_peers timed out")
        .expect("D connect_known_peers");
    assert!(connected_a >= 1 && connected_d >= 1, "A and D reach B");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let peers = b.connected_peers().await;
        if peers.iter().any(|p| p.peer_id == a_peer) && peers.iter().any(|p| p.peer_id == d_peer) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "B sees both A and D"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let a_peers = a.connected_peers().await;
    assert_eq!(a_peers.len(), 1, "precondition: A only knows B");
    assert_eq!(a_peers[0].peer_id, b.peer_id());

    let conn = timeout(Duration::from_secs(30), a.connect_peer(d_peer))
        .await
        .expect("peer-ID dial via coordinator B timed out")
        .expect("peer-ID dial via coordinator B");
    assert_eq!(conn.peer_id, d_peer, "A reaches D with B as coordinator");
    assert!(!b.status().await.relay_service_enabled);
    assert_eq!(b.status().await.relay_sessions, 0, "B relays nothing");

    accept_b.abort();
    a.shutdown().await;
    d.shutdown().await;
    b.shutdown().await;
}

/// ADR-019 Validation 7: a garbage stream to a serving-off node gets no
/// answer (the stream is dropped) and does not panic the node, which keeps
/// refusing well-formed requests afterwards.
#[tokio::test]
async fn adr019_garbage_stream_to_serving_off_node_is_dropped() {
    let b = node(false).await;
    let a = node(true).await;
    let accept_b = spawn_accept(&b);
    timeout(Duration::from_secs(10), a.connect_addr(loopback(&b)))
        .await
        .expect("connect timed out")
        .expect("connect");

    // 1. A length prefix within bounds, followed by bytes that do not decode
    //    as a CONNECT-UDP request.
    // 2. A length prefix over the 1024-byte bound.
    let garbage: [&[u8]; 2] = [
        &[0, 0, 0, 6, 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff],
        &[0, 0, 0x10, 0, 1, 2, 3],
    ];
    for frame in garbage {
        let (mut send, mut recv) = raw_stream(&a, &b).await;
        send.write_all(frame).await.expect("write garbage");
        let _ = send.finish();
        let read = timeout(Duration::from_secs(5), recv.read_to_end(4096))
            .await
            .expect("B ends the garbage stream");
        // A dropped stream shows as a reset (an error), as today. If the read
        // ends cleanly instead, it must carry no response bytes.
        if let Ok(bytes) = read {
            assert!(bytes.is_empty(), "no response to garbage: {bytes:?}");
        }
    }
    assert_eq!(
        b.inner_endpoint()
            .stats()
            .await
            .relay_requests_refused_disabled,
        0,
        "garbage is not counted as a refused relay request"
    );

    // B is still alive and still refuses a well-formed request.
    let response = send_bind_request(&a, &b).await;
    assert!(response.is_relay_service_disabled());

    accept_b.abort();
    a.shutdown().await;
    b.shutdown().await;
}
