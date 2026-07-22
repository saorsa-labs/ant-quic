//! Regression tests for issue #224: standalone `P2pLinkTransport` defects.
//!
//! Defect B: `dial_addr` between two bare `P2pConfig::builder()` endpoints
//! appeared to hang indefinitely on loopback. The dial must either complete
//! or fail fast with a precise error — never hang.
//!
//! Defect A: `accept` ignored its `ProtocolId`. Accept lanes are now demuxed
//! by the connection's negotiated protocol; until the wire carries
//! `ProtocolId`, undifferentiated connections route to `ProtocolId::DEFAULT`
//! and acceptors for other protocols must not see them.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ant_quic::{
    BootstrapCacheConfig, LinkConn, LinkTransport, P2pConfig, P2pLinkTransport, ProtocolId,
};
use futures_util::StreamExt;

/// Dial ceiling: the bug reproduced as an indefinite hang, so any bounded
/// wait that lets a healthy direct loopback handshake complete proves the
/// fix. Direct loopback dials complete in well under a second.
const DIAL_CEILING: Duration = Duration::from_secs(10);

fn bare_config() -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        // Bare endpoints have no prior knowledge: pin the bootstrap cache to
        // memory so the test is deterministic regardless of the host's
        // persisted cache contents.
        .bootstrap_cache(BootstrapCacheConfig::builder().persist(false).build())
        .build()
        .expect("bare P2pConfig builds")
}

/// `local_addr()` may report an unspecified bind IP; dial via explicit
/// loopback so the target is unambiguous.
fn loopback_dial_addr(addr: SocketAddr) -> SocketAddr {
    let ip = if addr.ip().is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        addr.ip()
    };
    SocketAddr::new(ip, addr.port())
}

#[tokio::test]
async fn dial_addr_between_bare_endpoints_completes() {
    let listener = P2pLinkTransport::new(bare_config())
        .await
        .expect("listener transport starts");
    let dialer = P2pLinkTransport::new(bare_config())
        .await
        .expect("dialer transport starts");

    let listen_addr = loopback_dial_addr(listener.endpoint().local_addr().expect("listener bound"));

    let conn = tokio::time::timeout(
        DIAL_CEILING,
        dialer.dial_addr(listen_addr, ProtocolId::DEFAULT),
    )
    .await
    .expect("dial_addr hung past its ceiling (issue #224 defect B)")
    .expect("direct loopback dial between bare endpoints should succeed");

    assert!(conn.is_open(), "freshly dialed connection is open");
    assert_eq!(
        conn.peer(),
        listener.local_peer(),
        "dialer is connected to the listener's peer id"
    );

    dialer.shutdown().await;
    listener.shutdown().await;
}

#[tokio::test]
async fn dial_addr_to_dead_addr_fails_fast() {
    let dialer = P2pLinkTransport::new(bare_config())
        .await
        .expect("dialer transport starts");

    // Nothing listens on this loopback port. The dial must fail (fast),
    // not hang: a precise error naming the failed strategies is required.
    let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9); // discard port

    let result = tokio::time::timeout(
        DIAL_CEILING,
        dialer.dial_addr(dead_addr, ProtocolId::DEFAULT),
    )
    .await
    .expect("dial_addr to a dead address hung past its ceiling (issue #224 defect B)");

    let err = match result {
        Ok(_) => panic!("dialing a dead address must fail"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        !msg.is_empty(),
        "error must name what failed, got an empty message"
    );

    dialer.shutdown().await;
}

/// Positive accept filtering: a connection dialed without wire-level
/// protocol negotiation is routed to the `ProtocolId::DEFAULT` acceptor.
#[tokio::test]
async fn accept_routes_connection_to_default_acceptor() {
    let listener = P2pLinkTransport::new(bare_config())
        .await
        .expect("listener transport starts");
    let dialer = P2pLinkTransport::new(bare_config())
        .await
        .expect("dialer transport starts");
    let listen_addr = loopback_dial_addr(listener.endpoint().local_addr().expect("listener bound"));

    let mut incoming = listener.accept(ProtocolId::DEFAULT);

    dialer
        .dial_addr(listen_addr, ProtocolId::DEFAULT)
        .await
        .expect("dial succeeds");

    let accepted = tokio::time::timeout(DIAL_CEILING, incoming.next())
        .await
        .expect("accept must not hang")
        .expect("accept stream must not end while the endpoint is up")
        .expect("accepted connection is valid");

    assert_eq!(accepted.peer(), dialer.local_peer());

    dialer.shutdown().await;
    listener.shutdown().await;
}

/// Negative accept filtering: with two concurrent acceptors, a connection
/// that did not negotiate a wire protocol is delivered to the DEFAULT
/// acceptor and NOT to the acceptor for a different protocol. Previously
/// both acceptors raced on the same endpoint queue and either could receive
/// any connection regardless of protocol (issue #224 defect A).
#[tokio::test]
async fn accept_filters_out_non_matching_protocol() {
    let listener = P2pLinkTransport::new(bare_config())
        .await
        .expect("listener transport starts");
    let dialer = P2pLinkTransport::new(bare_config())
        .await
        .expect("dialer transport starts");
    let listen_addr = loopback_dial_addr(listener.endpoint().local_addr().expect("listener bound"));

    let proto_x = ProtocolId::from("saorsa-test/x1.0");
    let mut incoming_x = listener.accept(proto_x);
    let mut incoming_default = listener.accept(ProtocolId::DEFAULT);

    dialer
        .dial_addr(listen_addr, ProtocolId::DEFAULT)
        .await
        .expect("dial succeeds");

    // The DEFAULT acceptor receives the connection...
    let accepted = tokio::time::timeout(DIAL_CEILING, incoming_default.next())
        .await
        .expect("default acceptor must receive the undifferentiated connection")
        .expect("accept stream must not end while the endpoint is up")
        .expect("accepted connection is valid");
    assert_eq!(accepted.peer(), dialer.local_peer());

    // ...and the protocol-X acceptor does not (short window: delivery, when
    // misrouted, happens within milliseconds of the dial completing).
    let misrouted = tokio::time::timeout(Duration::from_secs(2), incoming_x.next()).await;
    assert!(
        misrouted.is_err(),
        "protocol-X acceptor must not receive a connection that was not negotiated for X"
    );

    dialer.shutdown().await;
    listener.shutdown().await;
}
