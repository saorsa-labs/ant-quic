//! Regression test for the reader-task replacement bug.
//!
//! **Bug**: When `spawn_reader_task()` was called for a `PeerId` that already
//! had a reader task, the old `AbortHandle` was overwritten without calling
//! `.abort()`, leaving a zombie reader on the dead connection.
//!
//! **Fix** (p2p_endpoint.rs): The old handle is now explicitly aborted before
//! inserting the new one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(5);

fn normalize(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

async fn make_node(known: Vec<SocketAddr>) -> P2pEndpoint {
    P2pEndpoint::new(
        P2pConfig::builder()
            .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .known_peers(known)
            .nat(NatConfig {
                enable_relay_fallback: false,
                ..Default::default()
            })
            .pqc(PqcConfig::default())
            .build()
            .expect("test config"),
    )
    .await
    .expect("node creation")
}

/// Verify recv() works after disconnect + reconnect to the same peer.
///
/// Both sides must disconnect to ensure clean QUIC state before reconnection.
/// Without the reader-task abort fix, the second recv() would hang because the
/// old zombie reader task (bound to the dead connection) would be the one
/// registered in `reader_handles`, shadowing the new reader task.
#[tokio::test]
async fn recv_after_reconnect() {
    let b = Arc::new(make_node(vec![]).await);
    let b_addr = normalize(b.local_addr().expect("bound addr"));
    let b_id = b.peer_id();

    let a = Arc::new(make_node(vec![b_addr]).await);
    let a_id = a.peer_id();

    // --- First session ---
    let b2 = Arc::clone(&b);
    let accept1 = tokio::spawn(async move { timeout(TIMEOUT, b2.accept()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let conn = a.connect_addr(b_addr).await.expect("connect");
    assert_eq!(conn.peer_id, b_id);
    let _ = accept1.await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify first session works
    a.send(&b_id, b"msg1").await.expect("send1");
    let (from, data) = timeout(TIMEOUT, b.recv())
        .await
        .expect("recv1 timeout")
        .expect("recv1 error");
    assert_eq!(from, a_id);
    assert_eq!(&data, b"msg1");

    // --- Disconnect BOTH sides for clean QUIC state ---
    a.disconnect(&b_id).await.expect("disconnect a→b");
    // B must also disconnect so its QUIC endpoint fully releases
    // the old connection, allowing a fresh accept on reconnection.
    let _ = b.disconnect(&a_id).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Second session (reconnection) ---
    let b3 = Arc::clone(&b);
    let accept2 = tokio::spawn(async move { timeout(TIMEOUT, b3.accept()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.connect_addr(b_addr).await.expect("reconnect");
    let _ = accept2.await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Regression check: recv() must work on the new connection.
    // Before the fix, the zombie reader task from session 1 would shadow
    // the new reader task, causing this recv() to hang.
    a.send(&b_id, b"msg2").await.expect("send2");
    let (from2, data2) = timeout(TIMEOUT, b.recv())
        .await
        .expect("recv2 TIMED OUT — reader task replacement bug regressed!")
        .expect("recv2 error");
    assert_eq!(from2, a_id);
    assert_eq!(&data2, b"msg2");

    let _ = timeout(Duration::from_secs(2), a.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), b.shutdown()).await;
}
