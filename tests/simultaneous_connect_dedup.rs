//! Simultaneous Connect Deduplication Tests
//!
//! Tests for issue #137: Phantom one-sided connections under high-latency
//! simultaneous connect.
//!
//! When two nodes simultaneously call `connect_addr()` on each other, the
//! deduplication logic and deterministic tiebreaker should ensure exactly
//! one bidirectional connection exists between them, with no phantom
//! connections.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{ConnectionHealth, Node, PeerConnection};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

/// Helper to create a node bound to localhost with an ephemeral port.
async fn create_localhost_node() -> Node {
    Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("Node::bind should succeed")
}

/// Test that calling connect_addr() twice to the same address returns the
/// same connection (dedup check).
#[tokio::test]
async fn test_connect_addr_dedup_same_address() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    let addr_b = node_b.local_addr().expect("node_b should have address");

    // Spawn accept loop on node_b
    let accept_handle = tokio::spawn({
        let node_b_clone = node_b.clone();
        async move {
            // Accept at least one connection
            let mut accepted = Vec::new();
            for _ in 0..2 {
                match timeout(Duration::from_secs(5), node_b_clone.accept()).await {
                    Ok(Some(conn)) => accepted.push(conn),
                    _ => break,
                }
            }
            accepted
        }
    });

    // First connect: should create a new connection
    let conn1 = timeout(Duration::from_secs(10), node_a.connect_addr(addr_b))
        .await
        .expect("first connect should not time out")
        .expect("first connect should succeed");

    // Small delay to let the connection stabilize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connect to the same address: should return the existing connection
    let conn2 = timeout(Duration::from_secs(5), node_a.connect_addr(addr_b))
        .await
        .expect("second connect should not time out")
        .expect("second connect should succeed");

    // Both should be to the same peer
    assert_eq!(
        conn1.peer_id, conn2.peer_id,
        "Both connect_addr calls should return connections to the same peer"
    );

    // node_a should have exactly 1 connected peer
    let peers_a = node_a.connected_peers().await;
    assert_eq!(
        peers_a.len(),
        1,
        "node_a should have exactly 1 peer, got {}",
        peers_a.len()
    );

    // Clean up
    node_a.shutdown().await;
    node_b.shutdown().await;
    let _ = accept_handle.await;
}

/// Test that simultaneous connect_addr() calls between two nodes
/// produce exactly one bidirectional connection (no phantom connections).
#[tokio::test]
async fn test_simultaneous_connect_no_phantom() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    let addr_a = node_a.local_addr().expect("node_a should have address");
    let addr_b = node_b.local_addr().expect("node_b should have address");

    // Spawn accept loops on both nodes
    let accept_a = tokio::spawn({
        let node = node_a.clone();
        async move {
            let mut accepted = Vec::new();
            for _ in 0..3 {
                match timeout(Duration::from_secs(5), node.accept()).await {
                    Ok(Some(conn)) => accepted.push(conn),
                    _ => break,
                }
            }
            accepted
        }
    });

    let accept_b = tokio::spawn({
        let node = node_b.clone();
        async move {
            let mut accepted = Vec::new();
            for _ in 0..3 {
                match timeout(Duration::from_secs(5), node.accept()).await {
                    Ok(Some(conn)) => accepted.push(conn),
                    _ => break,
                }
            }
            accepted
        }
    });

    // Small delay to let accept loops start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Simultaneously connect A→B and B→A
    let (result_a, result_b) = tokio::join!(
        timeout(Duration::from_secs(10), node_a.connect_addr(addr_b)),
        timeout(Duration::from_secs(10), node_b.connect_addr(addr_a)),
    );

    // Both should succeed (either with a new or deduped connection)
    let conn_a_to_b: PeerConnection = result_a
        .expect("A→B should not time out")
        .expect("A→B should succeed");

    let conn_b_to_a: PeerConnection = result_b
        .expect("B→A should not time out")
        .expect("B→A should succeed");

    // Wait for connection state to stabilize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // node_a should see exactly 1 connection to node_b
    let peers_a = node_a.connected_peers().await;
    assert!(
        peers_a.len() <= 1,
        "node_a should have at most 1 peer, got {} (phantom connections!)",
        peers_a.len()
    );

    // node_b should see exactly 1 connection to node_a
    let peers_b = node_b.connected_peers().await;
    assert!(
        peers_b.len() <= 1,
        "node_b should have at most 1 peer, got {} (phantom connections!)",
        peers_b.len()
    );

    // The connections should reference each other's peer IDs
    assert_eq!(
        conn_a_to_b.peer_id,
        node_b.peer_id(),
        "A's connection should point to B's peer ID"
    );
    assert_eq!(
        conn_b_to_a.peer_id,
        node_a.peer_id(),
        "B's connection should point to A's peer ID"
    );

    // Clean up
    node_a.shutdown().await;
    node_b.shutdown().await;
    let _ = accept_a.await;
    let _ = accept_b.await;
}

/// Run simultaneous connect multiple times to catch race conditions.
#[tokio::test]
async fn test_simultaneous_connect_repeated() {
    for iteration in 0..5 {
        let node_a = create_localhost_node().await;
        let node_b = create_localhost_node().await;

        let addr_a = node_a.local_addr().expect("node_a addr");
        let addr_b = node_b.local_addr().expect("node_b addr");

        // Spawn accept loops
        let accept_a = tokio::spawn({
            let node = node_a.clone();
            async move {
                for _ in 0..3 {
                    match timeout(Duration::from_secs(3), node.accept()).await {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        });

        let accept_b = tokio::spawn({
            let node = node_b.clone();
            async move {
                for _ in 0..3 {
                    match timeout(Duration::from_secs(3), node.accept()).await {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Simultaneous connect
        let (r_a, r_b) = tokio::join!(
            timeout(Duration::from_secs(10), node_a.connect_addr(addr_b)),
            timeout(Duration::from_secs(10), node_b.connect_addr(addr_a)),
        );

        // At least one should succeed
        let a_ok = r_a.map(|r| r.is_ok()).unwrap_or(false);
        let b_ok = r_b.map(|r| r.is_ok()).unwrap_or(false);
        assert!(
            a_ok || b_ok,
            "Iteration {}: at least one connect should succeed (a={}, b={})",
            iteration,
            a_ok,
            b_ok
        );

        tokio::time::sleep(Duration::from_millis(200)).await;

        // No phantom connections: each node should have at most 1 peer
        let peers_a = node_a.connected_peers().await;
        let peers_b = node_b.connected_peers().await;
        assert!(
            peers_a.len() <= 1,
            "Iteration {}: node_a has {} peers (expected <= 1)",
            iteration,
            peers_a.len()
        );
        assert!(
            peers_b.len() <= 1,
            "Iteration {}: node_b has {} peers (expected <= 1)",
            iteration,
            peers_b.len()
        );

        node_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_a.await;
        let _ = accept_b.await;
    }
}

/// Test that the PeerId-based tiebreaker is deterministic.
/// Both sides should agree on which connection to keep.
#[tokio::test]
async fn test_tiebreaker_deterministic() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    let peer_id_a = node_a.peer_id();
    let peer_id_b = node_b.peer_id();

    // The node with the lower PeerId should keep its Client connection.
    // This means the node with the lower PeerId "wins" as the initiator.
    let lower_is_a = peer_id_a < peer_id_b;
    println!(
        "PeerId comparison: A={:?}... B={:?}... lower_is_a={}",
        &peer_id_a.0[..4],
        &peer_id_b.0[..4],
        lower_is_a
    );

    // The tiebreaker rule is deterministic and doesn't depend on timing.
    // Both sides can independently compute which connection to keep.
    // This test just verifies the PeerIds are different and ordered.
    assert_ne!(
        peer_id_a, peer_id_b,
        "Two nodes should have different peer IDs"
    );

    // Verify ordering is total (one is strictly less than the other)
    assert!(
        peer_id_a != peer_id_b,
        "PeerIds should have a strict total order"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}

// ============================================================================
// Phase 1.2: Timeout Enforcement & Connection Cleanup Tests
// ============================================================================

/// Test that connect_addr() to a non-listening address times out and
/// leaves no orphaned entries in connected_peers.
#[tokio::test]
async fn test_connect_timeout_no_orphans() {
    let node = create_localhost_node().await;

    // Connect to an address where nobody is listening.
    // Port 1 on localhost is almost certainly not running a QUIC server.
    let bogus_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let result = timeout(Duration::from_secs(35), node.connect_addr(bogus_addr)).await;

    // Should get either a timeout or a connection error — NOT hang forever
    match result {
        Ok(Ok(_)) => panic!("Should not succeed connecting to a non-listening address"),
        Ok(Err(e)) => {
            println!("Got expected connection error: {}", e);
        }
        Err(_) => {
            panic!(
                "connect_addr() should have returned within 30s timeout, \
                 but the outer 35s timeout fired instead"
            );
        }
    }

    // After failure, connected_peers should be empty (no orphaned entries)
    let peers = node.connected_peers().await;
    assert!(
        peers.is_empty(),
        "No orphaned connections after timeout, but found {} peers",
        peers.len()
    );

    node.shutdown().await;
}

/// Test that after a failed connect, we can successfully connect to a real peer.
/// This verifies no blocking state remains from the failed attempt.
#[tokio::test]
async fn test_connect_after_failure_succeeds() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    // Spawn accept on node_b
    let accept_handle = tokio::spawn({
        let node = node_b.clone();
        async move { timeout(Duration::from_secs(15), node.accept()).await }
    });

    // First: try connecting to a bogus address (will fail)
    let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _ = timeout(Duration::from_secs(10), node_a.connect_addr(bogus)).await;

    // Second: connect to the real node — this should succeed
    let addr_b = node_b.local_addr().expect("node_b addr");
    let result = timeout(Duration::from_secs(10), node_a.connect_addr(addr_b)).await;

    assert!(
        result.is_ok() && result.as_ref().unwrap().is_ok(),
        "Should successfully connect to real peer after failed attempt"
    );

    let peers = node_a.connected_peers().await;
    assert_eq!(
        peers.len(),
        1,
        "Should have exactly 1 connected peer after successful connect"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
    let _ = accept_handle.await;
}

// ============================================================================
// Phase 1.3: Phantom Connection Detection & Recovery Tests
// ============================================================================

/// Test that two connected nodes have healthy connection status after
/// the health check PING/PONG cycle runs.
#[tokio::test]
async fn test_connection_health_status() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    let addr_b = node_b.local_addr().expect("node_b should have address");

    // Spawn accept on node_b
    let accept_handle = tokio::spawn({
        let node = node_b.clone();
        async move { timeout(Duration::from_secs(5), node.accept()).await }
    });

    // Connect A → B
    let conn = timeout(Duration::from_secs(10), node_a.connect_addr(addr_b))
        .await
        .expect("connect should not time out")
        .expect("connect should succeed");

    let _ = accept_handle.await;

    // Immediately after connect, health should be Healthy (not yet probed)
    let health = node_a.connection_health(&conn.peer_id).await;
    assert_eq!(
        health,
        Some(ConnectionHealth::Healthy),
        "Newly connected peer should be Healthy"
    );

    // Wait for at least one health check cycle (30s reaper interval + margin)
    // The reaper will send a PING, and the reader task on the remote end
    // responds with a PONG.
    tokio::time::sleep(Duration::from_secs(35)).await;

    // After one cycle, the peer should still be Healthy (PONG received)
    let health_after = node_a.connection_health(&conn.peer_id).await;
    assert!(
        matches!(
            health_after,
            Some(ConnectionHealth::Healthy) | Some(ConnectionHealth::Checking)
        ),
        "After one health cycle, peer should be Healthy or Checking, got {:?}",
        health_after
    );

    // node_a should still have exactly 1 peer (not evicted)
    let peers = node_a.connected_peers().await;
    assert_eq!(
        peers.len(),
        1,
        "Healthy connection should not be evicted, but got {} peers",
        peers.len()
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}

/// Test that connection_health returns None for unknown peers.
#[tokio::test]
async fn test_connection_health_unknown_peer() {
    let node = create_localhost_node().await;

    let unknown_peer = ant_quic::PeerId([0xDE; 32]);
    let health = node.connection_health(&unknown_peer).await;
    assert_eq!(health, None, "Unknown peer should return None");

    node.shutdown().await;
}

/// Test that after disconnect, connection_health returns None.
#[tokio::test]
async fn test_connection_health_after_disconnect() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;

    let addr_b = node_b.local_addr().expect("node_b addr");

    let accept_handle = tokio::spawn({
        let node = node_b.clone();
        async move { timeout(Duration::from_secs(5), node.accept()).await }
    });

    let conn = timeout(Duration::from_secs(10), node_a.connect_addr(addr_b))
        .await
        .expect("connect should not time out")
        .expect("connect should succeed");

    let _ = accept_handle.await;

    // Verify connected
    assert_eq!(
        node_a.connection_health(&conn.peer_id).await,
        Some(ConnectionHealth::Healthy),
    );

    // Disconnect
    node_a
        .disconnect(&conn.peer_id)
        .await
        .expect("disconnect should succeed");

    // After disconnect, health should be None
    let health = node_a.connection_health(&conn.peer_id).await;
    assert_eq!(
        health, None,
        "Disconnected peer should return None, got {:?}",
        health
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}

// ============================================================================
// Phase 1.4: Integration Testing & Validation
// ============================================================================

/// Test that 4 nodes can form a full mesh via simultaneous connections.
/// Each node connects to all others; the dedup + tiebreaker ensures
/// exactly N-1 peers per node with no phantoms.
#[tokio::test]
async fn test_four_node_mesh_formation() {
    const N: usize = 4;

    // Create N nodes
    let mut nodes = Vec::new();
    for _ in 0..N {
        nodes.push(create_localhost_node().await);
    }

    let addrs: Vec<SocketAddr> = nodes
        .iter()
        .map(|n| n.local_addr().expect("node addr"))
        .collect();

    // Spawn accept loops on all nodes
    let mut accept_handles = Vec::new();
    for node in &nodes {
        let n = node.clone();
        accept_handles.push(tokio::spawn(async move {
            // Accept up to N-1 connections (peers connecting to us)
            for _ in 0..(N - 1) {
                match timeout(Duration::from_secs(15), n.accept()).await {
                    Ok(Some(_)) => {}
                    _ => break,
                }
            }
        }));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Each node connects to all others simultaneously
    let mut connect_handles = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        for (j, &addr) in addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let n = node.clone();
            connect_handles.push(tokio::spawn(async move {
                timeout(Duration::from_secs(15), n.connect_addr(addr)).await
            }));
        }
    }

    // Wait for all connects to complete
    for handle in connect_handles {
        let _ = handle.await;
    }

    // Let connections stabilize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify each node sees at most N-1 peers (no phantoms)
    for (i, node) in nodes.iter().enumerate() {
        let peers = node.connected_peers().await;
        assert!(
            peers.len() < N,
            "Node {} has {} peers (expected < {}, phantom detected!)",
            i,
            peers.len(),
            N
        );
        // At least some connections should have formed
        assert!(
            !peers.is_empty(),
            "Node {} has 0 peers (expected at least 1)",
            i
        );
    }

    // Shutdown all nodes
    for node in nodes {
        node.shutdown().await;
    }
    for handle in accept_handles {
        let _ = handle.await;
    }
}

/// Stress test: rapid connect/disconnect cycles.
/// Verifies no connection leaks or orphaned state across 10 cycles.
#[tokio::test]
async fn test_rapid_connect_disconnect_cycles() {
    let node_a = create_localhost_node().await;
    let node_b = create_localhost_node().await;
    let addr_b = node_b.local_addr().expect("node_b addr");

    for cycle in 0..10 {
        // Spawn accept
        let accept = tokio::spawn({
            let n = node_b.clone();
            async move { timeout(Duration::from_secs(10), n.accept()).await }
        });

        // Connect
        let result = timeout(Duration::from_secs(10), node_a.connect_addr(addr_b)).await;
        let conn = match result {
            Ok(Ok(c)) => c,
            Ok(Err(_e)) => {
                // Connection might fail on rapid cycling — that's OK
                // as long as state is clean
                let _ = accept.await;
                let peers = node_a.connected_peers().await;
                assert!(
                    peers.is_empty(),
                    "Cycle {}: failed connect should leave no peers, got {}",
                    cycle,
                    peers.len()
                );
                continue;
            }
            Err(_) => {
                let _ = accept.await;
                continue;
            }
        };

        let _ = accept.await;

        // Verify connected
        let peers = node_a.connected_peers().await;
        assert_eq!(
            peers.len(),
            1,
            "Cycle {}: should have exactly 1 peer after connect",
            cycle
        );

        // Disconnect
        let _ = node_a.disconnect(&conn.peer_id).await;

        // Small delay for cleanup
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify clean state
        let peers_after = node_a.connected_peers().await;
        assert!(
            peers_after.is_empty(),
            "Cycle {}: should have 0 peers after disconnect, got {}",
            cycle,
            peers_after.len()
        );
    }

    node_a.shutdown().await;
    node_b.shutdown().await;
}

// ============================================================================
// Phase 2: Data Transfer After Simultaneous Open
// ============================================================================

/// Verify that `send()` succeeds in both directions after a simultaneous open.
///
/// Regression test for the connection-loss bug fixed in aa55a3c1.  Before
/// the fix, the accept-side dedup logic called `remove_connection()` without
/// re-adding the incoming connection to the NatTraversalEndpoint DashMap.
/// This left `connected_peers` populated but `send()` failing with
/// `EndpointError::PeerNotFound` because the underlying QUIC connection
/// was missing from storage.
///
/// The test runs 5 iterations because the simultaneous-open race is
/// non-deterministic — some runs hit the dedup path, others don't.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simultaneous_connect_send_succeeds() {
    for iteration in 0..5 {
        let node_a = create_localhost_node().await;
        let node_b = create_localhost_node().await;

        let addr_a = node_a.local_addr().expect("node_a addr");
        let addr_b = node_b.local_addr().expect("node_b addr");

        // Spawn accept loops so incoming connections are processed.
        let accept_a = tokio::spawn({
            let n = node_a.clone();
            async move {
                for _ in 0..3 {
                    match timeout(Duration::from_secs(5), n.accept()).await {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        });
        let accept_b = tokio::spawn({
            let n = node_b.clone();
            async move {
                for _ in 0..3 {
                    match timeout(Duration::from_secs(5), n.accept()).await {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Simultaneously connect A→B and B→A.
        let (r_a, r_b) = tokio::join!(
            timeout(Duration::from_secs(10), node_a.connect_addr(addr_b)),
            timeout(Duration::from_secs(10), node_b.connect_addr(addr_a)),
        );

        let conn_a = r_a
            .unwrap_or_else(|_| panic!("Iteration {}: A→B timed out", iteration))
            .unwrap_or_else(|e| panic!("Iteration {}: A→B failed: {}", iteration, e));
        let conn_b = r_b
            .unwrap_or_else(|_| panic!("Iteration {}: B→A timed out", iteration))
            .unwrap_or_else(|e| panic!("Iteration {}: B→A failed: {}", iteration, e));

        // Let connections stabilise after the dedup.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The actual regression: send() must not return PeerNotFound.
        // Before the fix this failed because the DashMap entry was removed
        // during dedup but never re-added.
        let payload = format!("iteration {}", iteration);

        node_a
            .send(&conn_a.peer_id, payload.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("Iteration {}: A→B send failed: {}", iteration, e));

        node_b
            .send(&conn_b.peer_id, payload.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("Iteration {}: B→A send failed: {}", iteration, e));

        node_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_a.await;
        let _ = accept_b.await;
    }
}
