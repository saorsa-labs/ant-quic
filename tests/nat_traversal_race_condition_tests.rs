// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Tests for NAT traversal race condition prevention
//!
//! These tests verify that hole punching and NAT traversal are skipped when
//! a direct connection already exists, preventing resource waste and unnecessary
//! network traffic.
//!
//! v0.13.0+: Updated for symmetric P2P node architecture - no roles.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    crypto::raw_public_keys::pqc::{derive_peer_id_from_public_key, generate_ml_dsa_keypair},
    nat_traversal_api::{
        NatTraversalConfig, NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, PeerId,
    },
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Barrier, mpsc};
use tracing::info;

#[derive(Debug, Default)]
struct EventCounters {
    coordination_requested: AtomicUsize,
    hole_punching_started: AtomicUsize,
    connection_established: AtomicUsize,
}

impl EventCounters {
    fn reset(&self) {
        self.coordination_requested.store(0, Ordering::SeqCst);
        self.hole_punching_started.store(0, Ordering::SeqCst);
        self.connection_established.store(0, Ordering::SeqCst);
    }

    fn coordination_requested(&self) -> usize {
        self.coordination_requested.load(Ordering::SeqCst)
    }

    fn hole_punching_started(&self) -> usize {
        self.hole_punching_started.load(Ordering::SeqCst)
    }

    fn connection_established(&self) -> usize {
        self.connection_established.load(Ordering::SeqCst)
    }
}

/// Helper to create a NAT traversal endpoint with event tracking and counting
async fn create_endpoint_with_event_counters(
    known_peers: Vec<SocketAddr>,
) -> Result<
    (
        Arc<NatTraversalEndpoint>,
        mpsc::UnboundedReceiver<NatTraversalEvent>,
        Arc<EventCounters>,
    ),
    NatTraversalError,
> {
    let config = NatTraversalConfig {
        known_peers,
        bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        ..NatTraversalConfig::default()
    };

    let counters = Arc::new(EventCounters::default());
    let counters_clone = counters.clone();

    let (tx, rx) = mpsc::unbounded_channel();
    let event_callback = Box::new(move |event: NatTraversalEvent| {
        match event {
            NatTraversalEvent::CoordinationRequested { .. } => {
                counters_clone
                    .coordination_requested
                    .fetch_add(1, Ordering::SeqCst);
            }
            NatTraversalEvent::HolePunchingStarted { .. } => {
                counters_clone
                    .hole_punching_started
                    .fetch_add(1, Ordering::SeqCst);
            }
            NatTraversalEvent::ConnectionEstablished { .. } => {
                counters_clone
                    .connection_established
                    .fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        let _ = tx.send(event);
    });

    let endpoint = Arc::new(NatTraversalEndpoint::new(config, Some(event_callback), None).await?);
    Ok((endpoint, rx, counters))
}

/// Helper to generate a random peer ID
fn generate_random_peer_id() -> PeerId {
    let (public_key, _) = generate_ml_dsa_keypair().expect("Failed to generate keypair");
    derive_peer_id_from_public_key(&public_key)
}

async fn create_listening_endpoint_pair() -> Result<
    (
        Arc<NatTraversalEndpoint>,
        Arc<NatTraversalEndpoint>,
        PeerId,
        SocketAddr,
        Arc<EventCounters>,
        Arc<EventCounters>,
    ),
    NatTraversalError,
> {
    let (endpoint_a, _rx_a, counters_a) = create_endpoint_with_event_counters(vec![]).await?;
    let (endpoint_b, _rx_b, counters_b) = create_endpoint_with_event_counters(vec![]).await?;

    endpoint_b
        .start_listening(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await?;

    let b_endpoint = endpoint_b.get_endpoint().ok_or_else(|| {
        NatTraversalError::ConfigError("endpoint B should have a QUIC endpoint".to_string())
    })?;
    let b_addr = b_endpoint.local_addr().map_err(|error| {
        NatTraversalError::NetworkError(format!("failed to read endpoint B local address: {error}"))
    })?;
    let peer_id_b = endpoint_b.local_peer_id();

    Ok((
        endpoint_a, endpoint_b, peer_id_b, b_addr, counters_a, counters_b,
    ))
}

async fn add_existing_connection_to_peer(
    endpoint: &NatTraversalEndpoint,
    peer_id: PeerId,
    remote_addr: SocketAddr,
) -> Result<(), NatTraversalError> {
    let connection = endpoint
        .connect_to_peer(peer_id, "localhost", remote_addr)
        .await?;
    endpoint.add_connection(peer_id, connection)?;

    let existing = endpoint.get_connection(&peer_id)?;
    assert!(
        existing.is_some(),
        "Connection should exist after add_connection"
    );

    Ok(())
}

async fn drain_endpoint_events(endpoint: &NatTraversalEndpoint) -> Result<(), NatTraversalError> {
    for _ in 0..5 {
        let _ = endpoint.poll(std::time::Instant::now())?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

async fn assert_no_redundant_traversal_work(
    endpoint: &NatTraversalEndpoint,
    counters: &EventCounters,
    context: &str,
) -> Result<(), NatTraversalError> {
    drain_endpoint_events(endpoint).await?;

    assert_eq!(
        counters.coordination_requested(),
        0,
        "{context}: CoordinationRequested was emitted even though the peer is already connected"
    );
    assert_eq!(
        counters.hole_punching_started(),
        0,
        "{context}: HolePunchingStarted was emitted even though the peer is already connected"
    );
    assert_eq!(
        counters.connection_established(),
        0,
        "{context}: a redundant connection was established even though the peer is already connected"
    );

    Ok(())
}

async fn create_pair_with_registered_connection() -> Result<
    (
        Arc<NatTraversalEndpoint>,
        Arc<NatTraversalEndpoint>,
        PeerId,
        SocketAddr,
        Arc<EventCounters>,
        Arc<EventCounters>,
    ),
    NatTraversalError,
> {
    let (endpoint_a, endpoint_b, peer_id_b, b_addr, counters_a, counters_b) =
        create_listening_endpoint_pair().await?;
    add_existing_connection_to_peer(endpoint_a.as_ref(), peer_id_b, b_addr).await?;
    drain_endpoint_events(endpoint_a.as_ref()).await?;
    drain_endpoint_events(endpoint_b.as_ref()).await?;
    counters_a.reset();
    counters_b.reset();

    Ok((
        endpoint_a, endpoint_b, peer_id_b, b_addr, counters_a, counters_b,
    ))
}

async fn create_active_session_with_existing_connection() -> Result<
    (
        Arc<NatTraversalEndpoint>,
        Arc<NatTraversalEndpoint>,
        PeerId,
        Arc<EventCounters>,
    ),
    NatTraversalError,
> {
    let (endpoint_a, endpoint_b, peer_id_b, _b_addr, counters_a, _counters_b) =
        create_pair_with_registered_connection().await?;
    let connection = endpoint_a
        .remove_connection(&peer_id_b)?
        .ok_or_else(|| NatTraversalError::ConfigError("expected registered connection".into()))?;

    endpoint_a.initiate_nat_traversal(peer_id_b, test_coordinator_addr())?;
    counters_a.reset();
    endpoint_a.add_connection(peer_id_b, connection)?;

    let existing = endpoint_a.get_connection(&peer_id_b)?;
    assert!(
        existing.is_some(),
        "Connection should exist before polling active traversal session"
    );

    Ok((endpoint_a, endpoint_b, peer_id_b, counters_a))
}

fn test_coordinator_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 9000)
}

// ===== Test 1: initiate_nat_traversal() MUST skip when connection exists =====

/// This test verifies that initiate_nat_traversal() checks for existing connections.
///
/// Expected behavior:
/// - If a connection already exists to the peer, return Ok() immediately
/// - NO CoordinationRequested events should be emitted
/// - NO new session should be created
#[tokio::test]
async fn test_initiate_nat_traversal_must_skip_when_connection_exists() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint_a, endpoint_b, peer_id_b, _b_addr, counters_a, _counters_b) =
        create_pair_with_registered_connection()
            .await
            .expect("Failed to create connected endpoint pair");

    // Now call initiate_nat_traversal - WITH the connection already existing
    // This should return immediately without creating a session
    let result = endpoint_a.initiate_nat_traversal(peer_id_b, test_coordinator_addr());
    assert!(result.is_ok(), "Should return Ok even when skipping");

    assert_no_redundant_traversal_work(
        endpoint_a.as_ref(),
        counters_a.as_ref(),
        "initiate_nat_traversal",
    )
    .await
    .expect("poll should succeed");

    // Cleanup
    let _ = endpoint_a.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}

// ===== Test 2: initiate_hole_punching() MUST skip when connection exists =====

/// This test verifies that initiate_hole_punching() checks for existing connections.
///
/// Because initiate_hole_punching is a private method, we test it indirectly
/// by checking that HolePunchingStarted events are NOT emitted when a connection
/// exists during the punching phase.
#[tokio::test]
async fn test_initiate_hole_punching_must_skip_when_connection_exists() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint_a, endpoint_b, _peer_id_b, counters_a) =
        create_active_session_with_existing_connection()
            .await
            .expect("Failed to create active session with existing connection");

    assert_no_redundant_traversal_work(
        endpoint_a.as_ref(),
        counters_a.as_ref(),
        "initiate_hole_punching",
    )
    .await
    .expect("poll should succeed");

    // Cleanup
    let _ = endpoint_a.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}

// ===== Test 3: Deferred hole punch loop MUST recheck connections =====

/// This test verifies that the deferred hole punch execution loop
/// checks for connections before calling initiate_hole_punching.
///
/// The poll() method has a two-phase approach:
/// 1. Phase 1: Collect hole punch requests into hole_punch_requests Vec
/// 2. Phase 2: Execute requests by calling initiate_hole_punching for each
///
/// Between phase 1 and 2, a connection might be established by another
/// async task. The code should re-check before executing.
#[tokio::test]
async fn test_deferred_hole_punch_must_recheck_connections() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, endpoint_b, _peer_id_b, counters) =
        create_active_session_with_existing_connection()
            .await
            .expect("Failed to create active session with existing connection");

    assert_no_redundant_traversal_work(endpoint.as_ref(), counters.as_ref(), "deferred_hole_punch")
        .await
        .expect("poll should succeed");

    // Cleanup
    let _ = endpoint.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}

// ===== Test 4: attempt_connection_to_candidate() MUST check connections =====

/// This test documents that attempt_connection_to_candidate() needs a connection
/// check at the beginning to prevent redundant connection attempts.
#[tokio::test]
async fn test_candidate_attempt_must_check_existing_connection() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, endpoint_b, _peer_id_b, counters) =
        create_active_session_with_existing_connection()
            .await
            .expect("Failed to create active session with existing connection");

    assert_no_redundant_traversal_work(endpoint.as_ref(), counters.as_ref(), "candidate_attempt")
        .await
        .expect("poll should succeed");

    // Cleanup
    let _ = endpoint.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}

// ===== Test 5: Async task spawn MUST check connection first =====

/// This test documents that before spawning async connection tasks,
/// we need to verify no connection exists to prevent race conditions.
#[tokio::test]
async fn test_async_task_spawn_must_check_connection() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, endpoint_b, _peer_id_b, counters) =
        create_active_session_with_existing_connection()
            .await
            .expect("Failed to create active session with existing connection");

    assert_no_redundant_traversal_work(endpoint.as_ref(), counters.as_ref(), "async_task_spawn")
        .await
        .expect("poll should succeed");

    // Cleanup
    let _ = endpoint.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}

// ===== Test 6: Coordinator connection MUST check for existing =====

/// This test verifies that when establishing coordinator connections,
/// we check if we're already connected to that coordinator.
#[tokio::test]
async fn test_coordinator_connection_must_check_existing() {
    let _ = tracing_subscriber::fmt::try_init();

    let (
        endpoint,
        coordinator_endpoint,
        _coordinator_peer,
        coordinator_addr,
        counters,
        peer_counters,
    ) = create_pair_with_registered_connection()
        .await
        .expect("Failed to create endpoint pair with existing coordinator connection");

    let peer_id1 = generate_random_peer_id();
    let peer_id2 = generate_random_peer_id();

    // Start first traversal - this will try to connect to coordinator
    let result1 = endpoint.initiate_nat_traversal(peer_id1, coordinator_addr);
    assert!(result1.is_ok());

    // Start second traversal with same coordinator
    // Should reuse existing coordinator connection
    let result2 = endpoint.initiate_nat_traversal(peer_id2, coordinator_addr);
    assert!(result2.is_ok());

    assert_eq!(
        counters.coordination_requested(),
        2,
        "Both traversal requests should use the existing coordinator connection"
    );

    drain_endpoint_events(coordinator_endpoint.as_ref())
        .await
        .expect("coordinator events should drain");
    assert_eq!(
        peer_counters.connection_established(),
        0,
        "Coordinator accepted a redundant connection even though one already existed"
    );

    // Cleanup
    let _ = endpoint.shutdown().await;
    let _ = coordinator_endpoint.shutdown().await;
}

// ===== Test 7: Concurrent calls MUST not create duplicate work =====

/// Test that concurrent calls to initiate_nat_traversal() for the same peer
/// are properly handled without duplicate sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_initiate_nat_traversal_same_peer() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx, counters) = create_endpoint_with_event_counters(vec![])
        .await
        .expect("Failed to create endpoint");

    let peer_id = generate_random_peer_id();
    let coordinator = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 9000);

    const CONCURRENT_CALLS: usize = 5;
    let start_barrier = Arc::new(Barrier::new(CONCURRENT_CALLS));

    // Spawn multiple calls and release them together so the synchronous
    // initiation path runs on multiple runtime workers.
    let handles: Vec<_> = (0..CONCURRENT_CALLS)
        .map(|i| {
            let ep = endpoint.clone();
            let barrier = start_barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                let result = ep.initiate_nat_traversal(peer_id, coordinator);
                info!("Concurrent call {} result: {:?}", i, result);
                result
            })
        })
        .collect();

    // Wait for all to complete
    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Task should not panic");
        if let Ok(inner) = result {
            assert!(inner.is_ok(), "Concurrent call should succeed");
        }
    }

    // Allow events to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The existing session check should limit this to 1 coordination event
    // (first call creates session, subsequent calls return early)
    let count = counters.coordination_requested();
    info!(
        "Coordination events from {} concurrent calls: {}",
        CONCURRENT_CALLS, count
    );

    // The existing code has session deduplication, so this should be 1
    // This test verifies the session check works
    assert!(
        count <= 1,
        "Only one coordination event should be emitted for concurrent calls to same peer"
    );

    // Cleanup
    let _ = endpoint.shutdown().await;
}

// ===== Integration test: Full round-trip verification =====

/// Integration test that establishes a real connection and verifies
/// that initiate_nat_traversal properly skips when connection exists.
#[tokio::test]
async fn test_full_roundtrip_connection_check() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, endpoint_b, peer_id, _b_addr, counters, _counters_b) =
        create_pair_with_registered_connection()
            .await
            .expect("Failed to create connected endpoint pair");

    // A real localhost connection already exists, so traversal must not
    // fall back to the duplicate-session behavior this test used to cover.
    endpoint
        .initiate_nat_traversal(peer_id, test_coordinator_addr())
        .expect("traversal call should return Ok when skipping");
    assert_no_redundant_traversal_work(
        endpoint.as_ref(),
        counters.as_ref(),
        "full_roundtrip_connection_check",
    )
    .await
    .expect("poll should succeed");

    // Cleanup
    let _ = endpoint.shutdown().await;
    let _ = endpoint_b.shutdown().await;
}
