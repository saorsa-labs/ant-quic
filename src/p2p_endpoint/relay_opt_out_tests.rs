//! ADR-019 relay-serving opt-out: endpoint-level tests.
//!
//! Loopback nodes: A (client), B (relay serving off), C (relay serving on)
//! and T (dial target). On loopback a direct dial always succeeds, so the
//! dials below set the test-only `force_relay_stage` switch on the dialer:
//! the ladder skips its direct and hole-punch stages as if a NAT blocked
//! every direct path, and the real relay stage runs with the real default
//! relay selection (`default_relay_addrs`), CONNECT-UDP handshake and
//! relayed QUIC connection. The raw wire answer (Validation 3, 7) and
//! coordination (Validation 5) are covered from the public API in
//! `tests/relay_serving_opt_out.rs`.

#![allow(clippy::expect_used)]

use super::*;
use crate::bootstrap_cache::BootstrapCacheConfig;

const DIAL_BUDGET: Duration = Duration::from_secs(30);
const RECV_WINDOW: Duration = Duration::from_secs(10);

struct TestNode {
    endpoint: P2pEndpoint,
    addr: SocketAddr,
    accept: tokio::task::JoinHandle<()>,
    _cache_dir: tempfile::TempDir,
}

impl TestNode {
    async fn start(relay_serving: bool) -> Self {
        Self::start_with(relay_serving, |_| {}).await
    }

    async fn start_with(relay_serving: bool, configure: impl FnOnce(&mut P2pConfig)) -> Self {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let mut config = P2pConfig::builder()
            .bind_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
            .port_mapping_enabled(false)
            .mdns_enabled(false)
            .relay_service_enabled(relay_serving)
            .bootstrap_cache(
                BootstrapCacheConfig::builder()
                    .cache_dir(cache_dir.path().to_path_buf())
                    .persist(false)
                    .build(),
            )
            .build()
            .expect("valid config");
        configure(&mut config);
        let endpoint = P2pEndpoint::new(config).await.expect("endpoint starts");
        let local = endpoint.local_addr().expect("local addr");
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, local.port()));
        assert!(local.ip().is_loopback() || local.ip().is_unspecified());
        // Relay streams are served on connections the application accepts.
        let accept = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { while endpoint.accept().await.is_some() {} }
        });
        Self {
            endpoint,
            addr,
            accept,
            _cache_dir: cache_dir,
        }
    }

    fn peer(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    async fn connect(&self, other: &TestNode) {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.endpoint.connect_addr(other.addr),
        )
        .await
        .expect("connect does not time out")
        .expect("connect succeeds");
    }

    /// Hint `relay` as a relay-capable peer, so it enters the bootstrap
    /// cache's relay selection.
    async fn hint_relay(&self, relay: &TestNode) {
        self.endpoint
            .upsert_peer_hints(
                relay.peer(),
                vec![relay.addr],
                Some(PeerCapabilities {
                    supports_relay: true,
                    supports_coordination: true,
                    ..PeerCapabilities::default()
                }),
            )
            .await;
    }

    /// Dial `target` through the normal connect path with direct and
    /// hole-punch stages blocked, so the relay stage runs.
    async fn dial_via_relay(
        &self,
        target: &TestNode,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        self.endpoint
            .force_relay_stage
            .store(true, Ordering::Relaxed);
        tokio::time::timeout(
            DIAL_BUDGET,
            self.endpoint
                .connect_with_fallback(Some(target.addr), None, None, Some(target.peer())),
        )
        .await
        .expect("dial does not time out")
    }

    async fn relay_sessions(&self) -> (usize, u64) {
        let snapshot = self.endpoint.runtime_assist_snapshot().await;
        (
            snapshot.active_relay_sessions,
            snapshot.relay_bytes_forwarded,
        )
    }

    async fn stop(self) {
        self.endpoint.shutdown().await;
        self.accept.abort();
    }
}

async fn recv_within(node: &TestNode, from: PeerId, payload: &[u8]) -> bool {
    let deadline = tokio::time::Instant::now() + RECV_WINDOW;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, node.endpoint.recv()).await {
            Ok(Ok((peer, data))) if peer == from && data == payload => return true,
            Ok(Ok(_)) => continue,
            Ok(Err(_)) | Err(_) => return false,
        }
    }
}

/// Rank B above C in A's bootstrap cache: B with successes, C with
/// failures, so relay selection orders them B, C.
async fn rank_b_before_c(a: &TestNode, b: &TestNode, c: &TestNode) {
    a.hint_relay(b).await;
    a.hint_relay(c).await;
    for _ in 0..5 {
        a.endpoint
            .bootstrap_cache
            .record_success(&b.peer(), 5)
            .await;
        a.endpoint.bootstrap_cache.record_failure(&c.peer()).await;
    }
}

/// ADR-019 Validation 3: one real dial from A to T. B (serving off) is the
/// first relay candidate and C (serving on) the second. B answers 403 and
/// keeps no session; the same dial moves on to C and connects through C's
/// relay, and data flows A -> T through C.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr019_dial_falls_back_from_refusing_relay_to_serving_relay() {
    let a = TestNode::start(true).await;
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    let t = TestNode::start(true).await;
    rank_b_before_c(&a, &b, &c).await;
    let selection = a.endpoint.default_relay_addrs(Some(t.addr)).await;
    assert_eq!(
        selection.addrs.first(),
        Some(&b.addr),
        "precondition: B is the first relay candidate: {selection:?}"
    );

    let (conn, method) = a
        .dial_via_relay(&t)
        .await
        .expect("the dial falls back from B to C and connects");
    assert_eq!(conn.peer_id, t.peer());
    assert_eq!(
        method,
        ConnectionMethod::Relayed { relay: c.addr },
        "the connection goes through C's relay, not direct"
    );
    assert_eq!(conn.traversal_method, TraversalMethod::Relay);

    // B answered 403 and serves nothing.
    assert_eq!(b.endpoint.stats().await.relay_requests_refused_disabled, 1);
    assert_eq!(b.relay_sessions().await, (0, 0));
    let a_stats = a.endpoint.stats().await;
    assert_eq!(a_stats.relay_refusals_forbidden, 1);
    assert_eq!(a_stats.relay_refusal_cache_size, 1);
    assert!(a.endpoint.inner.is_relay_refused(&b.peer()));

    // Data path is C's relay.
    let (sessions, bytes_before) = c.relay_sessions().await;
    assert_eq!(sessions, 1, "C serves A's relay session");
    let payload = b"adr-019 via C";
    a.endpoint
        .send(&t.peer(), payload)
        .await
        .expect("A sends to T over the relayed connection");
    assert!(
        recv_within(&t, a.peer(), payload).await,
        "T receives A's data"
    );
    let (_, bytes_after) = c.relay_sessions().await;
    assert!(
        bytes_after > bytes_before && bytes_after > 0,
        "C forwarded the data: {bytes_before} -> {bytes_after}"
    );

    a.stop().await;
    b.stop().await;
    c.stop().await;
    t.stop().await;
}

/// ADR-019 Validation 4: B (serving off) still uses relays. B dials T
/// through C's relay with direct paths blocked, sends data, and T receives
/// it; C forwarded the bytes. (T is on loopback, not behind a real NAT: the
/// test proves B's client relay path end to end, not NAT behaviour.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr019_serving_off_node_still_uses_a_relay() {
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    let t = TestNode::start(true).await;
    b.hint_relay(&c).await;

    let (conn, method) = b
        .dial_via_relay(&t)
        .await
        .expect("B reaches T through C's relay");
    assert_eq!(conn.peer_id, t.peer());
    assert_eq!(method, ConnectionMethod::Relayed { relay: c.addr });
    assert!(!b.endpoint.relay_service_enabled());

    let payload = b"adr-019 leaf uses a relay";
    b.endpoint
        .send(&t.peer(), payload)
        .await
        .expect("B sends to T");
    assert!(
        recv_within(&t, b.peer(), payload).await,
        "T receives B's data"
    );
    let (sessions, bytes) = c.relay_sessions().await;
    assert_eq!(sessions, 1);
    assert!(bytes > 0, "C forwarded B's traffic");

    b.stop().await;
    c.stop().await;
    t.stop().await;
}

/// ADR-019 Validation 6: after the 403, A does not pick B as a relay before
/// the refusal-cache entry expires (bootstrap-cache selection, hinted relays
/// and connected peers), and does pick it again after expiry. Expiry uses
/// the cache's injected clock, not a real-time sleep. A 503 never creates an
/// entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr019_refusal_cache_skips_refusing_relay_until_expiry() {
    let a = TestNode::start(true).await;
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    a.connect(&b).await;
    a.connect(&c).await;
    let target = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9));
    a.hint_relay(&b).await;

    let before = a.endpoint.default_relay_addrs(Some(target)).await;
    assert!(
        before.addrs.contains(&b.addr) && !before.refused_any,
        "before any refusal B is a candidate: {before:?}"
    );
    assert!(
        a.endpoint
            .hinted_assist_addrs(true, false)
            .await
            .contains(&b.addr)
    );

    tokio::time::timeout(
        Duration::from_secs(10),
        a.endpoint.inner.establish_relay_session(b.addr),
    )
    .await
    .expect("handshake does not time out")
    .expect_err("B refuses with 403");

    let during = a.endpoint.default_relay_addrs(Some(target)).await;
    assert!(
        !during.addrs.contains(&b.addr) && during.refused_any,
        "before expiry B is not picked: {during:?}"
    );
    assert!(during.addrs.contains(&c.addr), "C is still offered");
    assert!(
        !a.endpoint
            .hinted_assist_addrs(true, false)
            .await
            .contains(&b.addr)
    );
    assert!(
        a.endpoint
            .hinted_assist_addrs(false, true)
            .await
            .contains(&b.addr),
        "B is still a hinted coordinator"
    );
    assert!(
        !a.endpoint
            .inner
            .connected_relay_candidates(target)
            .contains(&b.addr)
    );
    assert!(a.endpoint.inner.is_relay_addr_refused(b.addr));

    let cache = a.endpoint.inner.relay_refusal_cache();
    cache.advance_clock(cache.ttl() + Duration::from_secs(1));

    assert!(!a.endpoint.inner.is_relay_refused(&b.peer()));
    assert!(!a.endpoint.inner.is_relay_addr_refused(b.addr));
    let after = a.endpoint.default_relay_addrs(Some(target)).await;
    assert!(
        after.addrs.contains(&b.addr),
        "after expiry B is picked again: {after:?}"
    );
    assert!(
        a.endpoint
            .hinted_assist_addrs(true, false)
            .await
            .contains(&b.addr)
    );
    assert!(
        a.endpoint
            .inner
            .connected_relay_candidates(target)
            .contains(&b.addr)
    );
    assert_eq!(a.endpoint.stats().await.relay_refusal_cache_size, 0);

    // A 503 (capacity) is counted but never cached.
    assert!(!cache.observe_response(
        Some(c.peer()),
        Some(c.addr),
        &crate::masque::ConnectUdpResponse::error(503, "Server at capacity"),
        cache.now(),
    ));
    assert!(!a.endpoint.inner.is_relay_refused(&c.peer()));
    assert_eq!(a.endpoint.stats().await.relay_refusals_capacity, 1);

    a.stop().await;
    b.stop().await;
    c.stop().await;
}

/// ADR-019 cache bypass: an address-only relay source (static
/// `relay_nodes`) skips a relay once it refused us, and a dial whose every
/// relay candidate refused fails fast with `AllRelaysRefused` instead of
/// re-asking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr019_all_relays_refused_fails_fast_without_reasking() {
    let b = TestNode::start(false).await;
    let t = TestNode::start(true).await;
    let b_addr = b.addr;
    let a = TestNode::start_with(true, |config| {
        config.nat.relay_nodes = vec![b_addr];
    })
    .await;

    // First dial: B is tried (its peer ID is not known yet) and refuses.
    let first = a.dial_via_relay(&t).await;
    assert!(first.is_err(), "B is the only relay and refuses");
    assert_eq!(b.endpoint.stats().await.relay_requests_refused_disabled, 1);
    assert!(a.endpoint.inner.is_relay_refused(&b.peer()));

    // Second dial: no relay is asked again; the dial fails with the typed
    // error.
    let selection = a.endpoint.default_relay_addrs(Some(t.addr)).await;
    assert!(
        selection.addrs.is_empty() && selection.refused_any,
        "{selection:?}"
    );
    let second = a.dial_via_relay(&t).await;
    assert!(
        matches!(
            second,
            Err(EndpointError::NatTraversal(
                NatTraversalError::AllRelaysRefused
            ))
        ),
        "{second:?}"
    );
    assert_eq!(
        b.endpoint.stats().await.relay_requests_refused_disabled,
        1,
        "B is not re-asked before expiry"
    );

    a.stop().await;
    b.stop().await;
    t.stop().await;
}

/// ADR-019 refusal path read bound: a peer that sends a length prefix and
/// part of the body, then stalls, does not hold the serving-off node's
/// stream open. The node drops it after the refusal timeout (shortened to
/// 200 ms here; production is `RELAY_REFUSAL_REQUEST_TIMEOUT`, 5 s) with no
/// answer and no refusal counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adr019_stalled_request_to_serving_off_node_is_dropped_after_timeout() {
    let a = TestNode::start(true).await;
    let b = TestNode::start(false).await;
    let bound = Duration::from_millis(200);
    b.endpoint.inner.set_relay_refusal_timeout_for_test(bound);
    a.connect(&b).await;

    let conn = a
        .endpoint
        .get_quic_connection(&b.peer())
        .expect("lookup")
        .expect("connection to B");
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
        .await
        .expect("open_bi does not time out")
        .expect("open_bi");
    // Length 100, then only 4 of the 100 body bytes; the stream stays open.
    send.write_all(&[0, 0, 0, 100, 1, 2, 3, 4])
        .await
        .expect("write partial request");
    let started = Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(4096))
        .await
        .expect("B drops the stalled request stream within the bound");
    let waited = started.elapsed();
    if let Ok(bytes) = read {
        assert!(
            bytes.is_empty(),
            "no response to a stalled request: {bytes:?}"
        );
    }
    assert!(
        waited >= bound / 2,
        "the stream is held until the timeout, not dropped at once: {waited:?}"
    );
    assert_eq!(b.endpoint.stats().await.relay_requests_refused_disabled, 0);
    drop(send);

    a.stop().await;
    b.stop().await;
}
