//! ADR-019 relay-serving opt-out: endpoint-level tests.
//!
//! Three loopback nodes: A (client), B (relay serving off), C (relay serving
//! on). These tests cover ADR-019 § Validation 3, 4 and 6 at the level where
//! relay selection and the CONNECT-UDP handshake live. The raw wire answer
//! (Validation 3, 7) and coordination (Validation 5) are also covered from the
//! public API in `tests/relay_serving_opt_out.rs`.

#![allow(clippy::expect_used)]

use super::*;
use crate::bootstrap_cache::BootstrapCacheConfig;

struct TestNode {
    endpoint: P2pEndpoint,
    addr: SocketAddr,
    accept: tokio::task::JoinHandle<()>,
    _cache_dir: tempfile::TempDir,
}

impl TestNode {
    async fn start(relay_serving: bool) -> Self {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let config = P2pConfig::builder()
            .bind_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
            .port_mapping_enabled(false)
            .relay_service_enabled(relay_serving)
            .bootstrap_cache(
                BootstrapCacheConfig::builder()
                    .cache_dir(cache_dir.path().to_path_buf())
                    .persist(false)
                    .build(),
            )
            .build()
            .expect("valid config");
        let endpoint = P2pEndpoint::new(config).await.expect("endpoint starts");
        let local = endpoint.local_addr().expect("local addr");
        let addr = if local.ip().is_unspecified() {
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, local.port()))
        } else {
            local
        };
        assert!(addr.ip().is_loopback(), "tests bind loopback only");
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

    async fn connect(&self, other: &TestNode) {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.endpoint.connect_addr(other.addr),
        )
        .await
        .expect("connect does not time out")
        .expect("connect succeeds");
    }

    async fn stop(self) {
        self.endpoint.shutdown().await;
        self.accept.abort();
    }
}

async fn establish(
    client: &TestNode,
    relay: &TestNode,
) -> Result<
    (
        Option<SocketAddr>,
        Option<Arc<crate::masque::MasqueRelaySocket>>,
    ),
    crate::nat_traversal_api::NatTraversalError,
> {
    tokio::time::timeout(
        Duration::from_secs(10),
        client.endpoint.inner.establish_relay_session(relay.addr),
    )
    .await
    .expect("relay handshake does not time out")
}

/// ADR-019 Validation 3: A asks B (serving off) for a Bind session and gets
/// 403 with the reason; B has no relay session; A falls back to C (serving
/// on) and gets a session there.
#[tokio::test]
async fn adr019_refused_by_serving_off_relay_then_falls_back_to_serving_relay() {
    let a = TestNode::start(true).await;
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    a.connect(&b).await;
    a.connect(&c).await;
    let b_peer = b.endpoint.peer_id();
    let target = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9));

    let err = establish(&a, &b)
        .await
        .expect_err("a serving-off relay must refuse");
    let message = err.to_string();
    assert!(
        message.contains("relay service disabled") && message.contains("403"),
        "the refusal carries status 403 and the reason: {message}"
    );
    assert_eq!(
        b.endpoint
            .runtime_assist_snapshot()
            .await
            .active_relay_sessions,
        0,
        "B serves no relay session"
    );
    assert_eq!(b.endpoint.stats().await.relay_requests_refused_disabled, 1);
    let a_stats = a.endpoint.stats().await;
    assert_eq!(a_stats.relay_refusals_forbidden, 1);
    assert_eq!(a_stats.relay_refusals_capacity, 0);
    assert_eq!(a_stats.relay_refusal_cache_size, 1);
    assert!(a.endpoint.inner.is_relay_refused(&b_peer));

    // The fallback relay list no longer offers B; C is next.
    let candidates = a.endpoint.inner.connected_relay_candidates(target);
    assert!(
        !candidates.contains(&b.addr),
        "B must be skipped after its 403: {candidates:?}"
    );
    assert!(candidates.contains(&c.addr), "C stays a candidate");
    for relay_addr in candidates {
        assert_ne!(relay_addr, b.addr);
    }
    let (public_addr, _socket) = establish(&a, &c)
        .await
        .expect("the serving relay C grants a Bind session");
    assert!(public_addr.is_some(), "C allocates a public address");
    assert_eq!(
        c.endpoint
            .runtime_assist_snapshot()
            .await
            .active_relay_sessions,
        1,
        "C serves the session A fell back to"
    );

    a.stop().await;
    b.stop().await;
    c.stop().await;
}

/// ADR-019 Validation 4: B (serving off) still uses relays: it opens a Bind
/// session on C's relay. (Reaching a NATed peer end to end needs NAT
/// simulation, which this repository has no in-process harness for.)
#[tokio::test]
async fn adr019_serving_off_node_still_uses_a_relay() {
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    b.connect(&c).await;

    let (public_addr, socket) = establish(&b, &c)
        .await
        .expect("B can still use C as its relay");
    assert!(public_addr.is_some(), "C allocates B a public address");
    assert!(socket.is_some(), "B gets a relay socket");
    assert_eq!(b.endpoint.inner.relay_sessions().len(), 1);
    assert_eq!(
        c.endpoint
            .runtime_assist_snapshot()
            .await
            .active_relay_sessions,
        1
    );
    assert!(!b.endpoint.relay_service_enabled());

    b.stop().await;
    c.stop().await;
}

/// ADR-019 Validation 6: after the 403, A does not pick B as a relay before
/// the refusal-cache entry expires (bootstrap-cache selection, hinted relays
/// and connected peers), and does pick it again after expiry. A 503 never
/// creates an entry.
#[tokio::test]
async fn adr019_refusal_cache_skips_refusing_relay_until_expiry() {
    let a = TestNode::start(true).await;
    let b = TestNode::start(false).await;
    let c = TestNode::start(true).await;
    a.connect(&b).await;
    a.connect(&c).await;
    let b_peer = b.endpoint.peer_id();
    let target = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9));

    // B is hinted as a relay (and coordinator), so it enters the bootstrap
    // cache's relay selection and the hinted relay list.
    a.endpoint
        .upsert_peer_hints(
            b_peer,
            vec![b.addr],
            Some(PeerCapabilities {
                supports_relay: true,
                supports_coordination: true,
                ..PeerCapabilities::default()
            }),
        )
        .await;
    assert_eq!(
        a.endpoint.default_relay_addrs(Some(target)).await,
        vec![b.addr],
        "before any refusal, the bootstrap cache picks B"
    );
    assert!(
        a.endpoint
            .hinted_assist_addrs(true, false)
            .await
            .contains(&b.addr)
    );

    let ttl = Duration::from_secs(2);
    a.endpoint.inner.relay_refusal_cache().set_ttl(ttl);
    establish(&a, &b).await.expect_err("B refuses with 403");
    let refused_at = Instant::now();

    assert!(a.endpoint.inner.is_relay_refused(&b_peer));
    let relays = a.endpoint.default_relay_addrs(Some(target)).await;
    assert!(
        !relays.contains(&b.addr),
        "before expiry B is not picked: {relays:?}"
    );
    assert_eq!(relays, vec![c.addr], "the connected serving peer C is next");
    assert!(
        !a.endpoint
            .hinted_assist_addrs(true, false)
            .await
            .contains(&b.addr),
        "B is not a hinted relay before expiry"
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

    let wait =
        (refused_at + ttl + Duration::from_millis(200)).saturating_duration_since(Instant::now());
    tokio::time::sleep(wait).await;

    assert!(!a.endpoint.inner.is_relay_refused(&b_peer));
    assert_eq!(
        a.endpoint.default_relay_addrs(Some(target)).await,
        vec![b.addr],
        "after expiry B is picked again"
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
    let cache = a.endpoint.inner.relay_refusal_cache();
    assert!(!cache.observe_response(
        Some(c.endpoint.peer_id()),
        &crate::masque::ConnectUdpResponse::error(503, "Server at capacity"),
        Instant::now(),
    ));
    assert!(!a.endpoint.inner.is_relay_refused(&c.endpoint.peer_id()));
    assert_eq!(a.endpoint.stats().await.relay_refusals_capacity, 1);

    a.stop().await;
    b.stop().await;
    c.stop().await;
}
