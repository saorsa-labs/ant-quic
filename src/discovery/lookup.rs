// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! `AddressLookup` trait + parallel resolver registry (X0X-0038).
//!
//! Address resolution today is monolithic — `BootstrapCache` is the singleton
//! source, with mDNS and `DEFAULT_BOOTSTRAP_PEERS` as ad-hoc parallel paths.
//! This module introduces a single trait that wraps each source so they can be
//! composed into a [`LookupRegistry`] that fans out lookups in parallel and
//! tolerates per-service errors (mirrors iroh PRs #3960 + #4126).
//!
//! Phase A scope only:
//! - The trait + registry + three default impls.
//! - No wiring change to existing `Endpoint::connect` callers — this module is
//!   additive, integration into the connection pipeline lands in later
//!   tickets per the SOTA-Borrow plan.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::stream::{SelectAll, Stream, StreamExt};

use crate::bootstrap_cache::BootstrapCache;
use crate::link_transport::BoxStream;
use crate::nat_traversal_api::PeerId;

/// Error returned by a single `AddressLookup` service.
///
/// Per-service errors do not abort a [`LookupRegistry`] resolve — the registry
/// records the error against the failing source and continues to surface
/// successful items from peer services. Callers that care about per-source
/// distinguishability should hold the [`AddressLookup::name`] alongside the
/// error site.
#[derive(Debug, Clone)]
pub struct LookupError {
    /// Human-readable error message.
    pub message: String,
    /// Whether the failure is plausibly retryable (transient I/O, lock
    /// contention, etc.) versus structural (peer not present in source).
    pub retryable: bool,
}

impl LookupError {
    /// Build a transient (retryable) error.
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }

    /// Build a structural (non-retryable) error such as `NotFound`.
    pub fn structural(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lookup error: {}", self.message)
    }
}

impl std::error::Error for LookupError {}

/// A single address-resolution service.
///
/// Each implementation produces a stream of `(SocketAddr, LookupError)`
/// results for the requested `peer_id`. The stream is allowed to:
///
/// - Yield zero or more successful addresses then terminate.
/// - Yield mixed `Ok` / `Err` items — the registry forwards both unchanged.
/// - Terminate immediately with `None` if the source has no record.
/// - Run indefinitely if the source is push-based (e.g. mDNS).
pub trait AddressLookup: Send + Sync + 'static {
    /// Stable identifier for this source. Used in logs and registry traces.
    fn name(&self) -> &'static str;

    /// Begin a lookup for `peer_id`.
    fn lookup(&self, peer_id: PeerId) -> BoxStream<'static, Result<SocketAddr, LookupError>>;
}

// =============================================================================
// LookupRegistry — parallel fanout + per-service error tolerance
// =============================================================================

/// A registry of [`AddressLookup`] services that fans out lookups in parallel.
///
/// One service erroring or panicking does not abort the resolve — successful
/// items from peer services keep flowing. This mirrors iroh PR #4126.
#[derive(Default, Clone)]
pub struct LookupRegistry {
    services: Vec<Arc<dyn AddressLookup>>,
}

impl std::fmt::Debug for LookupRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupRegistry")
            .field("service_count", &self.services.len())
            .field(
                "services",
                &self.services.iter().map(|s| s.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl LookupRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service.
    pub fn add_service<S>(&mut self, service: S)
    where
        S: AddressLookup,
    {
        self.services.push(Arc::new(service));
    }

    /// Register an already-Arc'd service. Useful when the same source is
    /// shared across registries.
    pub fn add_service_arc(&mut self, service: Arc<dyn AddressLookup>) {
        self.services.push(service);
    }

    /// Number of registered services.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether this registry is empty.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Names of registered services in insertion order.
    pub fn service_names(&self) -> Vec<&'static str> {
        self.services.iter().map(|s| s.name()).collect()
    }

    /// Begin a parallel lookup across all registered services.
    ///
    /// The returned stream yields items as they become available from any
    /// service. Per-service errors are forwarded as `Err(LookupError)` items
    /// rather than terminating the overall stream — successful items from
    /// peer services keep flowing.
    ///
    /// Each per-service stream is drained to completion, so multi-address
    /// sources (e.g. [`BootstrapCacheLookup`] backed by a peer with several
    /// known addresses) surface every item, not just the first. See X0X-0055
    /// for the bug history that motivated treating named lookups as streams
    /// rather than futures.
    pub fn lookup(&self, peer_id: PeerId) -> ParallelLookupStream {
        let mut inner = SelectAll::new();

        for service in &self.services {
            let service = Arc::clone(service);
            inner.push(NamedLookup::new(service, peer_id));
        }

        ParallelLookupStream { inner }
    }
}

/// A stream that drains `(name, item)` pairs from all registered services in
/// parallel. Public so callers can hold it in their own state.
pub struct ParallelLookupStream {
    inner: SelectAll<NamedLookup>,
}

impl Stream for ParallelLookupStream {
    type Item = (&'static str, Result<SocketAddr, LookupError>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl std::fmt::Debug for ParallelLookupStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelLookupStream")
            .field("active_lookups", &self.inner.len())
            .finish()
    }
}

/// Per-service stream wrapper. Yields one tagged item per inner-stream item
/// and terminates (returns `Poll::Ready(None)`) when the inner stream ends.
///
/// This is a `Stream`, not a `Future` — that distinction is load-bearing.
/// Earlier (`ant-quic` 0.27.13, X0X-0038) `NamedLookup` was a `Future` that
/// completed on the first inner item; combining many of them via
/// `FuturesUnordered` silently dropped every address after the first per
/// source. See X0X-0055.
struct NamedLookup {
    name: &'static str,
    stream: BoxStream<'static, Result<SocketAddr, LookupError>>,
}

impl NamedLookup {
    fn new(service: Arc<dyn AddressLookup>, peer_id: PeerId) -> Self {
        let name = service.name();
        let stream = service.lookup(peer_id);
        Self { name, stream }
    }
}

impl Stream for NamedLookup {
    type Item = (&'static str, Result<SocketAddr, LookupError>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let name = self.name;
        match self.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some((name, item))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// =============================================================================
// Default impls
// =============================================================================

/// `AddressLookup` impl backed by a [`BootstrapCache`].
///
/// Yields each cached address for the peer (if any), then terminates.
#[derive(Clone)]
pub struct BootstrapCacheLookup {
    cache: Arc<BootstrapCache>,
}

impl BootstrapCacheLookup {
    /// Wrap an existing bootstrap cache.
    pub fn new(cache: Arc<BootstrapCache>) -> Self {
        Self { cache }
    }
}

impl std::fmt::Debug for BootstrapCacheLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapCacheLookup").finish()
    }
}

impl AddressLookup for BootstrapCacheLookup {
    fn name(&self) -> &'static str {
        "bootstrap-cache"
    }

    fn lookup(&self, peer_id: PeerId) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
        let cache = Arc::clone(&self.cache);
        let stream = futures_util::stream::once(async move {
            let peer = cache.get_peer(&peer_id).await;
            match peer {
                Some(p) if !p.addresses.is_empty() => Ok(p.addresses),
                Some(_) => Err(LookupError::structural(format!(
                    "bootstrap cache: peer {:?} present but has no addresses",
                    peer_id
                ))),
                None => Err(LookupError::structural(format!(
                    "bootstrap cache: peer {:?} not present",
                    peer_id
                ))),
            }
        })
        .flat_map(|res| match res {
            Ok(addrs) => {
                let items: Vec<Result<SocketAddr, LookupError>> =
                    addrs.into_iter().map(Ok).collect();
                futures_util::stream::iter(items).boxed()
            }
            Err(e) => futures_util::stream::iter(vec![Err(e)]).boxed(),
        });
        Box::pin(stream)
    }
}

/// `AddressLookup` impl that holds a manually-populated peer→address table.
///
/// Currently a thin shim: tests and Phase-A wiring populate the table, which
/// stands in for a live mDNS subscriber. Wiring to live mDNS is out of scope
/// for X0X-0038 per the SOTA-Borrow plan ("Don't yet rip out direct mDNS /
/// bootstrap-cache callers in p2p_endpoint.rs").
#[derive(Default, Clone)]
pub struct MdnsLookup {
    inner: Arc<tokio::sync::RwLock<HashMap<PeerId, Vec<SocketAddr>>>>,
}

impl MdnsLookup {
    /// Empty mDNS table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert/update the addresses we've seen for `peer_id`.
    pub async fn upsert(&self, peer_id: PeerId, addrs: Vec<SocketAddr>) {
        let mut guard = self.inner.write().await;
        guard.insert(peer_id, addrs);
    }

    /// Forget a peer.
    pub async fn forget(&self, peer_id: &PeerId) {
        let mut guard = self.inner.write().await;
        guard.remove(peer_id);
    }
}

impl std::fmt::Debug for MdnsLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsLookup").finish()
    }
}

impl AddressLookup for MdnsLookup {
    fn name(&self) -> &'static str {
        "mdns"
    }

    fn lookup(&self, peer_id: PeerId) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
        let inner = Arc::clone(&self.inner);
        let stream = futures_util::stream::once(async move {
            let guard = inner.read().await;
            match guard.get(&peer_id).cloned() {
                Some(addrs) if !addrs.is_empty() => Ok(addrs),
                Some(_) => Err(LookupError::structural(format!(
                    "mdns: peer {:?} present with empty address list",
                    peer_id
                ))),
                None => Err(LookupError::structural(format!(
                    "mdns: peer {:?} not present",
                    peer_id
                ))),
            }
        })
        .flat_map(|res| match res {
            Ok(addrs) => {
                let items: Vec<Result<SocketAddr, LookupError>> =
                    addrs.into_iter().map(Ok).collect();
                futures_util::stream::iter(items).boxed()
            }
            Err(e) => futures_util::stream::iter(vec![Err(e)]).boxed(),
        });
        Box::pin(stream)
    }
}

/// `AddressLookup` impl over a fixed list of `(PeerId, SocketAddr)` pairs.
///
/// Useful for hardcoded bootstrap peers (e.g. x0x's `DEFAULT_BOOTSTRAP_PEERS`)
/// and for tests.
#[derive(Clone)]
pub struct HardcodedLookup {
    name: &'static str,
    table: Arc<HashMap<PeerId, Vec<SocketAddr>>>,
}

impl HardcodedLookup {
    /// Build from an explicit peer→address map.
    pub fn from_map(name: &'static str, table: HashMap<PeerId, Vec<SocketAddr>>) -> Self {
        Self {
            name,
            table: Arc::new(table),
        }
    }

    /// Build from a list of `(PeerId, Vec<SocketAddr>)` pairs.
    pub fn from_pairs(
        name: &'static str,
        pairs: impl IntoIterator<Item = (PeerId, Vec<SocketAddr>)>,
    ) -> Self {
        let mut table: HashMap<PeerId, Vec<SocketAddr>> = HashMap::new();
        for (peer, addrs) in pairs {
            table.entry(peer).or_default().extend(addrs);
        }
        Self::from_map(name, table)
    }
}

impl std::fmt::Debug for HardcodedLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardcodedLookup")
            .field("name", &self.name)
            .field("entries", &self.table.len())
            .finish()
    }
}

impl AddressLookup for HardcodedLookup {
    fn name(&self) -> &'static str {
        self.name
    }

    fn lookup(&self, peer_id: PeerId) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
        let addrs = self.table.get(&peer_id).cloned().unwrap_or_default();
        if addrs.is_empty() {
            let err = LookupError::structural(format!(
                "hardcoded[{}]: peer {:?} not present",
                self.name, peer_id
            ));
            Box::pin(futures_util::stream::iter(vec![Err(err)]))
        } else {
            let items: Vec<Result<SocketAddr, LookupError>> = addrs.into_iter().map(Ok).collect();
            Box::pin(futures_util::stream::iter(items))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_cache::BootstrapCacheConfig;
    use futures_util::StreamExt;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    /// Helper: drain a stream into a Vec.
    async fn drain<S, T>(mut s: Pin<Box<S>>) -> Vec<T>
    where
        S: Stream<Item = T> + ?Sized,
    {
        let mut out = Vec::new();
        while let Some(x) = s.next().await {
            out.push(x);
        }
        out
    }

    /// Helper: drain ParallelLookupStream into Vec of items.
    async fn drain_registry(
        mut s: ParallelLookupStream,
    ) -> Vec<(&'static str, Result<SocketAddr, LookupError>)> {
        let mut out = Vec::new();
        while let Some(x) = s.next().await {
            out.push(x);
        }
        out
    }

    #[tokio::test]
    async fn hardcoded_lookup_yields_addresses() {
        let p = peer(1);
        let lookup =
            HardcodedLookup::from_pairs("test-static", [(p, vec![addr(5000), addr(5001)])]);
        assert_eq!(lookup.name(), "test-static");

        let items = drain(Box::pin(lookup.lookup(p))).await;
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], Ok(a) if a.port() == 5000));
        assert!(matches!(&items[1], Ok(a) if a.port() == 5001));
    }

    #[tokio::test]
    async fn hardcoded_lookup_missing_peer_yields_structural_error() {
        let lookup = HardcodedLookup::from_pairs("static", []);
        let items = drain(Box::pin(lookup.lookup(peer(7)))).await;
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], Err(e) if !e.retryable));
    }

    #[tokio::test]
    async fn mdns_lookup_yields_after_upsert() {
        let lookup = MdnsLookup::new();
        let p = peer(2);
        lookup.upsert(p, vec![addr(6000)]).await;

        let items = drain(Box::pin(lookup.lookup(p))).await;
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], Ok(a) if a.port() == 6000));
    }

    #[tokio::test]
    async fn mdns_lookup_missing_yields_error() {
        let lookup = MdnsLookup::new();
        let items = drain(Box::pin(lookup.lookup(peer(9)))).await;
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], Err(_)));
    }

    fn cache_config(dir: &TempDir) -> BootstrapCacheConfig {
        BootstrapCacheConfig::builder()
            .cache_dir(dir.path().to_path_buf())
            .build()
    }

    #[tokio::test]
    async fn bootstrap_cache_lookup_yields_seeded_addresses() {
        let dir = TempDir::new().expect("tempdir");
        let cache = Arc::new(
            BootstrapCache::open(cache_config(&dir))
                .await
                .expect("open cache"),
        );
        let p = peer(3);
        cache.add_seed(p, vec![addr(7000), addr(7001)]).await;

        let lookup = BootstrapCacheLookup::new(Arc::clone(&cache));
        assert_eq!(lookup.name(), "bootstrap-cache");

        let items = drain(Box::pin(lookup.lookup(p))).await;
        let oks: Vec<_> = items
            .iter()
            .filter_map(|x| x.as_ref().ok().copied())
            .collect();
        assert!(oks.contains(&addr(7000)));
        assert!(oks.contains(&addr(7001)));
    }

    #[tokio::test]
    async fn bootstrap_cache_lookup_missing_yields_error() {
        let dir = TempDir::new().expect("tempdir");
        let cache = Arc::new(
            BootstrapCache::open(cache_config(&dir))
                .await
                .expect("open cache"),
        );
        let lookup = BootstrapCacheLookup::new(cache);
        let items = drain(Box::pin(lookup.lookup(peer(99)))).await;
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], Err(_)));
    }

    /// Acceptance test for X0X-0038:
    /// 3 services, 1 errors, 2 succeed → resolve still surfaces the 2 successes.
    #[tokio::test]
    async fn discovery_parallel_error_tolerance() {
        let p = peer(42);

        // Service A: hardcoded — yields one address.
        let svc_a = HardcodedLookup::from_pairs("svc-a", [(p, vec![addr(8000)])]);
        // Service B: hardcoded — yields a different address.
        let svc_b = HardcodedLookup::from_pairs("svc-b", [(p, vec![addr(8001)])]);
        // Service C: always errors. Use a custom impl to be sure the registry
        // doesn't abort on it.
        struct ErrorOnly;
        impl AddressLookup for ErrorOnly {
            fn name(&self) -> &'static str {
                "svc-c-error"
            }
            fn lookup(
                &self,
                _peer_id: PeerId,
            ) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
                Box::pin(futures_util::stream::iter(vec![Err(
                    LookupError::transient("synthetic"),
                )]))
            }
        }

        let mut reg = LookupRegistry::new();
        reg.add_service(svc_a);
        reg.add_service(svc_b);
        reg.add_service(ErrorOnly);
        assert_eq!(reg.len(), 3);
        assert_eq!(reg.service_names(), vec!["svc-a", "svc-b", "svc-c-error"]);

        let items = drain_registry(reg.lookup(p)).await;

        // 3 items overall (one from each service).
        assert_eq!(items.len(), 3);

        // 2 successful addresses surfaced.
        let oks: Vec<SocketAddr> = items
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok().copied())
            .collect();
        assert_eq!(oks.len(), 2);
        assert!(oks.contains(&addr(8000)));
        assert!(oks.contains(&addr(8001)));

        // 1 error tagged to the failing service.
        let errs: Vec<&'static str> = items
            .iter()
            .filter_map(|(name, r)| if r.is_err() { Some(*name) } else { None })
            .collect();
        assert_eq!(errs, vec!["svc-c-error"]);
    }

    /// Empty registry resolves to an empty stream rather than hanging.
    #[tokio::test]
    async fn empty_registry_yields_no_items() {
        let reg = LookupRegistry::new();
        assert!(reg.is_empty());
        let items = drain_registry(reg.lookup(peer(0))).await;
        assert!(items.is_empty());
    }

    /// The registry actually fans out — a slow service does not block a fast
    /// service's first item from being observable.
    #[tokio::test]
    async fn registry_is_concurrent() {
        let p = peer(7);

        struct SlowOk {
            counter: AtomicUsize,
        }
        impl AddressLookup for SlowOk {
            fn name(&self) -> &'static str {
                "slow"
            }
            fn lookup(
                &self,
                _peer_id: PeerId,
            ) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
                self.counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Box::pin(futures_util::stream::once(async {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Ok::<_, LookupError>(addr(9999))
                }))
            }
        }

        let mut reg = LookupRegistry::new();
        reg.add_service(HardcodedLookup::from_pairs("fast", [(p, vec![addr(8000)])]));
        reg.add_service(SlowOk {
            counter: AtomicUsize::new(0),
        });

        let start = std::time::Instant::now();
        let mut stream = reg.lookup(p);
        let first = stream.next().await.expect("first item");
        // Fast service must come first.
        assert!(first.1.is_ok());
        // Got the first item well before the slow service's 200ms.
        assert!(
            start.elapsed() < std::time::Duration::from_millis(150),
            "fanout did not happen in parallel: elapsed = {:?}",
            start.elapsed()
        );
    }

    /// Regression test for X0X-0055: a service that yields N addresses for
    /// the requested peer must surface all N items via the registry, not just
    /// the first.
    ///
    /// The pre-fix `NamedLookup` was a `Future` that completed on the first
    /// inner-stream item, so `FuturesUnordered<NamedLookup>` dropped the
    /// underlying stream after one item. This test exercises a 3-source
    /// registry where one source carries 3 addresses and asserts all three
    /// surface.
    #[tokio::test]
    async fn registry_surfaces_all_addresses_per_service() {
        let p = peer(11);

        // Source A: 3 addresses for `p`.
        let svc_a =
            HardcodedLookup::from_pairs("multi-a", [(p, vec![addr(7100), addr(7101), addr(7102)])]);
        // Source B: 1 address.
        let svc_b = HardcodedLookup::from_pairs("single-b", [(p, vec![addr(7200)])]);
        // Source C: error only.
        struct ErrorOnly;
        impl AddressLookup for ErrorOnly {
            fn name(&self) -> &'static str {
                "err-c"
            }
            fn lookup(
                &self,
                _peer_id: PeerId,
            ) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
                Box::pin(futures_util::stream::iter(vec![Err(
                    LookupError::transient("synthetic"),
                )]))
            }
        }

        let mut reg = LookupRegistry::new();
        reg.add_service(svc_a);
        reg.add_service(svc_b);
        reg.add_service(ErrorOnly);

        let items = drain_registry(reg.lookup(p)).await;
        // 3 from multi-a + 1 from single-b + 1 from err-c = 5 total items.
        assert_eq!(items.len(), 5, "expected 5 items (3+1+1), got: {:?}", items);

        // All 3 multi-a addresses surfaced.
        let multi_a_addrs: Vec<SocketAddr> = items
            .iter()
            .filter_map(|(name, r)| {
                if *name == "multi-a" {
                    r.as_ref().ok().copied()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            multi_a_addrs.len(),
            3,
            "multi-a must surface all 3 addresses, got: {:?}",
            multi_a_addrs
        );
        assert!(multi_a_addrs.contains(&addr(7100)));
        assert!(multi_a_addrs.contains(&addr(7101)));
        assert!(multi_a_addrs.contains(&addr(7102)));

        // single-b's one address surfaced.
        let single_b_addrs: Vec<SocketAddr> = items
            .iter()
            .filter_map(|(name, r)| {
                if *name == "single-b" {
                    r.as_ref().ok().copied()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(single_b_addrs, vec![addr(7200)]);

        // err-c's error surfaced.
        let err_c_count = items
            .iter()
            .filter(|(name, r)| *name == "err-c" && r.is_err())
            .count();
        assert_eq!(err_c_count, 1);
    }

    /// Registry survives a service whose stream is empty (no items, no error).
    #[tokio::test]
    async fn registry_handles_empty_stream() {
        struct EmptySvc;
        impl AddressLookup for EmptySvc {
            fn name(&self) -> &'static str {
                "empty"
            }
            fn lookup(
                &self,
                _peer_id: PeerId,
            ) -> BoxStream<'static, Result<SocketAddr, LookupError>> {
                Box::pin(futures_util::stream::empty())
            }
        }

        let mut reg = LookupRegistry::new();
        reg.add_service(EmptySvc);
        reg.add_service(HardcodedLookup::from_pairs(
            "static",
            [(peer(1), vec![addr(5000)])],
        ));

        let items = drain_registry(reg.lookup(peer(1))).await;
        // Only the static service yielded.
        assert_eq!(items.len(), 1);
        assert!(items[0].1.is_ok());
        assert_eq!(items[0].0, "static");
    }
}
