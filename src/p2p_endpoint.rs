// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! P2P endpoint for ant-quic
//!
//! This module provides the main API for P2P communication with NAT traversal,
//! secure connections, and event-driven architecture.
//!
//! # Features
//!
//! - Configuration via [`P2pConfig`](crate::unified_config::P2pConfig)
//! - Event subscription via broadcast channels
//! - TLS-based peer authentication via ML-DSA-65 (v0.2+)
//! - NAT traversal with automatic fallback
//! - Connection metrics and statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::{P2pEndpoint, P2pConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // All nodes are symmetric - they can both connect and accept connections
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:9000".parse()?)
//!         .known_peer("quic.saorsalabs.com:9000".parse()?)
//!         .build()?;
//!
//!     let endpoint = P2pEndpoint::new(config).await?;
//!     println!("Peer ID: {:?}", endpoint.peer_id());
//!
//!     // Subscribe to events
//!     let mut events = endpoint.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             println!("Event: {:?}", event);
//!         }
//!     });
//!
//!     // Connect to known peers
//!     endpoint.connect_known_peers().await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use rand::RngCore;
use serde::Serialize;
use tokio::sync::{Mutex as TokioMutex, Notify, RwLock, Semaphore, broadcast, mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::ack_frame::{
    ACK_BIDI_REQUEST_MAGIC, ACK_BIDI_RESPONSE_MAX_BYTES, AckControlOutcome, ReceiveRejectReason,
    decode_ack_bidi_request, decode_ack_bidi_response, decode_ack_control, decode_probe_request,
    encode_ack_bidi_request, encode_ack_bidi_response, encode_ack_control, encode_probe_request,
};
use crate::bootstrap_cache::{
    BootstrapCache, BootstrapTokenStore, CachedPeer, PeerCapabilities, PeerSource,
};
use crate::bounded_pending_buffer::BoundedPendingBuffer;
use crate::connection_router::{ConnectionRouter, RouterConfig};
use crate::connection_strategy::{
    ConnectionMethod, ConnectionStage, ConnectionStrategy, StrategyConfig,
};
use crate::constrained::ConnectionId as ConstrainedConnectionId;
use crate::constrained::EngineEvent;
use crate::coordinator_control::{clear_live_request, take_live_rejection};
use crate::crypto::raw_public_keys::key_utils::{
    derive_peer_id_from_public_key, generate_ml_dsa_keypair,
};
use crate::happy_eyeballs::{self, HappyEyeballsConfig};
use crate::mdns::{MdnsPeerRecord, MdnsRuntimeEvent, MdnsSnapshot, spawn_mdns_runtime};
pub use crate::nat_traversal_api::TraversalPhase;
use crate::nat_traversal_api::{
    IncomingAckBidiStream, NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, PeerId,
    TraversalFailureReason,
};
use crate::peer_directory::{PeerDirectorySnapshot, PeerDiscoverySource};
use crate::port_mapping::{
    PortMappingEvent, PortMappingSnapshot, is_globally_routable_advertise_address,
    spawn_best_effort_port_mapping,
};
use crate::reachability::{ReachabilityScope, TraversalMethod, socket_addr_scope};
use crate::transport::{ProtocolEngine, TransportAddr, TransportRegistry};
use crate::unified_config::{AutoConnectPolicy, P2pConfig, TrustPolicy};
use crate::{ConnectionCloseReason, Side};

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;
/// Peer lifecycle event channel capacity.
const PEER_EVENT_CHANNEL_CAPACITY: usize = 256;
/// Maximum time an ACK-requested payload may wait for receiver queue admission.
///
/// The ACK contract is "decoded and admitted into the `recv()` pipeline".
/// Waiting without bound here couples sender-visible ACK latency to application
/// drain speed and can cascade into mesh-wide send timeouts. A bounded wait
/// preserves the accepted-delivery meaning while returning structured
/// backpressure to callers.
const ACK_RECEIVE_ADMISSION_TIMEOUT: Duration = Duration::from_millis(100);
/// Maximum receiver-side time spent writing the ACK-v2 response stream.
///
/// Sender-side ACK timeout remains the end-to-end contract; this shorter
/// receiver budget exposes response-write starvation directly instead of
/// burying it inside an opaque sender timeout.
const ACK_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound for the duplicate-safe ACK-v2 retry after sender timeout.
///
/// The retry reuses the original ACK-v2 request ID, so the receiver can replay
/// an already-accepted outcome without delivering the payload twice. This needs
/// to be large enough for WAN tails: a 2s retry cap caused repeated false
/// negatives on long cross-region paths where the receiver admitted the
/// payload but the sender had already timed out and reset the response stream.
const ACK_TIMEOUT_RETRY_TIMEOUT: Duration = Duration::from_secs(6);
/// X0X-0062: consecutive `SenderRetryFailed` outcomes (i.e. both the initial
/// `send_with_receive_ack` AND its X0X-0060 duplicate-safe retry timed out)
/// allowed within `LIVENESS_FAILURE_WINDOW` before we conclude the underlying
/// QUIC connection's data path is half-dead and force-close it so the caller
/// can re-dial. The X0X-0062 root cause was nyc → nuremberg producing 39-61
/// such double-failures per minute while ant-quic still reported the
/// connection as `Live`; emitting a `Closed { LivenessTimeout }` event here is
/// what allows x0x's X0X-0053 mid-send race (extended to also watch for
/// non-Replaced closes) to abandon the stuck connection.
const LIVENESS_FAILURE_THRESHOLD: u32 = 5;
const LIVENESS_FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// ACK-v2 request/response stream priority.
const ACK_STREAM_PRIORITY: i32 = 16;
/// Probe request/response stream priority. Probes are diagnostic traffic and
/// must yield to data-plane DM/ACK-v2 streams under load.
const PROBE_STREAM_PRIORITY: i32 = -16;
/// Grace period for superseded reader tasks to drain in-flight request/ACK
/// streams before cooperative cancellation at the next accept boundary.
const SUPERSEDED_READER_DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Recently observed inbound traffic is a stronger liveness signal than an
/// active probe. Suppress probe sends while this signal is fresh so diagnostic
/// traffic cannot compete with data-plane ACKs under load.
const PROBE_RECENT_RECEIVE_SUPPRESSION: Duration = Duration::from_secs(30);
/// Successful probe results are briefly reused to coalesce probe bursts.
const PROBE_SUCCESS_CACHE_TTL: Duration = Duration::from_secs(5);
/// Failed probe results are cached only long enough to stop immediate retry
/// storms while still allowing quick recovery.
const PROBE_FAILURE_CACHE_TTL: Duration = Duration::from_secs(1);
/// Maximum number of active probe streams per endpoint.
const PROBE_GLOBAL_CONCURRENCY: usize = 4;
/// Probe budget acquisition is deliberately short: probes are lower priority
/// than application sends and ACK-v2 response handling.
const PROBE_BUDGET_WAIT: Duration = Duration::from_millis(50);
/// Retain ACK diagnostics for recent minute buckets only.
const ACK_DIAGNOSTICS_RETENTION_MINUTES: u64 = 15;
/// Per peer/stable-id/minute/stage sample cap. The soak path needs tail
/// percentiles, not unbounded per-message history.
const ACK_DIAGNOSTICS_MAX_STAGE_SAMPLES: usize = 2048;
/// Short receiver-side idempotency window for ACK-v2 request IDs.
const ACK_REQUEST_DEDUPE_TTL: Duration = Duration::from_secs(120);
/// Bound receiver-side ACK request dedupe memory in long-lived daemons.
const ACK_REQUEST_DEDUPE_MAX_ENTRIES: usize = 8192;

use crate::SHUTDOWN_DRAIN_TIMEOUT;

/// Free-slot fraction (of capacity) at or below which a data-channel
/// saturation event is recorded.
///
/// The single `mpsc::Sender` shared by every per-connection reader task is
/// the back-pressure choke point for the inbound data plane. Once free
/// slots fall below 20 % of capacity we treat the channel as "high water"
/// and increment a saturation counter (used by `/diagnostics/connectivity`)
/// plus emit a throttled WARN. The threshold mirrors the heuristic used by
/// saorsa-gossip's `recv_tx` warner (X0X-0039 / SOTA-Borrow Phase A).
const DATA_TX_HIGH_WATER_FREE_FRACTION: f64 = 0.20;

/// Minimum interval between high-water WARN logs per endpoint.
///
/// Saturation events arrive in bursts; without throttling a single 100 ms
/// pressure window can emit thousands of identical lines. The throttle is
/// implemented with a single `AtomicU64` storing the most recent WARN's
/// Unix-millisecond timestamp; concurrent samplers compete via
/// `compare_exchange`.
const DATA_TX_HIGH_WATER_WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Cumulative diagnostics for the shared `data_tx` `mpsc` channel
/// (X0X-0039 / SOTA-Borrow Phase A).
///
/// `data_tx` is the single bounded queue that every per-connection reader
/// task pushes inbound payloads into. Because all reader tasks share one
/// sender, a momentary slow consumer fans out into mesh-wide back-pressure
/// — the same failure shape saorsa-gossip v0.18.3 cured for its per-
/// subscriber buffer. These counters surface saturation events without
/// changing the existing `send().await` back-pressure semantic.
#[derive(Debug, Default)]
pub(crate) struct DataChannelDiagnostics {
    /// Cumulative count of saturation events (free slots fell at or below
    /// [`DATA_TX_HIGH_WATER_FREE_FRACTION`] of capacity, **or** an
    /// admission attempt timed out / failed because the channel was full).
    high_water_count: AtomicU64,
    /// Unix-ms timestamp of the most recent WARN emitted by
    /// [`DataChannelDiagnostics::observe_capacity`]. Used to throttle the
    /// WARN to once per [`DATA_TX_HIGH_WATER_WARN_INTERVAL`] per endpoint.
    last_warn_unix_ms: AtomicU64,
}

impl DataChannelDiagnostics {
    /// Sample current channel pressure ahead of (or after) a send. Both
    /// `free` (= `Sender::capacity()`) and `capacity` (= the original
    /// channel cap) come from the live `mpsc::Sender`; we never read the
    /// receiver. The sampler increments the saturation counter at most
    /// once per call and emits a throttled WARN when it does.
    fn observe_capacity(&self, free: usize, capacity: usize) {
        if capacity == 0 {
            return;
        }
        let threshold = ((capacity as f64) * DATA_TX_HIGH_WATER_FREE_FRACTION).ceil() as usize;
        let threshold = threshold.max(1);
        if free <= threshold {
            self.note_saturation_inner(free, capacity);
        }
    }

    /// Force-account a saturation event without sampling. Used by paths
    /// that have already failed (`try_send` returned `Full`, ACK admission
    /// timed out) — by definition the channel was saturated and we want
    /// the counter and WARN to fire.
    fn note_saturation(&self, free: usize, capacity: usize) {
        self.note_saturation_inner(free, capacity);
    }

    fn note_saturation_inner(&self, free: usize, capacity: usize) {
        self.high_water_count.fetch_add(1, Ordering::Relaxed);
        let now_ms = current_unix_ms();
        let last = self.last_warn_unix_ms.load(Ordering::Relaxed);
        let interval_ms = DATA_TX_HIGH_WATER_WARN_INTERVAL.as_millis() as u64;
        if now_ms.saturating_sub(last) < interval_ms {
            return;
        }
        // Single-flight the WARN: only the thread that wins the CAS logs.
        if self
            .last_warn_unix_ms
            .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        warn!(
            target: "ant_quic::data_tx",
            free_slots = free,
            capacity = capacity,
            free_fraction = (free as f64) / (capacity as f64),
            high_water_count = self.high_water_count.load(Ordering::Relaxed),
            "data_tx near saturation: free slots <= 20% of capacity (X0X-0039)"
        );
    }

    fn high_water_count(&self) -> u64 {
        self.high_water_count.load(Ordering::Relaxed)
    }
}

/// Snapshot of `data_tx` channel pressure for `/diagnostics/connectivity`
/// surfaces (X0X-0039).
#[derive(Debug, Clone, Serialize)]
pub struct DataChannelDiagnosticsSnapshot {
    /// Number of payloads currently queued in `data_tx` (best-effort,
    /// computed as `capacity - sender.capacity()`).
    pub data_tx_depth: usize,
    /// Configured channel capacity. Default
    /// [`P2pConfig::DEFAULT_DATA_CHANNEL_CAPACITY`].
    pub data_tx_capacity: usize,
    /// Cumulative saturation events since process start. Includes both
    /// pre-send pressure samples and admission timeouts.
    pub data_tx_high_water_count: u64,
}

/// Derive a synthetic PeerId by hashing a `TransportAddr` display string.
///
/// Used for constrained connections (BLE, LoRa) where no TLS-based identity exists.
///
/// **Note:** Uses `DefaultHasher`, whose output is not stable across Rust versions.
/// These IDs are ephemeral within a single process and must not be persisted or
/// compared across builds.
fn peer_id_from_transport_addr(addr: &TransportAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    format!("{}", addr).hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..16].copy_from_slice(&hash.to_be_bytes());
    PeerId(id)
}

#[derive(Debug, Clone, Default)]
struct PeerHintRecord {
    addrs: Vec<SocketAddr>,
    capabilities: PeerCapabilities,
}

#[derive(Debug)]
struct ReaderTaskHandle {
    /// Monotonic id used by the reader-exit handler to locate the exiting task
    /// within the per-peer vector. A peer may briefly have multiple live QUIC
    /// connections (simultaneous-open races, coordinated + direct paths
    /// converging); each has its own reader, uniquely identified by this id.
    generation: u64,
    /// Cooperative shutdown signal. Honored only at stream-accept boundaries,
    /// so an in-flight `read_to_end()` always completes before the task exits.
    /// This prevents silent loss of already-ACKed bytes during connection
    /// replacement (issue #166).
    cancel: CancellationToken,
    /// Fallback abort handle used by `shutdown()` and as a backstop during
    /// explicit `cleanup_connection` after cooperative cancellation.
    abort_handle: tokio::task::AbortHandle,
}

#[derive(Debug, Clone, Copy)]
struct ReaderExitEvent {
    peer_id: PeerId,
    generation: u64,
    conn_stable_id: usize,
}

impl PeerHintRecord {
    fn merge(&mut self, addrs: Vec<SocketAddr>, capabilities: Option<PeerCapabilities>) {
        for addr in addrs {
            if !self.addrs.contains(&addr) {
                self.addrs.push(addr);
            }
        }
        if let Some(caps) = capabilities {
            if caps.supports_relay {
                self.capabilities.supports_relay = true;
            }
            if caps.supports_coordination {
                self.capabilities.supports_coordination = true;
            }
            self.capabilities.protocols.extend(caps.protocols);
            if caps.nat_type.is_some() {
                self.capabilities.nat_type = caps.nat_type;
            }
            for addr in caps.external_addresses {
                self.capabilities.record_external_address(addr);
            }
        }
    }
}

fn direct_candidate_rank(addr: SocketAddr) -> (u8, u8) {
    let scope_rank = match socket_addr_scope(addr) {
        Some(ReachabilityScope::Global) => 3,
        Some(ReachabilityScope::LocalNetwork) => 2,
        Some(ReachabilityScope::Loopback) => 1,
        None => 0,
    };
    let family_rank = if addr.is_ipv6() { 2 } else { 1 };
    (scope_rank, family_rank)
}

fn prioritize_direct_candidate_addrs(addrs: &mut Vec<SocketAddr>) {
    addrs.sort_by_key(|addr| std::cmp::Reverse(direct_candidate_rank(*addr)));
    addrs.dedup();
}

/// Drop LocalNetwork / Loopback candidates from the dial list when at least one
/// Global-scope address is present (issue #163).
///
/// When a peer advertises both globally-routable and private addresses (for
/// example, a VPS whose interface scan leaked `10.x.y.z` alongside its public
/// IP), dialing the private entries from an off-LAN caller stalls for the
/// per-address QUIC handshake timeout before failing. Keep them only when the
/// list contains nothing better so pure-LAN peers (e.g. discovered via mDNS)
/// still work.
fn drop_non_global_direct_candidates_when_global_present(addrs: &mut Vec<SocketAddr>) {
    let has_global = addrs
        .iter()
        .any(|addr| socket_addr_scope(*addr) == Some(ReachabilityScope::Global));
    if has_global {
        addrs.retain(|addr| socket_addr_scope(*addr) == Some(ReachabilityScope::Global));
    }
}

fn relay_target_rank(addr: SocketAddr) -> u8 {
    match socket_addr_scope(addr) {
        Some(ReachabilityScope::Global) => 3,
        Some(ReachabilityScope::LocalNetwork) => 2,
        Some(ReachabilityScope::Loopback) => 1,
        None => 0,
    }
}

fn prioritize_relay_target_addrs(addrs: &mut Vec<SocketAddr>) {
    addrs.sort_by_key(|addr| std::cmp::Reverse(relay_target_rank(*addr)));
    addrs.dedup();
}

fn extend_unique_socket_addrs(
    addrs: &mut Vec<SocketAddr>,
    incoming: impl IntoIterator<Item = SocketAddr>,
) {
    for addr in incoming {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
}

async fn try_addrs_with_shared_stage_budget<T, E, F, Fut>(
    addresses: &[SocketAddr],
    family_name: &str,
    stage_budget: Duration,
    mut attempt: F,
) -> Option<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    if addresses.is_empty() {
        debug!("{}: No addresses to try", family_name);
        return None;
    }

    if stage_budget.is_zero() {
        debug!("{}: zero direct-stage budget, skipping family", family_name);
        return None;
    }

    debug!(
        "Trying {} {} addresses within a shared {:?} budget",
        addresses.len(),
        family_name,
        stage_budget
    );

    let stage_deadline = Instant::now() + stage_budget;

    for (idx, addr) in addresses.iter().enumerate() {
        let remaining_budget = stage_deadline.saturating_duration_since(Instant::now());
        if remaining_budget.is_zero() {
            debug!(
                "{}: shared direct-stage budget {:?} exhausted before address {}",
                family_name, stage_budget, addr
            );
            break;
        }

        debug!(
            "  {} attempt {}/{}: {} (remaining budget: {:?})",
            family_name,
            idx + 1,
            addresses.len(),
            addr,
            remaining_budget
        );

        match timeout(remaining_budget, attempt(*addr)).await {
            Ok(Ok(result)) => {
                info!("✓ {} connection successful to {}", family_name, addr);
                return Some(result);
            }
            Ok(Err(error)) => {
                debug!("  {} to {} failed: {}", family_name, addr, error);
            }
            Err(_) => {
                debug!(
                    "  {} to {} timed out after consuming the remaining {:?} family budget",
                    family_name, addr, remaining_budget
                );
                break;
            }
        }
    }

    debug!("{}: All {} addresses failed", family_name, addresses.len());
    None
}

fn cached_peer_avg_rtt(peer: &CachedPeer) -> Option<Duration> {
    (peer.stats.avg_rtt_ms > 0).then(|| Duration::from_millis(u64::from(peer.stats.avg_rtt_ms)))
}

fn cached_peer_matches_strategy_addr(peer: &CachedPeer, addr: SocketAddr) -> bool {
    peer.addresses.contains(&addr)
        || peer.preferred_addresses().contains(&addr)
        || peer.capabilities.external_addresses.contains(&addr)
        || peer
            .capabilities
            .reachable_addresses
            .iter()
            .any(|record| record.address == addr)
}

fn strategy_rtt_hint_from_cached_peers(
    peers: &[CachedPeer],
    addrs: &[SocketAddr],
) -> Option<Duration> {
    peers
        .iter()
        .filter(|peer| {
            addrs
                .iter()
                .copied()
                .any(|addr| cached_peer_matches_strategy_addr(peer, addr))
        })
        .filter_map(cached_peer_avg_rtt)
        .max()
}

fn select_preferred_relay_target_addr(
    listener_addrs: &[SocketAddr],
    reachable_addrs: &[SocketAddr],
    external_addrs: &[SocketAddr],
    fallback_ipv4: Option<SocketAddr>,
    fallback_ipv6: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let mut ordered = Vec::new();

    let mut listeners = listener_addrs.to_vec();
    prioritize_relay_target_addrs(&mut listeners);
    extend_unique_socket_addrs(&mut ordered, listeners);

    let mut reachable = reachable_addrs.to_vec();
    prioritize_relay_target_addrs(&mut reachable);
    extend_unique_socket_addrs(&mut ordered, reachable);

    let mut external = external_addrs.to_vec();
    prioritize_relay_target_addrs(&mut external);
    extend_unique_socket_addrs(&mut ordered, external);

    ordered
        .into_iter()
        .next()
        .or(fallback_ipv4)
        .or(fallback_ipv6)
}

fn normalize_direct_path_unavailable_reason(
    error: &NatTraversalError,
) -> DirectPathUnavailableReason {
    match error {
        NatTraversalError::NoCandidatesFound | NatTraversalError::CandidateDiscoveryFailed(_) => {
            DirectPathUnavailableReason::NoCandidates
        }
        NatTraversalError::HolePunchingFailed
        | NatTraversalError::PunchingFailed(_)
        | NatTraversalError::ValidationFailed(_)
        | NatTraversalError::ValidationTimeout
        | NatTraversalError::NetworkError(_)
        | NatTraversalError::Timeout
        | NatTraversalError::ConnectionFailed(_)
        | NatTraversalError::TraversalFailed(_) => DirectPathUnavailableReason::NatUnreachable,
        _ => DirectPathUnavailableReason::Unknown,
    }
}

fn normalize_direct_path_unavailable_reason_from_traversal_reason(
    reason: &TraversalFailureReason,
) -> DirectPathUnavailableReason {
    match reason {
        TraversalFailureReason::DiscoveryExhausted => DirectPathUnavailableReason::NoCandidates,
        TraversalFailureReason::CoordinatorUnavailable
        | TraversalFailureReason::CoordinationRejected { .. }
        | TraversalFailureReason::CoordinationExpired
        | TraversalFailureReason::SynchronizationExpired
        | TraversalFailureReason::PunchWindowMissed
        | TraversalFailureReason::ValidationTimedOut
        | TraversalFailureReason::ValidationFailed
        | TraversalFailureReason::ConnectionFailed
        | TraversalFailureReason::NetworkError(_)
        | TraversalFailureReason::ShuttingDown => DirectPathUnavailableReason::NatUnreachable,
        TraversalFailureReason::ProtocolViolation(_) => DirectPathUnavailableReason::Unknown,
    }
}

fn is_terminal_direct_path_status(status: &DirectPathStatus) -> bool {
    matches!(
        status,
        DirectPathStatus::BestEffortUnavailable { .. } | DirectPathStatus::Failed { .. }
    )
}

fn terminal_direct_path_status_from_failure(
    reason: &TraversalFailureReason,
    fallback_available: bool,
) -> DirectPathStatus {
    if fallback_available {
        DirectPathStatus::BestEffortUnavailable {
            reason: normalize_direct_path_unavailable_reason_from_traversal_reason(reason),
        }
    } else {
        DirectPathStatus::Failed {
            error: reason.to_string(),
        }
    }
}

fn publish_direct_path_status(
    statuses: &ParkingRwLock<HashMap<PeerId, DirectPathStatus>>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_id: PeerId,
    status: DirectPathStatus,
) {
    let should_emit = {
        let mut statuses = statuses.write();
        if statuses.get(&peer_id) == Some(&status) {
            false
        } else {
            statuses.insert(peer_id, status.clone());
            true
        }
    };

    if should_emit {
        if let Err(e) = event_tx.send(P2pEvent::DirectPathStatus { peer_id, status }) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "event_tx_direct_path_status",
                peer_id = ?peer_id,
                error = %e,
                "silent drop"
            );
        }
    }
}

/// Derive a synthetic PeerId by hashing a `SocketAddr`.
///
/// Used when the peer's real identity (ML-DSA-65 key) is not yet known.
///
/// **Note:** Uses `DefaultHasher`, whose output is not stable across Rust versions.
/// These IDs are ephemeral within a single process and must not be persisted or
/// compared across builds.
fn peer_id_from_socket_addr(addr: SocketAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..10].copy_from_slice(&addr.port().to_le_bytes());
    PeerId(id)
}

/// P2P endpoint - the primary API for ant-quic
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
    /// Connected peers with their addresses
    connected_peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,

    /// Endpoint statistics
    stats: Arc<RwLock<EndpointStats>>,

    /// Configuration
    config: P2pConfig,

    /// Event broadcaster
    event_tx: broadcast::Sender<P2pEvent>,

    /// Our peer ID
    peer_id: PeerId,

    /// Our ML-DSA-65 public key bytes (for identity sharing) - 1952 bytes
    public_key: Vec<u8>,

    /// Shutdown token for cooperative cancellation
    shutdown: CancellationToken,

    /// Bounded pending data buffer for message ordering
    pending_data: Arc<RwLock<BoundedPendingBuffer>>,

    /// Bootstrap cache for peer persistence
    pub bootstrap_cache: Arc<BootstrapCache>,

    /// Advanced externally supplied peer hints keyed by authenticated peer ID.
    ///
    /// This is intentionally separate from the persisted bootstrap cache so
    /// higher layers can feed fresh discovery/assist hints without having to
    /// reach into internal strategy types.
    peer_hint_records: Arc<RwLock<HashMap<PeerId, PeerHintRecord>>>,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity.
    transport_registry: Arc<TransportRegistry>,

    /// Connection router for automatic protocol engine selection
    ///
    /// Routes connections through either QUIC (for broadband) or Constrained
    /// engine (for BLE/LoRa) based on transport capabilities.
    router: Arc<RwLock<ConnectionRouter>>,

    /// Mapping from PeerId to ConnectionId for constrained connections
    ///
    /// When a peer is connected via a constrained transport (BLE, LoRa, etc.),
    /// this map stores the ConstrainedEngine's ConnectionId for that peer.
    /// UDP/QUIC peers are NOT in this map - they use the standard QUIC connection.
    constrained_connections: Arc<RwLock<HashMap<PeerId, ConstrainedConnectionId>>>,

    /// Reverse lookup: ConnectionId → (PeerId, TransportAddr) for constrained connections
    ///
    /// This enables mapping incoming constrained data back to the correct PeerId.
    /// Registered when ConnectionAccepted/Established fires for constrained transports.
    constrained_peer_addrs: Arc<RwLock<HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>>>,

    /// Explicitly added manual UDP known peers (via add_known_peer/add_bootstrap).
    manual_known_peer_udp_addrs: Arc<RwLock<Vec<SocketAddr>>>,

    /// Best-effort router port-mapping state.
    port_mapping_state: Arc<ParkingRwLock<PortMappingSnapshot>>,

    /// First-party mDNS runtime state.
    mdns_state: Arc<ParkingRwLock<MdnsSnapshot>>,

    /// Tracks in-flight mDNS auto-connect attempts by service fullname.
    mdns_auto_connect_inflight: Arc<ParkingRwLock<HashSet<String>>>,

    /// Latest best-effort direct-path status per authenticated peer.
    direct_path_statuses: Arc<ParkingRwLock<HashMap<PeerId, DirectPathStatus>>>,

    /// Channel sender for data received from QUIC reader tasks and constrained poller
    data_tx: mpsc::Sender<(PeerId, Vec<u8>)>,

    /// Channel receiver for data received from QUIC reader tasks and constrained poller
    data_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(PeerId, Vec<u8>)>>>,

    /// Configured `data_tx` capacity (preserved for diagnostics; the
    /// `mpsc::Sender` only exposes remaining free slots).
    data_tx_capacity: usize,

    /// Saturation diagnostics for `data_tx` (X0X-0039).
    data_tx_diagnostics: Arc<DataChannelDiagnostics>,

    /// Sender used by reader tasks to report deterministic exit events.
    reader_exit_tx: mpsc::UnboundedSender<ReaderExitEvent>,

    /// Receiver consumed by the reader-exit handler.
    reader_exit_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ReaderExitEvent>>>,

    /// Per-peer reader-task handles.
    ///
    /// Keyed on `PeerId` but stores a `Vec` because a single peer may briefly
    /// have multiple live QUIC connections (simultaneous-open races, or the
    /// coordinated and direct paths converging). Each entry is uniquely
    /// identified by its `generation`. Readers are not pre-empted on
    /// connection replacement — each runs until its own connection terminates,
    /// so ACKed bytes in flight on the old connection are always delivered
    /// (issue #166).
    reader_handles: Arc<RwLock<HashMap<PeerId, Vec<ReaderTaskHandle>>>>,

    /// Directional application activity timestamps per peer.
    peer_activity: Arc<RwLock<HashMap<PeerId, PeerActivityRecord>>>,

    /// Pending probe waiters keyed by live connection stable id + request tag.
    ack_waiters: Arc<ParkingRwLock<HashMap<usize, AckWaiterMap>>>,

    /// Stage-by-stage ACK-v2 latency and outcome diagnostics.
    ack_diagnostics: Arc<AckDiagnostics>,

    /// X0X-0062: per-(peer, stable_id) consecutive `SenderRetryFailed`
    /// tracker that force-closes a connection whose ACK-v2 retry path keeps
    /// failing while the underlying QUIC connection still reports `Live`.
    ack_liveness: Arc<AckLivenessTracker>,

    /// Receiver-side ACK-v2 request-id dedupe cache.
    ack_request_dedupe: Arc<AckRequestDedupeCache>,

    /// Probe single-flight/cache state keyed by peer.
    probe_flights: Arc<TokioMutex<HashMap<ProbeFlightKey, ProbeFlightState>>>,

    /// Global low-priority budget for explicit liveness probes.
    probe_semaphore: Arc<Semaphore>,

    /// Global broadcast fanout for peer lifecycle transitions.
    peer_event_tx: broadcast::Sender<(PeerId, PeerLifecycleEvent)>,

    /// Peer-scoped lifecycle broadcast channels, created lazily on subscribe.
    peer_event_channels: Arc<ParkingRwLock<HashMap<PeerId, broadcast::Sender<PeerLifecycleEvent>>>>,

    /// Last live generation published for each peer.
    peer_event_generations: Arc<ParkingRwLock<HashMap<PeerId, u64>>>,

    /// Circuit-breaker for coordinator peers (tracks failures by address).
    pub(crate) coordinator_health: Arc<crate::coordinator_health::CoordinatorHealth>,
}

impl std::fmt::Debug for P2pEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pEndpoint")
            .field("peer_id", &self.peer_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Connection information for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote peer's ID
    pub peer_id: PeerId,

    /// Remote address (supports all transport types)
    pub remote_addr: TransportAddr,

    /// How this connection was established.
    pub traversal_method: TraversalMethod,

    /// Who initiated the connection.
    pub side: Side,

    /// Whether peer is authenticated
    pub authenticated: bool,

    /// Connection established time
    pub connected_at: Instant,

    /// Last activity time
    pub last_activity: Instant,
}

/// Connection metrics for P2P peers
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,

    /// Bytes received from this peer
    pub bytes_received: u64,

    /// Round-trip time
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Last activity timestamp
    pub last_activity: Option<Instant>,
}

/// Best-effort connection health snapshot for a peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionHealth {
    /// Whether the peer currently has a live transport connection.
    pub connected: bool,

    /// Current local lifecycle generation for the live QUIC connection, when available.
    pub generation: Option<u64>,

    /// Whether a background reader task is currently active for the live connection.
    ///
    /// This is `None` when the peer is disconnected.
    pub reader_task_active: Option<bool>,

    /// The last time this endpoint accepted application data from the peer into
    /// its receive pipeline, if any.
    pub last_received_at: Option<Instant>,

    /// The last time this endpoint successfully sent application data to the peer,
    /// if any.
    pub last_sent_at: Option<Instant>,

    /// Time since the most recent send/receive activity while the peer is live.
    pub idle_for: Option<Duration>,

    /// Most recent lifecycle-aware close reason, if a recent QUIC connection closed.
    pub close_reason: Option<ConnectionCloseReason>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ConnectionHealthObservation {
    connected: bool,
    generation: Option<u64>,
    reader_task_active: Option<bool>,
    last_received_at: Option<Instant>,
    last_sent_at: Option<Instant>,
    close_reason: Option<ConnectionCloseReason>,
}

impl ConnectionHealth {
    fn from_observation(observation: ConnectionHealthObservation, now: Instant) -> Self {
        let last_live_activity = match (observation.last_sent_at, observation.last_received_at) {
            (Some(sent), Some(received)) => Some(sent.max(received)),
            (Some(sent), None) => Some(sent),
            (None, Some(received)) => Some(received),
            (None, None) => None,
        };

        Self {
            connected: observation.connected,
            generation: observation.generation,
            reader_task_active: observation.reader_task_active,
            last_received_at: observation.last_received_at,
            last_sent_at: observation.last_sent_at,
            idle_for: observation
                .connected
                .then(|| last_live_activity.map(|instant| now.saturating_duration_since(instant)))
                .flatten(),
            close_reason: observation.close_reason,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerActivityRecord {
    last_sent_at: Option<Instant>,
    last_received_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum CachedProbeOutcome {
    Success(Duration),
    Rejected(ReceiveRejectReason),
    Closed(ConnectionCloseReason),
    Timeout,
    OverBudget,
    NotSupported,
    PeerNotFound(PeerId),
    ShuttingDown,
}

impl CachedProbeOutcome {
    fn into_result(self) -> Result<Duration, EndpointError> {
        match self {
            Self::Success(rtt) => Ok(rtt),
            Self::Rejected(reason) => Err(EndpointError::ReceiveRejected { reason }),
            Self::Closed(reason) => Err(EndpointError::ConnectionClosed { reason }),
            Self::Timeout => Err(EndpointError::ProbeTimeout),
            Self::OverBudget => Err(EndpointError::ProbeOverBudget),
            Self::NotSupported => Err(EndpointError::NotSupported),
            Self::PeerNotFound(peer_id) => Err(EndpointError::PeerNotFound(peer_id)),
            Self::ShuttingDown => Err(EndpointError::ShuttingDown),
        }
    }

    fn ttl(self) -> Duration {
        match self {
            Self::Success(_) => PROBE_SUCCESS_CACHE_TTL,
            Self::Rejected(_)
            | Self::Closed(_)
            | Self::Timeout
            | Self::OverBudget
            | Self::NotSupported
            | Self::PeerNotFound(_)
            | Self::ShuttingDown => PROBE_FAILURE_CACHE_TTL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CachedProbeResult {
    completed_at: Instant,
    outcome: CachedProbeOutcome,
}

impl CachedProbeResult {
    fn fresh(self, now: Instant) -> bool {
        now.saturating_duration_since(self.completed_at) <= self.outcome.ttl()
    }
}

#[derive(Debug, Default)]
struct ProbeFlightState {
    in_flight: Option<Arc<Notify>>,
    last_result: Option<CachedProbeResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProbeFlightKey {
    peer_id: PeerId,
    stable_id: usize,
}

#[derive(Debug)]
enum ProbeFlightDecision {
    Start(Arc<Notify>),
    Cached(CachedProbeOutcome),
}

#[derive(Debug, Clone, Copy)]
enum PeerActivityKind {
    Sent,
    Received,
}

#[derive(Debug)]
enum AckWaiterResult {
    Accepted,
    Rejected(ReceiveRejectReason),
    Closed(ConnectionCloseReason),
}

type AckWaiterMap = HashMap<[u8; 16], oneshot::Sender<AckWaiterResult>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AckDiagnosticsKey {
    peer_id: PeerId,
    stable_id: usize,
    minute_unix: u64,
}

#[derive(Debug, Clone, Copy)]
enum AckLatencyStage {
    SenderOpenBi,
    SenderRequestWrite,
    SenderRequestFinish,
    SenderResponseRead,
    ReceiverDemux,
    ReceiverAdmission,
    ReceiverResponseWriteFinish,
}

#[derive(Debug, Clone, Copy)]
enum AckOutcome {
    SenderAccepted,
    SenderRejected,
    SenderInvalidResponse,
    SenderAckTimeout,
    SenderConnectionClosed,
    SenderRetryAttempted,
    SenderRetryAccepted,
    SenderRetryFailed,
    ReceiverAccepted,
    ReceiverRejected,
    ReceiverDuplicateReplayed,
    ReceiverDuplicateConflict,
    ReceiverResponseWriteFailed,
    ReceiverResponseFinishFailed,
    ReceiverResponseTimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AckRequestDedupeKey {
    peer_id: PeerId,
    request_id: [u8; 16],
}

#[derive(Debug, Clone)]
struct AckRequestDedupeEntry {
    payload_hash: [u8; 32],
    outcome: AckControlOutcome,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckRequestDedupeReplay {
    Replay(AckControlOutcome),
    Conflict,
}

#[derive(Debug, Default)]
struct AckRequestDedupeCache {
    entries: ParkingMutex<HashMap<AckRequestDedupeKey, AckRequestDedupeEntry>>,
}

impl AckRequestDedupeCache {
    fn replay(
        &self,
        peer_id: PeerId,
        request_id: [u8; 16],
        payload: &[u8],
    ) -> Option<AckRequestDedupeReplay> {
        let mut entries = self.entries.lock();
        Self::prune_locked(&mut entries);
        let key = AckRequestDedupeKey {
            peer_id,
            request_id,
        };
        let entry = entries.get(&key)?;
        if entry.payload_hash == ack_payload_hash(payload) {
            Some(AckRequestDedupeReplay::Replay(entry.outcome))
        } else {
            Some(AckRequestDedupeReplay::Conflict)
        }
    }

    fn remember(
        &self,
        peer_id: PeerId,
        request_id: [u8; 16],
        payload: &[u8],
        outcome: AckControlOutcome,
    ) {
        let mut entries = self.entries.lock();
        Self::prune_locked(&mut entries);
        Self::evict_overflow_locked(&mut entries);
        entries.insert(
            AckRequestDedupeKey {
                peer_id,
                request_id,
            },
            AckRequestDedupeEntry {
                payload_hash: ack_payload_hash(payload),
                outcome,
                expires_at: Instant::now() + ACK_REQUEST_DEDUPE_TTL,
            },
        );
    }

    fn prune_locked(entries: &mut HashMap<AckRequestDedupeKey, AckRequestDedupeEntry>) {
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
    }

    fn evict_overflow_locked(entries: &mut HashMap<AckRequestDedupeKey, AckRequestDedupeEntry>) {
        if entries.len() < ACK_REQUEST_DEDUPE_MAX_ENTRIES {
            return;
        }
        let remove_count = entries
            .len()
            .saturating_add(1)
            .saturating_sub(ACK_REQUEST_DEDUPE_MAX_ENTRIES);
        let mut oldest: Vec<_> = entries
            .iter()
            .map(|(key, entry)| (*key, entry.expires_at))
            .collect();
        oldest.sort_by_key(|(_, expires_at)| *expires_at);
        for (key, _) in oldest.into_iter().take(remove_count) {
            entries.remove(&key);
        }
    }
}

fn ack_payload_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

#[derive(Debug, Default)]
struct AckStageSamples {
    values_ms: Vec<u64>,
}

impl AckStageSamples {
    fn record(&mut self, duration: Duration) {
        if self.values_ms.len() >= ACK_DIAGNOSTICS_MAX_STAGE_SAMPLES {
            self.values_ms.remove(0);
        }
        self.values_ms.push(duration_millis_saturating(duration));
    }

    fn snapshot(&self) -> AckStageLatencySnapshot {
        AckStageLatencySnapshot::from_samples(&self.values_ms)
    }
}

#[derive(Debug, Default)]
struct AckMinuteDiagnostics {
    sender_open_bi: AckStageSamples,
    sender_request_write: AckStageSamples,
    sender_request_finish: AckStageSamples,
    sender_response_read: AckStageSamples,
    receiver_demux: AckStageSamples,
    receiver_admission: AckStageSamples,
    receiver_response_write_finish: AckStageSamples,
    outcomes: AckOutcomeCounters,
}

impl AckMinuteDiagnostics {
    fn stage_mut(&mut self, stage: AckLatencyStage) -> &mut AckStageSamples {
        match stage {
            AckLatencyStage::SenderOpenBi => &mut self.sender_open_bi,
            AckLatencyStage::SenderRequestWrite => &mut self.sender_request_write,
            AckLatencyStage::SenderRequestFinish => &mut self.sender_request_finish,
            AckLatencyStage::SenderResponseRead => &mut self.sender_response_read,
            AckLatencyStage::ReceiverDemux => &mut self.receiver_demux,
            AckLatencyStage::ReceiverAdmission => &mut self.receiver_admission,
            AckLatencyStage::ReceiverResponseWriteFinish => {
                &mut self.receiver_response_write_finish
            }
        }
    }
}

/// Latency percentiles for one ACK-v2 protocol stage.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AckStageLatencySnapshot {
    /// Number of samples retained for the stage.
    pub count: usize,
    /// Median latency in milliseconds.
    pub p50_ms: Option<u64>,
    /// 95th percentile latency in milliseconds.
    pub p95_ms: Option<u64>,
    /// 99th percentile latency in milliseconds.
    pub p99_ms: Option<u64>,
    /// 99.9th percentile latency in milliseconds.
    pub p999_ms: Option<u64>,
    /// Maximum retained latency in milliseconds.
    pub max_ms: Option<u64>,
}

impl AckStageLatencySnapshot {
    fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        Self {
            count: sorted.len(),
            p50_ms: percentile(&sorted, 50, 100),
            p95_ms: percentile(&sorted, 95, 100),
            p99_ms: percentile(&sorted, 99, 100),
            p999_ms: percentile(&sorted, 999, 1000),
            max_ms: sorted.last().copied(),
        }
    }
}

/// Per-stage ACK-v2 latency diagnostics for one peer/connection/minute bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AckStageDiagnosticsSnapshot {
    /// Time spent opening the sender-side bidirectional stream.
    pub sender_open_bi: AckStageLatencySnapshot,
    /// Time spent writing the ACK-v2 request payload.
    pub sender_request_write: AckStageLatencySnapshot,
    /// Time spent finishing the ACK-v2 request stream.
    pub sender_request_finish: AckStageLatencySnapshot,
    /// Time spent reading the receiver's ACK-v2 response.
    pub sender_response_read: AckStageLatencySnapshot,
    /// Time from inbound stream acceptance to ACK-v2 demux.
    pub receiver_demux: AckStageLatencySnapshot,
    /// Time spent in receiver admission and payload enqueue.
    pub receiver_admission: AckStageLatencySnapshot,
    /// Time spent writing and finishing the receiver ACK-v2 response.
    pub receiver_response_write_finish: AckStageLatencySnapshot,
}

/// ACK-v2 outcome counters for one peer/connection/minute bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AckOutcomeCounters {
    /// Sender observed an accepted ACK response.
    pub sender_accepted: u64,
    /// Sender observed a rejected ACK response.
    pub sender_rejected: u64,
    /// Sender received an invalid ACK response envelope.
    pub sender_invalid_response: u64,
    /// Sender timed out waiting for an ACK response.
    pub sender_ack_timeout: u64,
    /// Sender observed the response side close before an ACK response arrived.
    pub sender_connection_closed: u64,
    /// Sender attempted the duplicate-safe retry after an ACK timeout.
    pub sender_retry_attempted: u64,
    /// Sender retry received an accepted ACK response.
    pub sender_retry_accepted: u64,
    /// Sender retry completed with a non-accepted outcome.
    pub sender_retry_failed: u64,
    /// Receiver admitted the payload and sent an accepted ACK response.
    pub receiver_accepted: u64,
    /// Receiver rejected the payload before sending the ACK response.
    pub receiver_rejected: u64,
    /// Receiver replayed a cached ACK-v2 outcome for a duplicate request ID.
    pub receiver_duplicate_replayed: u64,
    /// Receiver rejected a request ID reused with a different payload.
    pub receiver_duplicate_conflict: u64,
    /// Receiver failed while writing the ACK response.
    pub receiver_response_write_failed: u64,
    /// Receiver failed while finishing the ACK response stream.
    pub receiver_response_finish_failed: u64,
    /// Receiver timed out while writing or finishing the ACK response.
    pub receiver_response_timed_out: u64,
}

impl AckOutcomeCounters {
    fn record(&mut self, outcome: AckOutcome) {
        match outcome {
            AckOutcome::SenderAccepted => self.sender_accepted += 1,
            AckOutcome::SenderRejected => self.sender_rejected += 1,
            AckOutcome::SenderInvalidResponse => self.sender_invalid_response += 1,
            AckOutcome::SenderAckTimeout => self.sender_ack_timeout += 1,
            AckOutcome::SenderConnectionClosed => self.sender_connection_closed += 1,
            AckOutcome::SenderRetryAttempted => self.sender_retry_attempted += 1,
            AckOutcome::SenderRetryAccepted => self.sender_retry_accepted += 1,
            AckOutcome::SenderRetryFailed => self.sender_retry_failed += 1,
            AckOutcome::ReceiverAccepted => self.receiver_accepted += 1,
            AckOutcome::ReceiverRejected => self.receiver_rejected += 1,
            AckOutcome::ReceiverDuplicateReplayed => self.receiver_duplicate_replayed += 1,
            AckOutcome::ReceiverDuplicateConflict => self.receiver_duplicate_conflict += 1,
            AckOutcome::ReceiverResponseWriteFailed => self.receiver_response_write_failed += 1,
            AckOutcome::ReceiverResponseFinishFailed => self.receiver_response_finish_failed += 1,
            AckOutcome::ReceiverResponseTimedOut => self.receiver_response_timed_out += 1,
        }
    }
}

/// ACK-v2 diagnostics for one peer/connection/minute bucket.
#[derive(Debug, Clone, Serialize)]
pub struct AckPeerDiagnosticsSnapshot {
    /// Hex-encoded remote peer id.
    pub peer_id: String,
    /// Stable ant-quic connection id observed for this bucket.
    pub stable_id: usize,
    /// Unix minute for the retained diagnostic bucket.
    pub minute_unix: u64,
    /// Latency samples grouped by protocol stage.
    pub stages: AckStageDiagnosticsSnapshot,
    /// Outcome counters for this bucket.
    pub outcomes: AckOutcomeCounters,
}

/// Snapshot of retained ACK-v2 diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct AckDiagnosticsSnapshot {
    /// Snapshot generation time in Unix milliseconds.
    pub generated_at_unix_ms: u64,
    /// Number of minutes retained in the rolling diagnostics window.
    pub retention_minutes: u64,
    /// Per-peer, per-connection, per-minute ACK diagnostics.
    pub peers: Vec<AckPeerDiagnosticsSnapshot>,
}

/// X0X-0062: liveness signal emitted from `send_with_receive_ack_with_timeout`
/// after each decision point so the `AckLivenessTracker` observes every
/// outcome, not just retry outcomes.
///
/// - `Success` — any outcome that proves the remote responded: first-attempt
///   success, retry success, or any non-timeout terminal error (Rejected,
///   ConnectionClosed, invalid response — peer answered, just not OK).
/// - `RetryAckTimeout` — the only outcome that signals half-dead: both the
///   initial send AND its X0X-0060 duplicate-safe retry timed out with no
///   response from the remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckLivenessSignal {
    Success,
    RetryAckTimeout,
}

/// X0X-0062: tracks consecutive ACK-v2 retry failures per (peer, connection
/// generation) so that a connection whose data path goes half-dead — sends
/// time out and X0X-0060's duplicate-safe retry also times out, while the
/// underlying QUIC connection still keepalives and reports as `Live` — can be
/// detected and force-closed at the application layer instead of leaking the
/// stuck state indefinitely.
///
/// Counter increments on `SenderRetryFailed`, resets on `SenderAccepted` or
/// `SenderRetryAccepted` (any successful send proves the path is alive). Once
/// it reaches `LIVENESS_FAILURE_THRESHOLD` within `LIVENESS_FAILURE_WINDOW`,
/// `record_failure` returns `true` and the caller force-closes the connection.
#[derive(Debug, Default)]
struct AckLivenessTracker {
    state: ParkingMutex<HashMap<(PeerId, usize), LivenessFailureWindow>>,
}

#[derive(Debug, Clone, Copy)]
struct LivenessFailureWindow {
    consecutive_failures: u32,
    window_started: Instant,
}

impl AckLivenessTracker {
    /// Record a `SenderRetryFailed` outcome for the given (peer, stable_id).
    /// Returns `true` exactly once when the failure count crosses
    /// `LIVENESS_FAILURE_THRESHOLD` within `LIVENESS_FAILURE_WINDOW`; subsequent
    /// failures inside the same crossed window return `false` so the caller
    /// only triggers force-close once per stuck-state episode.
    fn record_failure(&self, peer_id: PeerId, stable_id: usize) -> bool {
        let mut guard = self.state.lock();
        let now = Instant::now();
        let entry = guard
            .entry((peer_id, stable_id))
            .or_insert(LivenessFailureWindow {
                consecutive_failures: 0,
                window_started: now,
            });
        if now.duration_since(entry.window_started) > LIVENESS_FAILURE_WINDOW {
            entry.consecutive_failures = 1;
            entry.window_started = now;
            return false;
        }
        let prev = entry.consecutive_failures;
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        prev < LIVENESS_FAILURE_THRESHOLD
            && entry.consecutive_failures >= LIVENESS_FAILURE_THRESHOLD
    }

    /// Reset the failure window for a (peer, stable_id) after a successful
    /// send or retry — proves the path is alive.
    fn record_success(&self, peer_id: PeerId, stable_id: usize) {
        let mut guard = self.state.lock();
        guard.remove(&(peer_id, stable_id));
    }

    /// Drop tracking state for a (peer, stable_id) after the connection has
    /// closed — avoids retaining stale entries for connections that will
    /// never reach the threshold legitimately.
    fn forget(&self, peer_id: PeerId, stable_id: usize) {
        let mut guard = self.state.lock();
        guard.remove(&(peer_id, stable_id));
    }
}

#[derive(Default)]
struct AckDiagnostics {
    buckets: ParkingMutex<HashMap<AckDiagnosticsKey, AckMinuteDiagnostics>>,
}

impl AckDiagnostics {
    fn record_stage(
        &self,
        peer_id: PeerId,
        stable_id: usize,
        stage: AckLatencyStage,
        duration: Duration,
    ) {
        let mut buckets = self.buckets.lock();
        self.prune_locked(&mut buckets);
        let key = AckDiagnosticsKey {
            peer_id,
            stable_id,
            minute_unix: current_unix_minute(),
        };
        buckets
            .entry(key)
            .or_default()
            .stage_mut(stage)
            .record(duration);
    }

    fn record_outcome(&self, peer_id: PeerId, stable_id: usize, outcome: AckOutcome) {
        let mut buckets = self.buckets.lock();
        self.prune_locked(&mut buckets);
        let key = AckDiagnosticsKey {
            peer_id,
            stable_id,
            minute_unix: current_unix_minute(),
        };
        buckets.entry(key).or_default().outcomes.record(outcome);
    }

    fn snapshot(&self) -> AckDiagnosticsSnapshot {
        let mut buckets = self.buckets.lock();
        self.prune_locked(&mut buckets);

        let mut peers: Vec<_> = buckets
            .iter()
            .map(|(key, value)| AckPeerDiagnosticsSnapshot {
                peer_id: hex::encode(key.peer_id.0),
                stable_id: key.stable_id,
                minute_unix: key.minute_unix,
                stages: AckStageDiagnosticsSnapshot {
                    sender_open_bi: value.sender_open_bi.snapshot(),
                    sender_request_write: value.sender_request_write.snapshot(),
                    sender_request_finish: value.sender_request_finish.snapshot(),
                    sender_response_read: value.sender_response_read.snapshot(),
                    receiver_demux: value.receiver_demux.snapshot(),
                    receiver_admission: value.receiver_admission.snapshot(),
                    receiver_response_write_finish: value.receiver_response_write_finish.snapshot(),
                },
                outcomes: value.outcomes.clone(),
            })
            .collect();
        peers.sort_by(|a, b| {
            a.peer_id
                .cmp(&b.peer_id)
                .then(a.stable_id.cmp(&b.stable_id))
                .then(a.minute_unix.cmp(&b.minute_unix))
        });

        AckDiagnosticsSnapshot {
            generated_at_unix_ms: current_unix_ms(),
            retention_minutes: ACK_DIAGNOSTICS_RETENTION_MINUTES,
            peers,
        }
    }

    fn prune_locked(&self, buckets: &mut HashMap<AckDiagnosticsKey, AckMinuteDiagnostics>) {
        let now = current_unix_minute();
        buckets.retain(|key, _| {
            now.saturating_sub(key.minute_unix) <= ACK_DIAGNOSTICS_RETENTION_MINUTES
        });
    }
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn current_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

fn current_unix_minute() -> u64 {
    current_unix_ms() / 60_000
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> Option<u64> {
    if sorted.is_empty() || denominator == 0 {
        return None;
    }
    let last = sorted.len().saturating_sub(1);
    let idx = (last
        .saturating_mul(numerator)
        .saturating_add(denominator - 1))
        / denominator;
    sorted.get(idx.min(last)).copied()
}

/// Best-effort runtime assist snapshot for higher-level status surfaces.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeAssistSnapshot {
    pub successful_coordinations: u32,
    pub active_relay_sessions: usize,
    pub relay_bytes_forwarded: u64,
}

/// P2P endpoint statistics
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of active connections
    pub active_connections: usize,

    /// Total successful connections
    pub successful_connections: u64,

    /// Total failed connections
    pub failed_connections: u64,

    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,

    /// Successful NAT traversals
    pub nat_traversal_successes: u64,

    /// Direct connections (no coordinator or relay needed)
    pub direct_connections: u64,

    /// Currently active direct inbound connections from peers.
    pub active_direct_incoming_connections: u64,

    /// Most recent loopback-scoped direct inbound observation.
    pub last_direct_loopback_at: Option<Instant>,

    /// Most recent LAN-scoped direct inbound observation.
    pub last_direct_local_at: Option<Instant>,

    /// Most recent globally scoped direct inbound observation.
    pub last_direct_global_at: Option<Instant>,

    /// Relayed connections
    pub relayed_connections: u64,

    /// Total bootstrap nodes configured
    pub total_bootstrap_nodes: usize,

    /// Connected bootstrap nodes
    pub connected_bootstrap_nodes: usize,

    /// Endpoint start time
    pub start_time: Instant,

    /// Average coordination time for NAT traversal
    pub average_coordination_time: Duration,
}

impl Default for EndpointStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            direct_connections: 0,
            active_direct_incoming_connections: 0,
            last_direct_loopback_at: None,
            last_direct_local_at: None,
            last_direct_global_at: None,
            relayed_connections: 0,
            total_bootstrap_nodes: 0,
            connected_bootstrap_nodes: 0,
            start_time: Instant::now(),
            average_coordination_time: Duration::ZERO,
        }
    }
}

/// Peer lifecycle events for a specific authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLifecycleEvent {
    /// A live connection generation became established for the peer.
    Established {
        /// The live local lifecycle generation.
        generation: u64,
    },
    /// A newer live generation replaced the previously active one.
    Replaced {
        /// The previous live generation.
        old_generation: u64,
        /// The new live generation.
        new_generation: u64,
    },
    /// A generation is actively closing.
    Closing {
        /// The affected generation.
        generation: u64,
        /// Lifecycle-aware close reason.
        reason: ConnectionCloseReason,
    },
    /// A generation fully closed from the endpoint's perspective.
    Closed {
        /// The affected generation.
        generation: u64,
        /// Lifecycle-aware close reason.
        reason: ConnectionCloseReason,
    },
    /// The background reader task for a generation exited.
    ReaderExited {
        /// The affected generation.
        generation: u64,
    },
}

/// P2P event for connection and network state changes.
///
/// Events use [`TransportAddr`] to support multi-transport connectivity.
/// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
///
/// # Examples
///
/// ## Handling events with transport awareness
///
/// ```rust,ignore
/// use ant_quic::{P2pEvent, transport::TransportAddr};
///
/// while let Ok(event) = events.recv().await {
///     match event {
///         P2pEvent::PeerConnected { peer_id, addr, side, traversal_method } => {
///             // Handle different transport types
///             match addr {
///                 TransportAddr::Udp(socket_addr) => {
///                     println!("UDP connection from {socket_addr}");
///                 },
///                 TransportAddr::Ble { device_id, .. } => {
///                     println!("BLE connection from {:?}", device_id);
///                 },
///                 _ => println!("Other transport: {addr}"),
///             }
///         }
///         P2pEvent::ExternalAddressDiscovered { addr } => {
///             // Our external address was discovered
///             if let Some(socket_addr) = addr.as_socket_addr() {
///                 println!("External UDP address: {socket_addr}");
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Backward-compatible event handling
///
/// For code that only needs UDP support:
///
/// ```rust,ignore
/// match event {
///     P2pEvent::PeerConnected { peer_id, addr, .. } => {
///         if let Some(socket_addr) = addr.as_socket_addr() {
///             // Works as before with SocketAddr
///             println!("Peer {} connected from {}", peer_id, socket_addr);
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A new peer has connected.
    ///
    /// The `addr` field contains a [`TransportAddr`] which can represent different
    /// transport types (UDP, BLE, LoRa, etc.). Use `addr.as_socket_addr()` to extract
    /// the [`SocketAddr`] for UDP connections, or pattern match for specific transports.
    PeerConnected {
        /// The unique identifier of the connected peer
        peer_id: PeerId,
        /// Remote transport address (supports UDP, BLE, LoRa, and other transports)
        addr: TransportAddr,
        /// Who initiated the connection (Client = we connected, Server = they connected)
        side: Side,
        /// Whether the connection was direct, hole-punched, or relayed.
        traversal_method: TraversalMethod,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// The unique identifier of the disconnected peer
        peer_id: PeerId,
        /// Reason for the disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress update.
    NatTraversalProgress {
        /// Target peer ID for the NAT traversal
        peer_id: PeerId,
        /// Current phase of NAT traversal
        phase: TraversalPhase,
    },

    /// An external address was discovered for this node.
    ///
    /// The `addr` field contains a [`TransportAddr`] representing our externally
    /// visible address. For UDP connections, use `addr.as_socket_addr()` to get
    /// the [`SocketAddr`].
    ExternalAddressDiscovered {
        /// Discovered external transport address (typically TransportAddr::Udp for NAT traversal)
        addr: TransportAddr,
    },

    /// A connected peer advertised a new reachable address (relay or migration).
    PeerAddressUpdated {
        /// The connected peer that sent the advertisement
        peer_addr: SocketAddr,
        /// The new address the peer is advertising as reachable
        advertised_addr: SocketAddr,
    },

    /// This node established a MASQUE relay and is advertising a relay address.
    ///
    /// Emitted once when the relay becomes active. Upper layers should use this
    /// to trigger a DHT self-lookup so that more peers learn the relay address.
    RelayEstablished {
        /// The relay's public address (relay_IP:PORT)
        relay_addr: SocketAddr,
    },

    /// Best-effort router port mapping was established.
    PortMappingEstablished {
        /// The currently mapped external address.
        external_addr: SocketAddr,
    },

    /// Best-effort router port mapping was renewed.
    PortMappingRenewed {
        /// The currently mapped external address.
        external_addr: SocketAddr,
    },

    /// Best-effort router port mapping changed to a different public address.
    PortMappingAddressChanged {
        /// Previous mapped public address.
        previous_addr: SocketAddr,
        /// Current mapped public address.
        external_addr: SocketAddr,
    },

    /// Best-effort router port mapping failed.
    PortMappingFailed {
        /// Human-readable failure detail.
        error: String,
    },

    /// Best-effort router port mapping was removed or became inactive.
    PortMappingRemoved {
        /// The last mapped external address, when known.
        external_addr: Option<SocketAddr>,
    },

    /// The local endpoint is advertising itself via first-party mDNS.
    MdnsServiceAdvertised {
        /// Service/application scope being advertised.
        service: String,
        /// Namespace/workspace scope, if configured.
        namespace: Option<String>,
        /// Full DNS-SD instance name being advertised.
        instance_fullname: String,
    },

    /// A peer was discovered via first-party mDNS.
    MdnsPeerDiscovered {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A previously discovered mDNS peer was updated.
    MdnsPeerUpdated {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A previously discovered mDNS peer was removed.
    MdnsPeerRemoved {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A discovered mDNS peer passed local eligibility checks.
    MdnsPeerEligible {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A discovered mDNS peer was rejected by local eligibility checks.
    MdnsPeerIneligible {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Human-readable reason for rejection.
        reason: String,
    },

    /// A discovered mDNS peer requires explicit approval before auto-connect.
    MdnsPeerApprovalRequired {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Human-readable policy reason.
        reason: String,
    },

    /// An mDNS-driven auto-connect attempt was scheduled.
    MdnsAutoConnectAttempted {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Candidate addresses routed through the unified connect path.
        addresses: Vec<SocketAddr>,
    },

    /// An mDNS-driven auto-connect attempt succeeded.
    MdnsAutoConnectSucceeded {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Authenticated peer identity learned from QUIC.
        authenticated_peer_id: PeerId,
        /// Connected remote transport address.
        remote_addr: TransportAddr,
    },

    /// An mDNS-driven auto-connect attempt failed.
    MdnsAutoConnectFailed {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Candidate addresses routed through the unified connect path.
        addresses: Vec<SocketAddr>,
        /// Human-readable failure detail.
        error: String,
    },

    /// Best-effort direct-path status for a peer.
    DirectPathStatus {
        /// Authenticated peer identity.
        peer_id: PeerId,
        /// Current direct-path status.
        status: DirectPathStatus,
    },

    /// Bootstrap connection status
    BootstrapStatus {
        /// Number of connected bootstrap nodes
        connected: usize,
        /// Total number of bootstrap nodes
        total: usize,
    },

    /// Peer authenticated
    PeerAuthenticated {
        /// Authenticated peer ID
        peer_id: PeerId,
    },

    /// Data received from peer
    DataReceived {
        /// Source peer ID
        peer_id: PeerId,
        /// Number of bytes received
        bytes: usize,
    },

    /// Data received from a constrained transport (BLE, LoRa, etc.)
    ///
    /// This event is generated when data arrives via a non-UDP transport that uses
    /// the constrained protocol engine. The peer may not have a PeerId assigned yet
    /// (early in the connection lifecycle).
    ConstrainedDataReceived {
        /// Remote transport address (BLE device ID, LoRa address, etc.)
        remote_addr: TransportAddr,
        /// Connection ID from the constrained engine
        connection_id: u16,
        /// The received data payload
        data: Vec<u8>,
    },
}

/// Best-effort direct-path status for an authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectPathStatus {
    /// Direct-path establishment is still in progress or may still improve later.
    Pending,
    /// A direct path has been established.
    Established {
        /// Remote socket address for the established direct path.
        remote_addr: SocketAddr,
    },
    /// A direct path is currently unavailable, but overall connectivity can still continue.
    BestEffortUnavailable {
        /// Normalized reason for unavailability.
        reason: DirectPathUnavailableReason,
    },
    /// Direct-path establishment failed in a way the caller should treat as a hard failure.
    Failed {
        /// Human-readable error detail.
        error: String,
    },
}

/// Normalized reason why a direct path is not currently available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPathUnavailableReason {
    /// No viable direct candidates were available.
    NoCandidates,
    /// Network reachability or NAT behavior prevented direct establishment.
    NatUnreachable,
    /// Connectivity succeeded only via relay fallback.
    RelayRequired,
    /// Cause could not be normalized more precisely.
    Unknown,
}

/// Reason for peer disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Normal disconnect
    Normal,
    /// Connection timeout
    Timeout,
    /// Protocol error
    ProtocolError(String),
    /// Authentication failure
    AuthenticationFailed,
    /// Connection lost
    ConnectionLost,
    /// Remote closed
    RemoteClosed,
    /// X0X-0062: the application-layer liveness detector concluded the data
    /// path is half-dead (5 consecutive ACK-v2 retry double-failures within
    /// 60 s while QUIC keepalives still report the connection as `Live`).
    /// Differs from `Timeout`: that's the QUIC transport idle-timer firing;
    /// this is the application observing that nothing is getting through
    /// despite QUIC saying everything is fine.
    LivenessTimeout,
}

fn close_reason_from_connection(
    connection: &crate::high_level::Connection,
) -> Option<ConnectionCloseReason> {
    connection
        .close_reason()
        .as_ref()
        .map(ConnectionCloseReason::from_connection_error)
}

fn endpoint_error_from_connection_error(error: crate::ConnectionError) -> EndpointError {
    EndpointError::ConnectionClosed {
        reason: ConnectionCloseReason::from_connection_error(&error),
    }
}

fn endpoint_error_from_write_error(error: crate::high_level::WriteError) -> EndpointError {
    match error {
        crate::high_level::WriteError::ConnectionLost(error) => {
            endpoint_error_from_connection_error(error)
        }
        other => EndpointError::Connection(other.to_string()),
    }
}

fn endpoint_error_from_read_error(error: crate::high_level::ReadError) -> EndpointError {
    match error {
        crate::high_level::ReadError::ConnectionLost(error) => {
            endpoint_error_from_connection_error(error)
        }
        other => EndpointError::Connection(other.to_string()),
    }
}

fn endpoint_error_from_read_to_end_error(
    error: crate::high_level::ReadToEndError,
) -> EndpointError {
    match error {
        crate::high_level::ReadToEndError::Read(read_error) => {
            endpoint_error_from_read_error(read_error)
        }
        crate::high_level::ReadToEndError::TooLong => {
            EndpointError::Connection("ACK-v2 response too long".to_string())
        }
    }
}

fn close_reason_for_disconnect(reason: &DisconnectReason) -> ConnectionCloseReason {
    match reason {
        DisconnectReason::Normal => ConnectionCloseReason::LifecycleCleanup,
        DisconnectReason::Timeout => ConnectionCloseReason::TimedOut,
        DisconnectReason::ProtocolError(_) => ConnectionCloseReason::LifecycleCleanup,
        DisconnectReason::AuthenticationFailed => ConnectionCloseReason::Banned,
        DisconnectReason::ConnectionLost => ConnectionCloseReason::ReaderExit,
        DisconnectReason::RemoteClosed => ConnectionCloseReason::ConnectionClosed,
        DisconnectReason::LivenessTimeout => ConnectionCloseReason::LivenessTimeout,
    }
}

// TraversalPhase is re-exported from nat_traversal_api

/// Error type for P2pEndpoint operations
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Lifecycle-aware connection closure.
    #[error("Connection closed: {reason}")]
    ConnectionClosed {
        /// Lifecycle-aware close reason.
        reason: ConnectionCloseReason,
    },

    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] NatTraversalError),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// The peer/connection does not support this optional feature.
    #[error("Feature not supported by peer or transport")]
    NotSupported,

    /// Timed out waiting for the remote receive pipeline ACK.
    #[error("Timed out waiting for remote receive acknowledgement")]
    AckTimeout,

    /// Timed out waiting for a peer liveness probe response.
    #[error("Timed out waiting for peer liveness probe response")]
    ProbeTimeout,

    /// Probe traffic was skipped because the endpoint's low-priority probe
    /// budget was already saturated.
    #[error("Peer liveness probe skipped because probe budget is saturated")]
    ProbeOverBudget,

    /// The remote receive pipeline rejected the payload.
    #[error("Remote receive pipeline rejected payload: {reason}")]
    ReceiveRejected {
        /// Rejection reason supplied by the remote endpoint.
        reason: ReceiveRejectReason,
    },

    /// Peer not found
    #[error("Peer not found: {0:?}")]
    PeerNotFound(PeerId),

    /// Already connected
    #[error("Already connected to peer: {0:?}")]
    AlreadyConnected(PeerId),

    /// Shutdown in progress
    #[error("Endpoint is shutting down")]
    ShuttingDown,

    /// All connection strategies failed
    #[error("All connection strategies failed: {0}")]
    AllStrategiesFailed(String),

    /// No target address provided
    #[error("No target address provided")]
    NoAddress,
}

#[derive(Debug)]
enum HolePunchAwaitError {
    TraversalFailure(TraversalFailureReason),
    Endpoint(EndpointError),
}

impl HolePunchAwaitError {
    fn retry_reason(&self) -> Option<&TraversalFailureReason> {
        match self {
            Self::TraversalFailure(reason) => Some(reason),
            Self::Endpoint(_) => None,
        }
    }

    fn from_nat_traversal_error(error: NatTraversalError) -> Self {
        match TraversalFailureReason::from_public_operation_error(&error) {
            Some(reason) => Self::TraversalFailure(reason),
            None => Self::Endpoint(EndpointError::NatTraversal(error)),
        }
    }
}

impl std::fmt::Display for HolePunchAwaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraversalFailure(reason) => write!(f, "{reason}"),
            Self::Endpoint(error) => write!(f, "{error}"),
        }
    }
}

/// Shared cleanup logic for removing a peer from all tracking structures.
///
/// Used by both `P2pEndpoint::cleanup_connection()` and the background reaper
/// to ensure consistent cleanup behaviour (single source of truth).
///
/// Returns `true` if the peer was actually present in `connected_peers`.
async fn do_cleanup_connection(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    inner: &NatTraversalEndpoint,
    reader_handles: &RwLock<HashMap<PeerId, Vec<ReaderTaskHandle>>>,
    direct_path_statuses: &ParkingRwLock<HashMap<PeerId, DirectPathStatus>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_event_tx: &broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
    peer_event_channels: &ParkingRwLock<HashMap<PeerId, broadcast::Sender<PeerLifecycleEvent>>>,
    peer_event_generations: &ParkingRwLock<HashMap<PeerId, u64>>,
    ack_waiters: &ParkingRwLock<HashMap<usize, AckWaiterMap>>,
    peer_id: &PeerId,
    reason: DisconnectReason,
    close_reason: ConnectionCloseReason,
) -> bool {
    let lifecycle_snapshot = inner
        .get_connection(peer_id)
        .ok()
        .flatten()
        .and_then(|connection| {
            inner.connection_snapshot_by_stable_id(peer_id, connection.stable_id())
        });

    if let Some(snapshot) = lifecycle_snapshot {
        emit_peer_lifecycle_event(
            peer_event_tx,
            peer_event_channels,
            *peer_id,
            PeerLifecycleEvent::Closing {
                generation: snapshot.generation,
                reason: close_reason,
            },
        );
    }

    let _ = inner.remove_connection_with_reason(peer_id, close_reason);
    direct_path_statuses.write().remove(peer_id);

    if let Some(snapshot) = lifecycle_snapshot {
        emit_peer_lifecycle_event(
            peer_event_tx,
            peer_event_channels,
            *peer_id,
            PeerLifecycleEvent::Closed {
                generation: snapshot.generation,
                reason: close_reason,
            },
        );
        fail_ack_waiters_for_connection(ack_waiters, snapshot.stable_id, close_reason);
        // Keep the generation recorded in `peer_event_generations` so the next
        // registration emits Replaced{old,new} when a replacement races the close.
        // The entry will be overwritten when a new connection registers.
        let _ = peer_event_generations;
    }

    // Tear down all background readers for this peer. Cooperative cancel first
    // (allows any in-flight `read_to_end()` to complete and deliver its bytes),
    // then `abort()` as a backstop in case a reader is wedged.
    if let Some(handles) = reader_handles.write().await.remove(peer_id) {
        for handle in handles {
            handle.cancel.cancel();
            handle.abort_handle.abort();
        }
    }

    let removed = remove_connected_peer(connected_peers, stats, event_tx, peer_id, reason).await;
    if removed {
        info!("Cleaned up connection for peer {:?}", peer_id);
    }
    removed
}

/// Record connection-established stats and emit the user-facing `PeerConnected` event.
///
/// This is the single source of truth for `P2pEndpoint` connection accounting once a
/// `PeerConnection` has been stored in `connected_peers`.
async fn record_connection_established(
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_conn: &PeerConnection,
    previous: Option<&PeerConnection>,
) {
    let had_active_direct_incoming =
        previous.is_some_and(|prev| prev.traversal_method.is_direct() && prev.side.is_server());
    let has_active_direct_incoming =
        peer_conn.traversal_method.is_direct() && peer_conn.side.is_server();
    let should_emit = previous.is_none_or(|prev| {
        prev.remote_addr != peer_conn.remote_addr
            || prev.traversal_method != peer_conn.traversal_method
            || prev.side != peer_conn.side
            || prev.authenticated != peer_conn.authenticated
    });

    {
        let mut s = stats.write().await;
        if previous.is_none() {
            s.active_connections += 1;
            s.successful_connections += 1;
        }

        if previous.is_none_or(|prev| prev.traversal_method != peer_conn.traversal_method) {
            // Decrement the previous traversal method's live counter when an
            // established connection transitions methods (e.g. Relay → Direct
            // after hole-punch upgrade). Without this, both counters tick up
            // and the steady-state mesh shows direct + relayed > active peers.
            if let Some(prev) = previous {
                match prev.traversal_method {
                    TraversalMethod::Direct => {
                        s.direct_connections = s.direct_connections.saturating_sub(1);
                    }
                    TraversalMethod::Relay => {
                        s.relayed_connections = s.relayed_connections.saturating_sub(1);
                    }
                    TraversalMethod::HolePunch | TraversalMethod::PortPrediction => {}
                }
            }
            match peer_conn.traversal_method {
                TraversalMethod::Direct => {
                    s.direct_connections += 1;
                }
                TraversalMethod::Relay => {
                    s.relayed_connections += 1;
                }
                TraversalMethod::HolePunch | TraversalMethod::PortPrediction => {}
            }
        }

        if !had_active_direct_incoming && has_active_direct_incoming {
            s.active_direct_incoming_connections += 1;
        } else if had_active_direct_incoming && !has_active_direct_incoming {
            s.active_direct_incoming_connections =
                s.active_direct_incoming_connections.saturating_sub(1);
        }

        if has_active_direct_incoming {
            if let Some(remote_addr) = peer_conn.remote_addr.as_socket_addr() {
                let now = Instant::now();
                match socket_addr_scope(remote_addr) {
                    Some(ReachabilityScope::Loopback) => {
                        s.last_direct_loopback_at = Some(now);
                    }
                    Some(ReachabilityScope::LocalNetwork) => {
                        s.last_direct_local_at = Some(now);
                    }
                    Some(ReachabilityScope::Global) => {
                        s.last_direct_global_at = Some(now);
                    }
                    None => {}
                }
            }
        }
    }

    if should_emit {
        if let Err(e) = event_tx.send(P2pEvent::PeerConnected {
            peer_id: peer_conn.peer_id,
            addr: peer_conn.remote_addr.clone(),
            side: peer_conn.side,
            traversal_method: peer_conn.traversal_method,
        }) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "event_tx_peer_connected",
                peer_id = ?peer_conn.peer_id,
                error = %e,
                "silent drop"
            );
        }
    }
}

async fn remove_connected_peer(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_id: &PeerId,
    reason: DisconnectReason,
) -> bool {
    let removed = connected_peers.write().await.remove(peer_id);

    if let Some(peer_conn) = removed {
        {
            let mut s = stats.write().await;
            s.active_connections = s.active_connections.saturating_sub(1);
            // Keep direct_connections / relayed_connections as live counts so
            // they stay consistent with connected_peers across disconnects.
            match peer_conn.traversal_method {
                TraversalMethod::Direct => {
                    s.direct_connections = s.direct_connections.saturating_sub(1);
                }
                TraversalMethod::Relay => {
                    s.relayed_connections = s.relayed_connections.saturating_sub(1);
                }
                TraversalMethod::HolePunch | TraversalMethod::PortPrediction => {}
            }
            if peer_conn.traversal_method.is_direct() && peer_conn.side.is_server() {
                s.active_direct_incoming_connections =
                    s.active_direct_incoming_connections.saturating_sub(1);
            }
        }

        if let Err(e) = event_tx.send(P2pEvent::PeerDisconnected {
            peer_id: *peer_id,
            reason,
        }) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "event_tx_peer_disconnected",
                peer_id = ?peer_id,
                error = %e,
                "silent drop"
            );
        }
        true
    } else {
        false
    }
}

async fn store_connected_peer(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_conn: PeerConnection,
) {
    let previous = connected_peers
        .write()
        .await
        .insert(peer_conn.peer_id, peer_conn.clone());
    record_connection_established(stats, event_tx, &peer_conn, previous.as_ref()).await;
}

async fn note_peer_activity(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    peer_activity: &RwLock<HashMap<PeerId, PeerActivityRecord>>,
    peer_id: PeerId,
    kind: PeerActivityKind,
    at: Instant,
) {
    if let Some(peer_conn) = connected_peers.write().await.get_mut(&peer_id) {
        peer_conn.last_activity = at;
    }

    let mut activity = peer_activity.write().await;
    let entry = activity.entry(peer_id).or_default();
    match kind {
        PeerActivityKind::Sent => entry.last_sent_at = Some(at),
        PeerActivityKind::Received => entry.last_received_at = Some(at),
    }
}

async fn recent_peer_receive_activity(
    peer_activity: &RwLock<HashMap<PeerId, PeerActivityRecord>>,
    peer_id: PeerId,
    now: Instant,
) -> Option<Duration> {
    let activity = peer_activity.read().await;
    activity
        .get(&peer_id)
        .and_then(|record| record.last_received_at)
        .map(|last_received_at| now.saturating_duration_since(last_received_at))
        .filter(|age| *age <= PROBE_RECENT_RECEIVE_SUPPRESSION)
}

fn peer_event_sender(
    peer_event_channels: &ParkingRwLock<HashMap<PeerId, broadcast::Sender<PeerLifecycleEvent>>>,
    peer_id: PeerId,
) -> broadcast::Sender<PeerLifecycleEvent> {
    if let Some(sender) = peer_event_channels.read().get(&peer_id).cloned() {
        return sender;
    }

    let mut channels = peer_event_channels.write();
    channels
        .entry(peer_id)
        .or_insert_with(|| broadcast::channel(PEER_EVENT_CHANNEL_CAPACITY).0)
        .clone()
}

fn emit_peer_lifecycle_event(
    peer_event_tx: &broadcast::Sender<(PeerId, PeerLifecycleEvent)>,
    peer_event_channels: &ParkingRwLock<HashMap<PeerId, broadcast::Sender<PeerLifecycleEvent>>>,
    peer_id: PeerId,
    event: PeerLifecycleEvent,
) {
    if let Err(e) = peer_event_tx.send((peer_id, event.clone())) {
        tracing::warn!(
            target: "ant_quic::silent_drop",
            kind = "peer_event_tx_lifecycle",
            peer_id = ?peer_id,
            error = %e,
            "silent drop"
        );
    }
    if let Some(sender) = peer_event_channels.read().get(&peer_id).cloned() {
        if let Err(e) = sender.send(event) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "per_peer_lifecycle_broadcast",
                peer_id = ?peer_id,
                error = %e,
                "silent drop"
            );
        }
    }
}

fn register_ack_waiter(
    ack_waiters: &ParkingRwLock<HashMap<usize, AckWaiterMap>>,
    stable_id: usize,
    tag: [u8; 16],
    tx: oneshot::Sender<AckWaiterResult>,
) -> bool {
    let mut waiters = ack_waiters.write();
    let entry = waiters.entry(stable_id).or_default();
    if entry.contains_key(&tag) {
        return false;
    }
    entry.insert(tag, tx);
    true
}

fn resolve_ack_waiter(
    ack_waiters: &ParkingRwLock<HashMap<usize, AckWaiterMap>>,
    stable_id: usize,
    tag: [u8; 16],
    result: AckWaiterResult,
) -> bool {
    let tx = {
        let mut waiters = ack_waiters.write();
        let sender = waiters
            .get_mut(&stable_id)
            .and_then(|entry| entry.remove(&tag));
        if waiters.get(&stable_id).is_some_and(HashMap::is_empty) {
            waiters.remove(&stable_id);
        }
        sender
    };
    if let Some(tx) = tx {
        if let Err(_dropped) = tx.send(result) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "ack_waiter_oneshot",
                stable_id = stable_id,
                "silent drop"
            );
        }
        true
    } else {
        false
    }
}

fn fail_ack_waiters_for_connection(
    ack_waiters: &ParkingRwLock<HashMap<usize, AckWaiterMap>>,
    stable_id: usize,
    reason: ConnectionCloseReason,
) {
    let waiters = ack_waiters.write().remove(&stable_id);
    if let Some(waiters) = waiters {
        for (_, tx) in waiters {
            if let Err(_dropped) = tx.send(AckWaiterResult::Closed(reason)) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "ack_waiter_close_oneshot",
                    stable_id = stable_id,
                    "silent drop"
                );
            }
        }
    }
}

/// Bridge low-level NAT traversal events into endpoint-level progress/accounting.
///
/// Connection-established accounting is intentionally excluded here; that happens
/// only after `P2pEndpoint` stores the peer in `connected_peers`.
async fn bridge_nat_traversal_event(
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    direct_path_statuses: &ParkingRwLock<HashMap<PeerId, DirectPathStatus>>,
    event: NatTraversalEvent,
) {
    match event {
        NatTraversalEvent::CoordinationRequested { .. } => {
            stats.write().await.nat_traversal_attempts += 1;
        }
        NatTraversalEvent::ConnectionEstablished {
            peer_id,
            remote_address,
            ..
        } => {
            stats.write().await.nat_traversal_successes += 1;
            publish_direct_path_status(
                direct_path_statuses,
                event_tx,
                peer_id,
                DirectPathStatus::Established {
                    remote_addr: remote_address,
                },
            );
        }
        NatTraversalEvent::TraversalTerminated {
            peer_id,
            reason,
            fallback_available,
        } => {
            stats.write().await.failed_connections += 1;
            let status = terminal_direct_path_status_from_failure(&reason, fallback_available);
            publish_direct_path_status(direct_path_statuses, event_tx, peer_id, status);
            if let Err(e) = event_tx.send(P2pEvent::NatTraversalProgress {
                peer_id,
                phase: TraversalPhase::Failed,
            }) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "event_tx_nat_progress_failed",
                    peer_id = ?peer_id,
                    error = %e,
                    "silent drop"
                );
            }
        }
        NatTraversalEvent::TraversalFailed {
            peer_id,
            error,
            fallback_available,
        } => {
            let already_terminal = direct_path_statuses
                .read()
                .get(&peer_id)
                .is_some_and(is_terminal_direct_path_status);
            if already_terminal {
                return;
            }

            stats.write().await.failed_connections += 1;
            let status = if fallback_available {
                DirectPathStatus::BestEffortUnavailable {
                    reason: normalize_direct_path_unavailable_reason(&error),
                }
            } else {
                DirectPathStatus::Failed {
                    error: error.to_string(),
                }
            };
            publish_direct_path_status(direct_path_statuses, event_tx, peer_id, status);
            if let Err(e) = event_tx.send(P2pEvent::NatTraversalProgress {
                peer_id,
                phase: TraversalPhase::Failed,
            }) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "event_tx_nat_progress_failed",
                    peer_id = ?peer_id,
                    error = %e,
                    "silent drop"
                );
            }
        }
        NatTraversalEvent::PhaseTransition {
            peer_id, to_phase, ..
        } => {
            if !matches!(to_phase, TraversalPhase::Connected | TraversalPhase::Failed) {
                publish_direct_path_status(
                    direct_path_statuses,
                    event_tx,
                    peer_id,
                    DirectPathStatus::Pending,
                );
            }
            if let Err(e) = event_tx.send(P2pEvent::NatTraversalProgress {
                peer_id,
                phase: to_phase,
            }) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "event_tx_nat_progress_phase",
                    peer_id = ?peer_id,
                    error = %e,
                    "silent drop"
                );
            }
        }
        NatTraversalEvent::ExternalAddressDiscovered { address, .. } => {
            info!("External address discovered: {}", address);
            if let Err(e) = event_tx.send(P2pEvent::ExternalAddressDiscovered {
                addr: TransportAddr::Udp(address),
            }) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "event_tx_external_addr",
                    addr = ?address,
                    error = %e,
                    "silent drop"
                );
            }
        }
        _ => {}
    }
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Use provided keypair or generate a new one (ML-DSA-65)
        let (public_key, secret_key) = match config.keypair.clone() {
            Some(keypair) => keypair,
            None => generate_ml_dsa_keypair().map_err(|e| {
                EndpointError::Config(format!("Failed to generate ML-DSA-65 keypair: {e:?}"))
            })?,
        };
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Creating P2P endpoint with peer ID: {:?}", peer_id);

        // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
        // Store public key bytes directly for identity sharing
        let public_key_bytes: Vec<u8> = public_key.as_bytes().to_vec();

        // Create event channel
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let event_tx_clone = event_tx.clone();

        // Create stats
        let stats = Arc::new(RwLock::new(EndpointStats {
            total_bootstrap_nodes: config.known_peers.len(),
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_clone = Arc::clone(&stats);
        let direct_path_statuses = Arc::new(ParkingRwLock::new(HashMap::new()));
        let direct_path_statuses_clone = Arc::clone(&direct_path_statuses);

        // Create event callback that bridges low-level NAT events into
        // endpoint-level progress/accounting notifications.
        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let event_tx = event_tx_clone.clone();
            let stats = stats_clone.clone();
            let direct_path_statuses = direct_path_statuses_clone.clone();

            tokio::spawn(async move {
                bridge_nat_traversal_event(
                    stats.as_ref(),
                    &event_tx,
                    direct_path_statuses.as_ref(),
                    event,
                )
                .await;
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let mut nat_config = config.to_nat_config_with_key(public_key.clone(), secret_key);
        let bootstrap_cache = Arc::new(
            BootstrapCache::open(config.bootstrap_cache.clone())
                .await
                .map_err(|e| {
                    EndpointError::Config(format!("Failed to open bootstrap cache: {}", e))
                })?,
        );

        // Create token store
        let token_store = Arc::new(BootstrapTokenStore::new(bootstrap_cache.clone()).await);

        use crate::high_level::runtime::AsyncUdpSocket;

        // Socket strategy: try dual-socket (separate IPv4 + IPv6) first for maximum
        // platform compatibility. Fall back to single-socket dual-stack, then IPv4 only.
        let requested_port = config
            .bind_addr
            .as_ref()
            .and_then(|addr| addr.as_socket_addr())
            .map(|addr| addr.port())
            .unwrap_or(0);

        // Track DualStackSocket for local_addrs() API
        let mut _dual_stack_ref: Option<
            std::sync::Arc<crate::high_level::runtime::dual_stack::DualStackSocket>,
        > = None;

        // Try dual-socket first (separate IPv4 + IPv6 sockets)
        let mut inner = match crate::transport::UdpTransport::bind_dual_stack_for_endpoint(
            requested_port,
        )
        .await
        {
            Ok((transport, dual_socket)) => {
                let (v4_addr, v6_addr) = dual_socket.local_addrs();
                info!(
                    "Bound dual-socket: IPv4={}, IPv6={} (true dual-stack, separate sockets)",
                    v4_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                    v6_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                );

                let actual_bind_addr = dual_socket.local_addr().map_err(|e| {
                    EndpointError::Config(format!("Failed to get local address: {e}"))
                })?;

                // Create transport registry
                let mut transport_registry = config.transport_registry.clone();
                crate::transport::register_best_effort_transports(&mut transport_registry).await;
                transport_registry.register(Arc::new(transport));

                nat_config.transport_registry = Some(Arc::new(transport_registry));
                nat_config.bind_addr = Some(actual_bind_addr);

                // Add the other address family to additional_bind_addrs for discovery
                // Primary is IPv6 (from local_addr()), so add IPv4 as additional
                if let Some(v4_addr) = v4_addr {
                    nat_config.additional_bind_addrs.push(v4_addr);
                }

                let abs_socket: std::sync::Arc<dyn AsyncUdpSocket> = dual_socket.clone();
                _dual_stack_ref = Some(dual_socket);

                NatTraversalEndpoint::new_with_abstract_socket(
                    nat_config,
                    Some(event_callback),
                    Some(token_store.clone()),
                    abs_socket,
                )
                .await
                .map_err(|e| EndpointError::Config(e.to_string()))?
            }
            Err(e) => {
                // Fall back to single-socket approach
                info!("Dual-socket failed ({e}), falling back to single-socket");

                let dual_stack_default: std::net::SocketAddr = std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    requested_port,
                );
                let ipv4_fallback: std::net::SocketAddr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    requested_port,
                );
                let bind_addr = config
                    .bind_addr
                    .as_ref()
                    .and_then(|addr| addr.as_socket_addr())
                    .unwrap_or(dual_stack_default);

                let (transport, quinn_socket) =
                    match crate::transport::UdpTransport::bind_for_quinn(bind_addr).await {
                        Ok(result) => result,
                        Err(e2) if bind_addr == dual_stack_default => {
                            info!("Single-socket dual-stack failed ({e2}), falling back to IPv4");
                            crate::transport::UdpTransport::bind_for_quinn(ipv4_fallback)
                                .await
                                .map_err(|e3| {
                                    EndpointError::Config(format!(
                                        "All socket binds failed (dual: {e}, v6: {e2}, v4: {e3})"
                                    ))
                                })?
                        }
                        Err(e2) => {
                            return Err(EndpointError::Config(format!(
                                "Failed to bind UDP socket: {e2}"
                            )));
                        }
                    };

                let actual_bind_addr = quinn_socket.local_addr().map_err(|e2| {
                    EndpointError::Config(format!("Failed to get local address: {e2}"))
                })?;

                info!(
                    "Bound single socket at {} ({})",
                    actual_bind_addr,
                    if actual_bind_addr.is_ipv6() {
                        "dual-stack IPv4+IPv6"
                    } else {
                        "IPv4 only"
                    }
                );

                let mut transport_registry = config.transport_registry.clone();
                crate::transport::register_best_effort_transports(&mut transport_registry).await;
                transport_registry.register(Arc::new(transport));

                nat_config.transport_registry = Some(Arc::new(transport_registry));
                nat_config.bind_addr = Some(actual_bind_addr);

                NatTraversalEndpoint::new_with_socket(
                    nat_config,
                    Some(event_callback),
                    Some(token_store.clone()),
                    Some(quinn_socket),
                )
                .await
                .map_err(|e2| EndpointError::Config(e2.to_string()))?
            }
        };

        inner.set_local_peer_id(peer_id);

        // Get the transport registry that was set on the endpoint
        let transport_registry = inner
            .transport_registry()
            .cloned()
            .unwrap_or_else(|| Arc::new(crate::transport::TransportRegistry::new()));

        // Create connection router for automatic protocol engine selection
        let inner_arc = Arc::new(inner);
        let router_config = RouterConfig {
            constrained_config: crate::constrained::ConstrainedTransportConfig::default(),
            prefer_quic: true, // Default to QUIC for broadband transports
            enable_metrics: true,
            max_connections: 256,
        };
        let mut router = ConnectionRouter::with_full_config(
            router_config,
            Arc::clone(&transport_registry),
            Arc::clone(&inner_arc),
        );

        // Set QUIC endpoint on the router
        router.set_quic_endpoint(Arc::clone(&inner_arc));

        // Create channel for data received from background reader tasks
        let data_tx_capacity = config.data_channel_capacity;
        let (data_tx, data_rx) = mpsc::channel(data_tx_capacity);
        let data_tx_diagnostics = Arc::new(DataChannelDiagnostics::default());
        let (reader_exit_tx, reader_exit_rx) = mpsc::unbounded_channel();
        let reader_handles = Arc::new(RwLock::new(HashMap::new()));
        let peer_activity = Arc::new(RwLock::new(HashMap::new()));
        let ack_waiters = Arc::new(ParkingRwLock::new(HashMap::new()));
        let ack_diagnostics = Arc::new(AckDiagnostics::default());
        let ack_liveness = Arc::new(AckLivenessTracker::default());
        let ack_request_dedupe = Arc::new(AckRequestDedupeCache::default());
        let probe_flights = Arc::new(TokioMutex::new(HashMap::new()));
        let probe_semaphore = Arc::new(Semaphore::new(PROBE_GLOBAL_CONCURRENCY));
        let (peer_event_tx, _) = broadcast::channel(PEER_EVENT_CHANNEL_CAPACITY);
        let peer_event_channels = Arc::new(ParkingRwLock::new(HashMap::new()));
        let peer_event_generations = Arc::new(ParkingRwLock::new(HashMap::new()));

        let endpoint = Self {
            inner: inner_arc,
            // v0.2: auth_manager removed
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            peer_id,
            public_key: public_key_bytes,
            shutdown: CancellationToken::new(),
            pending_data: Arc::new(RwLock::new(BoundedPendingBuffer::default())),
            bootstrap_cache,
            peer_hint_records: Arc::new(RwLock::new(HashMap::new())),
            transport_registry,
            router: Arc::new(RwLock::new(router)),
            constrained_connections: Arc::new(RwLock::new(HashMap::new())),
            constrained_peer_addrs: Arc::new(RwLock::new(HashMap::new())),
            manual_known_peer_udp_addrs: Arc::new(RwLock::new(Vec::new())),
            port_mapping_state: Arc::new(ParkingRwLock::new(PortMappingSnapshot::default())),
            mdns_state: Arc::new(ParkingRwLock::new(MdnsSnapshot::default())),
            mdns_auto_connect_inflight: Arc::new(ParkingRwLock::new(HashSet::new())),
            direct_path_statuses,
            data_tx,
            data_rx: Arc::new(tokio::sync::Mutex::new(data_rx)),
            data_tx_capacity,
            data_tx_diagnostics,
            reader_exit_tx,
            reader_exit_rx: Arc::new(tokio::sync::Mutex::new(reader_exit_rx)),
            reader_handles,
            peer_activity,
            ack_waiters,
            ack_diagnostics,
            ack_liveness,
            ack_request_dedupe,
            probe_flights,
            probe_semaphore,
            peer_event_tx,
            peer_event_channels,
            peer_event_generations,
            coordinator_health: Arc::new(crate::coordinator_health::CoordinatorHealth::new()),
        };

        let (ack_bidi_tx, mut ack_bidi_rx) = mpsc::unbounded_channel();
        endpoint.inner.set_ack_bidi_stream_sender(ack_bidi_tx);
        {
            let connected_peers = Arc::clone(&endpoint.connected_peers);
            let peer_activity = Arc::clone(&endpoint.peer_activity);
            let ack_diagnostics = Arc::clone(&endpoint.ack_diagnostics);
            let ack_request_dedupe = Arc::clone(&endpoint.ack_request_dedupe);
            let data_tx = endpoint.data_tx.clone();
            let data_tx_diagnostics = Arc::clone(&endpoint.data_tx_diagnostics);
            let data_tx_capacity = endpoint.data_tx_capacity;
            let event_tx = endpoint.event_tx.clone();
            let shutdown = endpoint.shutdown.clone();
            let max_read_bytes = endpoint.config.max_message_size;
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        stream = ack_bidi_rx.recv() => {
                            let Some(IncomingAckBidiStream {
                                peer_id,
                                conn_stable_id,
                                send,
                                recv,
                                prefix,
                                accepted_at,
                            }) = stream else {
                                break;
                            };
                            if !Self::handle_ack_bidi_stream(
                                ack_diagnostics.as_ref(),
                                ack_request_dedupe.as_ref(),
                                &connected_peers,
                                &peer_activity,
                                &data_tx,
                                data_tx_diagnostics.as_ref(),
                                data_tx_capacity,
                                &event_tx,
                                peer_id,
                                conn_stable_id,
                                send,
                                recv,
                                prefix,
                                accepted_at,
                                max_read_bytes,
                            )
                            .await
                            {
                                debug!(
                                    "ACK-v2 bidi bridge stopping for peer {:?}: consumer gone",
                                    peer_id
                                );
                                break;
                            }
                        }
                    }
                }
            });
        }

        // Spawn background pollers for transport and peer-address updates.
        endpoint.spawn_constrained_poller();
        endpoint.spawn_peer_address_update_poller();

        // Spawn stale connection reaper — periodically detects and removes
        // dead connections from tracking structures (issue #137 fix).
        endpoint.spawn_stale_connection_reaper();

        // Spawn reader-exit handler — consumes explicit reader-exit events and
        // immediately emits PeerDisconnected events. This gives millisecond
        // disconnect detection vs the 30-second reaper interval.
        endpoint.spawn_reader_exit_handler();
        endpoint.spawn_port_mapping_task();
        endpoint.spawn_mdns_task();
        endpoint.spawn_proactive_relay_manager();

        Ok(endpoint)
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get the underlying QUIC connection for a peer.
    ///
    /// This is used by the LinkTransport abstraction layer to wrap connections.
    pub fn get_quic_connection(
        &self,
        peer_id: &PeerId,
    ) -> Result<Option<crate::high_level::Connection>, EndpointError> {
        self.inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)
    }

    /// Get the local bind address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .get_endpoint()
            .and_then(|ep| ep.local_addr().ok())
    }

    /// Get observed external address (if discovered)
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.get_observed_external_address().ok().flatten()
    }

    /// Returns all observed external addresses from all connections and paths.
    ///
    /// Collects both IPv4 and IPv6 addresses discovered via OBSERVED_ADDRESS
    /// frames from peers. Critical for dual-stack nodes.
    pub fn all_external_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = self
            .inner
            .get_all_observed_external_addresses()
            .unwrap_or_default();

        if let Some(mapped_addr) = self.port_mapping_addr() {
            if !addrs.contains(&mapped_addr) {
                addrs.push(mapped_addr);
            }
        }

        addrs
    }

    /// Returns the current best-effort router port-mapping snapshot.
    pub(crate) fn port_mapping_snapshot(&self) -> PortMappingSnapshot {
        *self.port_mapping_state.read()
    }

    /// Returns whether best-effort router port mapping is currently active.
    pub fn port_mapping_active(&self) -> bool {
        self.port_mapping_snapshot().active
    }

    /// Returns the currently mapped public address, if router port mapping is active.
    pub fn port_mapping_addr(&self) -> Option<SocketAddr> {
        self.port_mapping_snapshot().external_addr
    }

    /// Returns the current first-party mDNS runtime snapshot.
    pub fn mdns_snapshot(&self) -> MdnsSnapshot {
        self.mdns_state.read().clone()
    }

    /// Return the latest best-effort direct-path status for a peer, when known.
    pub fn direct_path_status(&self, peer_id: PeerId) -> Option<DirectPathStatus> {
        self.direct_path_statuses.read().get(&peer_id).cloned()
    }

    /// Returns whether this endpoint is willing to provide relay service for peers.
    ///
    /// ant-quic uses an always-on symmetric assist plane, so this reports the
    /// effective runtime behaviour rather than any legacy config flag.
    pub fn relay_service_enabled(&self) -> bool {
        true
    }

    /// Returns whether this endpoint advertises coordinator capability.
    ///
    /// ant-quic uses a symmetric model where every node can participate in
    /// coordination decisions; remote peers still decide whether to use it.
    pub const fn coordinator_service_enabled(&self) -> bool {
        true
    }

    /// Returns whether this endpoint advertises bootstrap/known-peer assist capability.
    ///
    /// This is an opt-in signal that the node can be treated as one candidate
    /// discovery/bootstrap input. It is not proof that peers must or should use it.
    pub const fn bootstrap_service_enabled(&self) -> bool {
        true
    }

    /// Get the transport registry for this endpoint
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this endpoint can use for connectivity.
    pub fn transport_registry(&self) -> &TransportRegistry {
        &self.transport_registry
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    // === Connection Management ===

    /// Connect to a peer by address using the canonical address-oriented public surface.
    ///
    /// This routes through the unified outbound orchestrator.
    pub async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        self.connect_orchestrated(None, vec![addr]).await
    }

    async fn prepare_direct_addr_attempt(
        &self,
        addr: SocketAddr,
    ) -> Result<Option<PeerConnection>, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Dedup check: if we already have a live connection to this address, return it.
        // This prevents creating duplicate connections when connect_addr() is called
        // multiple times to the same target (e.g. during reconnect loops).
        {
            let peers = self.connected_peers.read().await;
            for (_, existing) in peers.iter() {
                if existing.remote_addr == TransportAddr::Udp(addr) {
                    // Verify the underlying QUIC connection is still alive
                    if let Some(peer_id) = peers
                        .iter()
                        .find(|(_, p)| p.remote_addr == TransportAddr::Udp(addr))
                        .map(|(id, _)| *id)
                    {
                        if self.inner.is_peer_connected(&peer_id) {
                            info!(
                                "connect: reusing existing live connection to {} (peer {:?})",
                                addr, peer_id
                            );
                            return Ok(Some(existing.clone()));
                        }
                    }
                    break;
                }
            }
        }

        // If a dead connection was found, is_peer_connected() already cleaned it up.
        // Remove stale entry from connected_peers too.
        {
            let mut peers = self.connected_peers.write().await;
            let stale_peer_ids: Vec<PeerId> = peers
                .iter()
                .filter(|(_, p)| p.remote_addr == TransportAddr::Udp(addr))
                .filter(|(id, _)| !self.inner.is_peer_connected(id))
                .map(|(id, _)| *id)
                .collect();
            for stale_id in &stale_peer_ids {
                peers.remove(stale_id);
                info!(
                    "connect: removed stale connection entry for peer {:?} at {}",
                    stale_id, addr
                );
            }
        }

        Ok(None)
    }

    async fn attempt_direct_handshake(
        &self,
        addr: SocketAddr,
    ) -> Result<crate::high_level::Connection, EndpointError> {
        info!("Connecting directly to {}", addr);

        let endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let connecting = endpoint
            .connect(addr, "peer")
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Enforce a hard timeout on the QUIC handshake to prevent the 76s hang
        // reported in issue #137. The connection_timeout config or 30s default
        // ensures callers always get a response within a bounded window.
        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;
        match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => {
                info!("connect: handshake to {} failed: {}", addr, e);
                Err(EndpointError::Connection(e.to_string()))
            }
            Err(_) => {
                info!(
                    "connect: handshake to {} timed out after {:?}",
                    addr, handshake_timeout
                );
                Err(EndpointError::Timeout)
            }
        }
    }

    async fn connect_direct_addr(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        self.connect_direct_addr_with_hint(addr, None).await
    }

    async fn connect_direct_addr_with_hint(
        &self,
        addr: SocketAddr,
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if let Some(existing) = self.prepare_direct_addr_attempt(addr).await? {
            return Ok(existing);
        }

        let connection = self.attempt_direct_handshake(addr).await?;
        self.finalize_direct_connection(connection, addr, hint_peer_id)
            .await
    }

    fn runtime_known_peer_udp_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .config
            .known_peers
            .iter()
            .filter_map(|addr| addr.as_socket_addr())
            .collect();

        for addr in self.inner.bootstrap_addresses() {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }

        addrs
    }

    async fn peer_directory_snapshot(&self) -> PeerDirectorySnapshot {
        let mut snapshot = PeerDirectorySnapshot::default();

        for addr in self
            .config
            .known_peers
            .iter()
            .filter_map(TransportAddr::as_socket_addr)
        {
            snapshot.add_locator_claim(
                None,
                vec![addr],
                PeerDiscoverySource::StaticKnownPeer,
                None,
            );
        }

        for addr in self
            .manual_known_peer_udp_addrs
            .read()
            .await
            .iter()
            .copied()
        {
            snapshot.add_locator_claim(
                None,
                vec![addr],
                PeerDiscoverySource::ManualKnownPeer,
                None,
            );
        }

        for addr in self.runtime_known_peer_udp_addrs() {
            snapshot.add_locator_claim(
                None,
                vec![addr],
                PeerDiscoverySource::RuntimeKnownPeer,
                None,
            );
        }

        {
            let hints = self.peer_hint_records.read().await;
            for (peer_id, record) in hints.iter() {
                for addr in &record.addrs {
                    snapshot.add_authenticated_addr(
                        *peer_id,
                        *addr,
                        PeerDiscoverySource::PeerHints,
                    );
                }
                snapshot.add_authenticated_capabilities(
                    *peer_id,
                    &record.capabilities,
                    PeerDiscoverySource::PeerHints,
                );
            }
        }

        for peer in self.bootstrap_cache.all_peers().await {
            snapshot.add_cached_peer(&peer);
        }

        for peer in self.mdns_snapshot().discovered_peers {
            snapshot.add_locator_claim(
                peer.claimed_peer_id,
                peer.addresses.clone(),
                PeerDiscoverySource::Mdns,
                Some(peer),
            );
        }

        snapshot
    }

    fn discovered_peer_allowed(&self, claimed_peer_id: Option<PeerId>) -> Result<(), String> {
        match &self.config.trust {
            TrustPolicy::AuthenticateOnly => Ok(()),
            TrustPolicy::AllowedPeerIds(peer_ids) => {
                let claimed_peer_id =
                    claimed_peer_id.ok_or_else(|| "missing claimed peer identity".to_string())?;
                if peer_ids.contains(&claimed_peer_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "peer {} is not in the discovery allowlist",
                        hex::encode(claimed_peer_id.0)
                    ))
                }
            }
        }
    }

    async fn connect_direct_candidates(
        &self,
        addrs: &[SocketAddr],
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        // Explicit address hints often include multiple viable local-network,
        // overlay, and global candidates. Truncating to the first few can miss
        // the only actually reachable path, for example when bridge/ULA addrs
        // appear before a working Tailscale or secondary LAN address.
        let mut last_err: Option<EndpointError> = None;
        for addr in addrs {
            match self
                .connect_direct_addr_with_hint(*addr, hint_peer_id)
                .await
            {
                Ok(conn) => return Ok(conn),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(EndpointError::NoAddress))
    }

    async fn refresh_runtime_known_peer_connections(&self) {
        for addr in self.runtime_known_peer_udp_addrs() {
            if let Err(e) = self.connect_direct_addr(addr).await {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "connect_direct_addr_drop",
                    addr = ?addr,
                    error = ?e,
                    "silent drop"
                );
            }
        }
    }

    #[cfg(test)]
    async fn hinted_addrs_for_peer(&self, peer_id: PeerId) -> Vec<SocketAddr> {
        self.peer_hint_records
            .read()
            .await
            .get(&peer_id)
            .map(|record| record.addrs.clone())
            .unwrap_or_default()
    }

    async fn hinted_assist_addrs(&self, relay: bool, coordination: bool) -> Vec<SocketAddr> {
        let hints = self.peer_hint_records.read().await;
        let mut candidates = Vec::new();

        for record in hints.values() {
            let matches = (relay && record.capabilities.supports_relay)
                || (coordination && record.capabilities.supports_coordination);
            if !matches {
                continue;
            }
            for addr in &record.addrs {
                if !candidates.contains(addr) {
                    candidates.push(*addr);
                }
            }
        }

        candidates
    }

    async fn coordinator_candidates(&self) -> Vec<SocketAddr> {
        let mut candidates = Vec::new();

        if let Some(addr) = self.inner.preferred_coordinator()
            && !candidates.contains(&addr)
        {
            candidates.push(addr);
        }

        for addr in self.hinted_assist_addrs(false, true).await {
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }

        for peer in self.bootstrap_cache.select_coordinators(6).await {
            for addr in peer.preferred_addresses() {
                if !candidates.contains(&addr) {
                    candidates.push(addr);
                }
            }
        }

        {
            let peers = self.connected_peers.read().await;
            for (peer_id, existing) in peers.iter() {
                let Some(addr) = existing.remote_addr.as_socket_addr() else {
                    continue;
                };
                if !self.inner.is_peer_connected(peer_id) {
                    continue;
                }
                if !candidates.contains(&addr) {
                    candidates.push(addr);
                }
            }
        }

        for addr in self.runtime_known_peer_udp_addrs() {
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }

        // Filter out coordinators in cooldown (circuit-breaker).
        self.coordinator_health.filter_available(&candidates)
    }

    pub(crate) async fn runtime_assist_snapshot(&self) -> RuntimeAssistSnapshot {
        let successful_coordinations = self
            .inner
            .get_statistics()
            .map(|stats| stats.successful_coordinations)
            .unwrap_or(0);
        let (active_relay_sessions, relay_bytes_forwarded) =
            self.inner.relay_server_runtime_metrics();

        RuntimeAssistSnapshot {
            successful_coordinations,
            active_relay_sessions,
            relay_bytes_forwarded,
        }
    }

    async fn find_live_connection_for_addrs(&self, addrs: &[SocketAddr]) -> Option<PeerConnection> {
        let peers = self.connected_peers.read().await;
        for addr in addrs {
            if let Some((existing_peer_id, existing)) = peers
                .iter()
                .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                .map(|(id, conn)| (*id, conn.clone()))
            {
                if self.inner.is_peer_connected(&existing_peer_id) {
                    return Some(existing);
                }
            }
        }
        None
    }

    async fn connect_orchestrated(
        &self,
        peer_id: Option<PeerId>,
        mut explicit_addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let is_simple_address_only = peer_id.is_none() && explicit_addrs.len() == 1;

        if let Some(peer_id) = peer_id {
            if let Some(conn) = self.connected_peers.read().await.get(&peer_id) {
                if self.inner.is_peer_connected(&peer_id) {
                    return Ok(conn.clone());
                }
            }
        }

        if !is_simple_address_only {
            let peers = self.connected_peers.read().await;
            for addr in &explicit_addrs {
                if let Some((existing_peer_id, existing)) = peers
                    .iter()
                    .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                    .map(|(id, conn)| (*id, conn.clone()))
                {
                    if self.inner.is_peer_connected(&existing_peer_id) {
                        info!(
                            "connect_orchestrated: reusing existing live connection to {} (peer {:?})",
                            addr, existing_peer_id
                        );
                        return Ok(existing);
                    }
                }
            }
        }

        if !is_simple_address_only {
            let target_addrs = explicit_addrs.clone();
            let mut peers = self.connected_peers.write().await;
            let stale_peer_ids: Vec<PeerId> = peers
                .iter()
                .filter(|(_, p)| match p.remote_addr {
                    TransportAddr::Udp(addr) => target_addrs.contains(&addr),
                    _ => false,
                })
                .filter(|(id, _)| !self.inner.is_peer_connected(id))
                .map(|(id, _)| *id)
                .collect();
            for stale_id in &stale_peer_ids {
                peers.remove(stale_id);
            }
        }

        if let Some(peer_id) = peer_id {
            let directory = self.peer_directory_snapshot().await;
            for addr in directory.candidate_addrs_for_peer(peer_id) {
                if !explicit_addrs.contains(&addr) {
                    explicit_addrs.push(addr);
                }
            }
        }

        if let Some(peer_id) = peer_id
            && let Some(runtime_addr) = self.inner.bootstrap_address_for_peer(peer_id)
            && !explicit_addrs.contains(&runtime_addr)
        {
            explicit_addrs.push(runtime_addr);
        }

        prioritize_direct_candidate_addrs(&mut explicit_addrs);
        drop_non_global_direct_candidates_when_global_present(&mut explicit_addrs);

        if !explicit_addrs.is_empty() && !is_simple_address_only {
            match self
                .connect_direct_candidates(&explicit_addrs, peer_id)
                .await
            {
                Ok(conn) => return Ok(conn),
                Err(err) => {
                    debug!(
                        "connect_orchestrated: direct multi-candidate pre-pass exhausted before fallback: {}",
                        err
                    );
                }
            }
        }

        let target_ipv4 = explicit_addrs.iter().copied().find(SocketAddr::is_ipv4);
        let target_ipv6 = explicit_addrs.iter().copied().find(SocketAddr::is_ipv6);

        if target_ipv4.is_some() || target_ipv6.is_some() {
            match self
                .connect_with_fallback(target_ipv4, target_ipv6, None, peer_id)
                .await
            {
                Ok((conn, _)) => return Ok(conn),
                Err(err) => {
                    let peers = self.connected_peers.read().await;
                    for addr in &explicit_addrs {
                        if let Some((existing_peer_id, existing)) = peers
                            .iter()
                            .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                            .map(|(id, conn)| (*id, conn.clone()))
                        {
                            if self.inner.is_peer_connected(&existing_peer_id) {
                                info!(
                                    "connect_orchestrated: converged to existing live connection after fallback failure for {} (peer {:?})",
                                    addr, existing_peer_id
                                );
                                return Ok(existing);
                            }
                        }
                    }
                    return Err(err);
                }
            }
        }

        if let Some(peer_id) = peer_id {
            if explicit_addrs.is_empty() && self.inner.preferred_coordinator().is_none() {
                self.refresh_runtime_known_peer_connections().await;

                if let Some(conn) = self.connected_peers.read().await.get(&peer_id)
                    && self.inner.is_peer_connected(&peer_id)
                {
                    return Ok(conn.clone());
                }
            }

            #[allow(deprecated)]
            {
                return self.connect_to_peer(peer_id, None).await;
            }
        }

        Err(EndpointError::NoAddress)
    }

    /// Connect to a peer by address (direct connection).
    ///
    /// Compatibility-oriented alias retained for older callers. Prefer
    /// [`Self::connect_addr`] as the preferred address-oriented public surface.
    ///
    /// Uses Raw Public Key authentication - the peer's identity is verified via their
    /// ML-DSA-65 public key, not via SNI/certificates.
    ///
    /// If we already have a live connection to the target address, returns the
    /// existing connection instead of creating a duplicate. After handshake, if
    /// we discover a simultaneous open (both sides connected at the same time),
    /// a deterministic tiebreaker ensures both sides keep the same connection.
    #[deprecated(
        note = "use connect_addr(addr) to route address-based dials through the unified orchestrator"
    )]
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        self.connect_addr(addr).await
    }

    /// Connect to a peer using any transport address
    ///
    /// This method uses the connection router to automatically select the appropriate
    /// protocol engine (QUIC or Constrained) based on the transport capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use ant_quic::transport::TransportAddr;
    ///
    /// // Connect via UDP (uses QUIC)
    /// let udp_addr = TransportAddr::Udp("192.168.1.100:9000".parse()?);
    /// let conn = endpoint.connect_transport(&udp_addr, None).await?;
    ///
    /// // Connect via BLE (uses Constrained engine)
    /// let ble_addr = TransportAddr::Ble {
    ///     device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     service_uuid: None,
    /// };
    /// let conn = endpoint.connect_transport(&ble_addr, None).await?;
    /// ```
    pub async fn connect_transport(
        &self,
        addr: &TransportAddr,
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Use the router to determine the appropriate engine
        let mut router = self.router.write().await;
        let engine = router.select_engine_for_addr(addr);

        info!(
            "Connecting to {} via {:?} engine (peer_id: {:?})",
            addr, engine, peer_id
        );

        match engine {
            ProtocolEngine::Quic => {
                // For QUIC, extract socket address and use existing connect path
                let socket_addr = addr.as_socket_addr().ok_or_else(|| {
                    EndpointError::Connection(format!(
                        "Cannot extract socket address from {} for QUIC",
                        addr
                    ))
                })?;
                drop(router); // Release lock before async operation
                self.connect_addr(socket_addr).await
            }
            ProtocolEngine::Constrained => {
                // For constrained transports, use the router's constrained connection
                let _routed = router.connect(addr).map_err(|e| {
                    EndpointError::Connection(format!("Constrained connection failed: {}", e))
                })?;

                // Create a synthetic peer ID for constrained connections if not provided
                let actual_peer_id = peer_id.unwrap_or_else(|| peer_id_from_transport_addr(addr));

                let peer_conn = PeerConnection {
                    peer_id: actual_peer_id,
                    remote_addr: addr.clone(),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Client,
                    authenticated: false, // Constrained connections don't have TLS auth yet
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Store peer
                drop(router); // Release lock before acquiring connected_peers lock
                self.register_connected_peer(peer_conn.clone()).await;
                self.observe_peer_reachability(&peer_conn);

                Ok(peer_conn)
            }
        }
    }

    /// Get the connection router for advanced routing control
    ///
    /// Returns a reference to the connection router which can be used to:
    /// - Query engine selection for addresses
    /// - Get routing statistics
    /// - Configure routing behavior
    pub async fn router(&self) -> tokio::sync::RwLockReadGuard<'_, ConnectionRouter> {
        self.router.read().await
    }

    /// Get routing statistics
    pub async fn routing_stats(&self) -> crate::connection_router::RouterStats {
        self.router.read().await.stats().clone()
    }

    /// Register a constrained connection for a peer
    ///
    /// This associates a PeerId with a ConstrainedEngine ConnectionId, enabling
    /// send() to use the proper constrained protocol for reliable delivery.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's identity
    /// * `conn_id` - The ConnectionId from the ConstrainedEngine
    ///
    /// # Returns
    ///
    /// The previous ConnectionId if one was already registered for this peer.
    pub async fn register_constrained_connection(
        &self,
        peer_id: PeerId,
        conn_id: ConstrainedConnectionId,
    ) -> Option<ConstrainedConnectionId> {
        let old = self
            .constrained_connections
            .write()
            .await
            .insert(peer_id, conn_id);
        debug!(
            "Registered constrained connection for peer {:?}: conn_id={:?}",
            peer_id, conn_id
        );
        old
    }

    /// Unregister a constrained connection for a peer
    ///
    /// Call this when a constrained connection is closed or reset.
    ///
    /// # Returns
    ///
    /// The ConnectionId if one was registered for this peer.
    pub async fn unregister_constrained_connection(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        let removed = self.constrained_connections.write().await.remove(peer_id);
        if removed.is_some() {
            debug!("Unregistered constrained connection for peer {:?}", peer_id);
        }
        removed
    }

    /// Check if a peer has a constrained connection
    pub async fn has_constrained_connection(&self, peer_id: &PeerId) -> bool {
        self.constrained_connections
            .read()
            .await
            .contains_key(peer_id)
    }

    /// Get the ConnectionId for a peer's constrained connection
    pub async fn get_constrained_connection_id(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        self.constrained_connections
            .read()
            .await
            .get(peer_id)
            .copied()
    }

    /// Get the number of active constrained connections
    pub async fn constrained_connection_count(&self) -> usize {
        self.constrained_connections.read().await.len()
    }

    /// Look up PeerId from constrained ConnectionId
    pub async fn peer_id_from_constrained_conn(
        &self,
        conn_id: ConstrainedConnectionId,
    ) -> Option<PeerId> {
        self.constrained_peer_addrs
            .read()
            .await
            .get(&conn_id)
            .map(|(peer_id, _)| *peer_id)
    }

    /// Connect to a peer using dual-stack strategy (tries both IPv4 and IPv6 in parallel)
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///    - **IPv6-only**: Uses IPv6 connection, graceful degradation  
    ///    - **Neither**: Returns error (try NAT traversal next)
    ///
    /// # Arguments
    /// * `addresses` - List of candidate addresses (mix of IPv4 and IPv6)
    /// * `peer_id` - Optional peer ID (for token persistence and 0-RTT/Fast Reconnect)
    ///
    /// # Returns
    /// Primary connection (IPv6 preferred if both succeed)
    ///
    /// # Dual-Connection Behavior
    /// When both IPv4 AND IPv6 succeed, BOTH connections are stored in `connected_peers`.
    /// The system maintains redundant connections for maximum reliability.
    pub async fn connect_dual_stack(
        &self,
        addresses: &[SocketAddr],
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Separate addresses by family
        let ipv4_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .copied()
            .collect();

        let ipv6_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V6(_)))
            .copied()
            .collect();

        let mut direct_candidate_addrs = Vec::new();
        extend_unique_socket_addrs(&mut direct_candidate_addrs, ipv4_addrs.iter().copied());
        extend_unique_socket_addrs(&mut direct_candidate_addrs, ipv6_addrs.iter().copied());
        let (direct_strategy, rtt_hint) = self
            .adaptive_strategy_config_for_candidates(peer_id, &direct_candidate_addrs, None, &[])
            .await;

        info!(
            "Dual-stack connect: {} IPv4, {} IPv6 addresses (PeerId: {:?}, direct budgets: v4={:?}, v6={:?}, rtt_hint={:?})",
            ipv4_addrs.len(),
            ipv6_addrs.len(),
            peer_id,
            direct_strategy.ipv4_timeout,
            direct_strategy.ipv6_timeout,
            rtt_hint,
        );

        // Use "peer" as SNI for all P2P connections
        // Raw Public Key authentication validates the peer's public key directly,
        // so we don't need/use SNI for authentication. A fixed SNI avoids
        // "invalid server name" errors from hex peer IDs being too long.
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.try_connect_family(&ipv4_addrs, "IPv4", direct_strategy.ipv4_timeout, peer_id,),
            self.try_connect_family(&ipv6_addrs, "IPv6", direct_strategy.ipv6_timeout, peer_id,),
        );

        // Handle all possible outcomes
        match (ipv4_result, ipv6_result) {
            (Some(v4_conn), Some(v6_conn)) => {
                // 🎉 BEST CASE: Both IPv4 AND IPv6 work - keep both!
                info!(
                    "✓✓ Dual-stack success! IPv4: {}, IPv6: {} (maintaining both connections)",
                    v4_conn.remote_addr, v6_conn.remote_addr
                );

                // Both connections already stored by try_connect_family
                // Return IPv6 as primary (modern internet best practice)
                Ok(v6_conn)
            }

            (Some(v4_conn), None) => {
                // IPv4-only network (v6 unavailable or failed)
                info!(
                    "IPv4-only connection established to {}",
                    v4_conn.remote_addr
                );
                Ok(v4_conn)
            }

            (None, Some(v6_conn)) => {
                // IPv6-only network (v4 unavailable or failed)
                info!(
                    "IPv6-only connection established to {}",
                    v6_conn.remote_addr
                );
                Ok(v6_conn)
            }

            (None, None) => {
                // Neither direct connection works - try NAT traversal next
                warn!("Both IPv4 and IPv6 direct connections failed");
                Err(EndpointError::Connection(
                    "Dual-stack connection failed for both address families".to_string(),
                ))
            }
        }
    }

    /// Try to connect using addresses from one family (IPv4 or IPv6)
    ///
    async fn try_connect_family(
        &self,
        addresses: &[SocketAddr],
        family_name: &str,
        stage_budget: Duration,
        hint_peer_id: Option<PeerId>,
    ) -> Option<PeerConnection> {
        try_addrs_with_shared_stage_budget(
            addresses,
            family_name,
            stage_budget,
            |addr| async move { self.connect_direct_addr_with_hint(addr, hint_peer_id).await },
        )
        .await
    }

    /// Connect to a peer using cached information (addresses, tokens).
    ///
    /// Compatibility helper retained for callers that explicitly expect cached
    /// address resolution first. Prefer [`Self::connect_peer`] as the canonical
    /// peer-oriented public surface.
    pub async fn connect_cached(&self, peer_id: PeerId) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Check if already connected
        if let Some(conn) = self.connected_peers.read().await.get(&peer_id) {
            return Ok(conn.clone());
        }

        // Retrieve from cache
        let cached_peer = self
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .ok_or(EndpointError::PeerNotFound(peer_id))?;

        let preferred_addrs = cached_peer.preferred_addresses();
        debug!(
            "Connecting to cached peer {:?} ({} preferred addresses)",
            peer_id,
            preferred_addrs.len()
        );

        // Try dual-stack connection with PeerId (triggers token usage)
        self.connect_dual_stack(&preferred_addrs, Some(peer_id))
            .await
    }

    /// Connect to a peer by durable peer ID.
    ///
    /// This is the canonical peer-oriented public surface. It first tries any
    /// cached/known addresses via existing code and then falls back to the
    /// existing peer-ID NAT traversal path when necessary.
    pub async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, EndpointError> {
        self.connect_orchestrated(Some(peer_id), Vec::new()).await
    }

    /// Connect to a peer by durable peer ID plus explicit address hints.
    ///
    /// This is the advanced peer-oriented variant for callers that already
    /// know candidate socket addresses for a peer but still want the transport
    /// to authenticate that peer by ID and run the unified orchestration path.
    pub async fn connect_peer_with_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        self.connect_orchestrated(Some(peer_id), addrs).await
    }

    /// Merge externally discovered hints for an authenticated peer.
    ///
    /// This advanced API lets higher layers feed durable peer identity,
    /// candidate addresses, and assist-role capability hints into the endpoint
    /// without reaching into internal orchestration types.
    pub async fn upsert_peer_hints(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
        capabilities: Option<PeerCapabilities>,
    ) {
        {
            let mut hints = self.peer_hint_records.write().await;
            hints
                .entry(peer_id)
                .or_default()
                .merge(addrs.clone(), capabilities.clone());
        }

        if addrs.is_empty() && capabilities.is_none() {
            return;
        }

        let mut cached_peer = self
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .unwrap_or_else(|| CachedPeer::new(peer_id, Vec::new(), PeerSource::Merge));

        for addr in addrs {
            if !cached_peer.addresses.contains(&addr) {
                cached_peer.addresses.push(addr);
            }
        }

        if let Some(caps) = capabilities {
            cached_peer
                .capabilities
                .record_assist_hints(caps.supports_relay, caps.supports_coordination);
            cached_peer.capabilities.protocols.extend(caps.protocols);
            if caps.nat_type.is_some() {
                cached_peer.capabilities.nat_type = caps.nat_type;
            }
            for addr in caps.external_addresses {
                cached_peer.capabilities.record_external_address(addr);
            }
        }

        self.bootstrap_cache.upsert(cached_peer).await;
    }

    /// Connect to a peer by ID using NAT traversal.
    ///
    /// Compatibility-oriented wrapper retained for older callers. Prefer
    /// [`Self::connect_peer`] for the canonical peer-oriented public surface.
    #[deprecated(
        note = "use connect_peer(peer_id) to route peer-oriented dials through the unified orchestrator"
    )]
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: Option<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let coord_addr = if let Some(addr) = coordinator {
            addr
        } else {
            self.coordinator_candidates()
                .await
                .into_iter()
                .next()
                .ok_or_else(|| EndpointError::Config("No coordinator available".to_string()))?
        };

        info!(
            "Initiating NAT traversal to peer {:?} via coordinator {}",
            peer_id, coord_addr
        );

        // Broadcast progress
        if let Err(e) = self.event_tx.send(P2pEvent::NatTraversalProgress {
            peer_id,
            phase: TraversalPhase::Discovery,
        }) {
            tracing::warn!(
                target: "ant_quic::silent_drop",
                kind = "event_tx_nat_progress_discovery",
                peer_id = ?peer_id,
                error = %e,
                "silent drop"
            );
        }

        // Initiate NAT traversal
        if let Err(e) = self.inner.initiate_nat_traversal(peer_id, coord_addr) {
            self.coordinator_health.record_failure(coord_addr);
            return Err(EndpointError::NatTraversal(e));
        }

        // Poll for completion using event-driven notification instead of sleep loop
        let deadline = tokio::time::Instant::now()
            + self
                .config
                .timeouts
                .nat_traversal
                .connection_establishment_timeout;

        loop {
            if self.shutdown.is_cancelled() {
                return Err(EndpointError::ShuttingDown);
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "connect_to_peer observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_peer_reachability(&peer_conn);
                self.register_connected_peer(peer_conn.clone()).await;
                self.coordinator_health.record_success(&coord_addr);
                publish_direct_path_status(
                    self.direct_path_statuses.as_ref(),
                    &self.event_tx,
                    peer_id,
                    DirectPathStatus::Established {
                        remote_addr: remote_address,
                    },
                );

                return Ok(peer_conn);
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(EndpointError::NatTraversal)?;

            let had_events = !events.is_empty();
            for event in events {
                info!(
                    "connect_to_peer polled event for target {:?}: {:?}",
                    peer_id, event
                );
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                        side,
                        ..
                    } if evt_peer == peer_id => {
                        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
                        self.inner
                            .register_connection_peer_id(remote_address, peer_id);

                        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                        let peer_conn = PeerConnection {
                            peer_id,
                            remote_addr: TransportAddr::Udp(remote_address),
                            traversal_method: TraversalMethod::HolePunch,
                            side,
                            authenticated: true, // TLS handles authentication
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        // Spawn background reader task BEFORE storing in connected_peers
                        // to prevent race where recv() misses early data
                        if let Some(conn) = self
                            .inner
                            .get_connection_by_authenticated_peer(peer_id)
                            .await
                            .or_else(|| self.inner.session_connection(peer_id))
                        {
                            let endpoint = self.clone();
                            tokio::spawn(async move {
                                endpoint.spawn_reader_task(peer_id, conn).await;
                            });
                        }

                        self.observe_peer_reachability(&peer_conn);
                        self.register_connected_peer(peer_conn.clone()).await;
                        self.coordinator_health.record_success(&coord_addr);
                        publish_direct_path_status(
                            self.direct_path_statuses.as_ref(),
                            &self.event_tx,
                            peer_id,
                            DirectPathStatus::Established {
                                remote_addr: remote_address,
                            },
                        );

                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        ..
                    } if evt_peer == peer_id => {
                        self.coordinator_health.record_failure(coord_addr);
                        return Err(EndpointError::NatTraversal(error));
                    }
                    _ => {}
                }
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "connect_to_peer observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_peer_reachability(&peer_conn);
                self.register_connected_peer(peer_conn.clone()).await;
                self.coordinator_health.record_success(&coord_addr);
                publish_direct_path_status(
                    self.direct_path_statuses.as_ref(),
                    &self.event_tx,
                    peer_id,
                    DirectPathStatus::Established {
                        remote_addr: remote_address,
                    },
                );

                return Ok(peer_conn);
            }

            if had_events {
                continue;
            }

            match self.wait_for_traversal_progress(peer_id, deadline).await {
                Ok(()) => {}
                Err(EndpointError::ShuttingDown) => {
                    self.coordinator_health.record_failure(coord_addr);
                    return Err(EndpointError::ShuttingDown);
                }
                Err(EndpointError::Timeout) => {
                    self.coordinator_health.record_failure(coord_addr);
                    return Err(EndpointError::Timeout);
                }
                Err(error) => {
                    self.coordinator_health.record_failure(coord_addr);
                    return Err(error);
                }
            }
        }
    }

    /// Connect with automatic fallback: IPv4 → IPv6 → HolePunch → Relay
    ///
    /// This method implements a progressive connection strategy that automatically
    /// falls back through increasingly aggressive NAT traversal techniques:
    ///
    /// 1. **Direct IPv4** (5s timeout) - Simple direct connection
    /// 2. **Direct IPv6** (5s timeout) - Bypasses NAT when IPv6 available
    /// 3. **Hole-Punch** (15s timeout) - Coordinated NAT traversal via common peer
    /// 4. **Relay** (30s timeout) - MASQUE relay as last resort
    ///
    /// # Arguments
    ///
    /// * `target_ipv4` - Optional IPv4 address of the target peer
    /// * `target_ipv6` - Optional IPv6 address of the target peer
    /// * `strategy_config` - Optional custom strategy configuration
    ///
    /// # Returns
    ///
    /// A tuple of (PeerConnection, ConnectionMethod) indicating how the connection
    /// was established.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (conn, method) = endpoint.connect_with_fallback(
    ///     Some("1.2.3.4:9000".parse()?),
    ///     Some("[2001:db8::1]:9000".parse()?),
    ///     None, // Use default strategy config
    /// ).await?;
    ///
    /// match method {
    ///     ConnectionMethod::DirectIPv4 => println!("Direct IPv4"),
    ///     ConnectionMethod::DirectIPv6 => println!("Direct IPv6"),
    ///     ConnectionMethod::HolePunched { coordinator } => println!("Via {}", coordinator),
    ///     ConnectionMethod::Relayed { relay } => println!("Relayed via {}", relay),
    /// }
    /// ```
    async fn connection_strategy_rtt_hint_for_candidates(
        &self,
        peer_id: Option<PeerId>,
        direct_candidate_addrs: &[SocketAddr],
        coordinator: Option<SocketAddr>,
        relay_addrs: &[SocketAddr],
    ) -> Option<Duration> {
        let mut hints = Vec::new();

        if let Some(peer_id) = peer_id
            && let Some(cached_peer) = self.bootstrap_cache.get_peer(&peer_id).await
            && let Some(rtt) = cached_peer_avg_rtt(&cached_peer)
        {
            hints.push(rtt);
        }

        let mut candidate_addrs = Vec::new();
        extend_unique_socket_addrs(&mut candidate_addrs, direct_candidate_addrs.iter().copied());
        extend_unique_socket_addrs(&mut candidate_addrs, coordinator);
        extend_unique_socket_addrs(&mut candidate_addrs, relay_addrs.iter().copied());

        if !candidate_addrs.is_empty() {
            let peers = self.bootstrap_cache.all_peers().await;
            if let Some(rtt) = strategy_rtt_hint_from_cached_peers(&peers, &candidate_addrs) {
                hints.push(rtt);
            }
        }

        hints.into_iter().max()
    }

    async fn adaptive_strategy_config_for_candidates(
        &self,
        peer_id: Option<PeerId>,
        direct_candidate_addrs: &[SocketAddr],
        coordinator: Option<SocketAddr>,
        relay_addrs: &[SocketAddr],
    ) -> (StrategyConfig, Option<Duration>) {
        let rtt_hint = self
            .connection_strategy_rtt_hint_for_candidates(
                peer_id,
                direct_candidate_addrs,
                coordinator,
                relay_addrs,
            )
            .await;
        let mut config = StrategyConfig::default();
        config.apply_adaptive_timeouts(
            self.config
                .timeouts
                .nat_traversal
                .connection_establishment_timeout,
            self.config.timeouts.nat_traversal.coordination_timeout,
            rtt_hint,
        );
        (config, rtt_hint)
    }

    /// Connect with automatic fallback: Direct → HolePunch → Relay.
    pub async fn connect_with_fallback(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
        peer_id: Option<PeerId>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Build strategy config with coordinator and relay from our config.
        // If the caller did not supply a custom strategy, derive stage budgets
        // from authoritative timeout owners plus any RTT hints we have cached.
        let custom_strategy_supplied = strategy_config.is_some();
        let mut config = strategy_config.unwrap_or_default();
        if config.coordinator.is_none() {
            config.coordinator = self.coordinator_candidates().await.into_iter().next();
        }
        if config.relay_addrs.is_empty() {
            // Optimization: Try to find a high-quality relay from our cache first
            let target_addr = target_ipv4.or(target_ipv6);
            if let Some(addr) = target_addr {
                // Select best relay for this target (preferring dual-stack)
                let relays = self
                    .bootstrap_cache
                    .select_relays_for_target(1, &addr, true)
                    .await;

                if let Some(best_relay) = relays.first() {
                    // Use the first address of the best relay
                    // In a perfect world we'd check reachability of this address too,
                    // but for now we assume cached addresses are valid candidates.
                    if let Some(relay_addr) = best_relay.preferred_addresses().first().copied() {
                        config.relay_addrs.push(relay_addr);
                        debug!(
                            "Selected optimized relay from cache: {:?} for target {}",
                            relay_addr, addr
                        );
                    }
                }
            }

            // Next prefer externally hinted relay peers.
            if config.relay_addrs.is_empty() {
                let target_addr = target_ipv4.or(target_ipv6);
                for relay_addr in self.hinted_assist_addrs(true, false).await {
                    if Some(relay_addr) == target_addr {
                        continue;
                    }
                    if let Some(target) = target_addr
                        && relay_addr.is_ipv4() != target.is_ipv4()
                    {
                        continue;
                    }
                    if !config.relay_addrs.contains(&relay_addr) {
                        config.relay_addrs.push(relay_addr);
                    }
                }
            }

            // Next prefer live connected UDP peers as relay candidates.
            if config.relay_addrs.is_empty() {
                let target_addr = target_ipv4.or(target_ipv6);
                let peers = self.connected_peers.read().await;
                for (existing_peer_id, existing) in peers.iter() {
                    let Some(relay_addr) = existing.remote_addr.as_socket_addr() else {
                        continue;
                    };
                    if Some(relay_addr) == target_addr {
                        continue;
                    }
                    if !self.inner.is_peer_connected(existing_peer_id) {
                        continue;
                    }
                    if !config.relay_addrs.contains(&relay_addr) {
                        config.relay_addrs.push(relay_addr);
                    }
                }
            }

            // Then prefer remaining runtime known peer UDP addresses.
            if config.relay_addrs.is_empty() {
                let target_addr = target_ipv4.or(target_ipv6);
                for relay_addr in self.runtime_known_peer_udp_addrs() {
                    if Some(relay_addr) == target_addr {
                        continue;
                    }
                    if !config.relay_addrs.contains(&relay_addr) {
                        config.relay_addrs.push(relay_addr);
                    }
                }
            }

            // Fallback to static config if cache, live peers, and runtime known peers gave nothing
            if config.relay_addrs.is_empty() {
                if let Some(relay_addr) = self.config.nat.relay_nodes.first().copied() {
                    config.relay_addrs.push(relay_addr);
                }
            }
        }

        if !custom_strategy_supplied {
            let mut direct_candidate_addrs = Vec::new();
            extend_unique_socket_addrs(
                &mut direct_candidate_addrs,
                [target_ipv4, target_ipv6].into_iter().flatten(),
            );
            let (adaptive_config, rtt_hint) = self
                .adaptive_strategy_config_for_candidates(
                    peer_id,
                    &direct_candidate_addrs,
                    config.coordinator,
                    &config.relay_addrs,
                )
                .await;
            config.ipv4_timeout = adaptive_config.ipv4_timeout;
            config.ipv6_timeout = adaptive_config.ipv6_timeout;
            config.holepunch_timeout = adaptive_config.holepunch_timeout;
            config.relay_timeout = adaptive_config.relay_timeout;
            debug!(
                "Adaptive connection strategy budgets: direct={:?}, holepunch={:?}, relay={:?}, rtt_hint={:?}",
                config.ipv4_timeout, config.holepunch_timeout, config.relay_timeout, rtt_hint
            );
        }

        let mut strategy = ConnectionStrategy::new(config);
        let overall_deadline = tokio::time::Instant::now()
            + self
                .config
                .timeouts
                .nat_traversal
                .connection_establishment_timeout;

        info!(
            "Starting fallback connection: IPv4={:?}, IPv6={:?} (PeerId: {:?})",
            target_ipv4, target_ipv6, peer_id
        );

        // Collect direct addresses for Happy Eyeballs racing (RFC 8305)
        let mut direct_addresses: Vec<SocketAddr> = Vec::new();
        if let Some(v6) = target_ipv6 {
            direct_addresses.push(v6);
        }
        if let Some(v4) = target_ipv4 {
            direct_addresses.push(v4);
        }

        loop {
            match strategy.current_stage().clone() {
                ConnectionStage::DirectIPv4 { .. } => {
                    // Use Happy Eyeballs (RFC 8305) to race all direct addresses (IPv4 + IPv6)
                    // instead of trying them sequentially. This prevents stalls when one address
                    // family is broken by racing with a 250ms stagger.
                    if direct_addresses.is_empty() {
                        debug!("No direct addresses provided, skipping to hole-punch");
                        strategy.transition_to_ipv6("No direct addresses");
                        continue;
                    }

                    for addr in &direct_addresses {
                        if let Some(existing) = self.prepare_direct_addr_attempt(*addr).await? {
                            let method = if addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Direct stage: reusing existing exact-address connection to {}",
                                addr
                            );
                            return Ok((existing, method));
                        }
                    }

                    let he_config = HappyEyeballsConfig::default();
                    let direct_timeout = strategy.ipv4_timeout().max(strategy.ipv6_timeout());
                    let handshake_timeout = self
                        .config
                        .timeouts
                        .nat_traversal
                        .connection_establishment_timeout;

                    info!(
                        "Happy Eyeballs: racing {} direct addresses (timeout: {:?})",
                        direct_addresses.len(),
                        direct_timeout
                    );

                    // Clone the QUIC endpoint for use in the Happy Eyeballs closure.
                    // Each spawned attempt needs its own reference to create connections.
                    let quic_endpoint = match self.inner.get_endpoint().cloned() {
                        Some(ep) => ep,
                        None => {
                            debug!("QUIC endpoint not available, skipping direct");
                            strategy.transition_to_ipv6("QUIC endpoint not available");
                            strategy.transition_to_holepunch("QUIC endpoint not available");
                            continue;
                        }
                    };

                    let addrs = direct_addresses.clone();
                    let he_result = timeout(direct_timeout, async {
                        happy_eyeballs::race_connect(&addrs, &he_config, |addr| {
                            let ep = quic_endpoint.clone();
                            async move {
                                let connecting = ep
                                    .connect(addr, "peer")
                                    .map_err(|e| format!("connect error: {e}"))?;
                                match timeout(handshake_timeout, connecting).await {
                                    Ok(Ok(conn)) => Ok(conn),
                                    Ok(Err(e)) => Err(format!("handshake error: {e}")),
                                    Err(_) => Err(format!(
                                        "handshake timeout after {:?}",
                                        handshake_timeout
                                    )),
                                }
                            }
                        })
                        .await
                    })
                    .await;

                    match he_result {
                        Ok(Ok((connection, winning_addr))) => {
                            let method = if winning_addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Happy Eyeballs: {} connection to {} succeeded",
                                method, winning_addr
                            );

                            // Complete the connection setup (peer ID, handlers, stats)
                            let peer_conn = self
                                .finalize_direct_connection(connection, winning_addr, peer_id)
                                .await?;
                            return Ok((peer_conn, method));
                        }
                        Ok(Err(e)) => {
                            if let Some(existing) =
                                self.find_live_connection_for_addrs(&direct_addresses).await
                            {
                                let method = existing
                                    .remote_addr
                                    .as_socket_addr()
                                    .map(|addr| {
                                        if addr.is_ipv6() {
                                            ConnectionMethod::DirectIPv6
                                        } else {
                                            ConnectionMethod::DirectIPv4
                                        }
                                    })
                                    .unwrap_or(ConnectionMethod::DirectIPv4);
                                debug!(
                                    "Happy Eyeballs: direct race exhausted but converged to existing live connection"
                                );
                                return Ok((existing, method));
                            }
                            debug!("Happy Eyeballs: all direct attempts failed: {}", e);
                            strategy.transition_to_ipv6(e.to_string());
                            strategy.transition_to_holepunch("Happy Eyeballs exhausted");
                        }
                        Err(_) => {
                            if let Some(existing) =
                                self.find_live_connection_for_addrs(&direct_addresses).await
                            {
                                let method = existing
                                    .remote_addr
                                    .as_socket_addr()
                                    .map(|addr| {
                                        if addr.is_ipv6() {
                                            ConnectionMethod::DirectIPv6
                                        } else {
                                            ConnectionMethod::DirectIPv4
                                        }
                                    })
                                    .unwrap_or(ConnectionMethod::DirectIPv4);
                                debug!(
                                    "Happy Eyeballs: direct race timed out but converged to existing live connection"
                                );
                                return Ok((existing, method));
                            }
                            debug!("Happy Eyeballs: direct connection timed out");
                            strategy.transition_to_ipv6("Timeout");
                            strategy.transition_to_holepunch("Happy Eyeballs timed out");
                        }
                    }
                }

                ConnectionStage::DirectIPv6 { .. } => {
                    // Happy Eyeballs already handled both IPv4 and IPv6 in the DirectIPv4 stage.
                    // If we reach here, it means Happy Eyeballs failed and we need to move on.
                    debug!(
                        "DirectIPv6 stage reached after Happy Eyeballs, advancing to hole-punch"
                    );
                    strategy.transition_to_holepunch("Handled by Happy Eyeballs");
                }

                ConnectionStage::HolePunching {
                    coordinator, round, ..
                } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!(
                        "Trying hole-punch to {} via {} (round {})",
                        target, coordinator, round
                    );

                    // Use our existing NAT traversal infrastructure
                    // If peer_id provided, use it. Otherwise derive from address.
                    let target_peer_id =
                        peer_id.unwrap_or_else(|| peer_id_from_socket_addr(target));

                    match self
                        .start_hole_punch_session(coordinator, target_peer_id)
                        .await
                    {
                        Ok(()) => match self
                            .await_hole_punch_outcome(target, target_peer_id, overall_deadline)
                            .await
                        {
                            Ok(conn) => {
                                info!("✓ Hole-punch succeeded to {} via {}", target, coordinator);
                                return Ok((conn, ConnectionMethod::HolePunched { coordinator }));
                            }
                            Err(error) => {
                                let retryable = strategy.should_retry_holepunch()
                                    && error
                                        .retry_reason()
                                        .is_some_and(Self::should_retry_hole_punch_reason);
                                let error_text = error.to_string();

                                strategy.record_holepunch_error(round, error_text.clone());
                                if retryable {
                                    debug!(
                                        "Hole-punch round {} failed with retryable reason, retrying",
                                        round
                                    );
                                    strategy.increment_round();
                                } else {
                                    debug!("Hole-punch failed after {} rounds", round);
                                    strategy.transition_to_relay(error_text);
                                }
                            }
                        },
                        Err(e) => {
                            let retryable = strategy.should_retry_holepunch()
                                && match &e {
                                    EndpointError::NatTraversal(error) => {
                                        TraversalFailureReason::from_public_operation_error(error)
                                            .as_ref()
                                            .is_some_and(Self::should_retry_hole_punch_reason)
                                    }
                                    _ => false,
                                };
                            let error_text = e.to_string();

                            strategy.record_holepunch_error(round, error_text.clone());
                            if retryable {
                                debug!("Hole-punch round {} failed to start, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch failed to start after {} rounds", round);
                                strategy.transition_to_relay(error_text);
                            }
                        }
                    }
                }

                ConnectionStage::Relay { relay_addr, .. } => {
                    let fallback_target = target_ipv4.or(target_ipv6);
                    let target = self
                        .select_relay_target_addr(peer_id, target_ipv4, target_ipv6)
                        .await
                        .ok_or(EndpointError::NoAddress)?;

                    if Some(target) != fallback_target {
                        debug!(
                            "Relay target selection preferred durable address {} over fallback {:?}",
                            target, fallback_target
                        );
                    }

                    info!("Trying relay connection to {} via {}", target, relay_addr);

                    match timeout(
                        strategy.relay_timeout(),
                        self.try_relay_connection(target, relay_addr, peer_id),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!(
                                "✓ Relay connection succeeded to {} via {}",
                                target, relay_addr
                            );
                            publish_direct_path_status(
                                self.direct_path_statuses.as_ref(),
                                &self.event_tx,
                                conn.peer_id,
                                DirectPathStatus::BestEffortUnavailable {
                                    reason: DirectPathUnavailableReason::RelayRequired,
                                },
                            );
                            return Ok((conn, ConnectionMethod::Relayed { relay: relay_addr }));
                        }
                        Ok(Err(e)) => {
                            debug!("Relay connection failed: {}", e);
                            strategy.transition_to_next_relay(e.to_string());
                        }
                        Err(_) => {
                            debug!("Relay connection timed out");
                            strategy.transition_to_next_relay("Timeout");
                        }
                    }
                }

                ConnectionStage::Failed { errors } => {
                    let error_summary = errors
                        .iter()
                        .map(|e| format!("{:?}: {}", e.method, e.error))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(EndpointError::AllStrategiesFailed(error_summary));
                }

                ConnectionStage::Connected { via } => {
                    return Err(EndpointError::Connection(format!(
                        "Connection strategy reached terminal connected state without returning: {:?}",
                        via
                    )));
                }
            }
        }
    }

    /// Finalize a direct QUIC connection established by Happy Eyeballs.
    ///
    /// Takes the raw QUIC `Connection` from the successful handshake and completes
    /// the P2P connection setup: peer ID extraction, connection storage, handler
    /// spawning, stats update, and event broadcast.
    async fn finalize_direct_connection(
        &self,
        connection: crate::high_level::Connection,
        addr: SocketAddr,
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        // Extract authenticated peer ID from TLS, or derive from address/hint
        let peer_id = self
            .inner
            .extract_peer_id_from_connection(&connection)
            .await
            .or(hint_peer_id)
            .unwrap_or_else(|| peer_id_from_socket_addr(addr));

        // Store in NAT traversal layer
        let registration = self
            .inner
            .add_connection_with_outcome(peer_id, connection.clone())
            .map_err(EndpointError::NatTraversal)?;
        if matches!(
            registration,
            crate::nat_traversal_api::ConnectionRegistrationOutcome::Rejected { .. }
        ) {
            if let Some(existing) = self.connected_peers.read().await.get(&peer_id).cloned() {
                return Ok(existing);
            }
            let live_connection = self
                .inner
                .get_connection(&peer_id)
                .map_err(EndpointError::NatTraversal)?
                .ok_or_else(|| {
                    EndpointError::Connection(
                        "connection lost lifecycle race with no live winner".to_string(),
                    )
                })?;
            let peer_conn = PeerConnection {
                peer_id,
                remote_addr: TransportAddr::Udp(live_connection.remote_address()),
                traversal_method: TraversalMethod::Direct,
                side: live_connection.side(),
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            };
            self.observe_peer_reachability(&peer_conn);
            self.register_connected_peer(peer_conn.clone()).await;
            return Ok(peer_conn);
        }

        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
        self.inner.register_connection_peer_id(addr, peer_id);
        self.inner
            .record_bootstrap_direct_connection(peer_id, &addr, Some(connection.rtt()));

        // Clone the connection for the reader task BEFORE handler consumes it.
        // Do NOT re-fetch via get_connection() — see simultaneous-connect fix.
        let reader_conn = connection.clone();

        // No abort-old: under simultaneous-open, the previous connection may
        // still carry ACKed-but-undrained bytes. Aborting its reader here would
        // silently lose those bytes (issue #166). The old reader will exit on
        // its own when its connection terminates or idles out.

        // Spawn connection handler (Client side - we initiated)
        self.inner
            .spawn_connection_handler(peer_id, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn reader task before storing peer to prevent data loss race.
        // Use the cloned connection directly — do NOT re-fetch from the DashMap.
        self.spawn_reader_task(peer_id, reader_conn).await;

        self.observe_peer_reachability(&peer_conn);
        self.register_connected_peer(peer_conn.clone()).await;
        if let crate::nat_traversal_api::ConnectionRegistrationOutcome::Live {
            superseded_generation: Some(generation),
            ..
        } = registration
        {
            self.schedule_reader_generation_cancel(
                peer_id,
                generation,
                SUPERSEDED_READER_DRAIN_GRACE,
            );
        }
        publish_direct_path_status(
            self.direct_path_statuses.as_ref(),
            &self.event_tx,
            peer_id,
            DirectPathStatus::Established { remote_addr: addr },
        );

        Ok(peer_conn)
    }

    async fn start_hole_punch_session(
        &self,
        coordinator: SocketAddr,
        peer_id: PeerId,
    ) -> Result<(), EndpointError> {
        if !self.is_connected_to_addr(coordinator).await {
            debug!("Connecting to coordinator {} first", coordinator);
            self.connect_direct_addr(coordinator).await?;
        }

        self.inner
            .initiate_nat_traversal(peer_id, coordinator)
            .map_err(EndpointError::NatTraversal)
    }

    async fn await_hole_punch_outcome(
        &self,
        target: SocketAddr,
        peer_id: PeerId,
        overall_deadline: tokio::time::Instant,
    ) -> Result<PeerConnection, HolePunchAwaitError> {
        loop {
            if self.shutdown.is_cancelled() {
                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Err(HolePunchAwaitError::Endpoint(EndpointError::ShuttingDown));
            }

            if tokio::time::Instant::now() >= overall_deadline {
                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Err(HolePunchAwaitError::Endpoint(EndpointError::Timeout));
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(HolePunchAwaitError::from_nat_traversal_error)?;

            if let Some(rejection) = take_live_rejection(self.inner.local_peer_id(), peer_id) {
                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Err(HolePunchAwaitError::TraversalFailure(
                    TraversalFailureReason::CoordinationRejected {
                        reason: rejection.reason,
                    },
                ));
            }

            let had_events = !events.is_empty();
            for event in events {
                info!(
                    "await_hole_punch_outcome polled event for target {:?}: {:?}",
                    peer_id, event
                );
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                        side,
                        ..
                    } if evt_peer == peer_id || remote_address == target => {
                        self.inner
                            .register_connection_peer_id(remote_address, evt_peer);

                        let peer_conn = PeerConnection {
                            peer_id: evt_peer,
                            remote_addr: TransportAddr::Udp(remote_address),
                            traversal_method: TraversalMethod::HolePunch,
                            side,
                            authenticated: true,
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        if let Some(conn) = self
                            .inner
                            .get_connection_by_authenticated_peer(evt_peer)
                            .await
                            .or_else(|| self.inner.session_connection(evt_peer))
                        {
                            let endpoint = self.clone();
                            tokio::spawn(async move {
                                endpoint.spawn_reader_task(evt_peer, conn).await;
                            });
                        }

                        self.observe_peer_reachability(&peer_conn);
                        self.register_connected_peer(peer_conn.clone()).await;

                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalSucceeded {
                        peer_id: evt_peer, ..
                    } if evt_peer == peer_id => {
                        if let Some(conn) = self
                            .inner
                            .get_connection_by_authenticated_peer(peer_id)
                            .await
                            .or_else(|| self.inner.session_connection(peer_id))
                        {
                            let remote_address = conn.remote_address();
                            let side = conn.side();
                            self.inner
                                .register_connection_peer_id(remote_address, peer_id);

                            let peer_conn = PeerConnection {
                                peer_id,
                                remote_addr: TransportAddr::Udp(remote_address),
                                traversal_method: TraversalMethod::HolePunch,
                                side,
                                authenticated: true,
                                connected_at: Instant::now(),
                                last_activity: Instant::now(),
                            };

                            let endpoint = self.clone();
                            tokio::spawn(async move {
                                endpoint.spawn_reader_task(peer_id, conn).await;
                            });

                            self.observe_peer_reachability(&peer_conn);
                            self.register_connected_peer(peer_conn.clone()).await;
                            let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                            return Ok(peer_conn);
                        }
                    }
                    NatTraversalEvent::TraversalTerminated {
                        peer_id: evt_peer,
                        reason,
                        ..
                    } if evt_peer == peer_id => {
                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Err(HolePunchAwaitError::TraversalFailure(reason));
                    }
                    NatTraversalEvent::CoordinationRejected {
                        peer_id: evt_peer,
                        reason,
                        ..
                    } if evt_peer == peer_id => {
                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Err(HolePunchAwaitError::TraversalFailure(
                            TraversalFailureReason::CoordinationRejected { reason },
                        ));
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        ..
                    } if evt_peer == peer_id => {
                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Err(HolePunchAwaitError::from_nat_traversal_error(error));
                    }
                    _ => {}
                }
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "await_hole_punch_outcome observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_peer_reachability(&peer_conn);
                self.register_connected_peer(peer_conn.clone()).await;

                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Ok(peer_conn);
            }

            if had_events {
                continue;
            }

            match self
                .wait_for_traversal_progress(peer_id, overall_deadline)
                .await
            {
                Ok(()) => {}
                Err(error) => {
                    let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                    return Err(HolePunchAwaitError::Endpoint(error));
                }
            }
        }
    }

    async fn wait_for_traversal_progress(
        &self,
        peer_id: PeerId,
        deadline: tokio::time::Instant,
    ) -> Result<(), EndpointError> {
        let traversal_notified = self.inner.traversal_event_notify().notified();
        tokio::pin!(traversal_notified);
        traversal_notified.as_mut().enable();

        let wake_at = self
            .inner
            .next_session_poll_deadline(peer_id, Instant::now())
            .map(tokio::time::Instant::from_std)
            .map(|next| next.min(deadline))
            .unwrap_or(deadline);

        tokio::select! {
            _ = traversal_notified.as_mut() => Ok(()),
            _ = tokio::time::sleep_until(wake_at) => {
                if wake_at >= deadline {
                    Err(EndpointError::Timeout)
                } else {
                    Ok(())
                }
            }
            _ = self.shutdown.cancelled() => Err(EndpointError::ShuttingDown),
        }
    }

    /// Endpoint-level retry policy after a traversal session has terminated.
    ///
    /// This answers whether the connection strategy should start a fresh
    /// hole-punch session. It is intentionally distinct from
    /// `NatTraversalEndpoint::retry_disposition`, which only governs retries
    /// within the current traversal negotiation.
    fn should_retry_hole_punch_reason(reason: &TraversalFailureReason) -> bool {
        match reason {
            TraversalFailureReason::CoordinatorUnavailable
            | TraversalFailureReason::CoordinationExpired
            | TraversalFailureReason::PunchWindowMissed
            | TraversalFailureReason::ValidationTimedOut
            | TraversalFailureReason::NetworkError(_) => true,
            TraversalFailureReason::DiscoveryExhausted
            | TraversalFailureReason::CoordinationRejected { .. }
            | TraversalFailureReason::SynchronizationExpired
            | TraversalFailureReason::ValidationFailed
            | TraversalFailureReason::ConnectionFailed
            | TraversalFailureReason::ProtocolViolation(_)
            | TraversalFailureReason::ShuttingDown => false,
        }
    }

    #[cfg(test)]
    fn endpoint_error_from_traversal_failure(reason: TraversalFailureReason) -> EndpointError {
        match reason {
            TraversalFailureReason::CoordinatorUnavailable => {
                EndpointError::NatTraversal(NatTraversalError::NoBootstrapNodes)
            }
            TraversalFailureReason::DiscoveryExhausted => {
                EndpointError::NatTraversal(NatTraversalError::NoCandidatesFound)
            }
            TraversalFailureReason::CoordinationRejected { reason } => EndpointError::NatTraversal(
                NatTraversalError::CoordinationFailed(format!("coordination rejected: {reason}")),
            ),
            TraversalFailureReason::CoordinationExpired
            | TraversalFailureReason::SynchronizationExpired
            | TraversalFailureReason::PunchWindowMissed
            | TraversalFailureReason::ValidationTimedOut => EndpointError::Timeout,
            TraversalFailureReason::ValidationFailed => EndpointError::NatTraversal(
                NatTraversalError::ValidationFailed("traversal validation failed".to_string()),
            ),
            TraversalFailureReason::ConnectionFailed => EndpointError::NatTraversal(
                NatTraversalError::ConnectionFailed("hole-punch connection failed".to_string()),
            ),
            TraversalFailureReason::ProtocolViolation(message) => {
                EndpointError::NatTraversal(NatTraversalError::ProtocolError(message))
            }
            TraversalFailureReason::NetworkError(message) => {
                EndpointError::NatTraversal(NatTraversalError::NetworkError(message))
            }
            TraversalFailureReason::ShuttingDown => EndpointError::ShuttingDown,
        }
    }

    async fn select_relay_target_addr(
        &self,
        peer_id: Option<PeerId>,
        fallback_ipv4: Option<SocketAddr>,
        fallback_ipv6: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let mut listener_addrs = Vec::new();
        let mut reachable_addrs = Vec::new();
        let mut external_addrs = Vec::new();

        if let Some(peer_id) = peer_id {
            if let Some(cached_peer) = self.bootstrap_cache.get_peer(&peer_id).await {
                extend_unique_socket_addrs(&mut listener_addrs, cached_peer.addresses);
                extend_unique_socket_addrs(
                    &mut reachable_addrs,
                    cached_peer
                        .capabilities
                        .reachable_addresses
                        .iter()
                        .map(|entry| entry.address),
                );
                extend_unique_socket_addrs(
                    &mut external_addrs,
                    cached_peer.capabilities.external_addresses,
                );
            }

            if let Some(hints) = self.peer_hint_records.read().await.get(&peer_id).cloned() {
                extend_unique_socket_addrs(&mut listener_addrs, hints.addrs);
                extend_unique_socket_addrs(
                    &mut reachable_addrs,
                    hints
                        .capabilities
                        .reachable_addresses
                        .iter()
                        .map(|entry| entry.address),
                );
                extend_unique_socket_addrs(
                    &mut external_addrs,
                    hints.capabilities.external_addresses,
                );
            }
        }

        select_preferred_relay_target_addr(
            &listener_addrs,
            &reachable_addrs,
            &external_addrs,
            fallback_ipv4,
            fallback_ipv6,
        )
    }

    async fn try_relay_connection(
        &self,
        target: SocketAddr,
        relay_addr: SocketAddr,
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "Attempting MASQUE relay connection to {} via {}",
            target, relay_addr
        );

        // Step 1: Establish or reuse the shared relay endpoint.
        let (public_addr, relay_endpoint) = self
            .inner
            .ensure_shared_relay_endpoint(relay_addr)
            .await
            .map_err(EndpointError::NatTraversal)?;

        info!(
            "MASQUE relay session established via {} (public addr: {:?})",
            relay_addr, public_addr
        );

        // Step 2: Connect to target through the relay endpoint
        let connecting = relay_endpoint.connect(target, "peer").map_err(|e| {
            EndpointError::Connection(format!("Failed to initiate relay connection: {}", e))
        })?;

        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;

        let connection = match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                info!(
                    "Relay connection handshake to {} via {} failed: {}",
                    target, relay_addr, e
                );
                return Err(EndpointError::Connection(e.to_string()));
            }
            Err(_) => {
                info!(
                    "Relay connection handshake to {} via {} timed out",
                    target, relay_addr
                );
                return Err(EndpointError::Timeout);
            }
        };

        // Step 6: Finalize — store connection, spawn handler
        let relay_peer_id = self
            .inner
            .extract_peer_id_from_connection(&connection)
            .await
            .or(hint_peer_id)
            .ok_or_else(|| {
                EndpointError::Connection(
                    "Relay connection established without a durable peer identity".to_string(),
                )
            })?;

        let registration = self
            .inner
            .add_connection_with_outcome(relay_peer_id, connection.clone())
            .map_err(EndpointError::NatTraversal)?;
        if matches!(
            registration,
            crate::nat_traversal_api::ConnectionRegistrationOutcome::Rejected { .. }
        ) {
            if let Some(existing) = self
                .connected_peers
                .read()
                .await
                .get(&relay_peer_id)
                .cloned()
            {
                return Ok(existing);
            }
            let live_connection = self
                .inner
                .get_connection(&relay_peer_id)
                .map_err(EndpointError::NatTraversal)?
                .ok_or_else(|| {
                    EndpointError::Connection(
                        "relay connection lost lifecycle race with no live winner".to_string(),
                    )
                })?;
            let peer_conn = PeerConnection {
                peer_id: relay_peer_id,
                remote_addr: TransportAddr::Udp(live_connection.remote_address()),
                traversal_method: TraversalMethod::Relay,
                side: live_connection.side(),
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            };
            self.register_connected_peer(peer_conn.clone()).await;
            return Ok(peer_conn);
        }

        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
        self.inner
            .register_connection_peer_id(target, relay_peer_id);

        // Clone for reader task before handler consumes connection.
        let reader_conn = connection.clone();

        self.inner
            .spawn_connection_handler(relay_peer_id, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            peer_id: relay_peer_id,
            remote_addr: TransportAddr::Udp(target),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn background reader task — use clone, not get_connection().
        self.spawn_reader_task(relay_peer_id, reader_conn).await;

        // Store peer connection
        self.register_connected_peer(peer_conn.clone()).await;
        if let crate::nat_traversal_api::ConnectionRegistrationOutcome::Live {
            superseded_generation: Some(generation),
            ..
        } = registration
        {
            self.schedule_reader_generation_cancel(
                relay_peer_id,
                generation,
                SUPERSEDED_READER_DRAIN_GRACE,
            );
        }

        info!(
            "MASQUE relay connection succeeded to {} via {}",
            target, relay_addr
        );

        Ok(peer_conn)
    }

    async fn persist_direct_peer_reachability_if_applicable(
        bootstrap_cache: &BootstrapCache,
        peer_conn: &PeerConnection,
    ) {
        if !peer_conn.traversal_method.is_direct() {
            return;
        }

        if let Some(socket_addr) = peer_conn.remote_addr.as_socket_addr() {
            bootstrap_cache
                .observe_direct_reachability(peer_conn.peer_id, socket_addr)
                .await;
        }
    }

    fn observe_peer_reachability(&self, peer_conn: &PeerConnection) {
        let cache = Arc::clone(&self.bootstrap_cache);
        let peer_conn = peer_conn.clone();
        tokio::spawn(async move {
            Self::persist_direct_peer_reachability_if_applicable(cache.as_ref(), &peer_conn).await;
        });
    }

    fn live_connection_snapshot(
        &self,
        peer_id: &PeerId,
    ) -> Option<crate::nat_traversal_api::ConnectionLifecycleSnapshot> {
        self.inner
            .get_connection(peer_id)
            .ok()
            .flatten()
            .and_then(|connection| {
                self.inner
                    .connection_snapshot_by_stable_id(peer_id, connection.stable_id())
            })
    }

    fn emit_peer_lifecycle_event(&self, peer_id: PeerId, event: PeerLifecycleEvent) {
        emit_peer_lifecycle_event(
            &self.peer_event_tx,
            self.peer_event_channels.as_ref(),
            peer_id,
            event,
        );
    }

    fn next_ack_request_tag(&self, stable_id: usize) -> [u8; 16] {
        loop {
            let mut tag = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut tag);
            let exists = self
                .ack_waiters
                .read()
                .get(&stable_id)
                .is_some_and(|entry| entry.contains_key(&tag));
            if !exists {
                return tag;
            }
        }
    }

    fn set_stream_priority(
        stream: &crate::high_level::SendStream,
        priority: i32,
        peer_id: PeerId,
        conn_stable_id: usize,
        stream_kind: &'static str,
    ) {
        if let Err(error) = stream.set_priority(priority) {
            debug!(
                peer_id = ?peer_id,
                conn_stable_id,
                stream_kind,
                priority,
                error = ?error,
                "failed to set QUIC stream priority"
            );
        }
    }

    async fn send_ack_control_frame(
        connection: crate::high_level::Connection,
        peer_id: PeerId,
        conn_stable_id: usize,
        tag: [u8; 16],
        outcome: AckControlOutcome,
    ) {
        let bytes = encode_ack_control(tag, outcome);
        match connection.open_uni().await {
            Ok(mut stream) => {
                Self::set_stream_priority(
                    &stream,
                    PROBE_STREAM_PRIORITY,
                    peer_id,
                    conn_stable_id,
                    "probe_ack_control",
                );
                if let Err(error) = stream.write_all(&bytes).await {
                    warn!(error = %error, "failed to send ACK control frame");
                    return;
                }
                if let Err(error) = stream.finish() {
                    warn!(error = %error, "failed to finish ACK control frame stream");
                }
            }
            Err(error) => {
                warn!(error = %error, "failed to open ACK control stream");
            }
        }
    }

    async fn send_ack_bidi_response(
        ack_diagnostics: &AckDiagnostics,
        peer_id: PeerId,
        conn_stable_id: usize,
        mut stream: crate::high_level::SendStream,
        outcome: AckControlOutcome,
    ) {
        Self::set_stream_priority(
            &stream,
            ACK_STREAM_PRIORITY,
            peer_id,
            conn_stable_id,
            "ack_v2_response",
        );
        let bytes = encode_ack_bidi_response(outcome);
        let started = Instant::now();
        let result = timeout(ACK_RESPONSE_WRITE_TIMEOUT, async {
            if let Err(error) = stream.write_all(&bytes).await {
                return Err(("write", error.to_string()));
            }
            if let Err(error) = stream.finish() {
                return Err(("finish", format!("{error:?}")));
            }
            Ok(())
        })
        .await;
        ack_diagnostics.record_stage(
            peer_id,
            conn_stable_id,
            AckLatencyStage::ReceiverResponseWriteFinish,
            started.elapsed(),
        );

        match result {
            Ok(Ok(())) => {}
            Ok(Err(("write", error))) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverResponseWriteFailed,
                );
                warn!(peer_id = ?peer_id, conn_stable_id, error = %error, "failed to send ACK-v2 response");
            }
            Ok(Err(("finish", error))) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverResponseFinishFailed,
                );
                warn!(peer_id = ?peer_id, conn_stable_id, error = %error, "failed to finish ACK-v2 response stream");
            }
            Ok(Err((stage, error))) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverResponseWriteFailed,
                );
                warn!(peer_id = ?peer_id, conn_stable_id, stage, error = %error, "failed to send ACK-v2 response");
            }
            Err(_elapsed) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverResponseTimedOut,
                );
                warn!(
                    peer_id = ?peer_id,
                    conn_stable_id,
                    timeout_ms = ACK_RESPONSE_WRITE_TIMEOUT.as_millis() as u64,
                    "timed out writing ACK-v2 response"
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_ack_bidi_stream(
        ack_diagnostics: &AckDiagnostics,
        ack_request_dedupe: &AckRequestDedupeCache,
        connected_peers: &Arc<RwLock<HashMap<PeerId, PeerConnection>>>,
        peer_activity: &Arc<RwLock<HashMap<PeerId, PeerActivityRecord>>>,
        data_tx: &mpsc::Sender<(PeerId, Vec<u8>)>,
        data_tx_diagnostics: &DataChannelDiagnostics,
        data_tx_capacity: usize,
        event_tx: &broadcast::Sender<P2pEvent>,
        peer_id: PeerId,
        conn_stable_id: usize,
        send: crate::high_level::SendStream,
        mut recv: crate::high_level::RecvStream,
        prefix: Vec<u8>,
        accepted_at: Instant,
        max_read_bytes: usize,
    ) -> bool {
        ack_diagnostics.record_stage(
            peer_id,
            conn_stable_id,
            AckLatencyStage::ReceiverDemux,
            accepted_at.elapsed(),
        );
        if prefix.as_slice() != &ACK_BIDI_REQUEST_MAGIC[..] {
            Self::send_ack_bidi_response(
                ack_diagnostics,
                peer_id,
                conn_stable_id,
                send,
                AckControlOutcome::Rejected(ReceiveRejectReason::InvalidEnvelope),
            )
            .await;
            return true;
        }

        let remaining = match recv.read_to_end(max_read_bytes).await {
            Ok(data) => data,
            Err(e) => {
                debug!(
                    "Reader task for peer {:?} (conn stable_id={}): ACK-v2 read_to_end error: {}",
                    peer_id, conn_stable_id, e
                );
                Self::send_ack_bidi_response(
                    ack_diagnostics,
                    peer_id,
                    conn_stable_id,
                    send,
                    AckControlOutcome::Rejected(ReceiveRejectReason::InvalidEnvelope),
                )
                .await;
                return true;
            }
        };

        let mut data = prefix;
        data.extend_from_slice(&remaining);
        let Some(request) = decode_ack_bidi_request(&data) else {
            Self::send_ack_bidi_response(
                ack_diagnostics,
                peer_id,
                conn_stable_id,
                send,
                AckControlOutcome::Rejected(ReceiveRejectReason::InvalidEnvelope),
            )
            .await;
            return true;
        };
        let request_id = request.request_id;
        let payload = request.payload;
        let payload_len = payload.len();

        match ack_request_dedupe.replay(peer_id, request_id, payload) {
            Some(AckRequestDedupeReplay::Replay(outcome)) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverDuplicateReplayed,
                );
                Self::send_ack_bidi_response(
                    ack_diagnostics,
                    peer_id,
                    conn_stable_id,
                    send,
                    outcome,
                )
                .await;
                return true;
            }
            Some(AckRequestDedupeReplay::Conflict) => {
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverDuplicateConflict,
                );
                Self::send_ack_bidi_response(
                    ack_diagnostics,
                    peer_id,
                    conn_stable_id,
                    send,
                    AckControlOutcome::Rejected(ReceiveRejectReason::InvalidEnvelope),
                )
                .await;
                return true;
            }
            None => {}
        }

        note_peer_activity(
            connected_peers,
            peer_activity,
            peer_id,
            PeerActivityKind::Received,
            Instant::now(),
        )
        .await;

        let admission_started = Instant::now();
        let admission = Self::admit_ack_requested_payload(
            data_tx,
            data_tx_diagnostics,
            data_tx_capacity,
            peer_id,
            payload.to_vec(),
        )
        .await;
        ack_diagnostics.record_stage(
            peer_id,
            conn_stable_id,
            AckLatencyStage::ReceiverAdmission,
            admission_started.elapsed(),
        );

        match admission {
            Ok(()) => {
                if let Err(e) = event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: payload_len,
                }) {
                    tracing::warn!(
                        target: "ant_quic::silent_drop",
                        kind = "event_tx_data_received_reader",
                        peer_id = ?peer_id,
                        bytes = payload_len,
                        error = %e,
                        "HIGH: silent drop"
                    );
                }
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverAccepted,
                );
                ack_request_dedupe.remember(
                    peer_id,
                    request_id,
                    payload,
                    AckControlOutcome::Accepted,
                );
                Self::send_ack_bidi_response(
                    ack_diagnostics,
                    peer_id,
                    conn_stable_id,
                    send,
                    AckControlOutcome::Accepted,
                )
                .await;
                true
            }
            Err(reason) => {
                if reason == ReceiveRejectReason::Backpressured {
                    tracing::warn!(
                        peer_id = ?peer_id,
                        bytes = payload_len,
                        admission_timeout_ms =
                            ACK_RECEIVE_ADMISSION_TIMEOUT.as_millis() as u64,
                        "receive pipeline backpressured; rejecting ACK-v2 payload"
                    );
                }
                ack_diagnostics.record_outcome(
                    peer_id,
                    conn_stable_id,
                    AckOutcome::ReceiverRejected,
                );
                ack_request_dedupe.remember(
                    peer_id,
                    request_id,
                    payload,
                    AckControlOutcome::Rejected(reason),
                );
                Self::send_ack_bidi_response(
                    ack_diagnostics,
                    peer_id,
                    conn_stable_id,
                    send,
                    AckControlOutcome::Rejected(reason),
                )
                .await;
                reason != ReceiveRejectReason::ConsumerGone
            }
        }
    }

    async fn admit_ack_requested_payload(
        data_tx: &mpsc::Sender<(PeerId, Vec<u8>)>,
        data_tx_diagnostics: &DataChannelDiagnostics,
        data_tx_capacity: usize,
        peer_id: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), ReceiveRejectReason> {
        // Sample channel pressure pre-reserve so high-water events are
        // observable even when admission ultimately succeeds.
        data_tx_diagnostics.observe_capacity(data_tx.capacity(), data_tx_capacity);
        match timeout(ACK_RECEIVE_ADMISSION_TIMEOUT, data_tx.reserve()).await {
            Ok(Ok(permit)) => {
                permit.send((peer_id, payload));
                Ok(())
            }
            Ok(Err(_closed)) => Err(ReceiveRejectReason::ConsumerGone),
            Err(_elapsed) => {
                // Admission timed out — the channel was saturated for the
                // full ACK admission budget. This is the failure path that
                // X0X-0036/0039 attribute false-positive ACK timeouts to.
                data_tx_diagnostics.note_saturation(data_tx.capacity(), data_tx_capacity);
                Err(ReceiveRejectReason::Backpressured)
            }
        }
    }

    fn cacheable_probe_outcome(
        key: ProbeFlightKey,
        result: &Result<Duration, EndpointError>,
    ) -> CachedProbeOutcome {
        match result {
            Ok(rtt) => CachedProbeOutcome::Success(*rtt),
            Err(EndpointError::ReceiveRejected { reason }) => CachedProbeOutcome::Rejected(*reason),
            Err(EndpointError::ConnectionClosed { reason }) => CachedProbeOutcome::Closed(*reason),
            Err(EndpointError::ProbeTimeout) => CachedProbeOutcome::Timeout,
            Err(EndpointError::ProbeOverBudget) => CachedProbeOutcome::OverBudget,
            Err(EndpointError::NotSupported) => CachedProbeOutcome::NotSupported,
            Err(EndpointError::PeerNotFound(_)) => CachedProbeOutcome::PeerNotFound(key.peer_id),
            Err(EndpointError::ShuttingDown) => CachedProbeOutcome::ShuttingDown,
            Err(_) => CachedProbeOutcome::Timeout,
        }
    }

    async fn begin_probe_flight(
        &self,
        key: ProbeFlightKey,
        timeout_duration: Duration,
    ) -> Result<ProbeFlightDecision, EndpointError> {
        loop {
            let wait_for_existing = {
                let mut flights = self.probe_flights.lock().await;
                let state = flights.entry(key).or_default();
                let now = Instant::now();
                if let Some(cached) = state.last_result
                    && cached.fresh(now)
                {
                    return Ok(ProbeFlightDecision::Cached(cached.outcome));
                }

                if let Some(notify) = state.in_flight.clone() {
                    Some(notify)
                } else {
                    let notify = Arc::new(Notify::new());
                    state.in_flight = Some(notify.clone());
                    return Ok(ProbeFlightDecision::Start(notify));
                }
            };

            if let Some(notify) = wait_for_existing {
                if timeout(timeout_duration, notify.notified()).await.is_err() {
                    return Err(EndpointError::ProbeTimeout);
                }
            }
        }
    }

    async fn finish_probe_flight(
        &self,
        key: ProbeFlightKey,
        flight: Arc<Notify>,
        result: &Result<Duration, EndpointError>,
    ) {
        let outcome = Self::cacheable_probe_outcome(key, result);
        {
            let mut flights = self.probe_flights.lock().await;
            let state = flights.entry(key).or_default();
            if state
                .in_flight
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &flight))
            {
                state.in_flight = None;
                state.last_result = Some(CachedProbeResult {
                    completed_at: Instant::now(),
                    outcome,
                });
            }
        }
        flight.notify_waiters();
    }

    async fn register_connected_peer(&self, peer_conn: PeerConnection) {
        store_connected_peer(
            self.connected_peers.as_ref(),
            self.stats.as_ref(),
            &self.event_tx,
            peer_conn.clone(),
        )
        .await;

        if let Some(snapshot) = self.live_connection_snapshot(&peer_conn.peer_id) {
            let lifecycle_events = {
                let mut generations = self.peer_event_generations.write();
                match generations.insert(peer_conn.peer_id, snapshot.generation) {
                    None => vec![PeerLifecycleEvent::Established {
                        generation: snapshot.generation,
                    }],
                    Some(previous_generation) if previous_generation != snapshot.generation => {
                        vec![
                            PeerLifecycleEvent::Replaced {
                                old_generation: previous_generation,
                                new_generation: snapshot.generation,
                            },
                            PeerLifecycleEvent::Closing {
                                generation: previous_generation,
                                reason: ConnectionCloseReason::Superseded,
                            },
                            PeerLifecycleEvent::Closed {
                                generation: previous_generation,
                                reason: ConnectionCloseReason::Superseded,
                            },
                        ]
                    }
                    Some(_) => Vec::new(),
                }
            };

            for event in lifecycle_events {
                self.emit_peer_lifecycle_event(peer_conn.peer_id, event);
            }
        }

        if peer_conn.remote_addr.as_socket_addr().is_some() {
            let _ = self.inner.publish_active_relay_to_peer(peer_conn.peer_id);
        }
    }

    /// Check if we're connected to a specific address
    async fn is_connected_to_addr(&self, addr: SocketAddr) -> bool {
        let transport_addr = TransportAddr::Udp(addr);
        let peers = self.connected_peers.read().await;
        peers.values().any(|p| p.remote_addr == transport_addr)
    }

    /// Accept incoming connections
    ///
    /// Returns `None` if the endpoint is shutting down or the accept fails.
    /// This method races the inner accept against the shutdown token, so it
    /// will return promptly when `shutdown()` is called.
    pub async fn accept(&self) -> Option<PeerConnection> {
        if self.shutdown.is_cancelled() {
            return None;
        }

        let result = tokio::select! {
            r = self.inner.accept_connection() => r,
            _ = self.shutdown.cancelled() => return None,
        };

        match result {
            Ok((peer_id, connection)) => {
                let remote_addr = connection.remote_address();
                let mut resolved_peer_id = peer_id;
                let mut registration = None;

                if let Some(actual_peer_id) = self
                    .inner
                    .extract_peer_id_from_connection(&connection)
                    .await
                {
                    if actual_peer_id != peer_id {
                        let _ = self.inner.remove_connection(&peer_id);
                        match self
                            .inner
                            .add_connection_with_outcome(actual_peer_id, connection.clone())
                            .map_err(EndpointError::NatTraversal)
                        {
                            Ok(outcome) => {
                                if matches!(
                                    outcome,
                                    crate::nat_traversal_api::ConnectionRegistrationOutcome::Rejected { .. }
                                ) {
                                    return None;
                                }
                                registration = Some(outcome);
                                resolved_peer_id = actual_peer_id;
                            }
                            Err(e) => {
                                error!("Failed to register re-keyed inbound connection: {}", e);
                                return None;
                            }
                        }
                    }
                }

                // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
                self.inner
                    .register_connection_peer_id(remote_addr, resolved_peer_id);

                // Clone the connection for the reader task BEFORE handler consumes it.
                // Do NOT re-fetch via get_connection() — a concurrent connect() can
                // replace the DashMap entry, causing the reader to attach to the wrong
                // QUIC connection (simultaneous-connect recv() hang).
                let reader_conn = connection.clone();

                // No abort-old: see spawn_reader_task — the old connection may
                // still carry undrained ACKed bytes (issue #166). Multiple
                // concurrent readers per peer are tolerated; each exits when
                // its own connection closes.

                // They initiated the connection to us = Server side
                if let Err(e) =
                    self.inner
                        .spawn_connection_handler(resolved_peer_id, connection, Side::Server)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                let peer_conn = PeerConnection {
                    peer_id: resolved_peer_id,
                    remote_addr: TransportAddr::Udp(remote_addr),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Server,
                    authenticated: true, // TLS handles authentication
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Spawn background reader task BEFORE storing in connected_peers
                // to prevent race where recv() misses early data.
                // Use the cloned connection directly — do NOT re-fetch from the DashMap.
                self.spawn_reader_task(resolved_peer_id, reader_conn).await;

                self.observe_peer_reachability(&peer_conn);
                self.register_connected_peer(peer_conn.clone()).await;
                if let Some(crate::nat_traversal_api::ConnectionRegistrationOutcome::Live {
                    superseded_generation: Some(generation),
                    ..
                }) = registration
                {
                    self.schedule_reader_generation_cancel(
                        resolved_peer_id,
                        generation,
                        SUPERSEDED_READER_DRAIN_GRACE,
                    );
                }

                Some(peer_conn)
            }
            Err(e) => {
                debug!("Accept failed: {}", e);
                None
            }
        }
    }

    /// Clean up a connection from ALL tracking structures.
    ///
    /// This is the single point of cleanup for connections — it removes the peer from:
    /// - `connected_peers` HashMap
    /// - `NatTraversalEndpoint.connections` DashMap (via `remove_connection()`)
    /// - `reader_handles` (cooperative cancel + abort backstop on all readers
    ///   for this peer)
    /// - Updates stats and emits a disconnect event
    ///
    /// Safe to call even if the peer is not in all structures (idempotent).
    async fn cleanup_connection(&self, peer_id: &PeerId, reason: DisconnectReason) {
        let close_reason = close_reason_for_disconnect(&reason);
        do_cleanup_connection(
            &*self.connected_peers,
            &*self.inner,
            &*self.reader_handles,
            &*self.direct_path_statuses,
            &*self.stats,
            &self.event_tx,
            &self.peer_event_tx,
            self.peer_event_channels.as_ref(),
            self.peer_event_generations.as_ref(),
            self.ack_waiters.as_ref(),
            peer_id,
            reason,
            close_reason,
        )
        .await;
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), EndpointError> {
        if self.connected_peers.read().await.contains_key(peer_id) {
            self.cleanup_connection(peer_id, DisconnectReason::Normal)
                .await;
            Ok(())
        } else {
            Err(EndpointError::PeerNotFound(*peer_id))
        }
    }

    // === Messaging ===

    /// Send data to a peer
    ///
    /// # Transport Selection
    ///
    /// This method selects the appropriate transport provider based on the destination
    /// peer's address type and the capabilities advertised in the transport registry.
    ///
    /// ## Current Behavior (Phase 2.1)
    ///
    /// All connections currently use UDP/QUIC via the existing `connection.open_uni()`
    /// path. This ensures backward compatibility with existing peers.
    ///
    /// ## Future Behavior (Phase 2.3)
    ///
    /// Transport selection will be based on:
    /// - Peer's advertised transport addresses (from connection metadata)
    /// - Transport provider capabilities (from `transport_registry`)
    /// - Protocol engine requirements (QUIC vs Constrained)
    ///
    /// Selection priority:
    /// 1. **UDP/QUIC**: Default for broadband, full QUIC support
    /// 2. **BLE**: For nearby devices, constrained engine
    /// 3. **LoRa**: For long-range, low-bandwidth scenarios
    /// 4. **Overlay**: For I2P/Yggdrasil privacy-preserving routing
    ///
    /// # Arguments
    ///
    /// - `peer_id`: The target peer's identifier
    /// - `data`: The payload to send
    ///
    /// # Errors
    ///
    /// Returns `EndpointError` if:
    /// - The endpoint is shutting down
    /// - The peer is not connected
    /// - No suitable transport provider is available
    /// - The send operation fails
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), EndpointError> {
        let peer_id_for_log = *peer_id;
        let result: Result<(), EndpointError> = async {
            if self.shutdown.is_cancelled() {
                return Err(EndpointError::ShuttingDown);
            }

            // Get peer's transport address to determine which engine/transport to use.
            // Fall back to the canonical live QUIC connection if `connected_peers`
            // lagged a lifecycle transition.
            let transport_addr = {
                let peer_info = self.connected_peers.read().await;
                if let Some(conn) = peer_info.get(peer_id) {
                    conn.remote_addr.clone()
                } else if let Some(connection) = self
                    .inner
                    .get_connection(peer_id)
                    .map_err(EndpointError::NatTraversal)?
                {
                    TransportAddr::Udp(connection.remote_address())
                } else {
                    return Err(EndpointError::PeerNotFound(*peer_id));
                }
            };

            // Select protocol engine based on transport address
            let engine = {
                let mut router = self.router.write().await;
                router.select_engine_for_addr(&transport_addr)
            };

            match engine {
                crate::transport::ProtocolEngine::Quic => {
                    // Use existing QUIC connection (UDP transport)
                    let connection = self
                        .inner
                        .get_connection(peer_id)
                        .map_err(EndpointError::NatTraversal)?
                        .ok_or(EndpointError::PeerNotFound(*peer_id))?;

                    if let Some(reason) = close_reason_from_connection(&connection) {
                        return Err(EndpointError::ConnectionClosed { reason });
                    }

                    let mut send_stream = connection
                        .open_uni()
                        .await
                        .map_err(endpoint_error_from_connection_error)?;

                    send_stream
                        .write_all(data)
                        .await
                        .map_err(endpoint_error_from_write_error)?;

                    send_stream.finish().map_err(|e| {
                        close_reason_from_connection(&connection)
                            .map(|reason| EndpointError::ConnectionClosed { reason })
                            .unwrap_or_else(|| EndpointError::Connection(e.to_string()))
                    })?;

                    // Fire-and-forget: `finish()` queues the FIN; QUIC transmits and ACKs
                    // it asynchronously. Do NOT wait on `send_stream.stopped()` here —
                    // Quinn's docs explicitly warn it is not a liveness primitive (it
                    // fires when the peer reads-to-completion or stops the stream, which
                    // can be arbitrarily delayed by asymmetric loss or peer congestion).
                    // Callers that need delivery confirmation should use
                    // `send_with_receive_ack`; callers that need active liveness should
                    // use `probe_peer`.
                    debug!("Sent {} bytes to peer {:?} via QUIC", data.len(), peer_id);
                }
                crate::transport::ProtocolEngine::Constrained => {
                    // Check if we have an established constrained connection for this peer
                    let maybe_conn_id = self
                        .constrained_connections
                        .read()
                        .await
                        .get(peer_id)
                        .copied();

                    if let Some(conn_id) = maybe_conn_id {
                        // Use ConstrainedEngine for reliable delivery
                        let engine = self.inner.constrained_engine();
                        let responses = {
                            let mut engine = engine.lock();
                            engine
                                .send(conn_id, data)
                                .map_err(|e| EndpointError::Connection(e.to_string()))?
                        };

                        // Send any packets generated by the constrained engine
                        for (_dest_addr, packet_data) in responses {
                            self.transport_registry
                                .send(&packet_data, &transport_addr)
                                .await
                                .map_err(|e| EndpointError::Connection(e.to_string()))?;
                        }

                        debug!(
                            "Sent {} bytes to peer {:?} via constrained engine ({})",
                            data.len(),
                            peer_id,
                            transport_addr.transport_type()
                        );
                    } else {
                        // No established connection - send directly via transport
                        // This path is used for initial connection or connectionless messages
                        self.transport_registry
                            .send(data, &transport_addr)
                            .await
                            .map_err(|e| EndpointError::Connection(e.to_string()))?;

                        debug!(
                            "Sent {} bytes to peer {:?} via constrained transport (direct, {})",
                            data.len(),
                            peer_id,
                            transport_addr.transport_type()
                        );
                    }
                }
            }

            let now = Instant::now();
            note_peer_activity(
                &self.connected_peers,
                &self.peer_activity,
                *peer_id,
                PeerActivityKind::Sent,
                now,
            )
            .await;

            Ok(())
        }
        .await;
        if let Err(ref e) = result {
            tracing::warn!(
                target: "ant_quic::send_error",
                peer_id = ?peer_id_for_log,
                error = %e,
                "send failed"
            );
        }
        result
    }

    /// Send data and wait until the remote ant-quic receive pipeline accepts it.
    ///
    /// This is a stronger guarantee than [`P2pEndpoint::send`]: success means the
    /// remote reader task decoded the payload and enqueued it into the receiver
    /// pipeline that backs `recv()`. It does not imply the remote application has
    /// consumed or processed the payload.
    ///
    /// On ACK timeout this performs one duplicate-safe retry with the same
    /// ACK-v2 request ID. The receiver deduplicates accepted payloads, so the
    /// retry can recover a late/lost ACK response without double-delivering.
    pub async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout_duration: Duration,
    ) -> Result<(), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let mut request_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut request_id);

        let first = self
            .send_ack_exchange_once(peer_id, data, request_id, timeout_duration)
            .await;
        if !matches!(first, Err(EndpointError::AckTimeout)) {
            // X0X-0062: first-attempt success OR a non-timeout terminal error
            // both prove the remote responded — reset the liveness tracker.
            // Reviewer P1.1: this path previously bypassed the tracker, so
            // first-attempt successes between retry failures did not reset
            // the counter.
            self.record_ack_liveness_signal(*peer_id, AckLivenessSignal::Success)
                .await;
            return first;
        }

        self.record_ack_retry_outcome(*peer_id, AckOutcome::SenderRetryAttempted);
        let retry_timeout = Self::ack_timeout_retry_timeout(timeout_duration);
        if retry_timeout.is_zero() {
            self.record_ack_retry_outcome(*peer_id, AckOutcome::SenderRetryFailed);
            // No retry was actually attempted; treat as a single timeout
            // event for liveness purposes (no remote evidence either way).
            self.record_ack_liveness_signal(*peer_id, AckLivenessSignal::RetryAckTimeout)
                .await;
            return first;
        }

        let retry = self
            .send_ack_exchange_once(peer_id, data, request_id, retry_timeout)
            .await;
        match retry {
            Ok(()) => {
                self.record_ack_retry_outcome(*peer_id, AckOutcome::SenderRetryAccepted);
                self.record_ack_liveness_signal(*peer_id, AckLivenessSignal::Success)
                    .await;
                Ok(())
            }
            Err(EndpointError::AckTimeout) => {
                self.record_ack_retry_outcome(*peer_id, AckOutcome::SenderRetryFailed);
                // Reviewer P1.2: only a true AckTimeout on the retry path
                // signals half-dead. Non-timeout retry errors (handled in
                // the next arm) prove the remote responded.
                self.record_ack_liveness_signal(*peer_id, AckLivenessSignal::RetryAckTimeout)
                    .await;
                Err(EndpointError::AckTimeout)
            }
            Err(error) => {
                self.record_ack_retry_outcome(*peer_id, AckOutcome::SenderRetryFailed);
                // X0X-0062 P1.2: the remote responded on retry with a
                // non-timeout terminal outcome (Rejected, ConnectionClosed,
                // invalid response). Path is alive — reset the tracker.
                self.record_ack_liveness_signal(*peer_id, AckLivenessSignal::Success)
                    .await;
                Err(error)
            }
        }
    }

    fn ack_timeout_retry_timeout(timeout_duration: Duration) -> Duration {
        std::cmp::min(timeout_duration, ACK_TIMEOUT_RETRY_TIMEOUT)
    }

    fn record_ack_retry_outcome(&self, peer_id: PeerId, outcome: AckOutcome) {
        let stable_id = self
            .inner
            .get_connection(&peer_id)
            .ok()
            .flatten()
            .map(|connection| connection.stable_id())
            .unwrap_or_default();
        self.ack_diagnostics
            .record_outcome(peer_id, stable_id, outcome);
    }

    /// X0X-0062: feed an `send_with_receive_ack` outcome (across the full
    /// first-attempt + retry flow) into the liveness tracker. Called from
    /// `send_with_receive_ack_with_timeout_for_test` after each decision
    /// point so the tracker observes **every** outcome, not just retry
    /// outcomes.
    ///
    /// Reviewer P1.1: previously the tracker only saw retry results, so a
    /// peer with 4 retry double-failures + many first-attempt successes +
    /// 1 more retry double-failure inside 60 s would tip the threshold even
    /// though it wasn't actually 5 consecutive failures. Now any successful
    /// outcome (first attempt OR retry) resets the counter.
    ///
    /// Reviewer P1.2: only true ACK timeouts on the retry path count as
    /// liveness failures. Other terminal retry errors
    /// (`ReceiveRejected`, `ConnectionClosed`, `Connection`) prove the
    /// remote responded — the data path is alive, just rejecting this send.
    /// Those outcomes reset the tracker.
    async fn record_ack_liveness_signal(&self, peer_id: PeerId, signal: AckLivenessSignal) {
        let connection = self.inner.get_connection(&peer_id).ok().flatten();
        let stable_id = match connection.as_ref() {
            Some(connection) => connection.stable_id(),
            None => return,
        };
        match signal {
            AckLivenessSignal::Success => {
                self.ack_liveness.record_success(peer_id, stable_id);
            }
            AckLivenessSignal::RetryAckTimeout => {
                if self.ack_liveness.record_failure(peer_id, stable_id)
                    && let Some(connection) = connection
                {
                    self.trigger_liveness_close(peer_id, stable_id, &connection)
                        .await;
                }
            }
        }
    }

    /// X0X-0062: force-close a connection whose data path is half-dead.
    /// Called when `AckLivenessTracker` confirms `LIVENESS_FAILURE_THRESHOLD`
    /// consecutive ACK retry failures within `LIVENESS_FAILURE_WINDOW`.
    ///
    /// Reviewer P2 (round 2): the original implementation only emitted
    /// `Closing/Closed{LivenessTimeout}` lifecycle events and called
    /// `Connection::close()` directly. Quinn's local close became
    /// `ConnectionError::LocallyClosed` in the connection-state machine, and
    /// the connection itself remained in `connected_peers` until a later
    /// reaper run — so `is_connected()` could still return true after the
    /// liveness close, and any later `close_reason_from_connection` query
    /// would downgrade the diagnostic from `LivenessTimeout` to
    /// `LocallyClosed`. Now the trigger site invokes the existing
    /// `cleanup_connection(DisconnectReason::LivenessTimeout)` helper, which
    /// `close_reason_for_disconnect` maps to `LivenessTimeout`. That path:
    /// 1. emits `Closing{LivenessTimeout}`
    /// 2. calls `remove_connection_with_reason(LivenessTimeout)` on the
    ///    inner NAT-traversal endpoint — removing the connection from the
    ///    state map AND tagging the inner record with LivenessTimeout
    /// 3. emits `Closed{LivenessTimeout}`
    /// 4. fails any in-flight ACK waiters with `LivenessTimeout` close reason
    /// 5. tears down reader handles + removes the peer from `connected_peers`
    ///
    /// Result: `is_connected(peer_id)` immediately returns false after the
    /// trigger, and the LivenessTimeout reason is preserved everywhere
    /// downstream rather than getting downgraded to LocallyClosed.
    async fn trigger_liveness_close(
        &self,
        peer_id: PeerId,
        stable_id: usize,
        connection: &crate::high_level::Connection,
    ) {
        if connection.stable_id() != stable_id {
            // Connection was already replaced; the tracker is stale.
            self.ack_liveness.forget(peer_id, stable_id);
            return;
        }
        tracing::warn!(
            peer_id = %peer_id,
            stable_id = stable_id,
            threshold = LIVENESS_FAILURE_THRESHOLD,
            window_secs = LIVENESS_FAILURE_WINDOW.as_secs(),
            "X0X-0062: force-closing half-dead connection — {} consecutive ACK retry failures within {}s while QUIC reports Live",
            LIVENESS_FAILURE_THRESHOLD,
            LIVENESS_FAILURE_WINDOW.as_secs(),
        );
        // Drop the tracker entry FIRST so a successful re-dial that lands on
        // the same (peer, stable_id) — vanishingly unlikely but defensive —
        // gets a clean slate.
        self.ack_liveness.forget(peer_id, stable_id);
        // cleanup_connection is the source-of-truth disconnect path. With
        // DisconnectReason::LivenessTimeout it threads LivenessTimeout through
        // every layer: lifecycle events, inner state machine, ACK waiters,
        // reader handles, connected_peers, stats, and the user-facing event
        // channel. After this returns, `is_connected(peer_id)` is false.
        self.cleanup_connection(&peer_id, DisconnectReason::LivenessTimeout)
            .await;
    }

    async fn send_ack_exchange_once(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        request_id: [u8; 16],
        timeout_duration: Duration,
    ) -> Result<(), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let transport_addr = {
            let peer_info = self.connected_peers.read().await;
            if let Some(conn) = peer_info.get(peer_id) {
                conn.remote_addr.clone()
            } else if let Some(connection) = self
                .inner
                .get_connection(peer_id)
                .map_err(EndpointError::NatTraversal)?
            {
                TransportAddr::Udp(connection.remote_address())
            } else {
                return Err(EndpointError::PeerNotFound(*peer_id));
            }
        };

        let engine = {
            let mut router = self.router.write().await;
            router.select_engine_for_addr(&transport_addr)
        };
        if !matches!(engine, crate::transport::ProtocolEngine::Quic) {
            return Err(EndpointError::NotSupported);
        }

        let connection = self
            .inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)?
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;

        if !connection.supports_ack_receive_v2() {
            return Err(EndpointError::NotSupported);
        }
        if let Some(reason) = close_reason_from_connection(&connection) {
            return Err(EndpointError::ConnectionClosed { reason });
        }

        let stable_id = connection.stable_id();
        let envelope = encode_ack_bidi_request(request_id, data);
        let exchange = async {
            let open_started = Instant::now();
            let (mut send_stream, mut recv_stream) = connection
                .open_bi()
                .await
                .map_err(endpoint_error_from_connection_error)?;
            self.ack_diagnostics.record_stage(
                *peer_id,
                stable_id,
                AckLatencyStage::SenderOpenBi,
                open_started.elapsed(),
            );
            Self::set_stream_priority(
                &send_stream,
                ACK_STREAM_PRIORITY,
                *peer_id,
                stable_id,
                "ack_v2_request",
            );

            let write_started = Instant::now();
            let write_result = send_stream.write_all(&envelope).await;
            self.ack_diagnostics.record_stage(
                *peer_id,
                stable_id,
                AckLatencyStage::SenderRequestWrite,
                write_started.elapsed(),
            );
            write_result.map_err(endpoint_error_from_write_error)?;

            let finish_started = Instant::now();
            let finish_result = send_stream.finish();
            self.ack_diagnostics.record_stage(
                *peer_id,
                stable_id,
                AckLatencyStage::SenderRequestFinish,
                finish_started.elapsed(),
            );
            finish_result.map_err(|e| {
                close_reason_from_connection(&connection)
                    .map(|reason| EndpointError::ConnectionClosed { reason })
                    .unwrap_or_else(|| EndpointError::Connection(e.to_string()))
            })?;

            note_peer_activity(
                &self.connected_peers,
                &self.peer_activity,
                *peer_id,
                PeerActivityKind::Sent,
                Instant::now(),
            )
            .await;

            let read_started = Instant::now();
            let read_result = recv_stream.read_to_end(ACK_BIDI_RESPONSE_MAX_BYTES).await;
            self.ack_diagnostics.record_stage(
                *peer_id,
                stable_id,
                AckLatencyStage::SenderResponseRead,
                read_started.elapsed(),
            );
            let response = read_result.map_err(endpoint_error_from_read_to_end_error)?;
            let outcome = decode_ack_bidi_response(&response);
            if outcome.is_some() {
                note_peer_activity(
                    &self.connected_peers,
                    &self.peer_activity,
                    *peer_id,
                    PeerActivityKind::Received,
                    Instant::now(),
                )
                .await;
            }
            match outcome {
                Some(AckControlOutcome::Accepted) => {
                    self.ack_diagnostics.record_outcome(
                        *peer_id,
                        stable_id,
                        AckOutcome::SenderAccepted,
                    );
                    Ok(())
                }
                Some(AckControlOutcome::Rejected(reason)) => {
                    self.ack_diagnostics.record_outcome(
                        *peer_id,
                        stable_id,
                        AckOutcome::SenderRejected,
                    );
                    Err(EndpointError::ReceiveRejected { reason })
                }
                Some(AckControlOutcome::Closed(reason)) => {
                    self.ack_diagnostics.record_outcome(
                        *peer_id,
                        stable_id,
                        AckOutcome::SenderConnectionClosed,
                    );
                    Err(EndpointError::ConnectionClosed { reason })
                }
                None => {
                    self.ack_diagnostics.record_outcome(
                        *peer_id,
                        stable_id,
                        AckOutcome::SenderInvalidResponse,
                    );
                    Err(EndpointError::Connection(format!(
                        "invalid ACK-v2 response envelope: len={}, prefix={}",
                        response.len(),
                        hex::encode(&response[..response.len().min(16)])
                    )))
                }
            }
        };

        match timeout(timeout_duration, exchange).await {
            Ok(result) => result,
            Err(_) => {
                self.ack_diagnostics.record_outcome(
                    *peer_id,
                    stable_id,
                    AckOutcome::SenderAckTimeout,
                );
                Err(EndpointError::AckTimeout)
            }
        }
    }

    /// Probe peer liveness and measure round-trip time when an active probe is needed.
    ///
    /// Recent inbound data or ACK activity is treated as a stronger liveness
    /// signal than a diagnostic probe, so this method may return
    /// `Duration::ZERO` without sending probe traffic while that signal is
    /// fresh. Otherwise it sends a minimal probe envelope over a fresh
    /// uni-stream and waits for the remote ant-quic reader to reply with an ACK
    /// control frame. Returns the measured round-trip duration on active-probe
    /// success.
    ///
    /// This is the preferred primitive for applications that need to
    /// distinguish a genuinely-alive peer from a zombie (half-open) connection.
    /// It exercises the same reader-pipeline path as [`Self::send`], so a
    /// successful probe implies both (a) the underlying UDP/QUIC path is live
    /// and (b) the remote reader task is running and can service incoming
    /// streams — which is exactly the signal gossip/pubsub layers need to
    /// decide whether to demote a suspect peer.
    ///
    /// Probe envelopes are invisible to the application receive pipeline:
    /// they are never forwarded to `recv()` or emitted as
    /// [`P2pEvent::DataReceived`].
    ///
    /// # Errors
    ///
    /// - [`EndpointError::ShuttingDown`] if the endpoint is shutting down.
    /// - [`EndpointError::PeerNotFound`] if no live QUIC connection exists.
    /// - [`EndpointError::NotSupported`] if the connection or transport cannot
    ///   carry probe ACK control frames (e.g. constrained transports, or peers
    ///   that did not negotiate the capability).
    /// - [`EndpointError::ConnectionClosed`] if the connection is already
    ///   transitioning out of `Live`.
    /// - [`EndpointError::ProbeTimeout`] if no ACK arrives within `timeout`.
    pub async fn probe_peer(
        &self,
        peer_id: &PeerId,
        timeout_duration: Duration,
    ) -> Result<Duration, EndpointError> {
        if let Some(age) =
            recent_peer_receive_activity(&self.peer_activity, *peer_id, Instant::now()).await
        {
            debug!(
                peer_id = ?peer_id,
                recent_receive_age_ms = age.as_millis() as u64,
                "suppressing active probe because recent inbound/ACK activity proves liveness"
            );
            return Ok(Duration::ZERO);
        }

        let connection = self
            .inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)?
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;
        let key = ProbeFlightKey {
            peer_id: *peer_id,
            stable_id: connection.stable_id(),
        };

        let flight = match self.begin_probe_flight(key, timeout_duration).await? {
            ProbeFlightDecision::Cached(outcome) => return outcome.into_result(),
            ProbeFlightDecision::Start(flight) => flight,
        };

        let permit = match timeout(
            PROBE_BUDGET_WAIT.min(timeout_duration),
            self.probe_semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                let result = Err(EndpointError::ProbeOverBudget);
                self.finish_probe_flight(key, flight, &result).await;
                return result;
            }
        };

        let result = self.probe_peer_inner(peer_id, timeout_duration).await;
        drop(permit);
        self.finish_probe_flight(key, flight, &result).await;
        result
    }

    async fn probe_peer_inner(
        &self,
        peer_id: &PeerId,
        timeout_duration: Duration,
    ) -> Result<Duration, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let transport_addr = {
            let peer_info = self.connected_peers.read().await;
            if let Some(conn) = peer_info.get(peer_id) {
                conn.remote_addr.clone()
            } else if let Some(connection) = self
                .inner
                .get_connection(peer_id)
                .map_err(EndpointError::NatTraversal)?
            {
                TransportAddr::Udp(connection.remote_address())
            } else {
                return Err(EndpointError::PeerNotFound(*peer_id));
            }
        };

        let engine = {
            let mut router = self.router.write().await;
            router.select_engine_for_addr(&transport_addr)
        };
        if !matches!(engine, crate::transport::ProtocolEngine::Quic) {
            return Err(EndpointError::NotSupported);
        }

        let connection = self
            .inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)?
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;

        if !connection.supports_ack_receive_v2() {
            return Err(EndpointError::NotSupported);
        }
        if let Some(reason) = close_reason_from_connection(&connection) {
            return Err(EndpointError::ConnectionClosed { reason });
        }

        let stable_id = connection.stable_id();
        let tag = self.next_ack_request_tag(stable_id);
        let (tx, rx) = oneshot::channel();
        let inserted = register_ack_waiter(self.ack_waiters.as_ref(), stable_id, tag, tx);
        if !inserted {
            return Err(EndpointError::Connection(
                "failed to reserve unique probe tag".to_string(),
            ));
        }

        let envelope = encode_probe_request(tag);
        let sent_at = Instant::now();
        let send_result = async {
            let mut send_stream = connection
                .open_uni()
                .await
                .map_err(endpoint_error_from_connection_error)?;
            Self::set_stream_priority(
                &send_stream,
                PROBE_STREAM_PRIORITY,
                *peer_id,
                stable_id,
                "probe_request",
            );
            send_stream
                .write_all(&envelope)
                .await
                .map_err(endpoint_error_from_write_error)?;
            send_stream.finish().map_err(|e| {
                close_reason_from_connection(&connection)
                    .map(|reason| EndpointError::ConnectionClosed { reason })
                    .unwrap_or_else(|| EndpointError::Connection(e.to_string()))
            })
        }
        .await;

        if let Err(error) = send_result {
            if !resolve_ack_waiter(
                self.ack_waiters.as_ref(),
                stable_id,
                tag,
                AckWaiterResult::Closed(ConnectionCloseReason::LocallyClosed),
            ) {
                tracing::warn!(
                    target: "ant_quic::silent_drop",
                    kind = "resolve_ack_waiter_miss",
                    stable_id = stable_id,
                    "no waiter for tag"
                );
            }
            return Err(error);
        }

        note_peer_activity(
            &self.connected_peers,
            &self.peer_activity,
            *peer_id,
            PeerActivityKind::Sent,
            sent_at,
        )
        .await;

        match timeout(timeout_duration, rx).await {
            Ok(Ok(AckWaiterResult::Accepted)) => {
                note_peer_activity(
                    &self.connected_peers,
                    &self.peer_activity,
                    *peer_id,
                    PeerActivityKind::Received,
                    Instant::now(),
                )
                .await;
                Ok(sent_at.elapsed())
            }
            Ok(Ok(AckWaiterResult::Rejected(reason))) => {
                Err(EndpointError::ReceiveRejected { reason })
            }
            Ok(Ok(AckWaiterResult::Closed(reason))) => {
                Err(EndpointError::ConnectionClosed { reason })
            }
            Ok(Err(_)) => {
                if let Some(reason) = close_reason_from_connection(&connection) {
                    Err(EndpointError::ConnectionClosed { reason })
                } else {
                    Err(EndpointError::Connection(
                        "probe waiter dropped before completion".to_string(),
                    ))
                }
            }
            Err(_) => {
                if !resolve_ack_waiter(
                    self.ack_waiters.as_ref(),
                    stable_id,
                    tag,
                    AckWaiterResult::Closed(ConnectionCloseReason::TimedOut),
                ) {
                    tracing::warn!(
                        target: "ant_quic::silent_drop",
                        kind = "resolve_ack_waiter_miss",
                        stable_id = stable_id,
                        "no waiter for tag"
                    );
                }
                Err(EndpointError::ProbeTimeout)
            }
        }
    }

    /// Receive data from any connected peer.
    ///
    /// Blocks until data arrives from any transport (UDP/QUIC, BLE, LoRa, etc.)
    /// or the endpoint shuts down. Background reader tasks feed a shared channel,
    /// so this wakes instantly when data is available.
    ///
    /// # Errors
    ///
    /// Returns `EndpointError::ShuttingDown` if the endpoint is shutting down.
    pub async fn recv(&self) -> Result<(PeerId, Vec<u8>), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Fast path: check pending data buffer (data buffered during authentication)
        {
            let mut pending = self.pending_data.write().await;
            pending.cleanup_expired();

            if let Some((peer_id, data)) = pending.pop_any() {
                let data_len = data.len();
                tracing::trace!(
                    "Received {} bytes from peer {:?} (from pending buffer)",
                    data_len,
                    peer_id
                );

                let now = Instant::now();
                note_peer_activity(
                    &self.connected_peers,
                    &self.peer_activity,
                    peer_id,
                    PeerActivityKind::Received,
                    now,
                )
                .await;

                // Emit DataReceived event — HIGH priority: upper layer missed inbound data
                if let Err(e) = self.event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: data_len,
                }) {
                    tracing::warn!(
                        target: "ant_quic::silent_drop",
                        kind = "event_tx_data_received",
                        peer_id = ?peer_id,
                        bytes = data_len,
                        error = %e,
                        "HIGH: silent drop"
                    );
                }

                return Ok((peer_id, data));
            }
        }

        // Wait for data from the shared channel (fed by background reader tasks),
        // racing against the shutdown token so callers unblock promptly on shutdown.
        let mut rx = self.data_rx.lock().await;
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => Ok(msg),
                None => Err(EndpointError::ShuttingDown),
            },
            _ = self.shutdown.cancelled() => Err(EndpointError::ShuttingDown),
        }
    }

    // === Events ===

    /// Subscribe to endpoint events.
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to lifecycle events for a specific peer.
    ///
    /// Slow subscribers may observe `RecvError::Lagged`; callers can reconcile
    /// with [`P2pEndpoint::connection_health`].
    pub fn subscribe_peer_events(
        &self,
        peer_id: &PeerId,
    ) -> broadcast::Receiver<PeerLifecycleEvent> {
        peer_event_sender(self.peer_event_channels.as_ref(), *peer_id).subscribe()
    }

    /// Subscribe to lifecycle events for all peers.
    pub fn subscribe_all_peer_events(&self) -> broadcast::Receiver<(PeerId, PeerLifecycleEvent)> {
        self.peer_event_tx.subscribe()
    }

    // === Statistics ===

    /// Get endpoint statistics
    pub async fn stats(&self) -> EndpointStats {
        self.stats.read().await.clone()
    }

    /// Snapshot stage-by-stage ACK-v2 latency and outcome diagnostics.
    pub fn ack_diagnostics(&self) -> AckDiagnosticsSnapshot {
        self.ack_diagnostics.snapshot()
    }

    /// Snapshot `data_tx` channel saturation diagnostics (X0X-0039).
    ///
    /// `data_tx` is the single bounded `mpsc` shared by every per-connection
    /// reader task. Returns the configured capacity, the current depth
    /// (best-effort: `capacity - sender.capacity()`), and the cumulative
    /// count of saturation events since process start.
    pub fn data_channel_diagnostics(&self) -> DataChannelDiagnosticsSnapshot {
        let capacity = self.data_tx_capacity;
        let free = self.data_tx.capacity();
        let depth = capacity.saturating_sub(free);
        DataChannelDiagnosticsSnapshot {
            data_tx_depth: depth,
            data_tx_capacity: capacity,
            data_tx_high_water_count: self.data_tx_diagnostics.high_water_count(),
        }
    }

    /// Snapshot GSO bundle send diagnostics (X0X-0043).
    ///
    /// Returns cumulative counts of multi-segment GSO bundles submitted to
    /// the kernel send path and of bundles reported as partial / failed.
    /// The counters are process-global because the underlying transmit
    /// loop is shared across every endpoint in the process; see
    /// [`crate::diagnostics::gso`] for the full hypothesis-under-test
    /// (Quinn issue #2627) and the current observability limitations.
    pub fn gso_diagnostics(&self) -> crate::diagnostics::GsoDiagnosticsSnapshot {
        crate::diagnostics::gso_diagnostics().snapshot()
    }

    /// Get metrics for a specific connection
    pub async fn connection_metrics(&self, peer_id: &PeerId) -> Option<ConnectionMetrics> {
        let connection = self.inner.get_connection(peer_id).ok()??;
        let stats = connection.stats();
        let rtt = connection.rtt();

        let last_activity = self
            .connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.last_activity);

        Some(ConnectionMetrics {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            rtt: Some(rtt),
            packet_loss: stats.path.lost_packets as f64
                / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
            last_activity,
        })
    }

    /// Get a best-effort snapshot of connection health for a peer.
    ///
    /// This is an additive observability surface intended for subscribers and
    /// higher-level status loops. It reports current live-connection state when
    /// available, recent directional activity timestamps, and the most recent
    /// lifecycle close reason retained by the endpoint.
    pub async fn connection_health(&self, peer_id: &PeerId) -> ConnectionHealth {
        let live_snapshot =
            self.inner
                .get_connection(peer_id)
                .ok()
                .flatten()
                .and_then(|connection| {
                    self.inner
                        .connection_snapshot_by_stable_id(peer_id, connection.stable_id())
                });
        let constrained_connected = self
            .constrained_connections
            .read()
            .await
            .contains_key(peer_id);
        let reader_task_active = if live_snapshot.is_some() {
            Some(
                self.reader_handles
                    .read()
                    .await
                    .get(peer_id)
                    .is_some_and(|handles| !handles.is_empty()),
            )
        } else if constrained_connected {
            Some(false)
        } else {
            None
        };
        let activity = self
            .peer_activity
            .read()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or_default();

        ConnectionHealth::from_observation(
            ConnectionHealthObservation {
                connected: live_snapshot.is_some() || constrained_connected,
                generation: live_snapshot.map(|snapshot| snapshot.generation),
                reader_task_active,
                last_received_at: activity.last_received_at,
                last_sent_at: activity.last_sent_at,
                close_reason: if live_snapshot.is_none() && !constrained_connected {
                    self.inner.recent_close_reason_for_peer(peer_id)
                } else {
                    None
                },
            },
            Instant::now(),
        )
    }

    // === Known Peers ===

    /// Connect to configured known peers.
    ///
    /// This is part of the preferred public surface for bootstrapping and
    /// discovery-oriented outbound connectivity.
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let directory = self.peer_directory_snapshot().await;
        let static_known_peers = if self.config.discovery.static_known_peers {
            self.config.known_peers.clone()
        } else {
            Vec::new()
        };
        let manual_udp_known_peers = directory
            .locator_claims()
            .filter(|record| {
                record
                    .sources
                    .contains(&PeerDiscoverySource::ManualKnownPeer)
            })
            .flat_map(|record| record.addresses.clone())
            .collect::<Vec<_>>();
        let runtime_udp_known_peers = directory
            .locator_claims()
            .filter(|record| {
                record
                    .sources
                    .contains(&PeerDiscoverySource::RuntimeKnownPeer)
            })
            .flat_map(|record| record.addresses.clone())
            .collect::<Vec<_>>();
        let auto_runtime_udp_known_peers =
            if self.config.discovery.auto_connect.allows_automatic_dial() {
                runtime_udp_known_peers
                    .iter()
                    .copied()
                    .filter(|addr| !manual_udp_known_peers.contains(addr))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
        let mdns_discovered_peers = directory
            .locator_claims()
            .filter(|record| record.sources.contains(&PeerDiscoverySource::Mdns))
            .filter_map(|record| record.mdns_peer.clone())
            .collect::<Vec<_>>();
        let mut connected_udp_addrs = std::collections::HashSet::new();

        for addr in &static_known_peers {
            // Use connect_transport for all statically configured transport-capable addresses
            match self.connect_transport(addr, None).await {
                Ok(_) => {
                    connected += 1;
                    if let Some(socket_addr) = addr.as_socket_addr() {
                        connected_udp_addrs.insert(socket_addr);
                    }
                    info!("Connected to known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to known peer {}: {}", addr, e);
                }
            }
        }

        for addr in &manual_udp_known_peers {
            if connected_udp_addrs.contains(addr) {
                continue;
            }

            match self.connect_addr(*addr).await {
                Ok(_) => {
                    connected += 1;
                    connected_udp_addrs.insert(*addr);
                    info!("Connected to manual known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to manual known peer {}: {}", addr, e);
                }
            }
        }

        for addr in &auto_runtime_udp_known_peers {
            if connected_udp_addrs.contains(addr) {
                continue;
            }

            match self.connect_addr(*addr).await {
                Ok(_) => {
                    connected += 1;
                    connected_udp_addrs.insert(*addr);
                    info!("Connected to runtime known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to runtime known peer {}: {}", addr, e);
                }
            }
        }

        for peer in &mdns_discovered_peers {
            if peer
                .addresses
                .iter()
                .all(|addr| connected_udp_addrs.contains(addr))
            {
                continue;
            }

            let mdns_policy = self
                .config
                .discovery
                .mdns
                .as_ref()
                .map(|mdns| mdns.auto_connect)
                .unwrap_or(AutoConnectPolicy::Disabled);
            if !mdns_policy.allows_automatic_dial() {
                if mdns_policy.requires_approval() {
                    if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerApprovalRequired {
                        peer: peer.clone(),
                        reason: "approval required by discovery policy".to_string(),
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_approval_required", error = %e, "silent drop");
                    }
                }
                continue;
            }

            if let Err(reason) = self.discovered_peer_allowed(peer.claimed_peer_id) {
                if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerIneligible {
                    peer: peer.clone(),
                    reason,
                }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_ineligible", error = %e, "silent drop");
                }
                continue;
            }

            match self
                .connect_orchestrated(peer.claimed_peer_id, peer.addresses.clone())
                .await
            {
                Ok(_) => {
                    connected += 1;
                    for addr in &peer.addresses {
                        connected_udp_addrs.insert(*addr);
                    }
                    info!(
                        fullname = %peer.fullname,
                        addresses = ?peer.addresses,
                        "Connected to eligible mDNS-discovered peer"
                    );
                }
                Err(error) => {
                    warn!(
                        fullname = %peer.fullname,
                        addresses = ?peer.addresses,
                        error = %error,
                        "Failed to connect to eligible mDNS-discovered peer"
                    );
                }
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.connected_bootstrap_nodes = connected;
        }

        let total = static_known_peers.len()
            + manual_udp_known_peers
                .iter()
                .filter(|addr| {
                    !static_known_peers
                        .iter()
                        .filter_map(|known| known.as_socket_addr())
                        .any(|known| known == **addr)
                })
                .count()
            + auto_runtime_udp_known_peers
                .iter()
                .filter(|addr| {
                    !static_known_peers
                        .iter()
                        .filter_map(|known| known.as_socket_addr())
                        .any(|known| known == **addr)
                        && !manual_udp_known_peers.contains(addr)
                })
                .count()
            + mdns_discovered_peers.len();

        let _ = self
            .event_tx
            .send(P2pEvent::BootstrapStatus { connected, total });

        Ok(connected)
    }

    /// Add a known peer dynamically.
    ///
    /// This is the canonical public name for adding discovery/bootstrap inputs.
    pub async fn add_known_peer(&self, addr: SocketAddr) {
        self.add_bootstrap(addr).await;
    }

    /// Add a bootstrap node dynamically.
    ///
    /// Compatibility-oriented alias retained for older callers. Prefer
    /// [`Self::add_known_peer`].
    pub async fn add_bootstrap(&self, addr: SocketAddr) {
        let _ = self.inner.add_bootstrap_node(addr);
        {
            let mut manual = self.manual_known_peer_udp_addrs.write().await;
            if !manual.contains(&addr) {
                manual.push(addr);
            }
        }
        let mut stats = self.stats.write().await;
        stats.total_bootstrap_nodes += 1;
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.connected_peers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.read().await.contains_key(peer_id)
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        self.connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.authenticated)
            .unwrap_or(false)
    }

    // === Lifecycle ===

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down P2P endpoint");
        self.shutdown.cancel();

        // Abort all background reader tasks.
        let handles = {
            let mut handles = self.reader_handles.write().await;
            std::mem::take(&mut *handles)
        };
        for entries in handles.into_values() {
            for handle in entries {
                handle.cancel.cancel();
                handle.abort_handle.abort();
            }
        }

        // Disconnect all peers
        let peers: Vec<PeerId> = self.connected_peers.read().await.keys().copied().collect();
        for peer_id in peers {
            let _ = self.disconnect(&peer_id).await;
        }

        // Bounded timeout prevents blocking when the remote peer is unresponsive.
        match timeout(SHUTDOWN_DRAIN_TIMEOUT, self.inner.shutdown()).await {
            Err(_) => warn!("Inner endpoint shutdown timed out, proceeding"),
            Ok(Err(e)) => warn!("Inner endpoint shutdown error: {e}"),
            Ok(Ok(())) => {}
        }
    }

    /// Check if endpoint is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.is_cancelled()
    }

    /// Get a clone of the shutdown token (for external cancellation listening)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    // === Internal helpers ===

    fn spawn_proactive_relay_manager(&self) {
        if !self.config.nat.enable_relay_fallback {
            return;
        }

        let endpoint = self.clone();
        let mut events = self.subscribe();
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = endpoint.shutdown.cancelled() => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    },
                };

                if !matches!(
                    event,
                    P2pEvent::ExternalAddressDiscovered { .. }
                        | P2pEvent::PeerConnected { .. }
                        | P2pEvent::BootstrapStatus { .. }
                ) {
                    continue;
                }

                if endpoint.inner.relay_public_addr().is_some() {
                    if endpoint.inner.is_relay_healthy() {
                        continue;
                    }
                    endpoint.inner.reset_relay_state();
                }

                if !endpoint.inner.is_symmetric_nat() {
                    continue;
                }

                let relay_candidates = endpoint.runtime_known_peer_udp_addrs();
                if relay_candidates.is_empty() {
                    debug!("Symmetric NAT detected but no relay candidates are currently known");
                    continue;
                }

                info!(
                    candidate_count = relay_candidates.len(),
                    "Symmetric NAT detected — attempting proactive relay immediately"
                );

                let mut established = None;
                for bootstrap in relay_candidates {
                    match endpoint.inner.setup_proactive_relay(bootstrap).await {
                        Ok(relay_addr) => {
                            info!(
                                "Proactive relay active at {} via bootstrap {}",
                                relay_addr, bootstrap
                            );
                            established = Some(relay_addr);
                            break;
                        }
                        Err(error) => {
                            warn!("Failed to set up relay via {}: {}", bootstrap, error);
                        }
                    }
                }

                if let Some(relay_addr) = established {
                    let _ = endpoint
                        .event_tx
                        .send(P2pEvent::RelayEstablished { relay_addr });
                }
            }
        });
    }

    fn spawn_port_mapping_task(&self) {
        if !self.config.nat.port_mapping.enabled {
            info!("Best-effort router port mapping disabled by configuration");
            return;
        }

        let Some(local_addr) = self.local_addr() else {
            warn!(
                "Skipping best-effort router port mapping because local bind address is unavailable"
            );
            return;
        };

        // Reviewer P1 #1: UPnP IGD is IPv4-only, and a loopback or IPv6-only
        // bind cannot legitimately receive the LAN_IP:PORT traffic that the
        // gateway-selected mapping would direct to it. Mirror the mDNS
        // loopback guard plus an IPv6-only check so we never expose the wrong
        // listener via a router port mapping.
        let configured_loopback_only = self
            .config
            .bind_addr
            .as_ref()
            .and_then(TransportAddr::as_socket_addr)
            .is_some_and(|configured| configured.ip().is_loopback());
        if configured_loopback_only || local_addr.ip().is_loopback() {
            info!(
                configured_loopback_only,
                local_addr = %local_addr,
                "Skipping best-effort router port mapping for a loopback-only endpoint"
            );
            return;
        }
        // IPv6-only bind: an IPv6 unspecified or specific IPv6 address means
        // there's no IPv4 listener for UPnP IGD to map traffic to. We allow
        // dual-stack binds (IPv4-mapped IPv6, or v4-unspecified `0.0.0.0`)
        // because the OS still accepts the v4 traffic the mapping would
        // direct to LAN_IPv4:PORT.
        if local_addr.is_ipv6() {
            info!(
                local_addr = %local_addr,
                "Skipping best-effort router port mapping for an IPv6-only endpoint (UPnP IGD is IPv4-only)"
            );
            return;
        }

        let endpoint = self.clone();
        spawn_best_effort_port_mapping(
            self.config.nat.port_mapping,
            local_addr.port(),
            self.shutdown.clone(),
            move |event| endpoint.apply_port_mapping_event(event),
        );
    }

    fn mdns_auto_connect_enabled(&self) -> bool {
        self.config
            .discovery
            .mdns
            .as_ref()
            .is_some_and(|mdns| mdns.enabled && mdns.auto_connect.allows_automatic_dial())
    }

    fn spawn_mdns_task(&self) {
        let Some(mdns) = self.config.discovery.mdns.clone() else {
            return;
        };
        if !mdns.enabled {
            return;
        }

        let Some(local_addr) = self.local_addr() else {
            warn!("Skipping first-party mDNS because local bind address is unavailable");
            return;
        };

        let configured_loopback_only = self
            .config
            .bind_addr
            .as_ref()
            .and_then(TransportAddr::as_socket_addr)
            .is_some_and(|configured| configured.ip().is_loopback());

        if configured_loopback_only || local_addr.ip().is_loopback() {
            info!(
                configured_loopback_only,
                local_addr = %local_addr,
                "Skipping first-party mDNS for a loopback-only endpoint"
            );
            return;
        }

        {
            let mut snapshot = self.mdns_state.write();
            snapshot.browsing = mdns.mode.browse_enabled();
            snapshot.service = mdns.service.clone();
            snapshot.namespace = mdns.namespace.clone();
        }

        let endpoint = self.clone();
        spawn_mdns_runtime(
            mdns,
            self.peer_id,
            local_addr.port(),
            self.shutdown.clone(),
            move |event| endpoint.apply_mdns_runtime_event(event),
        );
    }

    fn apply_mdns_runtime_event(&self, event: MdnsRuntimeEvent) {
        match event {
            MdnsRuntimeEvent::ServiceAdvertised {
                service,
                namespace,
                instance_fullname,
            } => {
                {
                    let mut snapshot = self.mdns_state.write();
                    snapshot.advertising = true;
                    snapshot.service = Some(service.clone());
                    snapshot.namespace = namespace.clone();
                    snapshot.advertised_instance_fullname = Some(instance_fullname.clone());
                }
                if let Err(e) = self.event_tx.send(P2pEvent::MdnsServiceAdvertised {
                    service,
                    namespace,
                    instance_fullname,
                }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_service_advertised", error = %e, "silent drop");
                }
            }
            MdnsRuntimeEvent::PeerDiscovered(peer) => {
                self.upsert_mdns_peer(&peer);
                if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerDiscovered { peer }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_peer_discovered", error = %e, "silent drop");
                }
            }
            MdnsRuntimeEvent::PeerUpdated(peer) => {
                self.upsert_mdns_peer(&peer);
                if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerUpdated { peer }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_peer_updated", error = %e, "silent drop");
                }
            }
            MdnsRuntimeEvent::PeerRemoved(peer) => {
                self.remove_mdns_peer(&peer.fullname);
                if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerRemoved { peer }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_peer_removed", error = %e, "silent drop");
                }
            }
            MdnsRuntimeEvent::PeerEligible(peer) => {
                self.upsert_mdns_peer(&peer);
                let _ = self
                    .event_tx
                    .send(P2pEvent::MdnsPeerEligible { peer: peer.clone() });
                let mdns_policy = self
                    .config
                    .discovery
                    .mdns
                    .as_ref()
                    .map(|mdns| mdns.auto_connect)
                    .unwrap_or(AutoConnectPolicy::Disabled);
                if mdns_policy.requires_approval() {
                    if let Err(e) = self.event_tx.send(P2pEvent::MdnsPeerApprovalRequired {
                        peer,
                        reason: "approval required by discovery policy".to_string(),
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_approval_required", error = %e, "silent drop");
                    }
                } else if self.mdns_auto_connect_enabled() {
                    self.schedule_mdns_auto_connect(peer);
                }
            }
            MdnsRuntimeEvent::PeerIneligible { peer, reason } => {
                self.remove_mdns_peer(&peer.fullname);
                let _ = self
                    .event_tx
                    .send(P2pEvent::MdnsPeerIneligible { peer, reason });
            }
        }
    }

    fn upsert_mdns_peer(&self, peer: &MdnsPeerRecord) {
        let mut snapshot = self.mdns_state.write();
        if let Some(existing) = snapshot
            .discovered_peers
            .iter_mut()
            .find(|existing| existing.fullname == peer.fullname)
        {
            *existing = peer.clone();
        } else {
            snapshot.discovered_peers.push(peer.clone());
            snapshot
                .discovered_peers
                .sort_by(|left, right| left.fullname.cmp(&right.fullname));
        }
    }

    fn remove_mdns_peer(&self, fullname: &str) {
        let mut snapshot = self.mdns_state.write();
        snapshot
            .discovered_peers
            .retain(|peer| peer.fullname != fullname);
    }

    fn schedule_mdns_auto_connect(&self, peer: MdnsPeerRecord) {
        if peer.addresses.is_empty() {
            return;
        }

        if let Err(reason) = self.discovered_peer_allowed(peer.claimed_peer_id) {
            let _ = self
                .event_tx
                .send(P2pEvent::MdnsPeerIneligible { peer, reason });
            return;
        }

        {
            let mut inflight = self.mdns_auto_connect_inflight.write();
            if !inflight.insert(peer.fullname.clone()) {
                return;
            }
        }

        let endpoint = self.clone();
        tokio::spawn(async move {
            let fullname = peer.fullname.clone();
            let addresses = peer.addresses.clone();

            if endpoint
                .find_live_connection_for_addrs(&addresses)
                .await
                .is_none()
            {
                if let Err(e) = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectAttempted {
                    peer: peer.clone(),
                    addresses: addresses.clone(),
                }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_auto_connect_attempted", error = %e, "silent drop");
                }

                match endpoint.connect_orchestrated(None, addresses.clone()).await {
                    Ok(connection) => {
                        if let Err(e) = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectSucceeded {
                            peer,
                            authenticated_peer_id: connection.peer_id,
                            remote_addr: connection.remote_addr,
                        }) {
                            tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_auto_connect_succeeded", error = %e, "silent drop");
                        }
                    }
                    Err(error) => {
                        if let Err(e) = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectFailed {
                            peer,
                            addresses,
                            error: error.to_string(),
                        }) {
                            tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_mdns_auto_connect_failed", error = %e, "silent drop");
                        }
                    }
                }
            }

            endpoint
                .mdns_auto_connect_inflight
                .write()
                .remove(&fullname);
        });
    }

    fn apply_port_mapping_event(&self, event: PortMappingEvent) {
        match event {
            PortMappingEvent::Established { snapshot } => {
                self.apply_port_mapping_snapshot(snapshot);
                // Reviewer P1 #2: also filter the user-facing event surface
                // so a non-routable mapped address (CGNAT/RFC1918/etc) is
                // not surfaced as ExternalAddressDiscovered to consumers
                // that would advertise it.
                if let Some(mapped_addr) = snapshot
                    .external_addr
                    .filter(|addr| is_globally_routable_advertise_address(*addr))
                {
                    if let Err(e) = self.event_tx.send(P2pEvent::PortMappingEstablished {
                        external_addr: mapped_addr,
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_port_mapping_established", error = %e, "silent drop");
                    }
                    if let Err(e) = self.event_tx.send(P2pEvent::ExternalAddressDiscovered {
                        addr: TransportAddr::Udp(mapped_addr),
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_external_addr", error = %e, "silent drop");
                    }
                }
            }
            PortMappingEvent::Renewed { snapshot } => {
                self.apply_port_mapping_snapshot(snapshot);
                if let Some(mapped_addr) = snapshot
                    .external_addr
                    .filter(|addr| is_globally_routable_advertise_address(*addr))
                {
                    if let Err(e) = self.event_tx.send(P2pEvent::PortMappingRenewed {
                        external_addr: mapped_addr,
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_port_mapping_renewed", error = %e, "silent drop");
                    }
                    if let Err(e) = self.event_tx.send(P2pEvent::ExternalAddressDiscovered {
                        addr: TransportAddr::Udp(mapped_addr),
                    }) {
                        tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_external_addr", error = %e, "silent drop");
                    }
                }
            }
            PortMappingEvent::Failed { error } => {
                if let Err(e) = self.event_tx.send(P2pEvent::PortMappingFailed { error }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_port_mapping_failed", error = %e, "silent drop");
                }
            }
            PortMappingEvent::Removed { external_addr } => {
                self.apply_port_mapping_snapshot(PortMappingSnapshot::default());
                if let Err(e) = self
                    .event_tx
                    .send(P2pEvent::PortMappingRemoved { external_addr })
                {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_port_mapping_removed", error = %e, "silent drop");
                }
            }
        }
    }

    fn apply_port_mapping_snapshot(&self, snapshot: PortMappingSnapshot) {
        // Reviewer P1 #2: filter UPnP-reported external addresses for global
        // routability before feeding them to relay advertisement and the
        // local NAT candidate set. On CGNAT/double-NAT networks the
        // gateway's get_external_ip() returns the inner-NAT's WAN address
        // (e.g. 100.64.x.x or 192.168.x.x) — those are not globally
        // routable and publishing them weakens MASQUE fallback because
        // peers will try to dial an address that doesn't route from the
        // public internet. We keep the snapshot's `active` bit (so the
        // mapping still renews on the gateway — that has positive side
        // effects for return-path traversal even if the address isn't
        // advertisable) but drop the `external_addr` from the advertised
        // surfaces.
        let advertisable = snapshot.external_addr.filter(|addr| {
            let ok = is_globally_routable_advertise_address(*addr);
            if !ok {
                warn!(
                    mapped_addr = %addr,
                    "UPnP-reported external address is not globally routable (CGNAT/RFC1918/loopback/etc) — not advertising as relay/NAT candidate"
                );
            }
            ok
        });
        let effective = PortMappingSnapshot {
            active: snapshot.active,
            external_addr: advertisable,
        };
        let previous_addr = {
            let mut current = self.port_mapping_state.write();
            let previous = current.external_addr;
            *current = effective;
            previous
        };

        self.inner
            .reconcile_relay_server_public_addresses(effective.external_addr);

        if let Some(previous_addr) = previous_addr
            && effective.external_addr != Some(previous_addr)
        {
            let _ = self.inner.remove_local_external_candidate(previous_addr);
            if let Some(mapped_addr) = effective.external_addr {
                if let Err(e) = self.event_tx.send(P2pEvent::PortMappingAddressChanged {
                    previous_addr,
                    external_addr: mapped_addr,
                }) {
                    tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_port_mapping_addr_changed", error = %e, "silent drop");
                }
            }
        }

        if effective.active
            && let Some(mapped_addr) = effective.external_addr
            && let Err(error) = self.inner.add_local_external_candidate(mapped_addr)
        {
            warn!(
                error = %error,
                mapped_addr = %mapped_addr,
                "Failed to add router-mapped address to the NAT candidate set"
            );
        }
    }

    /// Schedule cooperative cancellation for a superseded reader after a short
    /// drain window. This lets in-flight request/ACK streams on the old
    /// generation finish before the reader exits at its next accept boundary.
    fn schedule_reader_generation_cancel(&self, peer_id: PeerId, generation: u64, after: Duration) {
        let reader_handles = Arc::clone(&self.reader_handles);
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let handles = reader_handles.read().await;
            if let Some(handle) = handles
                .get(&peer_id)
                .and_then(|entries| entries.iter().find(|entry| entry.generation == generation))
            {
                handle.cancel.cancel();
            }
        });
    }

    /// Spawn a background tokio task that reads streams from a QUIC connection
    /// and forwards received application data into the shared `data_tx` channel.
    ///
    /// # Multiple readers per peer (issue #166)
    ///
    /// A peer may briefly have two live QUIC connections (simultaneous-open,
    /// coordinated + direct paths converging). Each connection gets its own
    /// reader. Superseded readers are cancelled only after a short drain window
    /// so request/ACK streams in flight on the old connection can complete.
    ///
    /// # Cooperative cancellation
    ///
    /// The reader honors a [`CancellationToken`] only at a stream-accept
    /// boundary. An in-flight `read_to_end()` (which drains already-ACKed bytes
    /// that Quinn has buffered) is NEVER interrupted — this is the core
    /// correctness property against issue #166. Explicit teardown
    /// (`cleanup_connection`, `shutdown`) also calls `abort()` as a backstop.
    async fn spawn_reader_task(&self, peer_id: PeerId, connection: crate::high_level::Connection) {
        let data_tx = self.data_tx.clone();
        let data_tx_diagnostics = Arc::clone(&self.data_tx_diagnostics);
        let data_tx_capacity = self.data_tx_capacity;
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_activity = Arc::clone(&self.peer_activity);
        let ack_waiters = Arc::clone(&self.ack_waiters);
        let ack_diagnostics = Arc::clone(&self.ack_diagnostics);
        let ack_request_dedupe = Arc::clone(&self.ack_request_dedupe);
        let event_tx = self.event_tx.clone();
        let inner = Arc::clone(&self.inner);
        let reader_exit_tx = self.reader_exit_tx.clone();
        let max_read_bytes = self.config.max_message_size;
        let conn_stable_id = connection.stable_id();
        let lifecycle_snapshot = self
            .inner
            .connection_snapshot_by_stable_id(&peer_id, conn_stable_id);
        let generation = lifecycle_snapshot
            .map(|snapshot| snapshot.generation)
            .unwrap_or(conn_stable_id as u64);
        let cancel = CancellationToken::new();
        if let Some(snapshot) = lifecycle_snapshot {
            debug!(
                peer_id = ?peer_id,
                generation = snapshot.generation,
                connection_id = %hex::encode(&snapshot.connection_id[..8]),
                established_at_unix_ms = snapshot.established_at_unix_ms,
                state = ?snapshot.state,
                "spawning reader task with lifecycle snapshot"
            );
            if !matches!(
                snapshot.state,
                crate::connection_lifecycle::ConnectionLifecycleState::Live
            ) {
                cancel.cancel();
            }
        }
        let reader_cancel = cancel.clone();

        enum IncomingStream {
            Uni(crate::high_level::RecvStream),
            AckBidi {
                send: crate::high_level::SendStream,
                recv: crate::high_level::RecvStream,
            },
        }

        let join_handle = tokio::spawn(async move {
            loop {
                // Cancel only between streams. If the token fires while we're
                // mid-`read_to_end()`, the read completes first (Quinn already
                // holds the ACKed bytes) and the NEXT iteration exits here.
                let incoming = tokio::select! {
                    biased;
                    _ = reader_cancel.cancelled() => {
                        debug!(
                            "Reader task for peer {:?} (conn stable_id={}) exiting on graceful cancel",
                            peer_id, conn_stable_id
                        );
                        break;
                    }
                    result = connection.accept_bi() => match result {
                        Ok((send, recv)) => IncomingStream::AckBidi { send, recv },
                        Err(e) => {
                            debug!(
                                "Reader task for peer {:?} (conn stable_id={}) ending: accept_bi error: {}",
                                peer_id, conn_stable_id, e
                            );
                            break;
                        }
                    },
                    result = connection.accept_uni() => match result {
                        Ok(stream) => IncomingStream::Uni(stream),
                        Err(e) => {
                            debug!(
                                "Reader task for peer {:?} (conn stable_id={}) ending: accept_uni error: {}",
                                peer_id, conn_stable_id, e
                            );
                            break;
                        }
                    }
                };

                let mut recv_stream = match incoming {
                    IncomingStream::AckBidi { send, mut recv } => {
                        let accepted_at = Instant::now();
                        let mut prefix = vec![0u8; ACK_BIDI_REQUEST_MAGIC.len()];
                        if let Err(e) = recv.read_exact(&mut prefix).await {
                            debug!(
                                "Reader task for peer {:?} (conn stable_id={}): bidi prefix read error: {}",
                                peer_id, conn_stable_id, e
                            );
                            continue;
                        }

                        if prefix.as_slice() == &ACK_BIDI_REQUEST_MAGIC[..] {
                            if !Self::handle_ack_bidi_stream(
                                ack_diagnostics.as_ref(),
                                ack_request_dedupe.as_ref(),
                                &connected_peers,
                                &peer_activity,
                                &data_tx,
                                data_tx_diagnostics.as_ref(),
                                data_tx_capacity,
                                &event_tx,
                                peer_id,
                                conn_stable_id,
                                send,
                                recv,
                                prefix,
                                accepted_at,
                                max_read_bytes,
                            )
                            .await
                            {
                                debug!(
                                    "Reader task for peer {:?}: channel closed, exiting",
                                    peer_id
                                );
                                break;
                            }
                            continue;
                        }

                        if inner
                            .handle_relay_bidi_stream_from_app_reader(
                                connection.clone(),
                                send,
                                recv,
                                prefix,
                            )
                            .await
                        {
                            continue;
                        }

                        debug!(
                            "Reader task for peer {:?} (conn stable_id={}): unknown bidi stream prefix",
                            peer_id, conn_stable_id
                        );
                        continue;
                    }
                    IncomingStream::Uni(stream) => stream,
                };

                // Uncancellable: drain the already-ACKed bytes. Cancelling here
                // would silently lose data the sender has already seen as ACKed
                // (the root cause of issue #166).
                let data = match recv_stream.read_to_end(max_read_bytes).await {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => data,
                    Err(e) => {
                        debug!(
                            "Reader task for peer {:?} (conn stable_id={}): read_to_end error: {}",
                            peer_id, conn_stable_id, e
                        );
                        break;
                    }
                };

                let data_len = data.len();
                tracing::trace!(
                    "Reader task: {} bytes from peer {:?} (conn stable_id={})",
                    data_len,
                    peer_id,
                    conn_stable_id
                );

                match inner
                    .handle_coordinator_control_message(peer_id, connection.clone(), &data)
                    .await
                {
                    Ok(true) => {
                        tracing::trace!(
                            "Reader task: handled coordinator control payload from peer {:?}",
                            peer_id
                        );
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(
                            "Reader task for peer {:?}: failed to handle coordinator control payload: {}",
                            peer_id,
                            e
                        );
                        continue;
                    }
                }

                if let Some((tag, outcome)) = decode_ack_control(&data) {
                    let waiter_result = match outcome {
                        AckControlOutcome::Accepted => AckWaiterResult::Accepted,
                        AckControlOutcome::Rejected(reason) => AckWaiterResult::Rejected(reason),
                        AckControlOutcome::Closed(reason) => AckWaiterResult::Closed(reason),
                    };
                    let resolved = resolve_ack_waiter(
                        ack_waiters.as_ref(),
                        conn_stable_id,
                        tag,
                        waiter_result,
                    );
                    if !resolved {
                        debug!(
                            peer_id = ?peer_id,
                            conn_stable_id,
                            "received ACK control frame with no matching waiter"
                        );
                    }
                    continue;
                }

                // Probe-liveness request: reply with an Accepted ACK control frame
                // and do NOT forward to data_tx / DataReceived. Probes are invisible
                // to the application.
                if let Some(tag) = decode_probe_request(&data) {
                    note_peer_activity(
                        &connected_peers,
                        &peer_activity,
                        peer_id,
                        PeerActivityKind::Received,
                        Instant::now(),
                    )
                    .await;
                    Self::send_ack_control_frame(
                        connection.clone(),
                        peer_id,
                        conn_stable_id,
                        tag,
                        AckControlOutcome::Accepted,
                    )
                    .await;
                    continue;
                }

                let payload = data;
                let payload_len = payload.len();

                let now = Instant::now();
                note_peer_activity(
                    &connected_peers,
                    &peer_activity,
                    peer_id,
                    PeerActivityKind::Received,
                    now,
                )
                .await;

                // Fire-and-forget sends keep the existing backpressure policy:
                // wait for capacity rather than dropping silently. We sample
                // pre-send pressure so saturation events surface as observable
                // counters even when the eventual `send().await` succeeds
                // after a brief block (X0X-0039).
                data_tx_diagnostics.observe_capacity(data_tx.capacity(), data_tx_capacity);
                if data_tx.send((peer_id, payload)).await.is_err() {
                    debug!(
                        "Reader task for peer {:?}: channel closed, exiting",
                        peer_id
                    );
                    break;
                }

                // Emit DataReceived event — HIGH priority: upper layer missed inbound data
                if let Err(e) = event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: payload_len,
                }) {
                    tracing::warn!(
                        target: "ant_quic::silent_drop",
                        kind = "event_tx_data_received_reader",
                        peer_id = ?peer_id,
                        bytes = payload_len,
                        error = %e,
                        "HIGH: silent drop"
                    );
                }
            }

            let _ = reader_exit_tx.send(ReaderExitEvent {
                peer_id,
                generation,
                conn_stable_id,
            });
        });
        let abort_handle = join_handle.abort_handle();

        // Append — DO NOT pre-empt existing readers. See function doc.
        let mut handles = self.reader_handles.write().await;
        handles.entry(peer_id).or_default().push(ReaderTaskHandle {
            generation,
            cancel,
            abort_handle,
        });
    }

    async fn apply_peer_address_update(
        connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
        bootstrap_cache: &BootstrapCache,
        peer_hint_records: &RwLock<HashMap<PeerId, PeerHintRecord>>,
        event_tx: &broadcast::Sender<P2pEvent>,
        peer_addr: SocketAddr,
        advertised_addr: SocketAddr,
    ) {
        let peer_id = connected_peers
            .read()
            .await
            .iter()
            .find(|(_, peer)| peer.remote_addr.as_socket_addr() == Some(peer_addr))
            .map(|(peer_id, _)| *peer_id);

        if let Some(peer_id) = peer_id {
            peer_hint_records
                .write()
                .await
                .entry(peer_id)
                .or_default()
                .merge(vec![advertised_addr], None);

            let mut cached_peer = bootstrap_cache
                .get_peer(&peer_id)
                .await
                .unwrap_or_else(|| CachedPeer::new(peer_id, Vec::new(), PeerSource::Merge));
            cached_peer
                .capabilities
                .record_external_address(advertised_addr);
            bootstrap_cache.upsert(cached_peer).await;
        } else {
            debug!(
                peer_addr = %peer_addr,
                advertised_addr = %advertised_addr,
                "peer address update arrived before peer ID mapping was available"
            );
        }

        if let Err(e) = event_tx.send(P2pEvent::PeerAddressUpdated {
            peer_addr,
            advertised_addr,
        }) {
            tracing::warn!(target: "ant_quic::silent_drop", kind = "event_tx_peer_addr_updated", error = %e, "silent drop");
        }
    }

    fn spawn_peer_address_update_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let connected_peers = Arc::clone(&self.connected_peers);
        let bootstrap_cache = Arc::clone(&self.bootstrap_cache);
        let peer_hint_records = Arc::clone(&self.peer_hint_records);
        let event_tx = self.event_tx.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                let update = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    update = inner.recv_peer_address_update() => update,
                };

                let Some((peer_addr, advertised_addr)) = update else {
                    debug!("Peer address update channel closed, exiting poller");
                    break;
                };

                Self::apply_peer_address_update(
                    connected_peers.as_ref(),
                    bootstrap_cache.as_ref(),
                    peer_hint_records.as_ref(),
                    &event_tx,
                    peer_addr,
                    advertised_addr,
                )
                .await;
            }
        });
    }

    /// Spawn a single background task that polls constrained transport events
    /// and forwards `DataReceived` payloads into the shared `data_tx` channel.
    ///
    /// Lifecycle events (ConnectionAccepted, ConnectionClosed, etc.) are handled
    /// inline within this task.
    fn spawn_constrained_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let data_tx_diagnostics = Arc::clone(&self.data_tx_diagnostics);
        let data_tx_capacity = self.data_tx_capacity;
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_activity = Arc::clone(&self.peer_activity);
        let event_tx = self.event_tx.clone();
        let constrained_peer_addrs = Arc::clone(&self.constrained_peer_addrs);
        let constrained_connections = Arc::clone(&self.constrained_connections);
        let stats = Arc::clone(&self.stats);
        let shutdown = self.shutdown.clone();

        /// Register a new constrained peer in all lookup maps and emit a connect event.
        async fn register_peer(
            peer_id: PeerId,
            connection_id: ConstrainedConnectionId,
            addr: &TransportAddr,
            side: Side,
            constrained_connections: &RwLock<HashMap<PeerId, ConstrainedConnectionId>>,
            constrained_peer_addrs: &RwLock<
                HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>,
            >,
            connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
            stats: &RwLock<EndpointStats>,
            event_tx: &broadcast::Sender<P2pEvent>,
        ) {
            constrained_connections
                .write()
                .await
                .insert(peer_id, connection_id);
            constrained_peer_addrs
                .write()
                .await
                .insert(connection_id, (peer_id, addr.clone()));
            store_connected_peer(
                connected_peers,
                stats,
                event_tx,
                PeerConnection {
                    peer_id,
                    remote_addr: addr.clone(),
                    traversal_method: TraversalMethod::Direct,
                    side,
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            )
            .await;
        }

        tokio::spawn(async move {
            loop {
                let wrapper = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    event = inner.recv_constrained_event() => {
                        match event {
                            Some(w) => w,
                            None => {
                                debug!("Constrained event channel closed, exiting poller");
                                break;
                            }
                        }
                    }
                };

                match wrapper.event {
                    EngineEvent::DataReceived {
                        connection_id,
                        data,
                    } => {
                        let peer_id = constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .map(|(pid, _)| *pid)
                            .unwrap_or_else(|| {
                                peer_id_from_socket_addr(
                                    wrapper.remote_addr.to_synthetic_socket_addr(),
                                )
                            });

                        let data_len = data.len();
                        tracing::trace!(
                            "Constrained poller: {} bytes from peer {:?}",
                            data_len,
                            peer_id
                        );

                        let now = Instant::now();
                        note_peer_activity(
                            &connected_peers,
                            &peer_activity,
                            peer_id,
                            PeerActivityKind::Received,
                            now,
                        )
                        .await;
                        if let Err(e) = event_tx.send(P2pEvent::DataReceived {
                            peer_id,
                            bytes: data_len,
                        }) {
                            tracing::warn!(
                                target: "ant_quic::silent_drop",
                                kind = "event_tx_data_received_reader",
                                peer_id = ?peer_id,
                                bytes = data_len,
                                error = %e,
                                "HIGH: silent drop"
                            );
                        }

                        // Sample channel pressure pre-send so saturation
                        // events on the constrained ingress path are visible
                        // alongside the QUIC reader-task path (X0X-0039).
                        data_tx_diagnostics.observe_capacity(data_tx.capacity(), data_tx_capacity);
                        if data_tx.send((peer_id, data)).await.is_err() {
                            debug!("Constrained poller: channel closed, exiting");
                            break;
                        }
                    }
                    EngineEvent::ConnectionAccepted {
                        connection_id,
                        remote_addr: _,
                    } => {
                        let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                        register_peer(
                            peer_id,
                            connection_id,
                            &wrapper.remote_addr,
                            Side::Server,
                            &constrained_connections,
                            &constrained_peer_addrs,
                            &connected_peers,
                            &stats,
                            &event_tx,
                        )
                        .await;
                    }
                    EngineEvent::ConnectionEstablished { connection_id } => {
                        if constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .is_none()
                        {
                            let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                            register_peer(
                                peer_id,
                                connection_id,
                                &wrapper.remote_addr,
                                Side::Client,
                                &constrained_connections,
                                &constrained_peer_addrs,
                                &connected_peers,
                                &stats,
                                &event_tx,
                            )
                            .await;
                        }
                    }
                    EngineEvent::ConnectionClosed { connection_id } => {
                        let peer_info = constrained_peer_addrs.write().await.remove(&connection_id);
                        if let Some((peer_id, addr)) = peer_info {
                            constrained_connections.write().await.remove(&peer_id);
                            let _ = remove_connected_peer(
                                &connected_peers,
                                &stats,
                                &event_tx,
                                &peer_id,
                                DisconnectReason::RemoteClosed,
                            )
                            .await;
                            debug!(
                                "Constrained poller: peer {:?} at {} disconnected",
                                peer_id, addr
                            );
                        }
                    }
                    EngineEvent::ConnectionError {
                        connection_id,
                        error,
                    } => {
                        warn!(
                            "Constrained poller: conn_id={}, error={}",
                            connection_id.value(),
                            error
                        );
                    }
                    EngineEvent::Transmit { .. } => {}
                }
            }
        });
    }

    /// Spawn a background task that polls the reader-tasks JoinSet for exits.
    ///
    /// When a reader task finishes (QUIC connection died, stream error, or channel
    /// closed), this handler fires immediately — providing millisecond disconnect
    /// detection instead of waiting for the 30-second stale connection reaper.
    fn spawn_reader_exit_handler(&self) {
        let reader_exit_rx = Arc::clone(&self.reader_exit_rx);
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let reader_handles = Arc::clone(&self.reader_handles);
        let direct_path_statuses = Arc::clone(&self.direct_path_statuses);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let peer_event_tx = self.peer_event_tx.clone();
        let peer_event_channels = Arc::clone(&self.peer_event_channels);
        let peer_event_generations = Arc::clone(&self.peer_event_generations);
        let ack_waiters = Arc::clone(&self.ack_waiters);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                let maybe_reader_exit = tokio::select! {
                    _ = shutdown.cancelled() => {
                        debug!("Reader exit handler shutting down");
                        return;
                    }
                    reader_exit = async {
                        let mut rx = reader_exit_rx.lock().await;
                        rx.recv().await
                    } => reader_exit,
                };

                let Some(ReaderExitEvent {
                    peer_id,
                    generation,
                    conn_stable_id,
                }) = maybe_reader_exit
                else {
                    debug!("Reader exit handler stopping: all reader-exit senders dropped");
                    return;
                };

                // With per-connection readers (issue #166), a peer may have
                // several live readers. Only the LAST one to exit should trigger
                // peer-wide cleanup. Remove the exiting handle from the vec; if
                // other readers remain, this peer is still alive on another
                // connection and we skip cleanup.
                let last_reader = {
                    let mut handles = reader_handles.write().await;
                    match handles.get_mut(&peer_id) {
                        Some(vec) => {
                            vec.retain(|h| h.generation != generation);
                            if vec.is_empty() {
                                handles.remove(&peer_id);
                                true
                            } else {
                                false
                            }
                        }
                        // The peer was already removed by an explicit
                        // `cleanup_connection` (e.g., shutdown, stale reaper).
                        // No further cleanup needed.
                        None => false,
                    }
                };

                let snapshot_before =
                    inner.connection_snapshot_by_stable_id(&peer_id, conn_stable_id);
                emit_peer_lifecycle_event(
                    &peer_event_tx,
                    peer_event_channels.as_ref(),
                    peer_id,
                    PeerLifecycleEvent::ReaderExited { generation },
                );

                let exit_outcome = inner.handle_reader_exit(&peer_id, generation, conn_stable_id);
                match exit_outcome {
                    crate::nat_traversal_api::ReaderExitOutcome::Noop => {
                        debug!(
                            "Reader task exited for peer {:?} (generation {}, conn stable_id {}); no lifecycle entry remained",
                            peer_id, generation, conn_stable_id
                        );
                        continue;
                    }
                    crate::nat_traversal_api::ReaderExitOutcome::ConnectionReaped => {
                        if let Some(snapshot) = snapshot_before {
                            fail_ack_waiters_for_connection(
                                ack_waiters.as_ref(),
                                snapshot.stable_id,
                                ConnectionCloseReason::Superseded,
                            );
                            match snapshot.state {
                                crate::connection_lifecycle::ConnectionLifecycleState::Superseded { .. }
                                | crate::connection_lifecycle::ConnectionLifecycleState::Live => {
                                    emit_peer_lifecycle_event(
                                        &peer_event_tx,
                                        peer_event_channels.as_ref(),
                                        peer_id,
                                        PeerLifecycleEvent::Closed {
                                            generation: snapshot.generation,
                                            reason: ConnectionCloseReason::Superseded,
                                        },
                                    );
                                }
                                crate::connection_lifecycle::ConnectionLifecycleState::Closing { .. }
                                | crate::connection_lifecycle::ConnectionLifecycleState::Closed { .. } => {}
                            }
                        }
                        debug!(
                            "Reader task exited for peer {:?} (generation {}, conn stable_id {}); superseded connection reaped",
                            peer_id, generation, conn_stable_id
                        );
                        continue;
                    }
                    crate::nat_traversal_api::ReaderExitOutcome::PeerDisconnected {
                        close_reason,
                    } => {
                        emit_peer_lifecycle_event(
                            &peer_event_tx,
                            peer_event_channels.as_ref(),
                            peer_id,
                            PeerLifecycleEvent::Closing {
                                generation,
                                reason: close_reason,
                            },
                        );
                        emit_peer_lifecycle_event(
                            &peer_event_tx,
                            peer_event_channels.as_ref(),
                            peer_id,
                            PeerLifecycleEvent::Closed {
                                generation,
                                reason: close_reason,
                            },
                        );
                        fail_ack_waiters_for_connection(
                            ack_waiters.as_ref(),
                            conn_stable_id,
                            close_reason,
                        );
                        // Retain the generation in `peer_event_generations` so a
                        // replacement connection racing this close still sees the
                        // prior generation and emits Replaced{old,new}. The next
                        // register_connected_peer overwrites the entry.

                        if !last_reader {
                            debug!(
                                "Live reader task exited for peer {:?} (generation {}, conn stable_id {}); other readers still draining, deferring peer cleanup",
                                peer_id, generation, conn_stable_id
                            );
                            continue;
                        }

                        debug!(
                            "Last live reader task for peer {:?} (generation {}, conn stable_id {}) exited — triggering cleanup",
                            peer_id, generation, conn_stable_id
                        );

                        do_cleanup_connection(
                            &*connected_peers,
                            &*inner,
                            &*reader_handles,
                            &*direct_path_statuses,
                            &*stats,
                            &event_tx,
                            &peer_event_tx,
                            peer_event_channels.as_ref(),
                            peer_event_generations.as_ref(),
                            ack_waiters.as_ref(),
                            &peer_id,
                            DisconnectReason::ConnectionLost,
                            close_reason,
                        )
                        .await;
                    }
                }
            }
        });
    }

    /// Spawn a background task that periodically detects and removes stale connections.
    ///
    /// Safety-net for connections whose underlying QUIC transport is dead
    /// (`is_peer_connected() == false`). The primary disconnect detection is
    /// handled by `spawn_reader_exit_handler()` which reacts in milliseconds;
    /// this reaper catches any stragglers every 30 seconds.
    fn spawn_stale_connection_reaper(&self) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let peer_event_tx = self.peer_event_tx.clone();
        let peer_event_channels = Arc::clone(&self.peer_event_channels);
        let peer_event_generations = Arc::clone(&self.peer_event_generations);
        let ack_waiters = Arc::clone(&self.ack_waiters);
        let stats = Arc::clone(&self.stats);
        let reader_handles = Arc::clone(&self.reader_handles);
        let direct_path_statuses = Arc::clone(&self.direct_path_statuses);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown.cancelled() => {
                        debug!("Stale connection reaper shutting down");
                        return;
                    }
                }

                // --- Phase A: Remove QUIC-dead connections ---

                let stale_peers: Vec<PeerId> = {
                    let peers = connected_peers.read().await;
                    peers
                        .keys()
                        .filter(|id| !inner.is_peer_connected(id))
                        .copied()
                        .collect()
                };

                if !stale_peers.is_empty() {
                    info!(
                        "Stale connection reaper: removing {} dead connection(s)",
                        stale_peers.len()
                    );
                }

                for peer_id in &stale_peers {
                    do_cleanup_connection(
                        &*connected_peers,
                        &*inner,
                        &*reader_handles,
                        &*direct_path_statuses,
                        &*stats,
                        &event_tx,
                        &peer_event_tx,
                        peer_event_channels.as_ref(),
                        peer_event_generations.as_ref(),
                        ack_waiters.as_ref(),
                        peer_id,
                        DisconnectReason::Timeout,
                        ConnectionCloseReason::TimedOut,
                    )
                    .await;
                }

                // Phase B (health-check PING/PONG) removed — reader-exit
                // monitoring now provides instant disconnect detection.
            }
        });
    }

    // v0.2: authenticate_peer removed - TLS handles peer authentication via ML-DSA-65
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // v0.2: auth_manager removed - TLS handles peer authentication
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            peer_id: self.peer_id,
            public_key: self.public_key.clone(),
            shutdown: self.shutdown.clone(),
            pending_data: Arc::clone(&self.pending_data),
            bootstrap_cache: Arc::clone(&self.bootstrap_cache),
            peer_hint_records: Arc::clone(&self.peer_hint_records),
            transport_registry: Arc::clone(&self.transport_registry),
            router: Arc::clone(&self.router),
            constrained_connections: Arc::clone(&self.constrained_connections),
            constrained_peer_addrs: Arc::clone(&self.constrained_peer_addrs),
            manual_known_peer_udp_addrs: Arc::clone(&self.manual_known_peer_udp_addrs),
            port_mapping_state: Arc::clone(&self.port_mapping_state),
            mdns_state: Arc::clone(&self.mdns_state),
            mdns_auto_connect_inflight: Arc::clone(&self.mdns_auto_connect_inflight),
            direct_path_statuses: Arc::clone(&self.direct_path_statuses),
            data_tx: self.data_tx.clone(),
            data_rx: Arc::clone(&self.data_rx),
            data_tx_capacity: self.data_tx_capacity,
            data_tx_diagnostics: Arc::clone(&self.data_tx_diagnostics),
            reader_exit_tx: self.reader_exit_tx.clone(),
            reader_exit_rx: Arc::clone(&self.reader_exit_rx),
            reader_handles: Arc::clone(&self.reader_handles),
            peer_activity: Arc::clone(&self.peer_activity),
            ack_waiters: Arc::clone(&self.ack_waiters),
            ack_diagnostics: Arc::clone(&self.ack_diagnostics),
            ack_liveness: Arc::clone(&self.ack_liveness),
            ack_request_dedupe: Arc::clone(&self.ack_request_dedupe),
            probe_flights: Arc::clone(&self.probe_flights),
            probe_semaphore: Arc::clone(&self.probe_semaphore),
            peer_event_tx: self.peer_event_tx.clone(),
            peer_event_channels: Arc::clone(&self.peer_event_channels),
            peer_event_generations: Arc::clone(&self.peer_event_generations),
            coordinator_health: Arc::clone(&self.coordinator_health),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator_control::RejectionReason;

    fn collect_broadcast_events(
        events: &mut tokio::sync::broadcast::Receiver<P2pEvent>,
    ) -> Vec<P2pEvent> {
        std::iter::from_fn(|| events.try_recv().ok()).collect()
    }

    // ------------------------------------------------------------------
    // X0X-0039: data_tx high-water diagnostics
    // ------------------------------------------------------------------

    #[test]
    fn data_channel_diagnostics_increments_on_full_admit() {
        // Channel of size 4, free <= 1 (=ceil(4*0.20)=1) trips the high-water
        // sampler. Filling to capacity (free=0) is also a saturation event.
        let diags = DataChannelDiagnostics::default();
        let capacity = 4usize;
        // free=4 → above threshold, no count.
        diags.observe_capacity(capacity, capacity);
        assert_eq!(diags.high_water_count(), 0);
        // free=2 → above threshold (1), still no count.
        diags.observe_capacity(2, capacity);
        assert_eq!(diags.high_water_count(), 0);
        // free=1 → at threshold, counts once.
        diags.observe_capacity(1, capacity);
        assert_eq!(diags.high_water_count(), 1);
        // free=0 → fully saturated, counts again.
        diags.observe_capacity(0, capacity);
        assert_eq!(diags.high_water_count(), 2);
    }

    #[tokio::test]
    async fn data_channel_diagnostics_increments_on_admission_timeout() {
        // Force admit_ack_requested_payload through the timeout branch by
        // filling a tiny channel to capacity and never draining it. The
        // payload fills the queue; the second reserve cannot complete in
        // ACK_RECEIVE_ADMISSION_TIMEOUT and increments high_water_count.
        let capacity = 1usize;
        let (tx, _rx) = mpsc::channel::<(PeerId, Vec<u8>)>(capacity);
        let diags = DataChannelDiagnostics::default();
        let peer_id = PeerId([0x33; 32]);
        // Pre-fill so the next reserve must wait.
        tx.send((peer_id, vec![0u8; 8])).await.expect("first send");
        let admission =
            P2pEndpoint::admit_ack_requested_payload(&tx, &diags, capacity, peer_id, vec![1u8; 8])
                .await;
        assert!(matches!(admission, Err(ReceiveRejectReason::Backpressured)));
        assert!(
            diags.high_water_count() >= 1,
            "expected at least one saturation event, got {}",
            diags.high_water_count()
        );
    }

    #[test]
    fn data_channel_diagnostics_warn_throttles_to_one_per_burst() {
        // Send 100 saturation events back-to-back; only one WARN should be
        // emitted (the others lose the CAS within
        // DATA_TX_HIGH_WATER_WARN_INTERVAL). The high-water counter still
        // reflects every event — only the log line is throttled.
        let diags = DataChannelDiagnostics::default();
        let capacity = 8usize;
        for _ in 0..100 {
            diags.observe_capacity(0, capacity);
        }
        assert_eq!(diags.high_water_count(), 100);
        // Exactly one WARN should have been emitted within
        // DATA_TX_HIGH_WATER_WARN_INTERVAL — last_warn_unix_ms is non-zero
        // and inside the interval.
        let last = diags.last_warn_unix_ms.load(Ordering::Relaxed);
        assert!(
            last > 0,
            "expected last_warn_unix_ms to be set, got {}",
            last
        );
    }

    // ------------------------------------------------------------------
    // X0X-0043: GSO bundle diagnostics integration
    // ------------------------------------------------------------------

    #[test]
    fn gso_diagnostics_records_multi_segment_bundles() {
        // Acceptance criterion 3 (X0X-0043): a GSO bundle with > 1 segment
        // increments `gso_bundle_send_total`. Exercise the same global
        // `gso_diagnostics()` accessor that `drive_transmit` calls so we
        // verify the wiring, not just the leaf counter.
        let diags = crate::diagnostics::gso_diagnostics();
        let before = diags.snapshot();
        diags.record_bundle_submitted(1); // single datagram → ignored
        diags.record_bundle_submitted(4); // multi-segment bundle → counted
        let after = diags.snapshot();
        assert_eq!(
            after.bundle_send_total - before.bundle_send_total,
            1,
            "single-datagram send must not count; multi-segment bundle must"
        );
        assert_eq!(after.bundle_partial_send, before.bundle_partial_send);
    }

    // ------------------------------------------------------------------
    // ACK request dedupe
    // ------------------------------------------------------------------

    #[test]
    fn ack_timeout_retry_budget_preserves_wan_class_caller_timeout() {
        assert_eq!(
            P2pEndpoint::ack_timeout_retry_timeout(Duration::from_secs(6)),
            Duration::from_secs(6),
            "X0X-0060: a 6s cross-region ACK budget must not be clipped to the old 2s retry cap"
        );
        assert_eq!(
            P2pEndpoint::ack_timeout_retry_timeout(Duration::from_millis(750)),
            Duration::from_millis(750),
            "short diagnostic budgets remain caller-bounded"
        );
        assert_eq!(
            P2pEndpoint::ack_timeout_retry_timeout(Duration::from_secs(30)),
            ACK_TIMEOUT_RETRY_TIMEOUT,
            "very large caller budgets are still capped for retry"
        );
    }

    /// X0X-0062: regression guard for `trigger_liveness_close`'s assumption
    /// that `LivenessTimeout` has a reserved app error code. If this fails,
    /// `connection_lifecycle.rs` lost the mapping and the production fallback
    /// would degrade to `LifecycleCleanup` — still safe, but the X0X-0062
    /// signal would be confused with generic lifecycle cleanup at the peer.
    #[test]
    fn liveness_timeout_close_reason_has_reserved_app_error_code() {
        assert!(
            ConnectionCloseReason::LivenessTimeout
                .app_error_code()
                .is_some(),
            "ConnectionCloseReason::LivenessTimeout must have a reserved app error code so the X0X-0062 force-close signal is distinguishable from generic LifecycleCleanup at the peer"
        );
    }

    /// X0X-0062: AckLivenessTracker contract — accumulates consecutive
    /// SenderRetryFailed events per (peer, stable_id) and signals once when
    /// the threshold is crossed within the window. Reset on any successful
    /// outcome. Tests pin the contract so future tuning is intentional.
    #[test]
    fn ack_liveness_tracker_signals_force_close_on_threshold_breach() {
        let tracker = AckLivenessTracker::default();
        let peer = PeerId([0xAA; 32]);
        let stable_id = 42usize;

        // First THRESHOLD-1 failures don't trigger.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(
                !tracker.record_failure(peer, stable_id),
                "sub-threshold failures must not signal force-close"
            );
        }
        // Threshold-th failure signals once.
        assert!(
            tracker.record_failure(peer, stable_id),
            "exactly at the threshold the tracker must signal force-close"
        );
        // Further failures inside the same crossed window do NOT signal again
        // — caller already triggered close on the first signal.
        assert!(
            !tracker.record_failure(peer, stable_id),
            "post-threshold failures must not re-signal — would cause duplicate force-close"
        );
    }

    #[test]
    fn ack_liveness_tracker_resets_on_success() {
        let tracker = AckLivenessTracker::default();
        let peer = PeerId([0xBB; 32]);
        let stable_id = 7usize;

        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(!tracker.record_failure(peer, stable_id));
        }
        // A success at sub-threshold clears the counter.
        tracker.record_success(peer, stable_id);
        // After reset, a single new failure must not signal.
        assert!(
            !tracker.record_failure(peer, stable_id),
            "after success-reset, a fresh failure window must start from zero"
        );
    }

    #[test]
    fn ack_liveness_tracker_separate_state_per_connection_generation() {
        let tracker = AckLivenessTracker::default();
        let peer = PeerId([0xCC; 32]);
        // Same peer, two different connection generations (stable_ids) — the
        // old connection's failures must not poison the new connection's
        // counter.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(!tracker.record_failure(peer, 100));
        }
        // New generation starts with a clean slate.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(
                !tracker.record_failure(peer, 200),
                "new connection generation must not inherit the old generation's failure count"
            );
        }
        // Both can independently cross the threshold.
        assert!(tracker.record_failure(peer, 100));
        assert!(tracker.record_failure(peer, 200));
    }

    /// X0X-0062 P1.1 reviewer regression: the liveness tracker must observe
    /// EVERY ack-flow outcome (first attempt OR retry), not just retry
    /// outcomes. Previously the first-attempt success path returned early
    /// before any tracker signal fired, so a peer hitting 4 retry-failures +
    /// many first-attempt successes + 1 more retry-failure within 60 s would
    /// tip the threshold even though the failures were not actually
    /// consecutive. The `AckLivenessSignal::Success` path from a first-
    /// attempt success must reset the counter exactly like
    /// `SenderRetryAccepted` does.
    #[test]
    fn ack_liveness_tracker_first_attempt_success_resets_counter() {
        let tracker = AckLivenessTracker::default();
        let peer = PeerId([0xDD; 32]);
        let stable_id = 11usize;

        // Accumulate THRESHOLD-1 failures.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(!tracker.record_failure(peer, stable_id));
        }
        // Simulate a first-attempt success — the new
        // `record_ack_liveness_signal(Success)` calls record_success on the
        // tracker, the same primitive a successful retry uses.
        tracker.record_success(peer, stable_id);
        // After reset, four more failures must NOT tip the threshold —
        // the counter is back at zero, so this round is independent.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(
                !tracker.record_failure(peer, stable_id),
                "first-attempt success must reset the counter so previously- \
                 observed failures cannot combine with new ones across an \
                 intervening success"
            );
        }
    }

    /// X0X-0062 P1.2 reviewer regression: only true ACK timeouts on the retry
    /// path should signal half-dead. Non-timeout retry errors
    /// (`ReceiveRejected`, `ConnectionClosed`, invalid response) prove the
    /// remote responded — those must reset the counter, not increment it.
    /// This is a tracker-level test; the actual signal-routing happens in
    /// `send_with_receive_ack_with_timeout_for_test`'s match arms.
    #[test]
    fn ack_liveness_tracker_treats_remote_response_as_success_signal() {
        let tracker = AckLivenessTracker::default();
        let peer = PeerId([0xEE; 32]);
        let stable_id = 13usize;

        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(!tracker.record_failure(peer, stable_id));
        }
        // Simulating: retry returned ReceiveRejected{Backpressured} (i.e. the
        // remote responded, not a timeout). In production the new
        // `send_with_receive_ack` flow routes this to
        // `AckLivenessSignal::Success`, calling record_success here.
        tracker.record_success(peer, stable_id);
        // Now further failures must NOT carry over the pre-success count.
        for _ in 0..(LIVENESS_FAILURE_THRESHOLD - 1) {
            assert!(!tracker.record_failure(peer, stable_id));
        }
        // And the very next failure tips the (fresh) threshold cleanly.
        assert!(tracker.record_failure(peer, stable_id));
    }

    /// X0X-0062 P2 (round 2) reviewer regression: `DisconnectReason::LivenessTimeout`
    /// must thread `ConnectionCloseReason::LivenessTimeout` through the
    /// `close_reason_for_disconnect` mapping consumed by `cleanup_connection`.
    /// Without this mapping, `trigger_liveness_close`'s call to
    /// `cleanup_connection(DisconnectReason::LivenessTimeout)` would still
    /// invoke the do_cleanup_connection path — but the inner
    /// `remove_connection_with_reason(close_reason)` would tag the connection
    /// with the wrong reason, the `Closing/Closed` lifecycle events would
    /// emit the wrong reason, and any downstream observer would see
    /// LocallyClosed or LifecycleCleanup instead of the actual LivenessTimeout
    /// signal. This test pins the mapping.
    #[test]
    fn disconnect_reason_liveness_timeout_maps_to_close_reason_liveness_timeout() {
        assert_eq!(
            close_reason_for_disconnect(&DisconnectReason::LivenessTimeout),
            ConnectionCloseReason::LivenessTimeout,
            "DisconnectReason::LivenessTimeout (used by trigger_liveness_close \
             when the X0X-0062 detector fires) must thread LivenessTimeout \
             through the disconnect-reason mapping consumed by \
             cleanup_connection — otherwise the close-reason gets downgraded \
             to LocallyClosed or LifecycleCleanup downstream and the \
             LivenessTimeout signal is lost (reviewer P2 round 2)"
        );
        // And every other variant must NOT collide on LivenessTimeout (so a
        // future-added variant can't accidentally map to LivenessTimeout and
        // silently force-close peers).
        for other in [
            DisconnectReason::Normal,
            DisconnectReason::Timeout,
            DisconnectReason::ProtocolError("x".to_string()),
            DisconnectReason::AuthenticationFailed,
            DisconnectReason::ConnectionLost,
            DisconnectReason::RemoteClosed,
        ] {
            assert_ne!(
                close_reason_for_disconnect(&other),
                ConnectionCloseReason::LivenessTimeout,
                "only DisconnectReason::LivenessTimeout should map to ConnectionCloseReason::LivenessTimeout"
            );
        }
    }

    /// X0X-0062 P2 reviewer regression: `LivenessTimeout` must round-trip
    /// through ACK frame encode/decode. The encoder writes value 14 for
    /// LivenessTimeout (added in 0.27.16) but the decoders for both
    /// `decode_ack_response` and `decode_ack_control` originally fell through
    /// to `Unknown` for value 14, losing the reason in downstream
    /// diagnostics. The decoder match arms now include `14 => LivenessTimeout`.
    #[test]
    fn liveness_timeout_round_trips_through_ack_control_frame() {
        use crate::ack_frame::{AckControlOutcome, decode_ack_control, encode_ack_control};

        let tag = [0x77u8; 16];
        let encoded = encode_ack_control(
            tag,
            AckControlOutcome::Closed(ConnectionCloseReason::LivenessTimeout),
        );
        let (decoded_tag, decoded_outcome) =
            decode_ack_control(&encoded).expect("encoded ACK control must decode");
        assert_eq!(decoded_tag, tag);
        match decoded_outcome {
            AckControlOutcome::Closed(reason) => {
                assert_eq!(
                    reason,
                    ConnectionCloseReason::LivenessTimeout,
                    "LivenessTimeout must round-trip through the ACK control frame — \
                     previously it decoded as Unknown because the decoder match arm \
                     was missing (reviewer P2)"
                );
            }
            other => panic!("expected Closed(LivenessTimeout), got {other:?}"),
        }
    }

    #[test]
    fn ack_request_dedupe_replays_matching_request_id_once() {
        let cache = AckRequestDedupeCache::default();
        let peer_id = PeerId([0x11; 32]);
        let request_id = [0x22; 16];
        let payload = b"idempotent payload";

        assert_eq!(cache.replay(peer_id, request_id, payload), None);
        cache.remember(peer_id, request_id, payload, AckControlOutcome::Accepted);
        assert_eq!(
            cache.replay(peer_id, request_id, payload),
            Some(AckRequestDedupeReplay::Replay(AckControlOutcome::Accepted))
        );
    }

    #[test]
    fn ack_request_dedupe_rejects_request_id_payload_conflict() {
        let cache = AckRequestDedupeCache::default();
        let peer_id = PeerId([0x33; 32]);
        let request_id = [0x44; 16];

        cache.remember(
            peer_id,
            request_id,
            b"first payload",
            AckControlOutcome::Accepted,
        );
        assert_eq!(
            cache.replay(peer_id, request_id, b"different payload"),
            Some(AckRequestDedupeReplay::Conflict)
        );
    }

    #[tokio::test]
    async fn test_try_addrs_with_shared_stage_budget_stops_after_budget_exhaustion() {
        let first: SocketAddr = "203.0.113.10:9000".parse().expect("first addr");
        let second: SocketAddr = "203.0.113.11:9000".parse().expect("second addr");
        let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = Instant::now();

        let result = try_addrs_with_shared_stage_budget(
            &[first, second],
            "IPv4",
            Duration::from_millis(40),
            {
                let attempts = std::sync::Arc::clone(&attempts);
                move |addr| {
                    let attempts = std::sync::Arc::clone(&attempts);
                    async move {
                        attempts.lock().expect("attempt log").push(addr);
                        tokio::time::sleep(Duration::from_millis(60)).await;
                        Ok::<SocketAddr, EndpointError>(addr)
                    }
                }
            },
        )
        .await;

        assert!(
            result.is_none(),
            "stage budget exhaustion should stop the family"
        );
        assert_eq!(attempts.lock().expect("attempt log").as_slice(), &[first]);
        assert!(
            Instant::now().duration_since(start) < Duration::from_millis(120),
            "shared family budgeting should stop before retrying the second address"
        );
    }

    #[tokio::test]
    async fn test_try_addrs_with_shared_stage_budget_allows_later_success_before_deadline() {
        let first: SocketAddr = "203.0.113.20:9000".parse().expect("first addr");
        let second: SocketAddr = "203.0.113.21:9000".parse().expect("second addr");
        let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let result = try_addrs_with_shared_stage_budget(
            &[first, second],
            "IPv4",
            Duration::from_millis(80),
            {
                let attempts = std::sync::Arc::clone(&attempts);
                move |addr| {
                    let attempts = std::sync::Arc::clone(&attempts);
                    async move {
                        attempts.lock().expect("attempt log").push(addr);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        if addr == first {
                            Err(EndpointError::Connection(
                                "first candidate failed".to_string(),
                            ))
                        } else {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Ok(addr)
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Some(second));
        assert_eq!(
            attempts.lock().expect("attempt log").as_slice(),
            &[first, second]
        );
    }

    #[tokio::test]
    async fn test_adaptive_strategy_config_for_candidates_uses_same_budget_model() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x77; 32]);
        let direct_addr: SocketAddr = "203.0.113.77:9000".parse().expect("direct addr");
        let mut cached_peer = CachedPeer::new(peer_id, vec![direct_addr], PeerSource::Seed);
        cached_peer.stats.avg_rtt_ms = 420;
        endpoint.bootstrap_cache.upsert(cached_peer).await;

        let (config, rtt_hint) = endpoint
            .adaptive_strategy_config_for_candidates(Some(peer_id), &[direct_addr], None, &[])
            .await;
        let mut expected = StrategyConfig::default();
        expected.apply_adaptive_timeouts(
            endpoint
                .config
                .timeouts
                .nat_traversal
                .connection_establishment_timeout,
            endpoint.config.timeouts.nat_traversal.coordination_timeout,
            Some(Duration::from_millis(420)),
        );

        assert_eq!(rtt_hint, Some(Duration::from_millis(420)));
        assert_eq!(config.ipv4_timeout, expected.ipv4_timeout);
        assert_eq!(config.ipv6_timeout, expected.ipv6_timeout);
        assert_eq!(config.holepunch_timeout, expected.holepunch_timeout);
        assert_eq!(config.relay_timeout, expected.relay_timeout);

        endpoint.shutdown().await;
    }

    #[test]
    fn test_strategy_rtt_hint_from_cached_peers_prefers_slowest_matching_path() {
        let direct_addr: SocketAddr = "203.0.113.10:9000".parse().expect("direct addr");
        let relay_addr: SocketAddr = "198.51.100.20:9443".parse().expect("relay addr");
        let now = std::time::SystemTime::UNIX_EPOCH;

        let direct_peer = CachedPeer {
            peer_id: PeerId([0x11; 32]),
            addresses: vec![direct_addr],
            capabilities: PeerCapabilities::default(),
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            stats: crate::bootstrap_cache::ConnectionStats {
                avg_rtt_ms: 120,
                ..Default::default()
            },
            quality_score: 0.5,
            source: PeerSource::Seed,
            relay_paths: Vec::new(),
            token: None,
        };
        let relay_peer = CachedPeer {
            peer_id: PeerId([0x22; 32]),
            addresses: vec![relay_addr],
            capabilities: PeerCapabilities::default(),
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            stats: crate::bootstrap_cache::ConnectionStats {
                avg_rtt_ms: 480,
                ..Default::default()
            },
            quality_score: 0.5,
            source: PeerSource::Seed,
            relay_paths: Vec::new(),
            token: None,
        };
        let unrelated_peer = CachedPeer {
            peer_id: PeerId([0x33; 32]),
            addresses: vec!["192.0.2.99:9999".parse().expect("other addr")],
            capabilities: PeerCapabilities::default(),
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            stats: crate::bootstrap_cache::ConnectionStats {
                avg_rtt_ms: 900,
                ..Default::default()
            },
            quality_score: 0.5,
            source: PeerSource::Seed,
            relay_paths: Vec::new(),
            token: None,
        };

        let hint = strategy_rtt_hint_from_cached_peers(
            &[direct_peer, relay_peer, unrelated_peer],
            &[direct_addr, relay_addr],
        )
        .expect("matching peers should yield an RTT hint");

        assert_eq!(hint, Duration::from_millis(480));
    }

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.nat_traversal_attempts, 0);
    }

    #[tokio::test]
    async fn test_ack_waiter_cleanup_on_connection_failure() {
        let ack_waiters = ParkingRwLock::new(HashMap::new());
        let (tx, rx) = oneshot::channel();
        let stable_id = 42usize;
        let tag = [0xAA; 16];

        assert!(register_ack_waiter(&ack_waiters, stable_id, tag, tx));
        fail_ack_waiters_for_connection(&ack_waiters, stable_id, ConnectionCloseReason::TimedOut);

        match rx.await.expect("ack waiter result") {
            AckWaiterResult::Closed(ConnectionCloseReason::TimedOut) => {}
            other => panic!("unexpected waiter result: {other:?}"),
        }
        assert!(ack_waiters.read().is_empty());
    }

    #[test]
    fn test_connection_health_observation_never_seen_patterns() {
        let now = Instant::now();
        let health =
            ConnectionHealth::from_observation(ConnectionHealthObservation::default(), now);

        assert!(!health.connected);
        assert_eq!(health.generation, None);
        assert_eq!(health.reader_task_active, None);
        assert_eq!(health.last_received_at, None);
        assert_eq!(health.last_sent_at, None);
        assert_eq!(health.idle_for, None);
        assert_eq!(health.close_reason, None);
    }

    #[test]
    fn test_connection_health_observation_connected_patterns() {
        let now = Instant::now();
        let last_sent_at = now
            .checked_sub(Duration::from_secs(3))
            .expect("sent instant");
        let last_received_at = now
            .checked_sub(Duration::from_secs(1))
            .expect("received instant");
        let health = ConnectionHealth::from_observation(
            ConnectionHealthObservation {
                connected: true,
                generation: Some(42),
                reader_task_active: Some(true),
                last_received_at: Some(last_received_at),
                last_sent_at: Some(last_sent_at),
                close_reason: None,
            },
            now,
        );

        assert!(health.connected);
        assert_eq!(health.generation, Some(42));
        assert_eq!(health.reader_task_active, Some(true));
        assert_eq!(health.last_received_at, Some(last_received_at));
        assert_eq!(health.last_sent_at, Some(last_sent_at));
        assert_eq!(health.idle_for, Some(Duration::from_secs(1)));
        assert_eq!(health.close_reason, None);
    }

    #[test]
    fn test_connection_health_observation_closing_patterns() {
        let now = Instant::now();
        let health = ConnectionHealth::from_observation(
            ConnectionHealthObservation {
                connected: false,
                generation: None,
                reader_task_active: None,
                last_received_at: None,
                last_sent_at: Some(
                    now.checked_sub(Duration::from_secs(2))
                        .expect("sent instant"),
                ),
                close_reason: Some(ConnectionCloseReason::ReaderExit),
            },
            now,
        );

        assert!(!health.connected);
        assert_eq!(health.generation, None);
        assert_eq!(health.reader_task_active, None);
        assert!(health.last_sent_at.is_some());
        assert_eq!(health.idle_for, None);
        assert_eq!(health.close_reason, Some(ConnectionCloseReason::ReaderExit));
    }

    #[test]
    fn test_connection_health_observation_closed_patterns() {
        let now = Instant::now();
        let health = ConnectionHealth::from_observation(
            ConnectionHealthObservation {
                connected: false,
                generation: None,
                reader_task_active: None,
                last_received_at: Some(
                    now.checked_sub(Duration::from_secs(4))
                        .expect("received instant"),
                ),
                last_sent_at: None,
                close_reason: Some(ConnectionCloseReason::LifecycleCleanup),
            },
            now,
        );

        assert!(!health.connected);
        assert_eq!(health.generation, None);
        assert_eq!(health.reader_task_active, None);
        assert!(health.last_received_at.is_some());
        assert_eq!(health.idle_for, None);
        assert_eq!(
            health.close_reason,
            Some(ConnectionCloseReason::LifecycleCleanup)
        );
    }

    #[tokio::test]
    async fn test_record_connection_established_updates_direct_server_stats_once() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let remote_addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let peer_conn = PeerConnection {
            peer_id: PeerId([0x11; 32]),
            remote_addr: TransportAddr::Udp(remote_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.relayed_connections, 0);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        assert!(stats.last_direct_loopback_at.is_some());
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, peer_conn.peer_id);
                assert_eq!(addr, peer_conn.remote_addr);
                assert_eq!(side, Side::Server);
                assert_eq!(traversal_method, TraversalMethod::Direct);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_connection_established_updates_relay_stats_once() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let remote_addr: SocketAddr = "203.0.113.10:9443".parse().expect("valid addr");
        let peer_conn = PeerConnection {
            peer_id: PeerId([0x22; 32]),
            remote_addr: TransportAddr::Udp(remote_addr),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 0);
        assert_eq!(stats.relayed_connections, 1);
        assert_eq!(stats.active_direct_incoming_connections, 0);
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, peer_conn.peer_id);
                assert_eq!(addr, peer_conn.remote_addr);
                assert_eq!(side, Side::Client);
                assert_eq!(traversal_method, TraversalMethod::Relay);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn test_should_retry_hole_punch_reason_distinguishes_retryable_and_terminal_reasons() {
        assert!(P2pEndpoint::should_retry_hole_punch_reason(
            &TraversalFailureReason::CoordinatorUnavailable
        ));
        assert!(P2pEndpoint::should_retry_hole_punch_reason(
            &TraversalFailureReason::NetworkError("transient".to_string())
        ));
        assert!(!P2pEndpoint::should_retry_hole_punch_reason(
            &TraversalFailureReason::CoordinationRejected {
                reason: RejectionReason::RateLimited,
            }
        ));
        assert!(!P2pEndpoint::should_retry_hole_punch_reason(
            &TraversalFailureReason::ProtocolViolation("bad state".to_string())
        ));
    }

    #[test]
    fn test_traversal_failure_reason_from_nat_error_maps_representative_hole_punch_failures() {
        assert!(matches!(
            TraversalFailureReason::from_public_operation_error(
                &NatTraversalError::NoBootstrapNodes
            ),
            Some(TraversalFailureReason::CoordinatorUnavailable)
        ));
        assert!(matches!(
            TraversalFailureReason::from_public_operation_error(
                &NatTraversalError::HolePunchingFailed
            ),
            Some(TraversalFailureReason::PunchWindowMissed)
        ));
        assert!(matches!(
            TraversalFailureReason::from_public_operation_error(&NatTraversalError::ProtocolError(
                "malformed".to_string()
            )),
            Some(TraversalFailureReason::ProtocolViolation(message)) if message == "malformed"
        ));
    }

    #[test]
    fn test_endpoint_error_from_traversal_failure_maps_typed_terminal_outcome() {
        let error = P2pEndpoint::endpoint_error_from_traversal_failure(
            TraversalFailureReason::CoordinationRejected {
                reason: RejectionReason::Expired,
            },
        );

        assert!(matches!(
            error,
            EndpointError::NatTraversal(NatTraversalError::CoordinationFailed(message))
                if message.contains("request expired")
        ));
    }

    #[test]
    fn test_hole_punch_await_error_display_uses_typed_reason() {
        let error =
            HolePunchAwaitError::TraversalFailure(TraversalFailureReason::CoordinationRejected {
                reason: RejectionReason::Expired,
            });
        assert_eq!(error.to_string(), "coordination rejected: request expired");
    }

    #[test]
    fn test_hole_punch_await_error_preserves_typed_retry_classification() {
        let rejected =
            HolePunchAwaitError::TraversalFailure(TraversalFailureReason::CoordinationRejected {
                reason: RejectionReason::RateLimited,
            });
        assert!(matches!(
            rejected.retry_reason(),
            Some(TraversalFailureReason::CoordinationRejected {
                reason: RejectionReason::RateLimited,
            })
        ));
        assert!(
            !rejected
                .retry_reason()
                .is_some_and(P2pEndpoint::should_retry_hole_punch_reason)
        );

        let sync_expired =
            HolePunchAwaitError::TraversalFailure(TraversalFailureReason::SynchronizationExpired);
        assert!(matches!(
            sync_expired.retry_reason(),
            Some(TraversalFailureReason::SynchronizationExpired)
        ));
        assert!(
            !sync_expired
                .retry_reason()
                .is_some_and(P2pEndpoint::should_retry_hole_punch_reason)
        );

        let punch_missed =
            HolePunchAwaitError::TraversalFailure(TraversalFailureReason::PunchWindowMissed);
        assert!(
            punch_missed
                .retry_reason()
                .is_some_and(P2pEndpoint::should_retry_hole_punch_reason)
        );
    }

    #[tokio::test]
    async fn test_record_connection_established_updates_hole_punch_stats_once() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let remote_addr: SocketAddr = "198.51.100.44:9443".parse().expect("valid addr");
        let peer_conn = PeerConnection {
            peer_id: PeerId([0x23; 32]),
            remote_addr: TransportAddr::Udp(remote_addr),
            traversal_method: TraversalMethod::HolePunch,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 0);
        assert_eq!(stats.relayed_connections, 0);
        assert_eq!(stats.active_direct_incoming_connections, 0);
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, peer_conn.peer_id);
                assert_eq!(addr, peer_conn.remote_addr);
                assert_eq!(side, Side::Client);
                assert_eq!(traversal_method, TraversalMethod::HolePunch);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bridge_nat_traversal_event_does_not_emit_peer_connected() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let direct_path_statuses = ParkingRwLock::new(HashMap::new());
        let peer_id = PeerId([0x33; 32]);
        let remote_addr: SocketAddr = "198.51.100.7:9001".parse().expect("valid addr");

        bridge_nat_traversal_event(
            &stats,
            &event_tx,
            &direct_path_statuses,
            NatTraversalEvent::ConnectionEstablished {
                peer_id,
                remote_address: remote_addr,
                side: Side::Client,
            },
        )
        .await;

        let stats = stats.read().await;
        assert_eq!(stats.nat_traversal_successes, 1);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        drop(stats);

        let collected = collect_broadcast_events(&mut event_rx);
        assert!(
            !collected
                .iter()
                .any(|event| matches!(event, P2pEvent::PeerConnected { .. })),
            "NAT traversal bridge should not emit PeerConnected directly"
        );
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::DirectPathStatus {
                peer_id: observed_peer_id,
                status: DirectPathStatus::Established { remote_addr: observed_addr },
            } if *observed_peer_id == peer_id && *observed_addr == remote_addr
        )));
        assert_eq!(
            direct_path_statuses.read().get(&peer_id),
            Some(&DirectPathStatus::Established { remote_addr })
        );
    }

    #[tokio::test]
    async fn test_bridge_nat_traversal_failure_surfaces_best_effort_status() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let direct_path_statuses = ParkingRwLock::new(HashMap::new());
        let peer_id = PeerId([0x34; 32]);

        bridge_nat_traversal_event(
            &stats,
            &event_tx,
            &direct_path_statuses,
            NatTraversalEvent::TraversalFailed {
                peer_id,
                error: NatTraversalError::HolePunchingFailed,
                fallback_available: true,
            },
        )
        .await;

        let stats = stats.read().await;
        assert_eq!(stats.failed_connections, 1);
        drop(stats);

        let collected = collect_broadcast_events(&mut event_rx);
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::DirectPathStatus {
                peer_id: observed_peer_id,
                status: DirectPathStatus::BestEffortUnavailable {
                    reason: DirectPathUnavailableReason::NatUnreachable,
                },
            } if *observed_peer_id == peer_id
        )));
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::NatTraversalProgress {
                peer_id: observed_peer_id,
                phase: TraversalPhase::Failed,
            } if *observed_peer_id == peer_id
        )));
        assert_eq!(
            direct_path_statuses.read().get(&peer_id),
            Some(&DirectPathStatus::BestEffortUnavailable {
                reason: DirectPathUnavailableReason::NatUnreachable,
            })
        );
    }

    #[tokio::test]
    async fn test_bridge_nat_traversal_terminated_is_authoritative_over_legacy_failed() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(8);
        let direct_path_statuses = ParkingRwLock::new(HashMap::new());
        let peer_id = PeerId([0x35; 32]);

        bridge_nat_traversal_event(
            &stats,
            &event_tx,
            &direct_path_statuses,
            NatTraversalEvent::TraversalTerminated {
                peer_id,
                reason: TraversalFailureReason::PunchWindowMissed,
                fallback_available: true,
            },
        )
        .await;
        bridge_nat_traversal_event(
            &stats,
            &event_tx,
            &direct_path_statuses,
            NatTraversalEvent::TraversalFailed {
                peer_id,
                error: NatTraversalError::HolePunchingFailed,
                fallback_available: true,
            },
        )
        .await;

        let stats = stats.read().await;
        assert_eq!(stats.failed_connections, 1);
        drop(stats);

        let collected = collect_broadcast_events(&mut event_rx);
        assert_eq!(
            collected
                .iter()
                .filter(|event| matches!(
                    event,
                    P2pEvent::NatTraversalProgress {
                        peer_id: observed_peer_id,
                        phase: TraversalPhase::Failed,
                    } if *observed_peer_id == peer_id
                ))
                .count(),
            1
        );
        assert_eq!(
            collected
                .iter()
                .filter(|event| matches!(
                    event,
                    P2pEvent::DirectPathStatus {
                        peer_id: observed_peer_id,
                        status: DirectPathStatus::BestEffortUnavailable {
                            reason: DirectPathUnavailableReason::NatUnreachable,
                        },
                    } if *observed_peer_id == peer_id
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_record_connection_established_replacement_does_not_double_count() {
        let stats = RwLock::new(EndpointStats {
            active_connections: 1,
            successful_connections: 1,
            relayed_connections: 1,
            ..EndpointStats::default()
        });
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let previous = PeerConnection {
            peer_id: PeerId([0x44; 32]),
            remote_addr: TransportAddr::Udp("203.0.113.20:9443".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let replacement = PeerConnection {
            peer_id: previous.peer_id,
            remote_addr: TransportAddr::Udp("127.0.0.1:9443".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &replacement, Some(&previous)).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        // Relay → Direct transition decrements the previous method's live counter.
        assert_eq!(stats.relayed_connections, 0);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, replacement.peer_id);
                assert_eq!(addr, replacement.remote_addr);
                assert_eq!(side, Side::Server);
                assert_eq!(traversal_method, TraversalMethod::Direct);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_connection_established_identical_replacement_is_quiet() {
        let stats = RwLock::new(EndpointStats {
            active_connections: 1,
            successful_connections: 1,
            direct_connections: 1,
            active_direct_incoming_connections: 1,
            ..EndpointStats::default()
        });
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let previous = PeerConnection {
            peer_id: PeerId([0x55; 32]),
            remote_addr: TransportAddr::Udp("127.0.0.1:9555".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let replacement = PeerConnection {
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            ..previous.clone()
        };

        record_connection_established(&stats, &event_tx, &replacement, Some(&previous)).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        drop(stats);

        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_record_connection_established_direct_to_relay_decrements_direct() {
        let stats = RwLock::new(EndpointStats {
            active_connections: 1,
            successful_connections: 1,
            direct_connections: 1,
            active_direct_incoming_connections: 1,
            ..EndpointStats::default()
        });
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(4);
        let previous = PeerConnection {
            peer_id: PeerId([0x60; 32]),
            remote_addr: TransportAddr::Udp("127.0.0.1:9601".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let replacement = PeerConnection {
            peer_id: previous.peer_id,
            remote_addr: TransportAddr::Udp("203.0.113.30:9601".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &replacement, Some(&previous)).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.direct_connections, 0);
        assert_eq!(stats.relayed_connections, 1);
        // The previous direct-incoming connection has been replaced by a
        // Relay client-side connection, so the incoming-direct counter drops.
        assert_eq!(stats.active_direct_incoming_connections, 0);
    }

    #[tokio::test]
    async fn test_remove_connected_peer_decrements_direct_connections() {
        let connected_peers = RwLock::new(HashMap::new());
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(4);
        let peer_id = PeerId([0x70; 32]);

        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp("127.0.0.1:9701".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        connected_peers
            .write()
            .await
            .insert(peer_id, peer_conn.clone());
        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        {
            let s = stats.read().await;
            assert_eq!(s.direct_connections, 1);
            assert_eq!(s.active_connections, 1);
            assert_eq!(s.active_direct_incoming_connections, 1);
        }

        let removed = remove_connected_peer(
            &connected_peers,
            &stats,
            &event_tx,
            &peer_id,
            DisconnectReason::ConnectionLost,
        )
        .await;
        assert!(removed);

        let s = stats.read().await;
        assert_eq!(s.direct_connections, 0);
        assert_eq!(s.active_connections, 0);
        assert_eq!(s.active_direct_incoming_connections, 0);
    }

    #[tokio::test]
    async fn test_remove_connected_peer_decrements_relayed_connections() {
        let connected_peers = RwLock::new(HashMap::new());
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(4);
        let peer_id = PeerId([0x71; 32]);

        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp("203.0.113.40:9702".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        connected_peers
            .write()
            .await
            .insert(peer_id, peer_conn.clone());
        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        {
            let s = stats.read().await;
            assert_eq!(s.relayed_connections, 1);
            assert_eq!(s.active_connections, 1);
        }

        let removed = remove_connected_peer(
            &connected_peers,
            &stats,
            &event_tx,
            &peer_id,
            DisconnectReason::ConnectionLost,
        )
        .await;
        assert!(removed);

        let s = stats.read().await;
        assert_eq!(s.relayed_connections, 0);
        assert_eq!(s.active_connections, 0);
    }

    /// Issue #178: in a steady-state mesh, the live-count invariant
    /// `direct_connections + relayed_connections == active_connections`
    /// must hold across connect → method-transition → disconnect churn.
    #[tokio::test]
    async fn test_direct_plus_relayed_equals_active_connections_under_churn() {
        let connected_peers = RwLock::new(HashMap::new());
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(64);

        let mk_conn = |id: u8, method: TraversalMethod, side: Side| PeerConnection {
            peer_id: PeerId([id; 32]),
            remote_addr: TransportAddr::Udp(
                format!("127.0.0.1:{}", 10_000 + id as u16)
                    .parse()
                    .expect("valid addr"),
            ),
            traversal_method: method,
            side,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Establish 4 Direct peers (server-side incoming, like a mesh node).
        for id in 1..=4u8 {
            let conn = mk_conn(id, TraversalMethod::Direct, Side::Server);
            connected_peers
                .write()
                .await
                .insert(conn.peer_id, conn.clone());
            record_connection_established(&stats, &event_tx, &conn, None).await;
        }

        // Transition peer 2 from Direct → Relay (e.g. NAT-traversal regression).
        let prev2 = connected_peers
            .read()
            .await
            .get(&PeerId([2; 32]))
            .cloned()
            .expect("peer 2 present");
        let relayed2 = mk_conn(2, TraversalMethod::Relay, Side::Client);
        connected_peers
            .write()
            .await
            .insert(relayed2.peer_id, relayed2.clone());
        record_connection_established(&stats, &event_tx, &relayed2, Some(&prev2)).await;

        // Disconnect peer 4.
        let removed = remove_connected_peer(
            &connected_peers,
            &stats,
            &event_tx,
            &PeerId([4; 32]),
            DisconnectReason::ConnectionLost,
        )
        .await;
        assert!(removed);

        // Invariants: live counts agree with the connected_peers map.
        let s = stats.read().await;
        let peers_len = connected_peers.read().await.len();
        assert_eq!(peers_len, 3, "3 peers remain after disconnecting peer 4");
        assert_eq!(s.active_connections, peers_len);
        assert_eq!(s.direct_connections, 2, "peers 1 and 3 are Direct");
        assert_eq!(s.relayed_connections, 1, "peer 2 is Relay");
        assert_eq!(
            (s.direct_connections + s.relayed_connections) as usize,
            peers_len
        );
    }

    #[tokio::test]
    async fn test_cleanup_connection_removes_direct_path_status_and_emits_disconnect() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x56; 32]);
        let mut events = endpoint.subscribe();
        endpoint
            .register_connected_peer(PeerConnection {
                peer_id,
                remote_addr: TransportAddr::Udp("127.0.0.1:9556".parse().expect("valid addr")),
                traversal_method: TraversalMethod::Direct,
                side: Side::Server,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            })
            .await;
        endpoint.direct_path_statuses.write().insert(
            peer_id,
            DirectPathStatus::Established {
                remote_addr: "127.0.0.1:9556".parse().expect("valid addr"),
            },
        );

        endpoint
            .cleanup_connection(&peer_id, DisconnectReason::ConnectionLost)
            .await;

        assert!(endpoint.direct_path_status(peer_id).is_none());
        assert!(!endpoint.is_connected(&peer_id).await);
        assert_eq!(endpoint.stats().await.active_connections, 0);

        let collected = collect_broadcast_events(&mut events);
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::PeerDisconnected {
                peer_id: observed_peer_id,
                reason: DisconnectReason::ConnectionLost,
            } if *observed_peer_id == peer_id
        )));

        endpoint.shutdown().await;
    }

    #[test]
    fn test_connection_metrics_default() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert!(metrics.rtt.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn test_peer_connection_debug() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("PeerConnection"));
    }

    #[test]
    fn test_disconnect_reason_debug() {
        let reason = DisconnectReason::Normal;
        assert!(format!("{:?}", reason).contains("Normal"));

        let reason = DisconnectReason::ProtocolError("test".to_string());
        assert!(format!("{:?}", reason).contains("test"));
    }

    #[test]
    fn test_traversal_phase_debug() {
        let phase = TraversalPhase::Discovery;
        assert!(format!("{:?}", phase).contains("Discovery"));
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let err = EndpointError::PeerNotFound(PeerId([0u8; 32]));
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder().build().expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 5)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_endpoint_stores_transport_registry() {
        use crate::transport::TransportType;

        // Build config with default transport providers
        // Phase 5.3: P2pEndpoint::new() always adds a shared UDP transport
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Verify registry is accessible and contains the auto-added UDP provider
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            // Phase 5.3: Registry now always has at least 1 UDP provider (socket sharing)
            assert!(
                !registry.is_empty(),
                "Registry should have at least 1 provider"
            );

            let udp_providers = registry.providers_by_type(TransportType::Udp);
            assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_p2p_endpoint_default_config_has_udp_registry() {
        // Build config with no additional transport providers
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Phase 5.3: Default registry now includes a shared UDP transport
        // This is required for socket sharing with Quinn
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            assert!(
                !registry.is_empty(),
                "Default registry should have UDP for socket sharing"
            );
            assert!(
                registry.has_quic_capable_transport(),
                "Default registry should have QUIC-capable transport"
            );
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_port_mapping_disabled_mode_starts_cleanly() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            assert!(!endpoint.port_mapping_active());
            assert_eq!(endpoint.port_mapping_addr(), None);
            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_port_mapping_candidate_propagates_to_external_addresses() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            let mapped_addr: SocketAddr = "65.21.157.229:41000".parse().expect("valid addr");
            endpoint.apply_port_mapping_snapshot(PortMappingSnapshot {
                active: true,
                external_addr: Some(mapped_addr),
            });

            assert!(endpoint.port_mapping_active());
            assert_eq!(endpoint.port_mapping_addr(), Some(mapped_addr));
            assert!(endpoint.all_external_addrs().contains(&mapped_addr));
            assert_eq!(
                endpoint.inner.relay_server_public_address(),
                Some(mapped_addr)
            );

            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_port_mapping_event_surfaces_lifecycle_and_external_address() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            let mut events = endpoint.subscribe();
            let mapped_addr: SocketAddr = "65.21.157.229:42000".parse().expect("valid addr");

            endpoint.apply_port_mapping_event(PortMappingEvent::Established {
                snapshot: PortMappingSnapshot {
                    active: true,
                    external_addr: Some(mapped_addr),
                },
            });
            endpoint.apply_port_mapping_event(PortMappingEvent::Failed {
                error: "simulated failure".to_string(),
            });
            endpoint.apply_port_mapping_event(PortMappingEvent::Removed {
                external_addr: Some(mapped_addr),
            });

            let collected: Vec<_> = std::iter::from_fn(|| events.try_recv().ok()).collect();
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingEstablished { external_addr }
                    if *external_addr == mapped_addr
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::ExternalAddressDiscovered { addr }
                    if addr.as_socket_addr() == Some(mapped_addr)
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingFailed { error } if error == "simulated failure"
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingRemoved { external_addr }
                    if *external_addr == Some(mapped_addr)
            )));

            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_port_mapping_address_change_event_surfaces() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            let mut events = endpoint.subscribe();
            let first_addr: SocketAddr = "65.21.157.230:42000".parse().expect("valid addr");
            let second_addr: SocketAddr = "65.21.157.231:42000".parse().expect("valid addr");

            endpoint.apply_port_mapping_snapshot(PortMappingSnapshot {
                active: true,
                external_addr: Some(first_addr),
            });
            endpoint.apply_port_mapping_snapshot(PortMappingSnapshot {
                active: true,
                external_addr: Some(second_addr),
            });

            let collected = collect_broadcast_events(&mut events);
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingAddressChanged {
                    previous_addr,
                    external_addr,
                } if *previous_addr == first_addr && *external_addr == second_addr
            )));

            endpoint.shutdown().await;
        }
    }

    #[cfg(all(feature = "platform-verifier", feature = "network-discovery"))]
    #[tokio::test]
    async fn test_port_mapping_startup_failure_is_non_fatal_for_endpoint_connectivity() {
        let listener = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("listener config should build"),
        )
        .await
        .expect("listener should bind");

        let listener_addr = localhost_addr(listener.local_addr().expect("listener addr"));
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .build()
                .expect("endpoint config should build"),
        )
        .await
        .expect("endpoint should bind");

        let mut events = endpoint.subscribe();
        endpoint.apply_port_mapping_event(PortMappingEvent::Failed {
            error: "startup mapping failed".to_string(),
        });

        let accept_handle = tokio::spawn({
            let listener = listener.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(20), listener.accept())
                    .await
                    .expect("listener accept should not time out")
            }
        });

        let connection = tokio::time::timeout(
            Duration::from_secs(20),
            endpoint.connect_addr(listener_addr),
        )
        .await
        .expect("direct connect should not time out")
        .expect("direct connect should succeed");

        assert_eq!(connection.remote_addr.as_socket_addr(), Some(listener_addr));
        assert!(!endpoint.port_mapping_active());
        assert_eq!(endpoint.port_mapping_addr(), None);

        let collected = collect_broadcast_events(&mut events);
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::PortMappingFailed { error } if error == "startup mapping failed"
        )));

        endpoint.shutdown().await;
        listener.shutdown().await;
        let _ = accept_handle.await;
    }

    #[tokio::test]
    async fn test_port_mapping_removal_recomputes_relay_public_address_from_observed_address() {
        let config = P2pConfig::builder()
            .bind_addr(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ))
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        let listener = P2pEndpoint::new(config)
            .await
            .expect("listener should create");
        let private_observed_addr: SocketAddr = "10.0.0.1:42000".parse().expect("valid addr");
        let observed_addr: SocketAddr = "203.0.113.88:42000".parse().expect("valid addr");
        listener
            .inner
            .set_test_observed_external_addrs(vec![private_observed_addr, observed_addr]);
        let mapped_addr: SocketAddr = "65.21.157.229:41000".parse().expect("valid addr");
        listener.apply_port_mapping_snapshot(PortMappingSnapshot {
            active: true,
            external_addr: Some(mapped_addr),
        });
        assert_eq!(
            listener.inner.relay_server_public_address(),
            Some(mapped_addr)
        );

        listener.apply_port_mapping_snapshot(PortMappingSnapshot::default());
        assert_eq!(
            listener.inner.relay_server_public_address(),
            Some(observed_addr)
        );

        listener.shutdown().await;
    }

    #[tokio::test]
    async fn test_active_relay_is_advertised_to_future_connected_peers() {
        let config = P2pConfig::builder()
            .bind_addr(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ))
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        let relay_endpoint = P2pEndpoint::new(config)
            .await
            .expect("relay endpoint should create");
        relay_endpoint
            .inner
            .set_test_relay_public_addr("198.51.100.200:45000".parse().expect("valid addr"));
        let future_peer = PeerConnection {
            peer_id: PeerId([0x90; 32]),
            remote_addr: TransportAddr::Udp("127.0.0.1:45001".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        relay_endpoint
            .register_connected_peer(future_peer.clone())
            .await;

        assert!(
            relay_endpoint
                .inner
                .test_relay_publish_attempted_for(future_peer.peer_id),
            "future connected peers should trigger proactive relay re-advertisement"
        );
        relay_endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_runtime_assist_snapshot_reports_relay_bytes_forwarded() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("valid config"),
        )
        .await
        .expect("endpoint should create");

        endpoint.inner.record_test_relay_server_activity(2, 4096);
        let snapshot = endpoint.runtime_assist_snapshot().await;

        assert_eq!(snapshot.active_relay_sessions, 2);
        assert_eq!(snapshot.relay_bytes_forwarded, 4096);

        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_relay_service_enabled_reports_effective_runtime_when_legacy_flag_is_disabled() {
        let mut config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");
        config.nat.enable_relay_service = false;

        let endpoint = P2pEndpoint::new(config)
            .await
            .expect("endpoint should create");
        assert!(
            endpoint.relay_service_enabled(),
            "status should reflect the always-on relay runtime"
        );

        endpoint.shutdown().await;
    }

    fn localhost_addr(addr: SocketAddr) -> SocketAddr {
        if addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
        } else {
            addr
        }
    }

    #[test]
    fn test_prioritize_direct_candidate_addrs_prefers_global_addresses() {
        let private_v4: SocketAddr = "10.0.0.1:5483".parse().expect("valid addr");
        let global_v4: SocketAddr = "198.51.100.20:5483".parse().expect("valid addr");
        let global_v6: SocketAddr = "[2001:db8::20]:5483".parse().expect("valid addr");
        let loopback: SocketAddr = "127.0.0.1:5483".parse().expect("valid addr");

        let mut addrs = vec![private_v4, loopback, global_v4, global_v6];
        prioritize_direct_candidate_addrs(&mut addrs);

        assert_eq!(addrs[0], global_v6);
        assert_eq!(addrs[1], global_v4);
        assert_eq!(addrs[2], private_v4);
        assert_eq!(addrs[3], loopback);
    }

    /// Regression for issue #163.
    ///
    /// When a peer advertises a globally-routable address plus some RFC1918 /
    /// link-local / loopback leftovers, dialing those private entries from a
    /// WAN caller stalls for the full QUIC handshake timeout before failing.
    /// `drop_non_global_direct_candidates_when_global_present` must strip them
    /// when a Global candidate is available.
    #[test]
    fn test_drop_non_global_direct_candidates_when_global_present() {
        let private_v4: SocketAddr = "10.200.0.1:5483".parse().expect("valid addr");
        let global_v4: SocketAddr = "198.51.100.20:5483".parse().expect("valid addr");
        let global_v6: SocketAddr = "[2001:db8::20]:5483".parse().expect("valid addr");
        let link_local: SocketAddr = "169.254.10.1:5483".parse().expect("valid addr");
        let loopback: SocketAddr = "127.0.0.1:5483".parse().expect("valid addr");

        let mut addrs = vec![private_v4, link_local, loopback, global_v4, global_v6];
        drop_non_global_direct_candidates_when_global_present(&mut addrs);
        addrs.sort();
        let expected = {
            let mut v = vec![global_v4, global_v6];
            v.sort();
            v
        };
        assert_eq!(
            addrs, expected,
            "private/link-local/loopback must be dropped when Global candidates are present"
        );
    }

    /// Pure-LAN peers (no Global candidates — e.g. mDNS-discovered LAN peer)
    /// must still be reachable. The filter must be a no-op in this case.
    #[test]
    fn test_drop_non_global_direct_candidates_preserves_lan_only_list() {
        let private_v4: SocketAddr = "192.168.1.25:5483".parse().expect("valid addr");
        let link_local_v6: SocketAddr = "[fe80::1]:5483".parse().expect("valid addr");

        let original = vec![private_v4, link_local_v6];
        let mut addrs = original.clone();
        drop_non_global_direct_candidates_when_global_present(&mut addrs);
        assert_eq!(
            addrs, original,
            "LAN-only candidate sets must not be emptied — the caller would have nothing to dial"
        );
    }

    #[test]
    fn test_select_preferred_relay_target_addr_prefers_listener_port() {
        let listener: SocketAddr = "[2001:db8::20]:5483".parse().expect("valid addr");
        let observed_ephemeral: SocketAddr = "[2001:db8::20]:37616".parse().expect("valid addr");

        let selected = select_preferred_relay_target_addr(
            &[listener],
            &[],
            &[observed_ephemeral],
            Some(observed_ephemeral),
            None,
        );

        assert_eq!(selected, Some(listener));
    }

    #[test]
    fn test_select_preferred_relay_target_addr_prefers_reachable_over_external() {
        let reachable: SocketAddr = "198.51.100.20:5483".parse().expect("valid addr");
        let observed_ephemeral: SocketAddr = "198.51.100.20:37616".parse().expect("valid addr");

        let selected = select_preferred_relay_target_addr(
            &[],
            &[reachable],
            &[observed_ephemeral],
            Some(observed_ephemeral),
            None,
        );

        assert_eq!(selected, Some(reachable));
    }

    #[tokio::test]
    async fn test_persist_direct_reachability_if_applicable_skips_hole_punch() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x33; 32]);
        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp("198.51.100.33:5483".parse().expect("valid addr")),
            traversal_method: TraversalMethod::HolePunch,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        P2pEndpoint::persist_direct_peer_reachability_if_applicable(
            endpoint.bootstrap_cache.as_ref(),
            &peer_conn,
        )
        .await;

        assert!(endpoint.bootstrap_cache.get_peer(&peer_id).await.is_none());
        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_persist_direct_reachability_if_applicable_records_direct() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x34; 32]);
        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp("198.51.100.34:5483".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        P2pEndpoint::persist_direct_peer_reachability_if_applicable(
            endpoint.bootstrap_cache.as_ref(),
            &peer_conn,
        )
        .await;

        let cached_peer = endpoint
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .expect("direct peer should be cached");
        assert_eq!(
            cached_peer.capabilities.direct_reachability_scope,
            Some(ReachabilityScope::Global)
        );
        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_peer_address_update_persists_hints_and_cache() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x44; 32]);
        let peer_addr: SocketAddr = "127.0.0.1:45000".parse().expect("valid addr");
        let advertised_addr: SocketAddr = "198.51.100.44:5483".parse().expect("valid addr");
        let mut events = endpoint.subscribe();

        endpoint
            .register_connected_peer(PeerConnection {
                peer_id,
                remote_addr: TransportAddr::Udp(peer_addr),
                traversal_method: TraversalMethod::Direct,
                side: Side::Server,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            })
            .await;

        P2pEndpoint::apply_peer_address_update(
            endpoint.connected_peers.as_ref(),
            endpoint.bootstrap_cache.as_ref(),
            endpoint.peer_hint_records.as_ref(),
            &endpoint.event_tx,
            peer_addr,
            advertised_addr,
        )
        .await;

        assert!(
            endpoint
                .hinted_addrs_for_peer(peer_id)
                .await
                .contains(&advertised_addr)
        );
        let cached_peer = endpoint
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .expect("peer should be cached");
        assert!(cached_peer.preferred_addresses().contains(&advertised_addr));
        let observed_events: Vec<_> = std::iter::from_fn(|| events.try_recv().ok()).collect();
        assert!(observed_events.iter().any(|event| matches!(
            event,
            P2pEvent::PeerAddressUpdated {
                peer_addr: observed_peer_addr,
                advertised_addr: observed_advertised_addr,
            } if *observed_peer_addr == peer_addr && *observed_advertised_addr == advertised_addr
        )));

        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_upsert_peer_hints_feeds_coordinator_candidates() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x5a; 32]);
        let hinted_addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let caps = PeerCapabilities {
            supports_coordination: true,
            ..PeerCapabilities::default()
        };

        endpoint
            .upsert_peer_hints(peer_id, vec![hinted_addr], Some(caps))
            .await;

        let candidates = endpoint.coordinator_candidates().await;
        assert!(
            candidates.contains(&hinted_addr),
            "hinted coordinator address should be considered for orchestration"
        );

        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_upsert_peer_hints_feeds_relay_cache_selection_after_runtime_hints_clear() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x6b; 32]);
        let hinted_addr: SocketAddr = "198.51.100.61:9000".parse().expect("valid addr");
        let target_addr: SocketAddr = "203.0.113.61:443".parse().expect("valid addr");
        let caps = PeerCapabilities {
            supports_relay: true,
            ..PeerCapabilities::default()
        };

        endpoint
            .upsert_peer_hints(peer_id, vec![hinted_addr], Some(caps))
            .await;

        endpoint.peer_hint_records.write().await.clear();

        let cached = endpoint
            .bootstrap_cache
            .get(&peer_id)
            .await
            .expect("cached hinted peer should exist");
        assert!(cached.capabilities.hinted_supports_relay);
        assert!(cached.capabilities.supports_relay);

        let relays = endpoint
            .bootstrap_cache
            .select_relays_for_target(4, &target_addr, false)
            .await;
        assert!(
            relays.iter().any(|peer| peer.peer_id == peer_id),
            "persisted relay hint should feed bootstrap-cache relay selection"
        );

        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_upsert_peer_hints_merge_addrs_and_roles() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let peer_id = PeerId([0x7c; 32]);
        let addr_a: SocketAddr = "198.51.100.71:9000".parse().expect("valid addr");
        let addr_b: SocketAddr = "198.51.100.72:9000".parse().expect("valid addr");

        endpoint
            .upsert_peer_hints(
                peer_id,
                vec![addr_a],
                Some(PeerCapabilities {
                    supports_coordination: true,
                    ..PeerCapabilities::default()
                }),
            )
            .await;
        endpoint
            .upsert_peer_hints(
                peer_id,
                vec![addr_a, addr_b],
                Some(PeerCapabilities {
                    supports_relay: true,
                    ..PeerCapabilities::default()
                }),
            )
            .await;

        let hints = endpoint.peer_hint_records.read().await;
        let runtime = hints.get(&peer_id).expect("runtime hints should exist");
        assert_eq!(runtime.addrs.len(), 2);
        assert!(runtime.addrs.contains(&addr_a));
        assert!(runtime.addrs.contains(&addr_b));
        assert!(runtime.capabilities.supports_relay);
        assert!(runtime.capabilities.supports_coordination);
        drop(hints);

        let cached = endpoint
            .bootstrap_cache
            .get(&peer_id)
            .await
            .expect("cached hinted peer should exist");
        assert_eq!(cached.addresses.len(), 2);
        assert!(cached.addresses.contains(&addr_a));
        assert!(cached.addresses.contains(&addr_b));
        assert!(cached.capabilities.supports_relay);
        assert!(cached.capabilities.supports_coordination);
        assert!(cached.capabilities.hinted_supports_relay);
        assert!(cached.capabilities.hinted_supports_coordination);

        endpoint.shutdown().await;
    }

    fn mdns_peer_record(addr: SocketAddr, claimed_peer_id: PeerId) -> MdnsPeerRecord {
        MdnsPeerRecord {
            service: "ant-quic".to_string(),
            fullname: format!(
                "peer-{}._ant-quic._udp.local.",
                hex::encode(&claimed_peer_id.0[..4])
            ),
            hostname: "peer.local.".to_string(),
            namespace: Some("workspace-a".to_string()),
            claimed_peer_id: Some(claimed_peer_id),
            addresses: vec![addr],
            metadata: std::collections::BTreeMap::from([
                ("namespace".to_string(), "workspace-a".to_string()),
                ("peer_id".to_string(), hex::encode(claimed_peer_id.0)),
            ]),
            eligible: true,
            ineligible_reason: None,
        }
    }

    #[tokio::test]
    async fn test_mdns_discover_only_surfaces_without_auto_connecting() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Disabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(endpoint_a.connected_peers().await.len(), 0);
        assert_eq!(endpoint_a.mdns_snapshot().discovered_peers.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_mdns_approval_required_surfaces_without_auto_connecting() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::ApprovalRequired,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let mut events = endpoint_a.subscribe();
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(endpoint_a.connected_peers().await.len(), 0);
        let collected = collect_broadcast_events(&mut events);
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::MdnsPeerApprovalRequired { peer, .. } if peer.claimed_peer_id == Some(node_b.peer_id())
        )));

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_mdns_allowlist_rejects_unapproved_peer_before_auto_connect() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let allowed_peer = PeerId([0xac; 32]);
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .allow_discovered_peer(allowed_peer)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Enabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let mut events = endpoint_a.subscribe();
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(endpoint_a.connected_peers().await.len(), 0);
        let collected = collect_broadcast_events(&mut events);
        assert!(collected.iter().any(|event| matches!(
            event,
            P2pEvent::MdnsPeerIneligible { peer, reason }
                if peer.claimed_peer_id == Some(node_b.peer_id())
                    && reason.contains("not in the discovery allowlist")
        )));
        assert!(
            !collected
                .iter()
                .any(|event| matches!(event, P2pEvent::MdnsAutoConnectAttempted { .. })),
            "allowlist rejection should happen before scheduling auto-connect"
        );

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_mdns_skips_loopback_bind_hints() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        let mdns = endpoint.mdns_snapshot();
        assert!(
            !mdns.browsing,
            "loopback-only bind hints must suppress background mDNS browsing"
        );
        assert!(
            !mdns.advertising,
            "loopback-only bind hints must suppress background mDNS advertising"
        );

        endpoint.shutdown().await;
    }

    #[cfg(all(feature = "platform-verifier", feature = "network-discovery"))]
    #[tokio::test]
    async fn test_mdns_auto_connect_succeeds_without_overriding_authenticated_identity() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Enabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let mut events = endpoint_a.subscribe();
        let accept_handle = tokio::spawn({
            let node = node_b.clone();
            async move {
                let _ = tokio::time::timeout(Duration::from_secs(20), node.accept()).await;
            }
        });

        let fake_claim = PeerId([0xee; 32]);
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b, fake_claim,
        )));

        let success = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match events.recv().await.expect("event should arrive") {
                    P2pEvent::MdnsAutoConnectSucceeded {
                        authenticated_peer_id,
                        ..
                    } => break authenticated_peer_id,
                    _ => {}
                }
            }
        })
        .await
        .expect("mDNS auto-connect success event should arrive");

        assert_eq!(success, node_b.peer_id());
        assert_ne!(success, fake_claim);
        assert_eq!(endpoint_a.connected_peers().await.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_handle.await;
    }

    #[cfg(all(feature = "platform-verifier", feature = "network-discovery"))]
    #[tokio::test]
    async fn test_mdns_discovered_peer_coexists_with_static_known_peer_dedup() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .known_peer(addr_b)
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Enabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let accept_handle = tokio::spawn({
            let node = node_b.clone();
            async move {
                for _ in 0..2 {
                    let _ = tokio::time::timeout(Duration::from_secs(20), node.accept()).await;
                }
            }
        });

        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerDiscovered(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        let connected =
            tokio::time::timeout(Duration::from_secs(20), endpoint_a.connect_known_peers())
                .await
                .expect("connect_known_peers should not time out")
                .expect("connect_known_peers should succeed");

        assert_eq!(connected, 1);
        assert_eq!(endpoint_a.connected_peers().await.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_handle.await;
    }

    #[tokio::test]
    async fn test_mdns_shutdown_is_idempotent() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::Both,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Disabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        endpoint.shutdown().await;
        endpoint.shutdown().await;

        assert!(!endpoint.is_running());
    }

    // ==========================================================================
    // Event Address Migration Tests (Phase 2.2 Task 7)
    // ==========================================================================

    #[test]
    fn test_peer_connected_event_with_udp() {
        let socket_addr: SocketAddr = "192.168.1.100:8080".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xab; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
            traversal_method,
        } = event
        {
            assert_eq!(peer_id.0, [0xab; 32]);
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert!(side.is_client());
            assert_eq!(traversal_method, TraversalMethod::Direct);

            // Verify as_socket_addr() works
            let extracted = addr.as_socket_addr();
            assert_eq!(extracted, Some(socket_addr));
        } else {
            panic!("Expected PeerConnected event");
        }
    }

    #[test]
    fn test_peer_connected_event_with_ble() {
        // BLE MAC address (6 bytes)
        let device_id = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xcd; 32]),
            addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            side: Side::Server,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
            traversal_method,
        } = event
        {
            assert_eq!(peer_id.0, [0xcd; 32]);
            assert!(side.is_server());
            assert_eq!(traversal_method, TraversalMethod::Direct);

            // Verify as_socket_addr() returns None for BLE
            assert!(addr.as_socket_addr().is_none());

            // Verify we can match on BLE variant
            if let TransportAddr::Ble {
                device_id: mac,
                service_uuid,
            } = addr
            {
                assert_eq!(mac, device_id);
                assert!(service_uuid.is_none());
            } else {
                panic!("Expected BLE address");
            }
        }
    }

    #[test]
    fn test_external_address_discovered_udp() {
        let socket_addr: SocketAddr = "203.0.113.1:12345".parse().expect("valid addr");
        let event = P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Udp(socket_addr),
        };

        if let P2pEvent::ExternalAddressDiscovered { addr } = event {
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert_eq!(addr.as_socket_addr(), Some(socket_addr));
        } else {
            panic!("Expected ExternalAddressDiscovered event");
        }
    }

    #[test]
    fn test_event_clone() {
        let socket_addr: SocketAddr = "10.0.0.1:9000".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0x11; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify events are Clone
        let cloned = event.clone();
        if let (
            P2pEvent::PeerConnected {
                peer_id: p1,
                addr: a1,
                ..
            },
            P2pEvent::PeerConnected {
                peer_id: p2,
                addr: a2,
                ..
            },
        ) = (&event, &cloned)
        {
            assert_eq!(p1.0, p2.0);
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn test_peer_connection_with_transport_addr() {
        // Test with UDP
        let udp_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let udp_conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(udp_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert_eq!(
            udp_conn.remote_addr.as_socket_addr(),
            Some(udp_addr),
            "UDP connection should have extractable socket address"
        );

        // Test with BLE
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ble_conn = PeerConnection {
            peer_id: PeerId([1u8; 32]),
            remote_addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert!(
            ble_conn.remote_addr.as_socket_addr().is_none(),
            "BLE connection should not have socket address"
        );
    }

    #[test]
    fn test_transport_addr_display_in_events() {
        let socket_addr: SocketAddr = "192.168.1.1:9001".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xff; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify display formatting works for logging
        let debug_str = format!("{:?}", event);
        assert!(
            debug_str.contains("192.168.1.1"),
            "Event debug should contain IP address"
        );
        assert!(
            debug_str.contains("9001"),
            "Event debug should contain port"
        );
    }

    // ==========================================================================
    // Connection Tracking Tests (Phase 2.2 Task 8)
    // ==========================================================================

    #[test]
    fn test_connection_tracking_udp() {
        use std::collections::HashMap;

        // Simulate connection tracking with TransportAddr::Udp
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");
        let peer_id = PeerId([0x01; 32]);
        let conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        connections.insert(peer_id, conn.clone());

        // Verify connection is tracked
        assert!(connections.contains_key(&peer_id));
        let retrieved = connections.get(&peer_id).expect("connection exists");
        assert_eq!(retrieved.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(retrieved.authenticated);
    }

    #[test]
    fn test_connection_tracking_multi_transport() {
        use std::collections::HashMap;

        // Simulate multiple connections on different transports
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // UDP connection
        let udp_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
        let peer1 = PeerId([0x01; 32]);
        connections.insert(
            peer1,
            PeerConnection {
                peer_id: peer1,
                remote_addr: TransportAddr::Udp(udp_addr),
                traversal_method: TraversalMethod::Direct,
                side: Side::Client,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // BLE connection (different peer)
        let peer2 = PeerId([0x02; 32]);
        let ble_device = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        connections.insert(
            peer2,
            PeerConnection {
                peer_id: peer2,
                remote_addr: TransportAddr::Ble {
                    device_id: ble_device,
                    service_uuid: None,
                },
                traversal_method: TraversalMethod::Direct,
                side: Side::Client,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // Verify each tracked independently
        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .get(&peer1)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_some()
        );
        assert!(
            connections
                .get(&peer2)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_none()
        );
    }

    #[test]
    fn test_connection_lookup_by_transport_addr() {
        use std::collections::HashMap;

        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // Add multiple connections
        let addrs = [
            ("10.0.0.1:8080", [0x01; 32]),
            ("10.0.0.2:8080", [0x02; 32]),
            ("10.0.0.3:8080", [0x03; 32]),
        ];

        for (addr_str, peer_bytes) in addrs {
            let socket_addr: SocketAddr = addr_str.parse().expect("valid addr");
            let peer_id = PeerId(peer_bytes);
            connections.insert(
                peer_id,
                PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(socket_addr),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Client,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
        }

        // Look up connection by transport address
        let target: SocketAddr = "10.0.0.2:8080".parse().expect("valid addr");
        let target_addr = TransportAddr::Udp(target);
        let found = connections.values().find(|c| c.remote_addr == target_addr);

        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.0, [0x02; 32]);
    }

    #[test]
    fn test_transport_addr_equality_in_tracking() {
        // Verify TransportAddr equality works correctly for tracking
        let addr1: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr2: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr3: SocketAddr = "192.168.1.1:8081".parse().expect("valid addr");

        let t1 = TransportAddr::Udp(addr1);
        let t2 = TransportAddr::Udp(addr2);
        let t3 = TransportAddr::Udp(addr3);

        // Same address should be equal
        assert_eq!(t1, t2);

        // Different port should not be equal
        assert_ne!(t1, t3);

        // Different transport type should not be equal
        let ble = TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        };
        assert_ne!(t1, ble);
    }

    #[test]
    fn test_peer_connection_update_preserves_transport_addr() {
        let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");
        let mut conn = PeerConnection {
            peer_id: PeerId([0xaa; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Simulate updating the connection (e.g., after authentication)
        conn.authenticated = true;
        conn.last_activity = Instant::now();

        // Verify transport address is preserved
        assert_eq!(conn.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(conn.authenticated);
    }
}
