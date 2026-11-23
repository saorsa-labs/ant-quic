// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Socket
//!
//! A virtual UDP socket that routes QUIC packets through a MASQUE relay.
//!
//! Supports two forwarding modes per ADR-016 and ADR-020:
//! - [`RelayForwardMode::Stream`] (default): all packets travel over the persistent
//!   bidirectional QUIC stream with `[4-byte BE length][UncompressedDatagram]` framing.
//! - [`RelayForwardMode::Hybrid`]: non-Initial packets that fit the negotiated QUIC
//!   `DATAGRAM` budget `P_max` travel as unreliable QUIC `DATAGRAM` frames (no
//!   head-of-line blocking, no nested retransmission), while QUIC Initial packets
//!   and packets larger than `P_max` stay on the length-prefixed stream lane.
//!
//! Hybrid is negotiated per relay session:
//! - `0.29.0+`: client sets [`crate::masque::connect::REQUEST_FLAG_HYBRID_DATAGRAM_LANE`]
//!   and relay answers [`crate::masque::connect::RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`].
//! - `0.30.0+` (ADR-020): client additionally sets
//!   [`crate::masque::connect::REQUEST_FLAG_DATAGRAM_MUX_V1`] and relay answers
//!   [`crate::masque::connect::RESPONSE_FLAG_DATAGRAM_MUX_V1`], enabling:
//!   1. RFC 9297 Context-ID `DatagramMux` with disjoint side-partitioned
//!      client-allocated even Context IDs (`Side::Client` `{2..=8, 18..=24, ...}`
//!      vs `Side::Server` `{10..=16, 26..=32, ...}`), eliminating Context ID `0`
//!      split-brain under mutual relaying and reuse-after-close while allowing
//!      concurrent `LinkConn::recv_datagrams` (e.g., voice) on odd Context ID `1`;
//!   2. `COMPRESSION_ASSIGN` / `ECN_COMPRESSION_ASSIGN` capsules (`1–2 B`
//!      [`CompressedDatagram`] headers instead of `8 B` IPv4 / `20 B` IPv6);
//!   3. `draft-seemann-masque-connect-udp-ecn-01` 4-context ECN propagation
//!      (`base + 0/2/4/6` for `Not-ECT`/`ECT(0)`/`ECT(1)`/`CE`);
//!   4. `900 B` `P_max` floor (superseding ADR-016 Decision 3's `1,232 B` floor)
//!      paired with an inner virtual-path MTU clamp (`min(P_max, 1380)`).
//!
//! Implements [`AsyncUdpSocket`] so it can be plugged into a Quinn endpoint
//! as a transparent replacement for a real UDP socket.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn_udp::{EcnCodepoint, RecvMeta, Transmit};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::coding::Codec;
use crate::high_level::{
    AsyncUdpSocket, Connection, SendDatagramError, UdpSender, WeakConnectionHandle,
};
use crate::masque::capsule::{Capsule, CompressionAssign};
use crate::masque::{CompressedDatagram, UncompressedDatagram};
use crate::{Side, VarInt};

/// Minimum QUIC Initial packet size per RFC 9000 §14.1.
pub const QUIC_INITIAL_MIN_SIZE: usize = 1200;

/// Legacy margin constant retained from ADR-016 Decision 3 (superseded by
/// ADR-020's `900 B` virtual-path floor).
pub const RELAY_DATAGRAM_BUDGET_MARGIN: usize = 32;

/// Smallest inner payload budget `P_max` for which the datagram lane is used
/// (ADR-020, superseding ADR-016 Decision 3's `1,232 B` floor).
pub const MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET: usize = 900;

/// Upper cap for the inner virtual-path MTU clamp (`min(P_max, 1380)`, ADR-020).
pub const MAX_INNER_RELAY_UDP_PAYLOAD_SIZE: usize = 1380;

/// Odd RFC 9297 Context ID reserved for multiplexed application datagrams
/// (`LinkConn::send_datagram` / `LinkConn::recv_datagrams`, e.g., x0x voice)
/// when `DATAGRAM_MUX_V1` is active on an outer connection.
///
/// Odd IDs are disjoint from even MASQUE Context IDs (`0, 2, 4, ...`).
pub const APP_DATAGRAM_CONTEXT_ID: u64 = 1;

/// Stride of one 4-context ECN quad (`base + 0/2/4/6`, 4 consecutive even IDs).
pub const ECN_CONTEXT_STRIDE: u64 = 8;

/// Stride between consecutive blocks allocated by ONE QUIC side on a connection.
///
/// `Side::Client` allocates `{2..=8, 18..=24, 34..=40, ...}` and `Side::Server`
/// allocates `{10..=16, 26..=32, 42..=48, ...}`, keeping both relay directions
/// mathematically disjoint under mutual relaying on the same outer connection.
pub const SIDE_BLOCK_STRIDE: u64 = 16;

/// Maximum number of compressed target entries tracked per relay session.
pub const DEFAULT_MAX_COMPRESSED_TARGETS: usize = 256;

/// Hard cap on total Context ID entries registered in one outer connection's
/// `DatagramMux` routing table (prevents unbounded heap growth DoS).
pub const MAX_MUX_ROUTES_PER_CONNECTION: usize = 2048;

/// Quarantine duration before a freed client-allocated 8-ID Context ID block
/// may be recycled for a subsequent session/target on the same outer connection.
///
/// Prevents a fast session close + reopen from colliding with a relay that is
/// still tearing down the prior stream or with stale in-flight datagrams.
pub const CTX_BLOCK_REUSE_COOLDOWN: Duration = Duration::from_secs(30);

/// Maximum bounded retries when a relay rejects a client's initial uncompressed
/// Context ID via `CompressionClose`.
const MAX_UNCOMPRESSED_CTX_RETRIES: usize = 3;

/// Maximum queued outbound packets before tail-drop engages.
pub const DEFAULT_RELAY_SEND_QUEUE_CAPACITY: usize = 256;

/// Maximum queued inbound packets before oldest-drop engages (UDP ring semantics).
pub const DEFAULT_RELAY_RECV_QUEUE_CAPACITY: usize = 256;

/// Relay data-plane forwarding mode (ADR-016 / ADR-020).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayForwardMode {
    /// Forward all packets over the length-prefixed reliable QUIC stream (ADR-009).
    #[default]
    Stream,
    /// Two-lane forwarding (ADR-016 / ADR-020): unreliable QUIC `DATAGRAM`
    /// frames for non-Initial packets `<= P_max`, length-prefixed stream for
    /// Initials and oversized packets. Used for a session only when both ends
    /// signal it in the CONNECT-UDP exchange.
    Hybrid,
}

/// Forwarding lane selected for a single inner UDP packet (ADR-016 / ADR-020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayLane {
    /// Unreliable QUIC `DATAGRAM` frame on the outer relay connection.
    Datagram,
    /// Length-prefixed frame on the reliable outer relay bidirectional stream.
    Stream,
}

/// Map a compressed target's even `base` Context ID and inner ECN codepoint to
/// the wire Context ID per `draft-seemann-masque-connect-udp-ecn-01`:
/// - `None` (`Not-ECT`) → `base + 0`
/// - `Some(Ect0)` → `base + 2`
/// - `Some(Ect1)` → `base + 4`
/// - `Some(Ce)` → `base + 6`
#[must_use]
pub fn ecn_context_id(base: VarInt, ecn: Option<EcnCodepoint>) -> VarInt {
    let offset = match ecn {
        None => 0,
        Some(EcnCodepoint::Ect0) => 2,
        Some(EcnCodepoint::Ect1) => 4,
        Some(EcnCodepoint::Ce) => 6,
    };
    VarInt::from_u64(base.into_inner().saturating_add(offset)).unwrap_or(base)
}

/// Decode the ECN codepoint from the offset `ctx_id - base` inside a 4-context
/// ECN quad (`0 => Not-ECT`, `2 => ECT(0)`, `4 => ECT(1)`, `6 => CE`).
#[must_use]
pub const fn decode_ecn_offset(offset: u64) -> Option<Option<EcnCodepoint>> {
    match offset {
        0 => Some(None),
        2 => Some(Some(EcnCodepoint::Ect0)),
        4 => Some(Some(EcnCodepoint::Ect1)),
        6 => Some(Some(EcnCodepoint::Ce)),
        _ => None,
    }
}

/// Overhead in bytes of an [`UncompressedDatagram`] header using Context ID `0`.
#[must_use]
pub const fn uncompressed_datagram_header_overhead(target: SocketAddr) -> usize {
    match target {
        SocketAddr::V4(_) => 1 + 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 1 + 16 + 2,
    }
}

/// Overhead in bytes of an [`UncompressedDatagram`] header with a specific
/// Context ID.
#[must_use]
pub fn uncompressed_datagram_header_overhead_for_ctx(
    context_id: VarInt,
    target: SocketAddr,
) -> usize {
    let ip_len = match target {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 16,
    };
    context_id.size() + 1 + ip_len + 2
}

/// Returns `true` if `payload` looks like a QUIC Initial packet (v1 or v2).
#[must_use]
pub fn is_quic_initial_packet(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    if (first & 0x80) == 0 {
        return false;
    }
    let long_type = (first & 0x30) >> 4;
    if payload.len() >= 5 {
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if version == 0x6b33_43cf {
            return long_type == 0x01;
        }
    }
    long_type == 0x00
}

/// Compute the inner UDP payload budget `P_max` that fits inside one outer
/// QUIC `DATAGRAM` frame given an explicit encapsulation header size `overhead`.
#[must_use]
pub fn compute_datagram_payload_budget_with_overhead(
    max_outer_datagram_size: Option<usize>,
    overhead: usize,
) -> Option<usize> {
    let outer = max_outer_datagram_size?;
    outer
        .checked_sub(overhead)
        .filter(|&budget| budget >= MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET)
}

/// Compute the inner UDP payload budget `P_max` for an uncompressed Context ID
/// `0` datagram to `target`.
#[must_use]
pub fn compute_datagram_payload_budget(
    max_outer_datagram_size: Option<usize>,
    target: SocketAddr,
) -> Option<usize> {
    compute_datagram_payload_budget_with_overhead(
        max_outer_datagram_size,
        uncompressed_datagram_header_overhead(target),
    )
}

/// Compute the recommended clamped inner virtual-path MTU (`min(P_max, 1380)`)
/// for an inner QUIC endpoint running over a hybrid MASQUE relay (ADR-020).
#[must_use]
pub fn compute_inner_virtual_path_mtu(
    max_outer_datagram_size: Option<usize>,
    overhead: usize,
) -> Option<u16> {
    let budget = compute_datagram_payload_budget_with_overhead(max_outer_datagram_size, overhead)?;
    let clamped = budget.min(MAX_INNER_RELAY_UDP_PAYLOAD_SIZE);
    u16::try_from(clamped).ok()
}

/// Select the forwarding lane for a single packet given explicit encapsulation
/// `overhead` (ADR-016 / ADR-020).
#[must_use]
pub fn select_relay_lane_with_overhead(
    payload: &[u8],
    overhead: usize,
    max_outer_datagram_size: Option<usize>,
    mode: RelayForwardMode,
) -> RelayLane {
    if mode == RelayForwardMode::Stream || is_quic_initial_packet(payload) {
        return RelayLane::Stream;
    }
    match compute_datagram_payload_budget_with_overhead(max_outer_datagram_size, overhead) {
        Some(p_max) if payload.len() <= p_max => RelayLane::Datagram,
        _ => RelayLane::Stream,
    }
}

/// Select the forwarding lane for a single packet using uncompressed Context ID
/// `0` overhead (ADR-016 / ADR-020).
#[must_use]
pub fn select_relay_lane(
    payload: &[u8],
    target: SocketAddr,
    max_outer_datagram_size: Option<usize>,
    mode: RelayForwardMode,
) -> RelayLane {
    select_relay_lane_with_overhead(
        payload,
        uncompressed_datagram_header_overhead(target),
        max_outer_datagram_size,
        mode,
    )
}

/// Why a [`DatagramLaneClaim`] could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramLaneError {
    /// The outer connection did not negotiate QUIC `DATAGRAM` frames.
    #[error("outer connection does not support QUIC datagrams")]
    Unsupported,
    /// Another legacy (non-muxed) hybrid relay session exclusively owns this
    /// connection's datagrams, or the per-connection route cap was hit.
    #[error("another hybrid relay session already reads this connection's datagrams")]
    ClaimedByRelaySession,
    /// A non-relay reader (for example `LinkConn::recv_datagrams`) already
    /// reads this connection's datagrams and a legacy exclusive claim was asked.
    #[error("another reader already consumes this connection's datagrams")]
    ClaimedByOtherReader,
}

#[derive(Debug, Clone)]
struct MasqueRoute {
    owner_session: u64,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    rx_dropped: Arc<AtomicU64>,
}

#[derive(Debug)]
struct ConnectionDatagramMux {
    /// Weak handle to the outer connection (never prevents idle close / drop).
    connection: WeakConnectionHandle,
    /// Confirmed legacy 0.29.0 exclusive hybrid relay claim active.
    legacy_exclusive_relay: bool,
    /// Client provisional-exclusive claim awaiting CONNECT-UDP answer.
    /// Allows `open_app_datagram_channel` without returning an empty stream;
    /// if an app reader subscribes during this window, `provisional_saw_app_reader`
    /// prevents falling back to legacy 0.29.0 exclusive mode.
    provisional_exclusive: bool,
    provisional_saw_app_reader: bool,
    /// Count of active `datagram_mux_v1` hybrid sessions on this connection.
    mux_v1_sessions: usize,
    /// Causal RX readiness (Relay T2a before writing `CompressionAck`/`Close`,
    /// Client T3 upon receiving first `CompressionAck`/`Close`).
    ///
    /// While `false` (direct / 0.28 / 0.29 / T0→T2 / T1→T3 / any pre-T2 abort),
    /// 100% of inbound datagrams pass raw to `app_subscribers` with zero
    /// stripping and zero drops. Rolled back to `false` if a pre-T2b relay
    /// claim drops before its `CompressionAck`/`Close` write commits.
    mux_v1_rx_ready: bool,
    /// Causal TX prefixing (Relay T2b after `CompressionAck`/`Close` write
    /// succeeds, Client T3 upon receiving first `CompressionAck`/`Close`).
    /// Sticky for the remainder of the outer connection's lifetime so teardown
    /// and subsequent sessions have zero asymmetry.
    mux_v1_tx_prefix: bool,
    /// Causal hard-mux RX drop barrier (Client T3 on first `CompressionAck`/`Close`,
    /// Relay T4 on first `0x01`-prefixed app frame or registered-ctx MASQUE
    /// datagram after T2a). Sticky once set.
    ///
    /// Unknown or closed Context IDs are dropped and counted ONLY once the peer
    /// is causally proven to prefix its outbound app datagrams.
    peer_tx_prefix_confirmed: bool,
    /// Legacy exclusive non-relay `register_other_datagram_reader` guards.
    legacy_other_readers: usize,
    /// Active `LinkConn::recv_datagrams` subscribers dispatched by `DatagramMux`.
    app_subscribers: HashMap<u64, tokio::sync::mpsc::Sender<Bytes>>,
    /// Registered MASQUE Context ID routes (`even >= 2`, bounded by
    /// `MAX_MUX_ROUTES_PER_CONNECTION`). Context ID `0` is never used by `mux_v1`.
    masque_routes: HashMap<u64, MasqueRoute>,
    /// Per-session locally allocated 8-ID blocks (kept inside `ConnectionDatagramMux`
    /// so all mux state lives under a single lock with zero lock-order inversions).
    session_allocated_blocks: HashMap<u64, Vec<u64>>,
    /// Relay-side currently active remote uncompressed Context ID per session
    /// (strictly at most one per session; replaced atomically on re-assign).
    session_uncompressed_ctx: HashMap<u64, u64>,
    /// Next locally allocated 8-ID block base for THIS QUIC side
    /// (`Side::Client` starts at 2, `Side::Server` starts at 10, step 16).
    next_local_block_base: u64,
    /// Quarantined 8-ID block bases `(base, freed_at)` recycled after
    /// `CTX_BLOCK_REUSE_COOLDOWN` so wire Context IDs stay `1–2 B` under churn
    /// without colliding with an in-flight relay teardown or stale datagrams.
    free_local_blocks: VecDeque<(u64, Instant)>,
    /// Monotonic local subscriber / session identifier.
    next_sub_id: u64,
    /// Count of frames dropped in hard-mux mode because their Context ID was
    /// unknown or closed.
    unknown_ctx_dropped: Arc<AtomicU64>,
    /// Count of app datagrams dropped because an app subscriber channel was full.
    app_rx_dropped: Arc<AtomicU64>,
    /// Cancel token for the single background `conn.read_datagram()` dispatcher.
    reader_cancel: Option<CancellationToken>,
}

impl ConnectionDatagramMux {
    fn new(connection: &Connection) -> Self {
        let first_block = match connection.side() {
            Side::Client => 2,
            Side::Server => 10,
        };
        Self {
            connection: connection.weak_handle(),
            legacy_exclusive_relay: false,
            provisional_exclusive: false,
            provisional_saw_app_reader: false,
            mux_v1_sessions: 0,
            mux_v1_rx_ready: false,
            mux_v1_tx_prefix: false,
            peer_tx_prefix_confirmed: false,
            legacy_other_readers: 0,
            app_subscribers: HashMap::new(),
            masque_routes: HashMap::new(),
            session_allocated_blocks: HashMap::new(),
            session_uncompressed_ctx: HashMap::new(),
            next_local_block_base: first_block,
            free_local_blocks: VecDeque::new(),
            next_sub_id: 1,
            unknown_ctx_dropped: Arc::new(AtomicU64::new(0)),
            app_rx_dropped: Arc::new(AtomicU64::new(0)),
            reader_cancel: None,
        }
    }

    fn has_active_users(&self) -> bool {
        self.legacy_exclusive_relay
            || self.provisional_exclusive
            || self.mux_v1_sessions > 0
            || self.legacy_other_readers > 0
            || !self.app_subscribers.is_empty()
            || !self.masque_routes.is_empty()
    }

    fn can_remove_from_map(&self) -> bool {
        if self.has_active_users() {
            return false;
        }
        if !self.connection.is_alive() {
            return true;
        }
        // Keep sticky mux_v1 negotiation state alive while the outer connection
        // is alive, and retain any still-quarantined freed blocks until
        // `CTX_BLOCK_REUSE_COOLDOWN` elapses (even if a session closed pre-T3
        // after sending `CompressionAssign`).
        let has_hot_quarantine = self
            .free_local_blocks
            .back()
            .is_some_and(|&(_, freed_at)| freed_at.elapsed() < CTX_BLOCK_REUSE_COOLDOWN);
        !self.mux_v1_tx_prefix && !has_hot_quarantine
    }

    fn needs_dispatcher(&self) -> bool {
        !self.app_subscribers.is_empty()
            || !self.masque_routes.is_empty()
            || self.mux_v1_sessions > 0
    }

    fn allocate_sub_id(&mut self) -> u64 {
        let id = self.next_sub_id;
        self.next_sub_id = self.next_sub_id.wrapping_add(1).max(1);
        id
    }

    /// Allocate one 8-ID even block `[base, base+2, base+4, base+6]` from THIS
    /// QUIC side's disjoint pool, recycling only blocks whose quarantine
    /// cooldown (`CTX_BLOCK_REUSE_COOLDOWN`) has elapsed.
    fn allocate_local_block(&mut self) -> Option<VarInt> {
        let now = Instant::now();
        while let Some(&(base, freed_at)) = self.free_local_blocks.front() {
            if now.saturating_duration_since(freed_at) < CTX_BLOCK_REUSE_COOLDOWN {
                // FIFO order: if the oldest entry is still in quarantine, all
                // newer entries are too. Allocate a fresh block instead.
                break;
            }
            self.free_local_blocks.pop_front();
            if !self.masque_routes.contains_key(&base)
                && !self.masque_routes.contains_key(&(base + 2))
                && !self.masque_routes.contains_key(&(base + 4))
                && !self.masque_routes.contains_key(&(base + 6))
            {
                return VarInt::from_u64(base).ok();
            }
        }
        loop {
            let base = self.next_local_block_base;
            let max_id = base.checked_add(6)?;
            if max_id > VarInt::MAX.into_inner() {
                return None;
            }
            self.next_local_block_base = base.saturating_add(SIDE_BLOCK_STRIDE);
            if !self.masque_routes.contains_key(&base)
                && !self.masque_routes.contains_key(&(base + 2))
                && !self.masque_routes.contains_key(&(base + 4))
                && !self.masque_routes.contains_key(&(base + 6))
            {
                return VarInt::from_u64(base).ok();
            }
        }
    }

    fn recycle_local_block(&mut self, base: u64) {
        if self.free_local_blocks.len() < MAX_MUX_ROUTES_PER_CONNECTION
            && !self.free_local_blocks.iter().any(|&(b, _)| b == base)
        {
            self.free_local_blocks.push_back((base, Instant::now()));
        }
    }
}

type SharedMux = Arc<parking_lot::Mutex<ConnectionDatagramMux>>;

/// Amortized O(1) registry of per-connection `DatagramMux` entries.
struct MuxRegistry {
    map: HashMap<usize, SharedMux>,
    /// Next map size at which an amortized dead-entry sweep triggers
    /// (`(live * 2).max(64)`), avoiding O(connections) scans on every claim.
    next_prune_threshold: usize,
}

impl MuxRegistry {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_prune_threshold: 64,
        }
    }
}

/// Per-connection RFC 9297 Context-ID datagram demultiplexers, keyed by
/// `Connection::stable_id`.
///
/// Lock order invariant (eliminates create/cleanup races and ABBA inversions):
/// whenever both locks are needed, ALWAYS acquire `DATAGRAM_MUXES` BEFORE
/// locking an individual `ConnectionDatagramMux`, and NEVER hold either lock
/// across an `.await`. There are no per-claim sub-mutexes.
static DATAGRAM_MUXES: LazyLock<parking_lot::Mutex<MuxRegistry>> =
    LazyLock::new(|| parking_lot::Mutex::new(MuxRegistry::new()));

/// Inspect the count of unknown/closed Context ID frames dropped in hard-mux
/// mode on `connection` (diagnostics & tests).
#[must_use]
pub fn mux_unknown_ctx_dropped(connection: &Connection) -> u64 {
    let key = connection.stable_id();
    let registry = DATAGRAM_MUXES.lock();
    registry.map.get(&key).map_or(0, |mux| {
        mux.lock().unknown_ctx_dropped.load(Ordering::Relaxed)
    })
}

/// Inspect the current number of registered MASQUE routes in `DatagramMux` for
/// `connection` (diagnostics & tests).
#[must_use]
pub fn mux_registered_route_count(connection: &Connection) -> usize {
    let key = connection.stable_id();
    let registry = DATAGRAM_MUXES.lock();
    registry
        .map
        .get(&key)
        .map_or(0, |mux| mux.lock().masque_routes.len())
}

#[cfg(test)]
pub(crate) fn prune_dead_muxes_for_test() -> usize {
    let mut registry = DATAGRAM_MUXES.lock();
    let before = registry.map.len();
    registry
        .map
        .retain(|_, existing| !existing.lock().can_remove_from_map());
    registry.next_prune_threshold = registry.map.len().saturating_mul(2).max(64);
    before.saturating_sub(registry.map.len())
}

#[cfg(test)]
pub(crate) fn mux_entry_present_for_test(stable_id: usize) -> bool {
    DATAGRAM_MUXES.lock().map.contains_key(&stable_id)
}

fn get_or_create_mux_locked(registry: &mut MuxRegistry, connection: &Connection) -> SharedMux {
    let key = connection.stable_id();
    if let Some(existing) = registry.map.get(&key) {
        return Arc::clone(existing);
    }
    // Amortized O(1) dead-entry sweep: only scan when new insertions hit the
    // doubling threshold, never on existing-key hot paths.
    if registry.map.len() >= registry.next_prune_threshold {
        registry
            .map
            .retain(|_, existing| !existing.lock().can_remove_from_map());
        registry.next_prune_threshold = registry.map.len().saturating_mul(2).max(64);
    }
    let mux = Arc::new(parking_lot::Mutex::new(ConnectionDatagramMux::new(
        connection,
    )));
    registry.map.insert(key, Arc::clone(&mux));
    mux
}

fn cleanup_mux_locked(registry: &mut MuxRegistry, key: usize, mux: &SharedMux) {
    let should_remove = {
        let mut state = mux.lock();
        if !state.needs_dispatcher()
            && let Some(cancel) = state.reader_cancel.take()
        {
            cancel.cancel();
        }
        state.can_remove_from_map()
    };
    if should_remove {
        registry.map.remove(&key);
    }
}

/// Ensure the single per-connection `conn.read_datagram()` dispatcher is
/// running. Safe to call outside a Tokio runtime (defers spawn until an async
/// consumer calls it inside a runtime).
fn ensure_dispatcher_running(connection: &Connection, mux: &SharedMux) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let cancel = {
        let mut state = mux.lock();
        if !state.needs_dispatcher() || state.reader_cancel.is_some() {
            return;
        }
        let token = CancellationToken::new();
        state.reader_cancel = Some(token.clone());
        token
    };

    let conn = connection.clone();
    let key = connection.stable_id();
    let mux_weak = Arc::downgrade(mux);
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = cancel.cancelled() => break,
                read = conn.read_datagram() => match read {
                    Ok(frame) => frame,
                    Err(e) => {
                        tracing::debug!(error = %e, "DatagramMux: outer datagram read ended");
                        break;
                    }
                },
            };

            let Some(mux) = mux_weak.upgrade() else {
                break;
            };

            let mut cursor = frame.clone();
            let decoded_ctx = VarInt::decode(&mut cursor).ok().map(VarInt::into_inner);

            enum Dispatch {
                Masque(MasqueRoute, Bytes),
                App(Bytes, Vec<tokio::sync::mpsc::Sender<Bytes>>, Arc<AtomicU64>),
                Drop,
            }

            let action = {
                let mut state = mux.lock();
                if !state.mux_v1_rx_ready {
                    // Direct / 0.28 / 0.29 / pre-T2 relay / pre-T3 client (and
                    // any T2-never-happens abort path): deliver 100% raw app
                    // datagrams with zero stripping and zero drops.
                    if state.app_subscribers.is_empty() {
                        Dispatch::Drop
                    } else {
                        Dispatch::App(
                            frame,
                            state.app_subscribers.values().cloned().collect(),
                            Arc::clone(&state.app_rx_dropped),
                        )
                    }
                } else if decoded_ctx == Some(APP_DATAGRAM_CONTEXT_ID) {
                    // RFC 9297 odd app context ID: peer is causally prefixing
                    // (T4 on relay); strip 1-byte prefix and deliver.
                    state.peer_tx_prefix_confirmed = true;
                    if state.app_subscribers.is_empty() {
                        Dispatch::Drop
                    } else {
                        Dispatch::App(
                            cursor,
                            state.app_subscribers.values().cloned().collect(),
                            Arc::clone(&state.app_rx_dropped),
                        )
                    }
                } else if let Some(ctx_id) = decoded_ctx
                    && let Some(route) = state.masque_routes.get(&ctx_id).cloned()
                {
                    // Peer sent a registered MASQUE context ID (causally proves
                    // client received CompressionAck and entered T3 -> T4 on relay).
                    state.peer_tx_prefix_confirmed = true;
                    Dispatch::Masque(route, frame)
                } else if !state.peer_tx_prefix_confirmed && !state.app_subscribers.is_empty() {
                    // Brief Relay T2a→T4 startup window while client's pre-T3
                    // raw app datagrams may still be in flight.
                    Dispatch::App(
                        frame,
                        state.app_subscribers.values().cloned().collect(),
                        Arc::clone(&state.app_rx_dropped),
                    )
                } else {
                    // Confirmed hard-mux RX mode (`peer_tx_prefix_confirmed`):
                    // unknown or closed Context IDs are dropped and counted,
                    // never handed raw to app subscribers.
                    state.unknown_ctx_dropped.fetch_add(1, Ordering::Relaxed);
                    Dispatch::Drop
                }
            };

            match action {
                Dispatch::Masque(route, frame) => {
                    if route.tx.try_send(frame).is_err() {
                        route.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Dispatch::App(payload, subs, drop_counter) => {
                    for tx in subs {
                        if tx.try_send(payload.clone()).is_err() {
                            drop_counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Dispatch::Drop => {}
            }
        }

        // Clear reader_cancel on natural connection close and prune if idle.
        if let Some(mux) = mux_weak.upgrade() {
            let mut registry = DATAGRAM_MUXES.lock();
            {
                let mut state = mux.lock();
                if state
                    .reader_cancel
                    .as_ref()
                    .is_some_and(|c| c.is_cancelled() || conn.close_reason().is_some())
                {
                    state.reader_cancel = None;
                }
            }
            cleanup_mux_locked(&mut registry, key, &mux);
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimMode {
    /// Confirmed legacy 0.29.0 exclusive claim (reads `conn.read_datagram()` directly).
    LegacyExclusive,
    /// Client-side provisional claim awaiting CONNECT-UDP response; allows
    /// concurrent `open_app_datagram_channel` without starving voice.
    ClientProvisionalExclusive,
    /// Client-side provisional `mux_v1`-only claim (app reader or mux_v1 already active).
    ClientProvisionalMuxOnly,
    /// Active RFC 9297 `DatagramMux` (`datagram_mux_v1`) lease (client or server).
    MuxV1 { is_relay_client: bool },
}

/// Claim on the QUIC `DATAGRAM` lane of one outer connection for a hybrid
/// MASQUE relay session.
pub struct DatagramLaneClaim {
    connection: Connection,
    key: usize,
    mux: SharedMux,
    mode: ClaimMode,
    session_id: u64,
    /// Locally allocated uncompressed Context ID (client-initiated `mux_v1`
    /// only; `None` on relay server until client sends `CompressionAssign`).
    /// Stored as `AtomicU64` (`u64::MAX` = unassigned) so N4 bounded retry can
    /// replace it cleanly without adding a per-claim mutex.
    uncompressed_ctx_id: AtomicU64,
    /// Per-session `rx_dropped` counter shared with `MasqueRelaySocketStats`.
    rx_dropped: Arc<AtomicU64>,
    tx: Option<tokio::sync::mpsc::Sender<Bytes>>,
    rx: Option<tokio::sync::mpsc::Receiver<Bytes>>,
}

const UNASSIGNED_LOCAL_CTX: u64 = u64::MAX;

impl DatagramLaneClaim {
    /// Take a legacy exclusive datagram-lane claim (0.29.0 semantics).
    pub fn try_claim(connection: &Connection) -> Result<Self, DatagramLaneError> {
        if connection.max_datagram_size().is_none() {
            return Err(DatagramLaneError::Unsupported);
        }
        let key = connection.stable_id();
        let mux = {
            let mut registry = DATAGRAM_MUXES.lock();
            let mux = get_or_create_mux_locked(&mut registry, connection);
            let mut state = mux.lock();
            if state.legacy_exclusive_relay
                || state.provisional_exclusive
                || state.mux_v1_sessions > 0
            {
                return Err(DatagramLaneError::ClaimedByRelaySession);
            }
            if state.legacy_other_readers > 0 || !state.app_subscribers.is_empty() {
                return Err(DatagramLaneError::ClaimedByOtherReader);
            }
            state.legacy_exclusive_relay = true;
            drop(state);
            mux
        };
        Ok(Self {
            connection: connection.clone(),
            key,
            mux,
            mode: ClaimMode::LegacyExclusive,
            session_id: 0,
            uncompressed_ctx_id: AtomicU64::new(0),
            rx_dropped: Arc::new(AtomicU64::new(0)),
            tx: None,
            rx: None,
        })
    }

    /// Take an active relay-server `0.30.0+` `DatagramMux` (`datagram_mux_v1`)
    /// lease on `connection`.
    ///
    /// Per ADR-020:
    /// - The relay server NEVER self-allocates Context IDs or Context ID `0`.
    /// - At T0 (`try_claim_muxed`), neither `mux_v1_rx_ready` nor
    ///   `mux_v1_tx_prefix` is armed yet so a failed or aborted pre-T2 session
    ///   never strips or drops raw app datagrams (`client <-> relay`).
    /// - `arm_relay_rx_ready()` arms `mux_v1_rx_ready` at T2a right before
    ///   writing `CompressionAck`/`Close`, and `confirm_relay_tx_prefix()` arms
    ///   sticky `mux_v1_tx_prefix` at T2b once that write succeeds.
    pub fn try_claim_muxed(connection: &Connection) -> Result<Self, DatagramLaneError> {
        if connection.max_datagram_size().is_none() {
            return Err(DatagramLaneError::Unsupported);
        }
        let key = connection.stable_id();
        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
        let (mux, session_id) = {
            let mut registry = DATAGRAM_MUXES.lock();
            let mux = get_or_create_mux_locked(&mut registry, connection);
            let mut state = mux.lock();
            if state.legacy_exclusive_relay {
                return Err(DatagramLaneError::ClaimedByRelaySession);
            }
            if state.legacy_other_readers > 0 {
                return Err(DatagramLaneError::ClaimedByOtherReader);
            }
            let session_id = state.allocate_sub_id();
            state.mux_v1_sessions += 1;
            drop(state);
            (mux, session_id)
        };
        ensure_dispatcher_running(connection, &mux);
        Ok(Self {
            connection: connection.clone(),
            key,
            mux,
            mode: ClaimMode::MuxV1 {
                is_relay_client: false,
            },
            session_id,
            uncompressed_ctx_id: AtomicU64::new(UNASSIGNED_LOCAL_CTX),
            rx_dropped: Arc::new(AtomicU64::new(0)),
            tx: Some(tx),
            rx: Some(rx),
        })
    }

    /// Take a client-side provisional claim before sending `CONNECT-UDP`:
    /// - If `connection` is idle and not yet in sticky `mux_v1`, allows BOTH
    ///   legacy `0.29.0` fallback (`0x02`) and `0.30.0` `DatagramMux` (`0x04`).
    /// - If `LinkConn::recv_datagrams`, another `mux_v1` session, or sticky
    ///   `mux_v1` is active, requests `0x04` ONLY so a `0.29.0` relay cleanly
    ///   stays stream-only.
    pub fn try_claim_for_client(connection: &Connection) -> Result<Self, DatagramLaneError> {
        if connection.max_datagram_size().is_none() {
            return Err(DatagramLaneError::Unsupported);
        }
        let key = connection.stable_id();
        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_RELAY_RECV_QUEUE_CAPACITY);

        let (mux, mode) = {
            let mut registry = DATAGRAM_MUXES.lock();
            let mux = get_or_create_mux_locked(&mut registry, connection);
            let mut state = mux.lock();
            if state.legacy_exclusive_relay {
                return Err(DatagramLaneError::ClaimedByRelaySession);
            }
            if state.legacy_other_readers > 0 {
                return Err(DatagramLaneError::ClaimedByOtherReader);
            }
            let mode = if !state.provisional_exclusive
                && !state.mux_v1_rx_ready
                && !state.mux_v1_tx_prefix
                && state.mux_v1_sessions == 0
                && state.app_subscribers.is_empty()
            {
                state.provisional_exclusive = true;
                state.provisional_saw_app_reader = false;
                ClaimMode::ClientProvisionalExclusive
            } else {
                ClaimMode::ClientProvisionalMuxOnly
            };
            drop(state);
            (mux, mode)
        };

        Ok(Self {
            connection: connection.clone(),
            key,
            mux,
            mode,
            session_id: 0,
            uncompressed_ctx_id: AtomicU64::new(UNASSIGNED_LOCAL_CTX),
            rx_dropped: Arc::new(AtomicU64::new(0)),
            tx: Some(tx),
            rx: Some(rx),
        })
    }

    /// Whether the client should set `REQUEST_FLAG_HYBRID_DATAGRAM_LANE` (`0x02`).
    #[must_use]
    pub fn should_request_legacy_hybrid(&self) -> bool {
        matches!(
            self.mode,
            ClaimMode::LegacyExclusive | ClaimMode::ClientProvisionalExclusive
        )
    }

    /// Whether the client should set `REQUEST_FLAG_DATAGRAM_MUX_V1` (`0x04`).
    #[must_use]
    pub fn should_request_mux_v1(&self) -> bool {
        matches!(
            self.mode,
            ClaimMode::ClientProvisionalExclusive
                | ClaimMode::ClientProvisionalMuxOnly
                | ClaimMode::MuxV1 { .. }
        )
    }

    /// Finalize a client-side provisional claim once the relay answers with
    /// `RESPONSE_FLAG_DATAGRAM_MUX_V1` (`0x08`) (T1).
    ///
    /// Allocates one disjoint even uncompressed Context ID from THIS QUIC side's
    /// pool and registers it in `DatagramMux`, WITHOUT arming `mux_v1_rx_ready`,
    /// `mux_v1_tx_prefix`, or `peer_tx_prefix_confirmed` yet. Those flags flip
    /// at T3 (`confirm_client_mux_v1_confirmed`) when the relay sends its first
    /// `CompressionAck`/`CompressionClose`, guaranteeing zero raw-voice
    /// stripping or blackout during T1→T2 or if T2 never happens.
    pub fn activate_mux_v1(&mut self) -> bool {
        match self.mode {
            ClaimMode::MuxV1 { .. } => true,
            ClaimMode::ClientProvisionalExclusive | ClaimMode::ClientProvisionalMuxOnly => {
                let Some(tx) = self.tx.clone() else {
                    return false;
                };
                let was_prov_excl = self.mode == ClaimMode::ClientProvisionalExclusive;
                let allocated = {
                    let _registry = DATAGRAM_MUXES.lock();
                    let mut state = self.mux.lock();
                    if was_prov_excl {
                        state.provisional_exclusive = false;
                        state.provisional_saw_app_reader = false;
                    }
                    if state.masque_routes.len() >= MAX_MUX_ROUTES_PER_CONNECTION {
                        return false;
                    }
                    let Some(u_ctx) = state.allocate_local_block() else {
                        return false;
                    };
                    let session_id = state.allocate_sub_id();
                    self.session_id = session_id;
                    state.masque_routes.insert(
                        u_ctx.into_inner(),
                        MasqueRoute {
                            owner_session: session_id,
                            tx,
                            rx_dropped: Arc::clone(&self.rx_dropped),
                        },
                    );
                    state
                        .session_allocated_blocks
                        .entry(session_id)
                        .or_default()
                        .push(u_ctx.into_inner());
                    state.mux_v1_sessions += 1;
                    u_ctx
                };
                self.uncompressed_ctx_id
                    .store(allocated.into_inner(), Ordering::Release);
                self.mode = ClaimMode::MuxV1 {
                    is_relay_client: true,
                };
                ensure_dispatcher_running(&self.connection, &self.mux);
                true
            }
            ClaimMode::LegacyExclusive => false,
        }
    }

    /// Finalize a client-side provisional claim when a legacy `0.29.0` relay
    /// answered `HYBRID` without `DATAGRAM_MUX_V1`.
    pub fn activate_legacy_hybrid(&mut self) -> bool {
        match self.mode {
            ClaimMode::LegacyExclusive => true,
            ClaimMode::ClientProvisionalExclusive => {
                let _registry = DATAGRAM_MUXES.lock();
                let mut state = self.mux.lock();
                state.provisional_exclusive = false;
                if state.provisional_saw_app_reader
                    || !state.app_subscribers.is_empty()
                    || state.mux_v1_sessions > 0
                {
                    state.provisional_saw_app_reader = false;
                    self.mode = ClaimMode::ClientProvisionalMuxOnly;
                    return false;
                }
                state.legacy_exclusive_relay = true;
                self.uncompressed_ctx_id.store(0, Ordering::Release);
                self.mode = ClaimMode::LegacyExclusive;
                true
            }
            ClaimMode::ClientProvisionalMuxOnly | ClaimMode::MuxV1 { .. } => false,
        }
    }

    /// T2a barrier on relay server: called when the relay receives the client's
    /// first `CompressionAssign`/`EcnCompressionAssign` capsule, right BEFORE
    /// writing `CompressionAck`/`CompressionClose` so the relay is ready to
    /// accept `0x01`-prefixed app frames and MASQUE datagrams as soon as the
    /// client receives the reply (T3).
    ///
    /// Does NOT arm `mux_v1_tx_prefix` yet; if writing the reply fails and this
    /// claim drops before T2b, `Drop` rolls back `mux_v1_rx_ready` to `false`.
    pub(crate) fn arm_relay_rx_ready(&self) {
        if self.is_mux_v1() {
            let mut state = self.mux.lock();
            state.mux_v1_rx_ready = true;
        }
    }

    /// T2b barrier on relay server: called right AFTER the relay successfully
    /// writes `CompressionAck`/`CompressionClose` to the stream, committing
    /// sticky `mux_v1_tx_prefix = true` (so relay's reply capsule is ordered
    /// ahead of its first `0x01`-prefixed app datagram).
    pub(crate) fn confirm_relay_tx_prefix(&self) {
        if self.is_mux_v1() {
            let mut state = self.mux.lock();
            state.mux_v1_rx_ready = true;
            state.mux_v1_tx_prefix = true;
        }
    }

    /// T3 barrier on relay client: called when the client receives the relay's
    /// first `CompressionAck` or `CompressionClose` capsule on the stream.
    ///
    /// Causally proves the relay reached T2 (`mux_v1_rx_ready = true` and
    /// `mux_v1_tx_prefix = true`), so the client safely commits sticky
    /// `mux_v1_rx_ready`, `mux_v1_tx_prefix`, and hard-mux RX
    /// `peer_tx_prefix_confirmed` together.
    pub(crate) fn confirm_client_mux_v1_confirmed(&self) {
        if self.is_mux_v1() {
            let mut state = self.mux.lock();
            state.mux_v1_rx_ready = true;
            state.mux_v1_tx_prefix = true;
            state.peer_tx_prefix_confirmed = true;
        }
    }

    /// Client-side N4 recovery: if the relay rejected our initial uncompressed
    /// Context ID via `CompressionClose`, unregister the rejected block (putting
    /// it into quarantine) and allocate + register a fresh disjoint block.
    pub(crate) fn reallocate_uncompressed_context(&self) -> Option<VarInt> {
        if !matches!(
            self.mode,
            ClaimMode::MuxV1 {
                is_relay_client: true
            }
        ) {
            return None;
        }
        let tx = self.tx.as_ref()?.clone();
        let old = self.uncompressed_ctx_id.load(Ordering::Acquire);
        let new_ctx = {
            let mut state = self.mux.lock();
            if old != UNASSIGNED_LOCAL_CTX {
                if state
                    .masque_routes
                    .get(&old)
                    .is_some_and(|r| r.owner_session == self.session_id)
                {
                    state.masque_routes.remove(&old);
                }
                if let Some(blocks) = state.session_allocated_blocks.get_mut(&self.session_id)
                    && let Some(pos) = blocks.iter().position(|&x| x == old)
                {
                    blocks.swap_remove(pos);
                    state.recycle_local_block(old);
                }
            }
            if state.masque_routes.len() >= MAX_MUX_ROUTES_PER_CONNECTION {
                return None;
            }
            let fresh = state.allocate_local_block()?;
            let c = fresh.into_inner();
            state.masque_routes.insert(
                c,
                MasqueRoute {
                    owner_session: self.session_id,
                    tx,
                    rx_dropped: Arc::clone(&self.rx_dropped),
                },
            );
            state
                .session_allocated_blocks
                .entry(self.session_id)
                .or_default()
                .push(c);
            fresh
        };
        self.uncompressed_ctx_id
            .store(new_ctx.into_inner(), Ordering::Release);
        Some(new_ctx)
    }

    /// Wire the socket's `rx_dropped` counter into this claim's `DatagramMux`
    /// routes so channel-full drops are never silent.
    pub(crate) fn attach_rx_dropped_counter(&mut self, counter: Arc<AtomicU64>) {
        self.rx_dropped = Arc::clone(&counter);
        if self.is_mux_v1() {
            let sid = self.session_id;
            let mut state = self.mux.lock();
            for route in state.masque_routes.values_mut() {
                if route.owner_session == sid {
                    route.rx_dropped = Arc::clone(&counter);
                }
            }
        }
    }

    /// Whether this claim runs in `0.30.0+` RFC 9297 `DatagramMux` mode.
    #[must_use]
    pub fn is_mux_v1(&self) -> bool {
        matches!(self.mode, ClaimMode::MuxV1 { .. })
    }

    /// Client-allocated uncompressed Context ID (`Some(u_ctx >= 2)` on a
    /// client `mux_v1` session, `Some(0)` on legacy `0.29.0`, `None` on relay
    /// server until the client sends `CompressionAssign::uncompressed`).
    #[must_use]
    pub fn uncompressed_context_id(&self) -> Option<VarInt> {
        let raw = self.uncompressed_ctx_id.load(Ordering::Acquire);
        if raw == UNASSIGNED_LOCAL_CTX {
            None
        } else {
            VarInt::from_u64(raw).ok()
        }
    }

    /// The outer connection whose datagram lane this claim holds.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Take the `DatagramMux` inbound datagram channel for this session.
    pub(crate) fn take_datagram_rx(&mut self) -> Option<tokio::sync::mpsc::Receiver<Bytes>> {
        self.rx.take()
    }

    /// Client-side: allocate and register a disjoint 4-context even ECN quad
    /// `{base, base+2, base+4, base+6}` on this connection's `DatagramMux`.
    pub(crate) fn allocate_ecn_quad(&self) -> Option<VarInt> {
        if !matches!(
            self.mode,
            ClaimMode::MuxV1 {
                is_relay_client: true
            }
        ) {
            return None;
        }
        let tx = self.tx.as_ref()?.clone();
        let mut state = self.mux.lock();
        if state.masque_routes.len() + 4 > MAX_MUX_ROUTES_PER_CONNECTION {
            return None;
        }
        let base = state.allocate_local_block()?;
        let b = base.into_inner();
        for offset in [0u64, 2, 4, 6] {
            state.masque_routes.insert(
                b + offset,
                MasqueRoute {
                    owner_session: self.session_id,
                    tx: tx.clone(),
                    rx_dropped: Arc::clone(&self.rx_dropped),
                },
            );
        }
        state
            .session_allocated_blocks
            .entry(self.session_id)
            .or_default()
            .push(b);
        Some(base)
    }

    /// Relay-side: register a client-assigned uncompressed Context ID,
    /// enforcing strictly **one** uncompressed ctx per session (replacing and
    /// unregistering any previous uncompressed ctx), rejecting `0` and odd IDs,
    /// and enforcing `MAX_MUX_ROUTES_PER_CONNECTION`.
    pub(crate) fn register_remote_uncompressed_context(&self, ctx_id: VarInt) -> bool {
        if !self.is_mux_v1() {
            return false;
        }
        let c = ctx_id.into_inner();
        if c < 2 || c % 2 != 0 {
            return false;
        }
        let Some(tx) = self.tx.as_ref().cloned() else {
            return false;
        };
        let mut state = self.mux.lock();
        if let Some(route) = state.masque_routes.get(&c)
            && route.owner_session != self.session_id
        {
            return false;
        }
        let prev = state
            .session_uncompressed_ctx
            .get(&self.session_id)
            .copied();
        let replacing_same = prev == Some(c);
        if !replacing_same
            && prev.is_none()
            && state.masque_routes.len() >= MAX_MUX_ROUTES_PER_CONNECTION
        {
            return false;
        }
        if let Some(old) = prev
            && old != c
            && state
                .masque_routes
                .get(&old)
                .is_some_and(|r| r.owner_session == self.session_id)
        {
            state.masque_routes.remove(&old);
        }
        state.masque_routes.insert(
            c,
            MasqueRoute {
                owner_session: self.session_id,
                tx,
                rx_dropped: Arc::clone(&self.rx_dropped),
            },
        );
        state.session_uncompressed_ctx.insert(self.session_id, c);
        true
    }

    /// Relay-side: register a client-assigned 4-context even ECN quad
    /// `{base, base+2, base+4, base+6}`. Rejects odd IDs, `< 2`, collisions
    /// with other sessions, and routes beyond `MAX_MUX_ROUTES_PER_CONNECTION`.
    pub(crate) fn register_remote_ecn_quad(&self, base: VarInt) -> bool {
        if !self.is_mux_v1() {
            return false;
        }
        let b = base.into_inner();
        if b < 2
            || b % 2 != 0
            || b.checked_add(6)
                .is_none_or(|m| m > VarInt::MAX.into_inner())
        {
            return false;
        }
        let Some(tx) = self.tx.as_ref().cloned() else {
            return false;
        };
        let mut state = self.mux.lock();
        let mut new_slots = 0usize;
        for offset in [0u64, 2, 4, 6] {
            match state.masque_routes.get(&(b + offset)) {
                Some(route) if route.owner_session != self.session_id => return false,
                Some(_) => {}
                None => new_slots += 1,
            }
        }
        if state.masque_routes.len() + new_slots > MAX_MUX_ROUTES_PER_CONNECTION {
            return false;
        }
        for offset in [0u64, 2, 4, 6] {
            state.masque_routes.insert(
                b + offset,
                MasqueRoute {
                    owner_session: self.session_id,
                    tx: tx.clone(),
                    rx_dropped: Arc::clone(&self.rx_dropped),
                },
            );
        }
        true
    }

    /// Relay-side: register a single client-assigned compressed Context ID.
    /// Rejects `< 2`, odd IDs, collisions, and routes past the per-connection cap.
    pub(crate) fn register_remote_context(&self, ctx_id: VarInt) -> bool {
        if !self.is_mux_v1() {
            return false;
        }
        let c = ctx_id.into_inner();
        if c < 2 || c % 2 != 0 {
            return false;
        }
        let Some(tx) = self.tx.as_ref().cloned() else {
            return false;
        };
        let mut state = self.mux.lock();
        let is_new = match state.masque_routes.get(&c) {
            Some(route) if route.owner_session != self.session_id => return false,
            Some(_) => false,
            None => true,
        };
        if is_new && state.masque_routes.len() >= MAX_MUX_ROUTES_PER_CONNECTION {
            return false;
        }
        state.masque_routes.insert(
            c,
            MasqueRoute {
                owner_session: self.session_id,
                tx,
                rx_dropped: Arc::clone(&self.rx_dropped),
            },
        );
        true
    }

    /// Unregister a 4-context ECN quad belonging to this session (and place the
    /// block into reuse quarantine if locally allocated).
    pub(crate) fn unregister_ecn_quad(&self, base: VarInt) {
        let b = base.into_inner();
        let mut state = self.mux.lock();
        for offset in [0u64, 2, 4, 6] {
            if state
                .masque_routes
                .get(&(b + offset))
                .is_some_and(|r| r.owner_session == self.session_id)
            {
                state.masque_routes.remove(&(b + offset));
            }
        }
        if let Some(blocks) = state.session_allocated_blocks.get_mut(&self.session_id)
            && let Some(pos) = blocks.iter().position(|&x| x == b)
        {
            blocks.swap_remove(pos);
            state.recycle_local_block(b);
        }
    }

    /// Unregister a single Context ID belonging to this session.
    pub(crate) fn unregister_context(&self, ctx_id: VarInt) {
        let c = ctx_id.into_inner();
        let mut state = self.mux.lock();
        if state
            .masque_routes
            .get(&c)
            .is_some_and(|r| r.owner_session == self.session_id)
        {
            state.masque_routes.remove(&c);
        }
        if state.session_uncompressed_ctx.get(&self.session_id) == Some(&c) {
            state.session_uncompressed_ctx.remove(&self.session_id);
        }
    }
}

impl fmt::Debug for DatagramLaneClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramLaneClaim")
            .field("connection", &self.key)
            .field("mode", &self.mode)
            .field("uncompressed_ctx_id", &self.uncompressed_context_id())
            .finish()
    }
}

impl Drop for DatagramLaneClaim {
    fn drop(&mut self) {
        let mut registry = DATAGRAM_MUXES.lock();
        {
            let mut state = self.mux.lock();
            match self.mode {
                ClaimMode::LegacyExclusive => {
                    state.legacy_exclusive_relay = false;
                }
                ClaimMode::ClientProvisionalExclusive => {
                    state.provisional_exclusive = false;
                    state.provisional_saw_app_reader = false;
                }
                ClaimMode::ClientProvisionalMuxOnly => {}
                ClaimMode::MuxV1 { .. } => {
                    let sid = self.session_id;
                    state.masque_routes.retain(|_, r| r.owner_session != sid);
                    state.session_uncompressed_ctx.remove(&sid);
                    if let Some(blocks) = state.session_allocated_blocks.remove(&sid) {
                        for base in blocks {
                            state.recycle_local_block(base);
                        }
                    }
                    state.mux_v1_sessions = state.mux_v1_sessions.saturating_sub(1);
                    // N2 rollback: if all mux_v1 sessions dropped before T2b/T3
                    // committed `mux_v1_tx_prefix`, roll back `mux_v1_rx_ready`
                    // so raw app datagrams are never stripped on an aborted link.
                    if state.mux_v1_sessions == 0 && !state.mux_v1_tx_prefix {
                        state.mux_v1_rx_ready = false;
                    }
                }
            }
        }
        cleanup_mux_locked(&mut registry, self.key, &self.mux);
    }
}

/// Legacy registration guard for a non-relay datagram reader (retained for
/// backward-compatible tests of the exclusive 0.29.0 claim).
pub(crate) struct OtherDatagramReaderGuard {
    _connection: Connection,
    key: usize,
    mux: SharedMux,
}

impl Drop for OtherDatagramReaderGuard {
    fn drop(&mut self) {
        let mut registry = DATAGRAM_MUXES.lock();
        {
            let mut state = self.mux.lock();
            state.legacy_other_readers = state.legacy_other_readers.saturating_sub(1);
        }
        cleanup_mux_locked(&mut registry, self.key, &self.mux);
    }
}

/// Register a legacy exclusive non-relay datagram reader on `connection`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn register_other_datagram_reader(
    connection: &Connection,
) -> Result<OtherDatagramReaderGuard, DatagramLaneError> {
    let key = connection.stable_id();
    let mux = {
        let mut registry = DATAGRAM_MUXES.lock();
        let mux = get_or_create_mux_locked(&mut registry, connection);
        let mut state = mux.lock();
        if state.legacy_exclusive_relay || state.provisional_exclusive || state.mux_v1_sessions > 0
        {
            return Err(DatagramLaneError::ClaimedByRelaySession);
        }
        state.legacy_other_readers += 1;
        drop(state);
        mux
    };
    Ok(OtherDatagramReaderGuard {
        _connection: connection.clone(),
        key,
        mux,
    })
}

/// Multiplexed subscription handle for `LinkConn::recv_datagrams` backed by
/// RFC 9297 `DatagramMux`.
pub(crate) struct AppDatagramSubscription {
    connection: Connection,
    key: usize,
    mux: SharedMux,
    sub_id: u64,
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl AppDatagramSubscription {
    pub(crate) async fn recv(&mut self) -> Option<Bytes> {
        // Lazily start the dispatcher inside an active Tokio runtime so
        // `LinkConn::recv_datagrams()` itself never panics outside a runtime.
        ensure_dispatcher_running(&self.connection, &self.mux);
        self.rx.recv().await
    }
}

impl Drop for AppDatagramSubscription {
    fn drop(&mut self) {
        let mut registry = DATAGRAM_MUXES.lock();
        {
            let mut state = self.mux.lock();
            state.app_subscribers.remove(&self.sub_id);
        }
        cleanup_mux_locked(&mut registry, self.key, &self.mux);
    }
}

/// Open a `LinkConn::recv_datagrams` subscription on `connection` through
/// `DatagramMux`.
///
/// Safe to call outside a Tokio runtime (dispatcher spawns lazily on first
/// poll). Coexists cleanly with `0.30.0+` `DATAGRAM_MUX_V1` hybrid sessions and
/// provisional client claims; refused only if a confirmed legacy `0.29.0`
/// exclusive hybrid claim holds the lane.
pub(crate) fn open_app_datagram_channel(
    connection: &Connection,
) -> Result<AppDatagramSubscription, DatagramLaneError> {
    let key = connection.stable_id();
    let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
    let (mux, sub_id) = {
        let mut registry = DATAGRAM_MUXES.lock();
        let mux = get_or_create_mux_locked(&mut registry, connection);
        let mut state = mux.lock();
        if state.legacy_exclusive_relay {
            return Err(DatagramLaneError::ClaimedByRelaySession);
        }
        if state.provisional_exclusive {
            state.provisional_saw_app_reader = true;
        }
        let sub_id = state.allocate_sub_id();
        state.app_subscribers.insert(sub_id, tx);
        drop(state);
        (mux, sub_id)
    };
    ensure_dispatcher_running(connection, &mux);
    Ok(AppDatagramSubscription {
        connection: connection.clone(),
        key,
        mux,
        sub_id,
        rx,
    })
}

/// Send an application (`LinkConn`) datagram on `connection`.
///
/// - Once symmetric `DATAGRAM_MUX_V1` (`mux_v1_tx_prefix == true`) is committed
///   on `connection` (Relay T2b / Client T3), prepends the 1-byte odd RFC 9297
///   Context ID [`APP_DATAGRAM_CONTEXT_ID`] (`0x01`) so the peer's `DatagramMux`
///   demultiplexes it cleanly from MASQUE even Context IDs.
/// - Otherwise (direct connections, `0.28.0`/`0.29.0` peers, or pre-T2/pre-T3
///   startup), sends `data` raw with zero overhead.
pub(crate) fn send_app_datagram(
    connection: &Connection,
    data: Bytes,
) -> Result<(), SendDatagramError> {
    let prefix_app = {
        let key = connection.stable_id();
        let registry = DATAGRAM_MUXES.lock();
        registry
            .map
            .get(&key)
            .is_some_and(|mux| mux.lock().mux_v1_tx_prefix)
    };
    if prefix_app {
        let ctx = VarInt::from_u32(APP_DATAGRAM_CONTEXT_ID as u32);
        let mut buf = BytesMut::with_capacity(ctx.size() + data.len());
        ctx.encode(&mut buf);
        buf.put_slice(&data);
        connection.send_datagram(buf.freeze())
    } else {
        connection.send_datagram(data)
    }
}

/// State of a target's compressed context registration within a relay session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompressedTargetState {
    Pending { base_ctx: VarInt, ecn_quad: bool },
    Active { base_ctx: VarInt, ecn_quad: bool },
}

/// Per-session bidirectional mapping between target `SocketAddr`s and compressed
/// MASQUE Context IDs (with optional 4-context ECN quads).
#[derive(Debug)]
pub(crate) struct SessionCompressionTable {
    target_to_entry: HashMap<SocketAddr, CompressedTargetState>,
    ctx_to_target: HashMap<u64, (SocketAddr, Option<EcnCodepoint>)>,
    base_to_target: HashMap<u64, (SocketAddr, bool)>,
    max_targets: usize,
}

impl SessionCompressionTable {
    pub(crate) fn new(max_targets: usize) -> Self {
        Self {
            target_to_entry: HashMap::new(),
            ctx_to_target: HashMap::new(),
            base_to_target: HashMap::new(),
            max_targets,
        }
    }

    pub(crate) fn active_for_target(&self, target: SocketAddr) -> Option<(VarInt, bool)> {
        match self.target_to_entry.get(&target) {
            Some(CompressedTargetState::Active { base_ctx, ecn_quad }) => {
                Some((*base_ctx, *ecn_quad))
            }
            _ => None,
        }
    }

    pub(crate) fn has_target(&self, target: SocketAddr) -> bool {
        self.target_to_entry.contains_key(&target)
    }

    pub(crate) fn can_add_target(&self) -> bool {
        self.target_to_entry.len() < self.max_targets
    }

    pub(crate) fn insert_pending_ecn_quad(&mut self, target: SocketAddr, base_ctx: VarInt) {
        let b = base_ctx.into_inner();
        self.target_to_entry.insert(
            target,
            CompressedTargetState::Pending {
                base_ctx,
                ecn_quad: true,
            },
        );
        self.base_to_target.insert(b, (target, true));
        for (offset, ecn) in [
            (0u64, None),
            (2, Some(EcnCodepoint::Ect0)),
            (4, Some(EcnCodepoint::Ect1)),
            (6, Some(EcnCodepoint::Ce)),
        ] {
            self.ctx_to_target.insert(b + offset, (target, ecn));
        }
    }

    pub(crate) fn insert_active(
        &mut self,
        target: SocketAddr,
        base_ctx: VarInt,
        ecn_quad: bool,
    ) -> bool {
        if self.target_to_entry.contains_key(&target) || !self.can_add_target() {
            return false;
        }
        let b = base_ctx.into_inner();
        self.target_to_entry
            .insert(target, CompressedTargetState::Active { base_ctx, ecn_quad });
        self.base_to_target.insert(b, (target, ecn_quad));
        if ecn_quad {
            for (offset, ecn) in [
                (0u64, None),
                (2, Some(EcnCodepoint::Ect0)),
                (4, Some(EcnCodepoint::Ect1)),
                (6, Some(EcnCodepoint::Ce)),
            ] {
                self.ctx_to_target.insert(b + offset, (target, ecn));
            }
        } else {
            self.ctx_to_target.insert(b, (target, None));
        }
        true
    }

    pub(crate) fn acknowledge(&mut self, base_ctx: VarInt) -> bool {
        let Some(&(target, ecn_quad)) = self.base_to_target.get(&base_ctx.into_inner()) else {
            return false;
        };
        self.target_to_entry
            .insert(target, CompressedTargetState::Active { base_ctx, ecn_quad });
        true
    }

    pub(crate) fn remove_by_base(&mut self, base_ctx: VarInt) -> Option<(SocketAddr, bool)> {
        let b = base_ctx.into_inner();
        let (target, ecn_quad) = self.base_to_target.remove(&b)?;
        self.target_to_entry.remove(&target);
        if ecn_quad {
            for offset in [0u64, 2, 4, 6] {
                self.ctx_to_target.remove(&(b + offset));
            }
        } else {
            self.ctx_to_target.remove(&b);
        }
        Some((target, ecn_quad))
    }

    pub(crate) fn lookup_context(
        &self,
        ctx_id: VarInt,
    ) -> Option<(SocketAddr, Option<EcnCodepoint>)> {
        self.ctx_to_target.get(&ctx_id.into_inner()).copied()
    }
}

/// Per-socket counters for relay lane usage, compression, ECN, and queue pressure.
#[derive(Debug, Default)]
pub struct MasqueRelaySocketStats {
    /// Outbound packets sent on the unreliable QUIC `DATAGRAM` lane.
    pub datagrams_sent: AtomicU64,
    /// Outbound packets sent on the reliable length-prefixed stream lane.
    pub stream_frames_sent: AtomicU64,
    /// Inbound packets received on the unreliable QUIC `DATAGRAM` lane.
    pub datagrams_received: AtomicU64,
    /// Inbound packets received on the reliable length-prefixed stream lane.
    pub stream_frames_received: AtomicU64,
    /// Outbound datagrams encoded with 1–2 B `CompressedDatagram` headers.
    pub compressed_datagrams_sent: AtomicU64,
    /// Inbound datagrams decoded from 1–2 B `CompressedDatagram` headers.
    pub compressed_datagrams_received: AtomicU64,
    /// Outbound compressed datagrams carrying a non-zero ECN codepoint.
    pub ecn_marked_sent: AtomicU64,
    /// Inbound compressed datagrams delivering a non-zero ECN codepoint.
    pub ecn_marked_received: AtomicU64,
    /// Outbound packets dropped because the bounded send queue was full.
    pub tx_dropped: AtomicU64,
    /// Inbound packets dropped/evicted because the bounded receive queue or
    /// `DatagramMux` dispatch channel was full.
    pub rx_dropped: AtomicU64,
}

impl MasqueRelaySocketStats {
    /// Total outbound packets sent across both lanes.
    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.datagrams_sent.load(Ordering::Relaxed)
            + self.stream_frames_sent.load(Ordering::Relaxed)
    }

    /// Total inbound packets received across both lanes.
    #[must_use]
    pub fn total_received(&self) -> u64 {
        self.datagrams_received.load(Ordering::Relaxed)
            + self.stream_frames_received.load(Ordering::Relaxed)
    }
}

struct OutboundRelayPacket {
    target: SocketAddr,
    ecn: Option<EcnCodepoint>,
    raw_payload: Bytes,
}

#[derive(Default)]
struct RecvState {
    queue: VecDeque<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    waker: Option<Waker>,
}

/// Bounded inbound packet ring with its waker under ONE lock.
struct RecvRing {
    state: std::sync::Mutex<RecvState>,
    capacity: usize,
}

impl RecvRing {
    fn new(capacity: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(RecvState {
                queue: VecDeque::with_capacity(capacity.min(64)),
                waker: None,
            }),
            capacity,
        }
    }

    fn push(&self, payload: Vec<u8>, source: SocketAddr, ecn: Option<EcnCodepoint>) -> bool {
        let (evicted, waker) = match self.state.lock() {
            Ok(mut state) => {
                let evicted = if state.queue.len() >= self.capacity {
                    state.queue.pop_front().is_some()
                } else {
                    false
                };
                state.queue.push_back((payload, source, ecn));
                (evicted, state.waker.take())
            }
            Err(_) => (false, None),
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        evicted
    }

    fn wake(&self) {
        let waker = self.state.lock().ok().and_then(|mut s| s.waker.take());
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn len(&self) -> usize {
        self.state.lock().map(|s| s.queue.len()).unwrap_or(0)
    }

    fn poll_pop(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Ok(mut state) = self.state.lock() else {
            return Poll::Ready(Err(io::Error::other("relay receive queue poisoned")));
        };
        let max_batch = bufs.len().min(meta.len());
        let mut count = 0;
        while count < max_batch {
            let Some((payload, source, ecn)) = state.queue.pop_front() else {
                break;
            };
            let len = payload.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&payload[..len]);

            let mut recv_meta = RecvMeta::default();
            recv_meta.len = len;
            recv_meta.stride = len;
            recv_meta.addr = source;
            recv_meta.ecn = ecn;
            recv_meta.dst_ip = None;
            meta[count] = recv_meta;
            count += 1;
        }
        if count > 0 {
            return Poll::Ready(Ok(count));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn make_target_assign(base_ctx: VarInt, target: SocketAddr) -> CompressionAssign {
    match target.ip() {
        IpAddr::V4(v4) => CompressionAssign::compressed_v4(base_ctx, v4, target.port()),
        IpAddr::V6(v6) => CompressionAssign::compressed_v6(base_ctx, v6, target.port()),
    }
}

/// A virtual UDP socket that tunnels packets through a MASQUE relay
/// via a persistent QUIC stream, optionally offloading regular packets
/// onto unreliable QUIC `DATAGRAM` frames (ADR-016 / ADR-020).
pub struct MasqueRelaySocket {
    relay_public_addr: SocketAddr,
    forward_mode: RelayForwardMode,
    mux_v1: bool,
    outer_connection: Option<Connection>,
    recv: RecvRing,
    send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
    stats: Arc<MasqueRelaySocketStats>,
    shutdown: CancellationToken,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field("forward_mode", &self.forward_mode)
            .field("mux_v1", &self.mux_v1)
            .field("recv_queue_len", &self.recv.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Drop for MasqueRelaySocket {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl MasqueRelaySocket {
    /// Create a stream-only relay socket (ADR-009 / default mode).
    pub fn new(
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::build(None, send_stream, recv_stream, relay_public_addr)
    }

    /// Create a hybrid relay socket (ADR-016 / ADR-020) for a session whose
    /// CONNECT-UDP exchange negotiated the datagram lane in both directions.
    pub fn new_hybrid(
        lane: DatagramLaneClaim,
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::build(Some(lane), send_stream, recv_stream, relay_public_addr)
    }

    fn build(
        mut lane: Option<DatagramLaneClaim>,
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        let (send_tx, mut send_rx) =
            tokio::sync::mpsc::channel::<OutboundRelayPacket>(DEFAULT_RELAY_SEND_QUEUE_CAPACITY);
        let stats = Arc::new(MasqueRelaySocketStats::default());
        let forward_mode = if lane.is_some() {
            RelayForwardMode::Hybrid
        } else {
            RelayForwardMode::Stream
        };
        let mux_v1 = lane.as_ref().is_some_and(DatagramLaneClaim::is_mux_v1);
        let outer_connection = lane.as_ref().map(|c| c.connection().clone());
        let shutdown = CancellationToken::new();

        // Wire mux `try_send` drop counter into this socket's `stats.rx_dropped`.
        let mux_drop_counter = Arc::new(AtomicU64::new(0));
        if let Some(ref mut claim) = lane {
            claim.attach_rx_dropped_counter(Arc::clone(&mux_drop_counter));
        }

        let socket = Arc::new(Self {
            relay_public_addr,
            forward_mode,
            mux_v1,
            outer_connection,
            recv: RecvRing::new(DEFAULT_RELAY_RECV_QUEUE_CAPACITY),
            send_tx,
            stats: Arc::clone(&stats),
            shutdown: shutdown.clone(),
        });

        let compression_table = Arc::new(parking_lot::RwLock::new(SessionCompressionTable::new(
            DEFAULT_MAX_COMPRESSED_TARGETS,
        )));
        // Legacy 0.29.0 ctx 0 is active immediately; mux_v1 client waits for
        // CompressionAck(u_ctx) before sending uncompressed datagrams so the
        // relay has explicitly registered `u_ctx` before any datagram uses it.
        let uncompressed_ctx_acked = Arc::new(AtomicBool::new(!mux_v1));
        let (retry_assign_tx, mut retry_assign_rx) =
            tokio::sync::mpsc::channel::<Bytes>(MAX_UNCOMPRESSED_CTX_RETRIES + 1);

        let mux_rx = lane.as_mut().and_then(DatagramLaneClaim::take_datagram_rx);
        let shared_claim = lane.map(Arc::new);

        // Background task: read length-prefixed frames from relay stream → bounded queue
        // (and handle `DATAGRAM_MUX_V1` control capsules).
        let stream_reader_socket = Arc::clone(&socket);
        let stream_reader_stats = Arc::clone(&stats);
        let stream_reader_table = Arc::clone(&compression_table);
        let stream_reader_claim = shared_claim.clone();
        let stream_reader_u_acked = Arc::clone(&uncompressed_ctx_acked);
        let session_over = shutdown.clone();
        tokio::spawn(async move {
            let mut uncompressed_ctx_retries = 0usize;
            loop {
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (length)");
                    break;
                }
                let frame_len = u32::from_be_bytes(len_buf) as usize;
                if frame_len > 65536 {
                    tracing::warn!(frame_len, "MasqueRelaySocket: oversized frame");
                    break;
                }

                let mut frame_buf = vec![0u8; frame_len];
                if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (data)");
                    break;
                }

                if mux_v1 && let Some(capsule_res) = Capsule::decode_stream_frame(&frame_buf) {
                    match capsule_res {
                        Ok(Capsule::CompressionAck(ack)) => {
                            // Client T3 barrier: relay sent a mux_v1 capsule reply,
                            // causally proving relay reached T2 (`rx_ready` + `tx_prefix`).
                            if let Some(ref claim) = stream_reader_claim {
                                claim.confirm_client_mux_v1_confirmed();
                            }
                            let current_u_ctx = stream_reader_claim
                                .as_deref()
                                .and_then(DatagramLaneClaim::uncompressed_context_id);
                            if current_u_ctx == Some(ack.context_id) {
                                stream_reader_u_acked.store(true, Ordering::Release);
                            } else {
                                stream_reader_table.write().acknowledge(ack.context_id);
                            }
                        }
                        Ok(Capsule::CompressionClose(close)) => {
                            // Client T3 barrier: even a CompressionClose causally
                            // proves the relay reached T2.
                            if let Some(ref claim) = stream_reader_claim {
                                claim.confirm_client_mux_v1_confirmed();
                            }
                            let current_u_ctx = stream_reader_claim
                                .as_deref()
                                .and_then(DatagramLaneClaim::uncompressed_context_id);
                            if current_u_ctx == Some(close.context_id) {
                                stream_reader_u_acked.store(false, Ordering::Release);
                                // N4 bounded recovery: if the relay rejected our
                                // uncompressed ctx (e.g. lingering prior-session route),
                                // allocate a fresh disjoint block and retry up to
                                // `MAX_UNCOMPRESSED_CTX_RETRIES` times.
                                if uncompressed_ctx_retries < MAX_UNCOMPRESSED_CTX_RETRIES
                                    && let Some(ref claim) = stream_reader_claim
                                    && let Some(fresh_u_ctx) =
                                        claim.reallocate_uncompressed_context()
                                {
                                    uncompressed_ctx_retries += 1;
                                    let frame = Capsule::CompressionAssign(
                                        CompressionAssign::uncompressed(fresh_u_ctx),
                                    )
                                    .encode_stream_frame();
                                    let _ = retry_assign_tx.try_send(frame);
                                }
                            } else {
                                let removed =
                                    stream_reader_table.write().remove_by_base(close.context_id);
                                if let (Some((_, ecn_quad)), Some(claim)) =
                                    (removed, &stream_reader_claim)
                                {
                                    if ecn_quad {
                                        claim.unregister_ecn_quad(close.context_id);
                                    } else {
                                        claim.unregister_context(close.context_id);
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            tracing::trace!("MasqueRelaySocket: failed to decode stream capsule");
                        }
                    }
                    continue;
                }

                let mut cursor = Bytes::from(frame_buf);
                match UncompressedDatagram::decode(&mut cursor) {
                    Ok(datagram) => {
                        stream_reader_stats
                            .stream_frames_received
                            .fetch_add(1, Ordering::Relaxed);
                        stream_reader_socket.enqueue_received(
                            datagram.payload.to_vec(),
                            datagram.target,
                            None,
                        );
                    }
                    Err(_) => {
                        tracing::trace!("MasqueRelaySocket: failed to decode stream frame");
                    }
                }
            }

            session_over.cancel();
            stream_reader_socket.recv.wake();
        });

        // Background task (hybrid): read QUIC DATAGRAM frames → bounded queue.
        if let Some(claim) = shared_claim.clone() {
            let weak = Arc::downgrade(&socket);
            let dgram_stats = Arc::clone(&stats);
            let dgram_table = Arc::clone(&compression_table);
            let dgram_mux_drops = Arc::clone(&mux_drop_counter);
            let stop = shutdown.clone();
            tokio::spawn(async move {
                let conn = claim.connection().clone();
                let mut mux_rx = mux_rx;
                loop {
                    let frame = if let Some(ref mut rx) = mux_rx {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            item = rx.recv() => match item {
                                Some(frame) => frame,
                                None => break,
                            },
                        }
                    } else {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            read = conn.read_datagram() => match read {
                                Ok(frame) => frame,
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "MasqueRelaySocket: outer datagram read ended"
                                    );
                                    break;
                                }
                            },
                        }
                    };

                    // Fold any mux channel-full drops into `stats.rx_dropped`.
                    let dropped = dgram_mux_drops.swap(0, Ordering::Relaxed);
                    if dropped > 0 {
                        dgram_stats.rx_dropped.fetch_add(dropped, Ordering::Relaxed);
                    }

                    let Some(socket) = weak.upgrade() else {
                        break;
                    };

                    let mut peek = frame.clone();
                    let ctx_id = match VarInt::decode(&mut peek) {
                        Ok(id) => id,
                        Err(_) => {
                            tracing::trace!("MasqueRelaySocket: malformed datagram varint");
                            continue;
                        }
                    };

                    if mux_v1 && let Some((source, ecn)) = dgram_table.read().lookup_context(ctx_id)
                    {
                        let mut cursor = frame;
                        match CompressedDatagram::decode(&mut cursor) {
                            Ok(comp) => {
                                dgram_stats
                                    .datagrams_received
                                    .fetch_add(1, Ordering::Relaxed);
                                dgram_stats
                                    .compressed_datagrams_received
                                    .fetch_add(1, Ordering::Relaxed);
                                if ecn.is_some() {
                                    dgram_stats
                                        .ecn_marked_received
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                socket.enqueue_received(comp.payload.to_vec(), source, ecn);
                            }
                            Err(_) => {
                                tracing::trace!(
                                    "MasqueRelaySocket: failed to decode compressed datagram"
                                );
                            }
                        }
                        continue;
                    }

                    let mut cursor = frame;
                    match UncompressedDatagram::decode(&mut cursor) {
                        Ok(datagram) => {
                            dgram_stats
                                .datagrams_received
                                .fetch_add(1, Ordering::Relaxed);
                            socket.enqueue_received(
                                datagram.payload.to_vec(),
                                datagram.target,
                                None,
                            );
                        }
                        Err(_) => {
                            tracing::trace!("MasqueRelaySocket: failed to decode datagram frame");
                        }
                    }
                }
                let dropped = dgram_mux_drops.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    dgram_stats.rx_dropped.fetch_add(dropped, Ordering::Relaxed);
                }
                if let Some(socket) = weak.upgrade() {
                    socket.recv.wake();
                }
                drop(claim);
            });
        }

        // Background task: write queued outbound packets via datagram lane (hybrid)
        // or stream lane, announcing client-allocated Context IDs on the stream.
        let writer_stats = Arc::clone(&stats);
        let writer_table = Arc::clone(&compression_table);
        let writer_claim = shared_claim;
        let writer_u_acked = uncompressed_ctx_acked;
        tokio::spawn(async move {
            // For every `mux_v1` client session, register its client-allocated
            // uncompressed Context ID on the stream immediately (this also
            // triggers the relay's T2 symmetric mux activation barrier!).
            if let Some(ref claim) = writer_claim
                && claim.is_mux_v1()
                && let Some(u_ctx) = claim.uncompressed_context_id()
            {
                let capsule = Capsule::CompressionAssign(CompressionAssign::uncompressed(u_ctx));
                let frame = capsule.encode_stream_frame();
                let frame_len = frame.len() as u32;
                if send_stream
                    .write_all(&frame_len.to_be_bytes())
                    .await
                    .is_err()
                    || send_stream.write_all(&frame).await.is_err()
                {
                    return;
                }
            }

            let mut retry_rx_open = true;
            loop {
                let packet = tokio::select! {
                    biased;
                    maybe_retry = retry_assign_rx.recv(), if retry_rx_open => {
                        match maybe_retry {
                            Some(frame) => {
                                let frame_len = frame.len() as u32;
                                if send_stream
                                    .write_all(&frame_len.to_be_bytes())
                                    .await
                                    .is_err()
                                    || send_stream.write_all(&frame).await.is_err()
                                {
                                    return;
                                }
                                continue;
                            }
                            None => {
                                retry_rx_open = false;
                                continue;
                            }
                        }
                    }
                    maybe_pkt = send_rx.recv() => {
                        let Some(packet) = maybe_pkt else {
                            if let Err(e) = send_stream.finish() {
                                tracing::debug!(error = %e, "MasqueRelaySocket: stream finish error");
                            }
                            return;
                        };
                        packet
                    }
                };

                if let Some(ref claim) = writer_claim {
                    let conn = claim.connection();
                    if claim.is_mux_v1() {
                        let active = writer_table.read().active_for_target(packet.target);
                        if let Some((base_ctx, ecn_quad)) = active {
                            let ctx_id = if ecn_quad {
                                ecn_context_id(base_ctx, packet.ecn)
                            } else {
                                base_ctx
                            };
                            let lane = select_relay_lane_with_overhead(
                                &packet.raw_payload,
                                ctx_id.size(),
                                conn.max_datagram_size(),
                                RelayForwardMode::Hybrid,
                            );
                            if lane == RelayLane::Datagram {
                                let encoded =
                                    CompressedDatagram::new(ctx_id, packet.raw_payload.clone())
                                        .encode();
                                match conn.send_datagram(encoded) {
                                    Ok(()) => {
                                        writer_stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                                        writer_stats
                                            .compressed_datagrams_sent
                                            .fetch_add(1, Ordering::Relaxed);
                                        if ecn_quad && packet.ecn.is_some() {
                                            writer_stats
                                                .ecn_marked_sent
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        continue;
                                    }
                                    Err(
                                        SendDatagramError::TooLarge
                                        | SendDatagramError::UnsupportedByPeer
                                        | SendDatagramError::Disabled,
                                    ) => {}
                                    Err(SendDatagramError::ConnectionLost(e)) => {
                                        tracing::debug!(
                                            error = %e,
                                            "MasqueRelaySocket: outer connection lost on compressed datagram send"
                                        );
                                        return;
                                    }
                                }
                            }
                        } else {
                            let assign_frame = {
                                let mut table = writer_table.write();
                                if !table.has_target(packet.target) && table.can_add_target() {
                                    claim.allocate_ecn_quad().map(|base_ctx| {
                                        table.insert_pending_ecn_quad(packet.target, base_ctx);
                                        Capsule::EcnCompressionAssign(make_target_assign(
                                            base_ctx,
                                            packet.target,
                                        ))
                                        .encode_stream_frame()
                                    })
                                } else {
                                    None
                                }
                            };
                            if let Some(frame) = assign_frame {
                                let frame_len = frame.len() as u32;
                                if send_stream
                                    .write_all(&frame_len.to_be_bytes())
                                    .await
                                    .is_err()
                                    || send_stream.write_all(&frame).await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }

                    // Uncompressed datagram path (legacy 0.29.0 ctx 0, or mux_v1
                    // once client-allocated `u_ctx` has been ACKed by the relay).
                    if writer_u_acked.load(Ordering::Acquire)
                        && let Some(u_ctx) = claim.uncompressed_context_id()
                    {
                        let overhead =
                            uncompressed_datagram_header_overhead_for_ctx(u_ctx, packet.target);
                        let lane = select_relay_lane_with_overhead(
                            &packet.raw_payload,
                            overhead,
                            conn.max_datagram_size(),
                            RelayForwardMode::Hybrid,
                        );
                        if lane == RelayLane::Datagram {
                            let encoded = UncompressedDatagram::new(
                                u_ctx,
                                packet.target,
                                packet.raw_payload.clone(),
                            )
                            .encode();
                            match conn.send_datagram(encoded) {
                                Ok(()) => {
                                    writer_stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                Err(
                                    SendDatagramError::TooLarge
                                    | SendDatagramError::UnsupportedByPeer
                                    | SendDatagramError::Disabled,
                                ) => {}
                                Err(SendDatagramError::ConnectionLost(e)) => {
                                    tracing::debug!(
                                        error = %e,
                                        "MasqueRelaySocket: outer connection lost on datagram send"
                                    );
                                    return;
                                }
                            }
                        }
                    }
                }

                // Stream fallback (or pre-ACK startup / stream-only mode).
                let encoded = UncompressedDatagram::new(
                    VarInt::from_u32(0),
                    packet.target,
                    packet.raw_payload,
                )
                .encode();
                let frame_len = encoded.len() as u32;
                if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (length)");
                    return;
                }
                if let Err(e) = send_stream.write_all(&encoded).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (data)");
                    return;
                }
                writer_stats
                    .stream_frames_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
        });

        socket
    }

    /// Return the forwarding mode negotiated for this relay session.
    #[must_use]
    pub fn forward_mode(&self) -> RelayForwardMode {
        self.forward_mode
    }

    /// Return whether `DATAGRAM_MUX_V1` (Context-ID demux + compression + ECN)
    /// is active for this relay session.
    #[must_use]
    pub fn is_mux_v1(&self) -> bool {
        self.mux_v1
    }

    /// Compute the recommended clamped inner virtual-path MTU (`min(P_max, 1380)`)
    /// from the outer connection's QUIC `DATAGRAM` budget at endpoint creation
    /// (ADR-020).
    #[must_use]
    pub fn recommended_inner_mtu(&self) -> Option<u16> {
        let conn = self.outer_connection.as_ref()?;
        let overhead = if self.mux_v1 { 2 } else { 8 };
        compute_inner_virtual_path_mtu(conn.max_datagram_size(), overhead)
    }

    /// Return per-lane and queue-pressure statistics for this relay socket.
    #[must_use]
    pub fn stats(&self) -> &Arc<MasqueRelaySocketStats> {
        &self.stats
    }

    fn enqueue_received(&self, payload: Vec<u8>, source: SocketAddr, ecn: Option<EcnCodepoint>) {
        if self.recv.push(payload, source, ecn) {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AsyncUdpSocket for MasqueRelaySocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MasqueRelaySender {
            send_tx: self.send_tx.clone(),
            stats: Arc::clone(&self.stats),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.recv.poll_pop(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.relay_public_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct MasqueRelaySender {
    send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
    stats: Arc<MasqueRelaySocketStats>,
}

impl UdpSender for MasqueRelaySender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let raw_payload = Bytes::copy_from_slice(transmit.contents);
        let packet = OutboundRelayPacket {
            target: transmit.destination,
            ecn: transmit.ecn,
            raw_payload,
        };

        match self.send_tx.try_send(packet) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::ConnectionAborted, "relay stream closed"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    fn v4_target() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 9000)
    }

    fn v6_target() -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9000,
        )
    }

    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn short_transmit(payload: &[u8]) -> Transmit<'_> {
        Transmit {
            destination: v4_target(),
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        }
    }

    #[test]
    fn default_relay_forward_mode_is_stream_per_adr_016() {
        assert_eq!(RelayForwardMode::default(), RelayForwardMode::Stream);
    }

    #[test]
    fn detects_quic_v1_and_v2_initial_packets() {
        let v1_initial = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(is_quic_initial_packet(&v1_initial));

        let v2_initial = [0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00];
        assert!(is_quic_initial_packet(&v2_initial));

        let v1_handshake = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(!is_quic_initial_packet(&v1_handshake));

        let short_1rtt = [0x40, 0x11, 0x22, 0x33, 0x44];
        assert!(!is_quic_initial_packet(&short_1rtt));
    }

    #[test]
    fn datagram_budget_respects_900b_floor_and_compressed_overhead() {
        let v4 = v4_target();
        let v6 = v6_target();
        let v4_floor_outer = MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET + 8;
        let v6_floor_outer = MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET + 20;

        assert_eq!(MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET, 900);
        assert_eq!(
            compute_datagram_payload_budget(Some(v4_floor_outer), v4),
            Some(MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET)
        );
        assert_eq!(
            compute_datagram_payload_budget(Some(v4_floor_outer - 1), v4),
            None
        );
        assert_eq!(
            compute_datagram_payload_budget(Some(v6_floor_outer), v6),
            Some(MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET)
        );
        assert_eq!(
            compute_datagram_payload_budget(Some(v6_floor_outer - 1), v6),
            None
        );

        assert_eq!(compute_datagram_payload_budget(Some(1180), v4), Some(1172));
        assert_eq!(compute_datagram_payload_budget(Some(1180), v6), Some(1160));
        assert_eq!(
            compute_datagram_payload_budget_with_overhead(Some(1180), 1),
            Some(1179)
        );
        assert_eq!(compute_inner_virtual_path_mtu(Some(1180), 1), Some(1179));
        assert_eq!(compute_inner_virtual_path_mtu(Some(1452), 2), Some(1380));
        assert_eq!(compute_datagram_payload_budget(Some(850), v4), None);
        assert_eq!(compute_datagram_payload_budget(None, v4), None);
        for outer in 0..4096 {
            if let Some(p_max) = compute_datagram_payload_budget(Some(outer), v6) {
                assert!(p_max >= MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET);
            }
        }
    }

    #[test]
    fn lane_selection_respects_mode_budget_and_initial_invariant() {
        let target_v4 = v4_target();
        let target_v6 = v6_target();
        let outer = Some(1400);

        let short_pkt = vec![0x40u8; 600];

        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, outer, RelayForwardMode::Stream),
            RelayLane::Stream
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v6, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );

        let p_max_v4 = compute_datagram_payload_budget(outer, target_v4).unwrap();
        assert_eq!(p_max_v4, 1392);
        let at_limit = vec![0x40u8; p_max_v4];
        let over_limit = vec![0x40u8; p_max_v4 + 1];
        assert_eq!(
            select_relay_lane(&at_limit, target_v4, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&over_limit, target_v4, outer, RelayForwardMode::Hybrid),
            RelayLane::Stream
        );

        let p_max_v6 = compute_datagram_payload_budget(outer, target_v6).unwrap();
        assert_eq!(p_max_v6, 1380);

        let mut small_initial = vec![0x00u8; 200];
        small_initial[0] = 0xc0;
        small_initial[4] = 0x01;
        assert_eq!(
            select_relay_lane(
                &small_initial,
                target_v4,
                Some(4000),
                RelayForwardMode::Hybrid
            ),
            RelayLane::Stream
        );

        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, Some(850), RelayForwardMode::Hybrid),
            RelayLane::Stream
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, None, RelayForwardMode::Hybrid),
            RelayLane::Stream
        );
    }

    #[test]
    fn path_challenge_over_sub_1200_virtual_path_rides_stream_lane() {
        let outer_1280_dgram_budget = Some(1180);
        let compressed_hdr = 1;
        let clamped_1rtt = compute_inner_virtual_path_mtu(outer_1280_dgram_budget, compressed_hdr)
            .expect("1280 B outer clears 900 B floor");
        assert!(clamped_1rtt < QUIC_INITIAL_MIN_SIZE as u16);

        let one_rtt_pkt = vec![0x40u8; clamped_1rtt as usize];
        assert_eq!(
            select_relay_lane_with_overhead(
                &one_rtt_pkt,
                compressed_hdr,
                outer_1280_dgram_budget,
                RelayForwardMode::Hybrid
            ),
            RelayLane::Datagram
        );

        let padded_path_challenge = vec![0x40u8; QUIC_INITIAL_MIN_SIZE];
        assert_eq!(
            select_relay_lane_with_overhead(
                &padded_path_challenge,
                compressed_hdr,
                outer_1280_dgram_budget,
                RelayForwardMode::Hybrid
            ),
            RelayLane::Stream
        );
    }

    #[test]
    fn ecn_context_id_mapping_roundtrips_all_codepoints() {
        let base = VarInt::from_u32(2);
        let cases = [
            (None, 2u64, 0u64),
            (Some(EcnCodepoint::Ect0), 4, 2),
            (Some(EcnCodepoint::Ect1), 6, 4),
            (Some(EcnCodepoint::Ce), 8, 6),
        ];
        for (ecn, expected_id, expected_offset) in cases {
            let cid = ecn_context_id(base, ecn);
            assert_eq!(cid.into_inner(), expected_id);
            assert_eq!(cid.into_inner() % 2, 0, "all ECN context IDs must be even");
            assert_eq!(
                decode_ecn_offset(cid.into_inner() - base.into_inner()),
                Some(ecn)
            );
            assert_eq!(cid.into_inner() - base.into_inner(), expected_offset);
            assert_eq!(cid.size(), 1, "first blocks fit in 1-byte VarInt");
        }
        assert_eq!(decode_ecn_offset(1), None);
        assert_eq!(decode_ecn_offset(8), None);
    }

    #[test]
    fn recv_ring_is_bounded_and_evicts_oldest() {
        let ring = RecvRing::new(DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
        let src = v4_target();
        let total = DEFAULT_RELAY_RECV_QUEUE_CAPACITY + 44;
        let mut evicted = 0;
        for i in 0..total {
            if ring.push(
                (i as u32).to_be_bytes().to_vec(),
                src,
                Some(EcnCodepoint::Ce),
            ) {
                evicted += 1;
            }
            assert!(ring.len() <= DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
        }
        assert_eq!(evicted, 44);
        assert_eq!(ring.len(), DEFAULT_RELAY_RECV_QUEUE_CAPACITY);

        let waker = Waker::from(Arc::new(CountingWaker(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        let mut b0 = [0u8; 8];
        let mut meta = [RecvMeta::default(); 1];
        let mut slices = [IoSliceMut::new(&mut b0)];
        match ring.poll_pop(&mut cx, &mut slices, &mut meta) {
            Poll::Ready(Ok(1)) => {}
            other => panic!("expected one packet, got {other:?}"),
        }
        assert_eq!(&b0[..4], &44u32.to_be_bytes());
        assert_eq!(meta[0].ecn, Some(EcnCodepoint::Ce));
    }

    #[test]
    fn send_queue_is_bounded_and_counts_drops() {
        let (send_tx, send_rx) =
            tokio::sync::mpsc::channel::<OutboundRelayPacket>(DEFAULT_RELAY_SEND_QUEUE_CAPACITY);
        let stats = Arc::new(MasqueRelaySocketStats::default());
        let mut sender = Box::pin(MasqueRelaySender {
            send_tx,
            stats: Arc::clone(&stats),
        });
        let waker = Waker::from(Arc::new(CountingWaker(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        let payload = [0x40u8; 32];
        let total = DEFAULT_RELAY_SEND_QUEUE_CAPACITY + 44;
        for _ in 0..total {
            match sender
                .as_mut()
                .poll_send(&short_transmit(&payload), &mut cx)
            {
                Poll::Ready(Ok(())) => {}
                other => panic!("tail-drop must report success, got {other:?}"),
            }
        }
        assert_eq!(stats.tx_dropped.load(Ordering::Relaxed), 44);
        assert_eq!(send_rx.len(), DEFAULT_RELAY_SEND_QUEUE_CAPACITY);

        drop(send_rx);
        match sender
            .as_mut()
            .poll_send(&short_transmit(&payload), &mut cx)
        {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted),
            other => panic!("closed channel must error, got {other:?}"),
        }
    }

    #[test]
    fn recv_ring_never_loses_a_wakeup_with_two_producers() {
        for _ in 0..200 {
            let ring = Arc::new(RecvRing::new(DEFAULT_RELAY_RECV_QUEUE_CAPACITY));
            let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            let mut cx = Context::from_waker(&waker);
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let producers: Vec<_> = (0..2u8)
                .map(|i| {
                    let ring = Arc::clone(&ring);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        ring.push(vec![i], v4_target(), None);
                    })
                })
                .collect();
            barrier.wait();
            let mut buf = [0u8; 4];
            let mut meta = [RecvMeta::default(); 1];
            let mut received = 0;
            let mut pending_polls = 0;
            while received < 2 {
                let mut slices = [IoSliceMut::new(&mut buf)];
                match ring.poll_pop(&mut cx, &mut slices, &mut meta) {
                    Poll::Ready(Ok(n)) => received += n,
                    Poll::Ready(Err(e)) => panic!("poll error: {e}"),
                    Poll::Pending => {
                        pending_polls += 1;
                        let start = std::time::Instant::now();
                        while counter.0.load(Ordering::SeqCst) < pending_polls {
                            assert!(
                                start.elapsed() < std::time::Duration::from_secs(5),
                                "wake-up lost after Pending"
                            );
                            std::thread::yield_now();
                        }
                    }
                }
            }
            for p in producers {
                p.join().unwrap();
            }
        }
    }
}
