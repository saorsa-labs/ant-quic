// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Unified multiplexed UDP socket combining 1..=`MAX_PHYSICAL_SLOTS` physical
//! dual-stack UDP bind slots with a non-re-entrant virtual MASQUE relay plane
//! (ADR-021).
//!
//! All direct, multi-port (`:443` + `:5483`), and relayed QUIC traffic shares a
//! single [`crate::high_level::Endpoint`] backed by [`MultiplexedUdpSocket`]:
//! - Every physical slot preserves exact `(remote_addr, local_slot)` identity on
//!   both receive and transmit.
//! - Virtual MASQUE routes are addressed via link-local-isolated synthetic IPv6
//!   ULAs (`fd00:53a0:5251::/48`, [`crate::socket_slot`]) and delivered strictly
//!   via bounded, non-blocking, drop-on-full channels so `poll_send_on_slot` and
//!   virtual ingress can never re-enter or deadlock [`crate::high_level::Endpoint`].
//! - Physical receive paths drop any datagram whose source IP matches the
//!   synthetic ULA prefix (`synthetic_prefix_spoof_dropped`), and physical send
//!   paths reject synthetic ULA destinations with `io::ErrorKind::InvalidInput`.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use crate::{
    MAX_PHYSICAL_SLOTS, MAX_VIRTUAL_ROUTES, SocketSlotId,
    high_level::Connection,
    masque::relay_socket::{
        MasqueRelaySocket, MasqueRelaySocketStats, OutboundRelayPacket,
        compute_inner_virtual_path_mtu,
    },
    shared::normalize_socket_addr,
    socket_slot::{
        decode_synthetic_virtual_addr, is_synthetic_virtual_addr, is_synthetic_virtual_ip,
        make_synthetic_virtual_addr,
    },
};

use super::{AsyncUdpSocket, UdpPollHelper, UdpPoller, UdpSender};

/// Default bounded capacity of the virtual MASQUE ingress queue inside
/// [`MultiplexedUdpSocket`].
pub const DEFAULT_VIRTUAL_RECV_QUEUE_CAPACITY: usize = 512;

/// Bounded per-source receive burst limit per `poll_recv_with_slots` call so no
/// single physical port or virtual relay can starve other active sources.
pub const MAX_RECV_BURST_PER_SOURCE: usize = 32;

/// Default idle timeout after which an inactive virtual route may be reclaimed
/// when `MAX_VIRTUAL_ROUTES` (4096) capacity is reached, without ever evicting
/// routes with recent activity.
pub const DEFAULT_VIRTUAL_ROUTE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Diagnostic counters for [`MultiplexedUdpSocket`] isolation and backpressure
/// invariants (ADR-021).
#[derive(Debug, Default)]
pub struct MultiplexedSocketStats {
    /// Physical datagrams dropped because their source IP fell inside the
    /// reserved synthetic virtual ULA prefix (`fd00:53a0:5251::/48`).
    pub synthetic_prefix_spoof_dropped: AtomicU64,
    /// Inbound virtual MASQUE datagrams dropped because the bounded virtual
    /// receive queue was full (non-blocking drop-on-full).
    pub virtual_recv_queue_dropped: AtomicU64,
    /// Outbound virtual MASQUE datagrams dropped because the bounded per-relay
    /// egress channel was full (non-blocking drop-on-full).
    pub virtual_tx_dropped: AtomicU64,
    /// Outbound virtual datagrams dropped because the destination route carried
    /// a stale `route_gen` (e.g. after relay reconnect or detach).
    pub virtual_stale_gen_dropped: AtomicU64,
    /// Virtual route allocations rejected because `MAX_VIRTUAL_ROUTES` (4096)
    /// was reached.
    pub virtual_route_cap_rejected: AtomicU64,
}

/// One physical UDP bind slot (dual-stack IPv4 + IPv6 sockets sharing a
/// [`SocketSlotId`], or a custom caller-provided [`AsyncUdpSocket`]).
pub struct PhysicalBindSlot {
    slot_id: SocketSlotId,
    v4: Option<Arc<tokio::net::UdpSocket>>,
    v6: Option<Arc<tokio::net::UdpSocket>>,
    v4_state: Option<Arc<UdpSocketState>>,
    v6_state: Option<Arc<UdpSocketState>>,
    v4_addr: Option<SocketAddr>,
    v6_addr: Option<SocketAddr>,
    abstract_socket: Option<Arc<dyn AsyncUdpSocket>>,
}

impl fmt::Debug for PhysicalBindSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhysicalBindSlot")
            .field("slot_id", &self.slot_id)
            .field("v4_addr", &self.v4_addr)
            .field("v6_addr", &self.v6_addr)
            .field("abstract_socket", &self.abstract_socket.is_some())
            .finish()
    }
}

impl PhysicalBindSlot {
    /// Construct a physical slot from optional IPv4 and IPv6 Tokio UDP sockets.
    ///
    /// `slot_id` must be a valid physical slot (`0..MAX_PHYSICAL_SLOTS`) and at
    /// least one of `v4` or `v6` must be `Some`.
    pub fn new(
        slot_id: SocketSlotId,
        v4: Option<tokio::net::UdpSocket>,
        v6: Option<tokio::net::UdpSocket>,
    ) -> io::Result<Self> {
        if !slot_id.is_physical() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid physical slot id {slot_id:?}"),
            ));
        }
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one socket (IPv4 or IPv6) must be provided for a physical slot",
            ));
        }
        let v4_addr = v4.as_ref().map(|s| s.local_addr()).transpose()?;
        let v6_addr = v6.as_ref().map(|s| s.local_addr()).transpose()?;
        let v4_state = v4
            .as_ref()
            .map(|s| UdpSocketState::new(UdpSockRef::from(s)).map(Arc::new))
            .transpose()?;
        let v6_state = v6
            .as_ref()
            .map(|s| UdpSocketState::new(UdpSockRef::from(s)).map(Arc::new))
            .transpose()?;
        Ok(Self {
            slot_id,
            v4: v4.map(Arc::new),
            v6: v6.map(Arc::new),
            v4_state,
            v6_state,
            v4_addr,
            v6_addr,
            abstract_socket: None,
        })
    }

    /// Wrap an existing `std::net::UdpSocket` as a single-family physical slot.
    pub fn from_std(slot_id: SocketSlotId, socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let tokio_sock = tokio::net::UdpSocket::from_std(socket)?;
        Self::from_tokio(slot_id, tokio_sock)
    }

    /// Wrap an already-bound `tokio::net::UdpSocket` as a single-family
    /// physical slot without round-tripping through `into_std()` / `from_std()`.
    ///
    /// Uses `quinn_udp::UdpSocketState` for GSO/GRO/ECN when supported, and
    /// gracefully falls back to a plain Tokio [`AsyncUdpSocket`] wrapper if
    /// `UdpSocketState::new` returns an OS error (for example on Windows sockets
    /// with `IPV6_V6ONLY=0` where `quinn-udp`'s `IPPROTO_IP` socket options
    /// fail with `WSAEINVAL`).
    pub fn from_tokio(slot_id: SocketSlotId, socket: tokio::net::UdpSocket) -> io::Result<Self> {
        if !slot_id.is_physical() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid physical slot id {slot_id:?}"),
            ));
        }
        let addr = socket.local_addr()?;
        match UdpSocketState::new(UdpSockRef::from(&socket)) {
            Ok(state) => {
                let sock = Arc::new(socket);
                let state = Arc::new(state);
                if addr.is_ipv6() {
                    Self::from_arc_sockets(
                        slot_id,
                        None,
                        Some(sock),
                        None,
                        Some(state),
                        None,
                        Some(addr),
                    )
                } else {
                    Self::from_arc_sockets(
                        slot_id,
                        Some(sock),
                        None,
                        Some(state),
                        None,
                        Some(addr),
                        None,
                    )
                }
            }
            Err(e) => {
                debug!(
                    %addr,
                    ?slot_id,
                    error = %e,
                    "quinn-udp UdpSocketState::new unsupported on socket; falling back to plain Tokio AsyncUdpSocket"
                );
                Self::from_abstract(slot_id, super::tokio::wrap_tokio_udp_socket(socket))
            }
        }
    }

    /// Wrap optional `std::net::UdpSocket` pairs into a physical slot.
    pub fn from_std_pair(
        slot_id: SocketSlotId,
        v4: Option<std::net::UdpSocket>,
        v6: Option<std::net::UdpSocket>,
    ) -> io::Result<Self> {
        let v4 = v4
            .map(|s| {
                s.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(s)
            })
            .transpose()?;
        let v6 = v6
            .map(|s| {
                s.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(s)
            })
            .transpose()?;
        Self::new(slot_id, v4, v6)
    }

    /// Build a [`PhysicalBindSlot`] from already-initialized Tokio sockets and
    /// `quinn_udp::UdpSocketState` handles (used when migrating a `DualStackSocket`
    /// onto [`MultiplexedUdpSocket`] without duplicating descriptors).
    pub(crate) fn from_arc_sockets(
        slot_id: SocketSlotId,
        v4: Option<Arc<tokio::net::UdpSocket>>,
        v6: Option<Arc<tokio::net::UdpSocket>>,
        v4_state: Option<Arc<UdpSocketState>>,
        v6_state: Option<Arc<UdpSocketState>>,
        v4_addr: Option<SocketAddr>,
        v6_addr: Option<SocketAddr>,
    ) -> io::Result<Self> {
        if !slot_id.is_physical() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid physical slot id {slot_id:?}"),
            ));
        }
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one socket (IPv4 or IPv6) must be provided for a physical slot",
            ));
        }
        Ok(Self {
            slot_id,
            v4,
            v6,
            v4_state,
            v6_state,
            v4_addr,
            v6_addr,
            abstract_socket: None,
        })
    }

    /// Wrap an arbitrary caller-provided [`AsyncUdpSocket`] as a physical slot
    /// (used by `NatTraversalEndpoint::new_with_abstract_socket` so custom
    /// sockets retain unified virtual MASQUE relay support).
    pub fn from_abstract(
        slot_id: SocketSlotId,
        socket: Arc<dyn AsyncUdpSocket>,
    ) -> io::Result<Self> {
        if !slot_id.is_physical() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid physical slot id {slot_id:?}"),
            ));
        }
        let addrs = socket
            .local_addrs()
            .or_else(|_| socket.local_addr().map(|addr| vec![addr]))?;
        let mut v4_addr = None;
        let mut v6_addr = None;
        for addr in addrs {
            match addr {
                SocketAddr::V4(_) if v4_addr.is_none() => v4_addr = Some(addr),
                SocketAddr::V6(_) if v6_addr.is_none() => v6_addr = Some(addr),
                _ => {}
            }
        }
        if v4_addr.is_none() && v6_addr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "abstract UDP socket reported no local addresses",
            ));
        }
        Ok(Self {
            slot_id,
            v4: None,
            v6: None,
            v4_state: None,
            v6_state: None,
            v4_addr,
            v6_addr,
            abstract_socket: Some(socket),
        })
    }

    /// Bind an extra physical slot on `addr` (using dual-stack IPv4+IPv6 when
    /// `addr.ip().is_unspecified()`, or binding the exact interface otherwise).
    pub fn bind_addr(slot_id: SocketSlotId, addr: SocketAddr) -> io::Result<Self> {
        if addr.ip().is_unspecified() {
            let (v4_std, v6_std) = super::dual_stack::create_dual_stack_sockets(addr.port())?;
            Self::from_std_pair(slot_id, v4_std, v6_std)
        } else {
            let std_sock = std::net::UdpSocket::bind(addr)?;
            Self::from_std(slot_id, std_sock)
        }
    }

    /// Return this slot's identifier.
    #[must_use]
    pub fn slot_id(&self) -> SocketSlotId {
        self.slot_id
    }

    /// Return the cached IPv4 local address, if bound.
    #[must_use]
    pub fn local_addr_v4(&self) -> Option<SocketAddr> {
        self.v4_addr
    }

    /// Return the cached IPv6 local address, if bound.
    #[must_use]
    pub fn local_addr_v6(&self) -> Option<SocketAddr> {
        self.v6_addr
    }
}

/// Handle returned when a MASQUE relay session is attached to a
/// [`MultiplexedUdpSocket`].
#[derive(Debug, Clone)]
pub struct VirtualRelayHandle {
    /// Assigned 1-based relay slot index (`1..=65535`).
    pub relay_slot: u16,
    /// Monotonic generation for this relay slot (`1..=u32::MAX`, never 0).
    pub route_gen: u32,
    /// Relay-allocated public UDP address.
    pub public_addr: SocketAddr,
    /// Shared live virtual-path MTU atomic (`0` = unset / stream-only).
    pub virtual_mtu: Arc<AtomicU16>,
}

struct RelaySessionSlot {
    #[allow(dead_code)]
    relay_addr: SocketAddr,
    #[allow(dead_code)]
    relay_slot: u16,
    route_gen: u32,
    #[allow(dead_code)]
    public_addr: SocketAddr,
    send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
    outer_connection: Option<Connection>,
    mux_v1: bool,
    relay_stats: Option<Arc<MasqueRelaySocketStats>>,
    virtual_mtu: Arc<AtomicU16>,
    /// Keep the underlying `MasqueRelaySocket` alive while attached so its
    /// background reader/writer tasks stay running.
    relay_socket: Option<Arc<MasqueRelaySocket>>,
}

impl RelaySessionSlot {
    /// Recompute and publish the live inner virtual-path MTU from the outer
    /// QUIC relay connection's current `max_datagram_size()`, if attached.
    fn refresh_virtual_mtu(&self) -> Option<u16> {
        if let Some(ref conn) = self.outer_connection {
            let overhead = if self.mux_v1 { 2 } else { 8 };
            if let Some(vp_mtu) = compute_inner_virtual_path_mtu(conn.max_datagram_size(), overhead)
            {
                self.virtual_mtu.store(vp_mtu, Ordering::Relaxed);
                return Some(vp_mtu);
            }
        }
        let v = self.virtual_mtu.load(Ordering::Relaxed);
        (v != 0).then_some(v)
    }
}

#[derive(Debug)]
struct VirtualRouteEntry {
    relay_slot: u16,
    route_gen: u32,
    #[allow(dead_code)]
    peer_id: u32,
    real_target: SocketAddr,
    #[allow(dead_code)]
    synthetic_addr: SocketAddr,
    /// Milliseconds since `VirtualRouteTable::created_at` of the latest
    /// outbound send, inbound receive, or registration on this route.
    last_activity_ms: AtomicU64,
}

impl VirtualRouteEntry {
    fn touch(&self, now_ms: u64) {
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
    }
}

struct VirtualRouteTable {
    /// Active relay sessions keyed by `relay_slot` (1..=65535).
    relays: HashMap<u16, RelaySessionSlot>,
    /// Normalized outer relay `SocketAddr` -> assigned `relay_slot`.
    relay_addr_to_slot: HashMap<SocketAddr, u16>,
    /// Monotonic generation tracker per `relay_slot` (persists across detach/re-attach).
    slot_generations: HashMap<u16, u32>,
    /// Next relay slot candidate (1..=65535).
    next_relay_slot: u16,
    /// Next 32-bit peer identifier for virtual routes.
    next_peer_id: u32,
    /// Synthetic ULA `SocketAddr` -> route entry.
    by_synthetic: HashMap<SocketAddr, VirtualRouteEntry>,
    /// `(relay_slot, normalized real_target)` -> synthetic ULA `SocketAddr`.
    by_target: HashMap<(u16, SocketAddr), SocketAddr>,
    /// Monotonic epoch for lock-free per-route activity timestamps.
    created_at: Instant,
    /// Minimum idle duration before a route is eligible for reclamation at cap.
    route_idle_timeout: Duration,
}

impl VirtualRouteTable {
    fn new() -> Self {
        Self {
            relays: HashMap::new(),
            relay_addr_to_slot: HashMap::new(),
            slot_generations: HashMap::new(),
            next_relay_slot: 1,
            next_peer_id: 1,
            by_synthetic: HashMap::new(),
            by_target: HashMap::new(),
            created_at: Instant::now(),
            route_idle_timeout: DEFAULT_VIRTUAL_ROUTE_IDLE_TIMEOUT,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.created_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }

    fn reap_idle_routes(&mut self, now_ms: u64) -> usize {
        let idle_timeout_ms = self
            .route_idle_timeout
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let mut expired = Vec::new();
        for (&synth, entry) in &self.by_synthetic {
            let last = entry.last_activity_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last) >= idle_timeout_ms {
                expired.push((synth, entry.relay_slot, entry.real_target));
            }
        }
        let count = expired.len();
        for (synth, relay_slot, real_target) in expired {
            self.by_synthetic.remove(&synth);
            if self.by_target.get(&(relay_slot, real_target)) == Some(&synth) {
                self.by_target.remove(&(relay_slot, real_target));
            }
        }
        count
    }

    fn remove_route(&mut self, synthetic_addr: SocketAddr) -> bool {
        let Some(entry) = self.by_synthetic.remove(&synthetic_addr) else {
            return false;
        };
        if self.by_target.get(&(entry.relay_slot, entry.real_target)) == Some(&synthetic_addr) {
            self.by_target
                .remove(&(entry.relay_slot, entry.real_target));
        }
        true
    }

    fn allocate_slot_and_gen(&mut self, relay_addr: SocketAddr) -> io::Result<(u16, u32)> {
        let normalized = normalize_socket_addr(relay_addr);
        let slot = if let Some(&existing) = self.relay_addr_to_slot.get(&normalized) {
            existing
        } else {
            let mut allocated = None;
            for _ in 0..u16::MAX {
                let candidate = self.next_relay_slot;
                self.next_relay_slot = self.next_relay_slot.wrapping_add(1).max(1);
                if !self.relays.contains_key(&candidate)
                    && !self.slot_generations.contains_key(&candidate)
                {
                    allocated = Some(candidate);
                    break;
                }
            }
            let slot = allocated.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no free virtual relay slot IDs available",
                )
            })?;
            self.relay_addr_to_slot.insert(normalized, slot);
            slot
        };

        // Monotonic non-zero generation bump guarantees all prior routes for
        // this slot are immediately stale after reconnect.
        let prev_gen = self.slot_generations.get(&slot).copied().unwrap_or(0);
        let next_gen = prev_gen.wrapping_add(1).max(1);
        self.slot_generations.insert(slot, next_gen);

        // Evict stale routes belonging to the previous generation of this slot.
        self.purge_routes_for_slot(slot);
        Ok((slot, next_gen))
    }

    fn purge_routes_for_slot(&mut self, relay_slot: u16) {
        self.by_synthetic
            .retain(|_, entry| entry.relay_slot != relay_slot);
        self.by_target.retain(|&(s, _), _| s != relay_slot);
    }

    fn get_or_insert_route(
        &mut self,
        relay_slot: u16,
        real_target: SocketAddr,
        stats: &MultiplexedSocketStats,
    ) -> io::Result<SocketAddr> {
        let normalized = normalize_socket_addr(real_target);
        let Some(relay) = self.relays.get(&relay_slot) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("virtual relay slot {relay_slot} is not attached"),
            ));
        };
        let route_gen = relay.route_gen;
        let now_ms = self.elapsed_ms();

        if let Some(&existing_synthetic) = self.by_target.get(&(relay_slot, normalized)) {
            if let Some(entry) = self.by_synthetic.get(&existing_synthetic) {
                if entry.route_gen == route_gen {
                    entry.touch(now_ms);
                    return Ok(existing_synthetic);
                }
            }
            // Stale entry; clean up before reallocating.
            self.by_synthetic.remove(&existing_synthetic);
            self.by_target.remove(&(relay_slot, normalized));
        }

        if self.by_synthetic.len() >= MAX_VIRTUAL_ROUTES {
            let reaped = self.reap_idle_routes(now_ms);
            if reaped > 0 {
                trace!(reaped, "reaped expired idle virtual routes at capacity");
            }
        }

        if self.by_synthetic.len() >= MAX_VIRTUAL_ROUTES {
            stats
                .virtual_route_cap_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("virtual route table cap ({MAX_VIRTUAL_ROUTES}) reached"),
            ));
        }

        let peer_id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1).max(1);
        let port = normalized.port().max(1);
        let synthetic_addr = make_synthetic_virtual_addr(relay_slot, route_gen, peer_id, port);
        let entry = VirtualRouteEntry {
            relay_slot,
            route_gen,
            peer_id,
            real_target: normalized,
            synthetic_addr,
            last_activity_ms: AtomicU64::new(now_ms),
        };
        self.by_synthetic.insert(synthetic_addr, entry);
        self.by_target
            .insert((relay_slot, normalized), synthetic_addr);
        Ok(synthetic_addr)
    }
}

struct VirtualRecvPacket {
    payload: Vec<u8>,
    source: SocketAddr,
    ecn: Option<EcnCodepoint>,
}

struct VirtualRecvState {
    queue: VecDeque<VirtualRecvPacket>,
    waker: Option<Waker>,
}

/// Bounded non-blocking drop-on-full virtual ingress queue (ADR-021 §1.1).
struct VirtualRecvQueue {
    state: Mutex<VirtualRecvState>,
    capacity: usize,
}

impl VirtualRecvQueue {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(VirtualRecvState {
                queue: VecDeque::with_capacity(capacity.min(64)),
                waker: None,
            }),
            capacity: capacity.max(1),
        }
    }

    /// Enqueue a decoded virtual packet without ever blocking.
    ///
    /// Returns `true` if queued, or `false` if dropped because the queue was full.
    fn try_push(&self, payload: Vec<u8>, source: SocketAddr, ecn: Option<EcnCodepoint>) -> bool {
        let (pushed, waker) = {
            let mut state = self.state.lock();
            if state.queue.len() >= self.capacity {
                (false, None)
            } else {
                state.queue.push_back(VirtualRecvPacket {
                    payload,
                    source,
                    ecn,
                });
                (true, state.waker.take())
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        pushed
    }

    fn poll_pop(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        slots: &mut [SocketSlotId],
        max_burst: usize,
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock();
        let limit = bufs.len().min(meta.len()).min(slots.len()).min(max_burst);
        let mut count = 0;
        while count < limit {
            let Some(pkt) = state.queue.pop_front() else {
                break;
            };
            let len = pkt.payload.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&pkt.payload[..len]);

            let mut recv_meta = RecvMeta::default();
            recv_meta.len = len;
            recv_meta.stride = len;
            recv_meta.addr = pkt.source;
            recv_meta.ecn = pkt.ecn;
            recv_meta.dst_ip = None;
            meta[count] = recv_meta;
            slots[count] = SocketSlotId::VIRTUAL;
            count += 1;
        }
        if count > 0 {
            if !state.queue.is_empty() {
                cx.waker().wake_by_ref();
            }
            return Poll::Ready(Ok(count));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Clone, Copy)]
enum PollSource {
    Physical { slot_idx: usize, is_v6: bool },
    PhysicalAbstract { slot_idx: usize },
    Virtual,
}

/// Unified multiplexed UDP socket combining physical bind slots (1..=4) and a
/// virtual MASQUE relay plane under a single [`AsyncUdpSocket`] (ADR-021).
pub struct MultiplexedUdpSocket {
    physical_slots: Arc<[PhysicalBindSlot]>,
    /// True if any physical slot owns an IPv6 socket (in which case
    /// `local_addr()` returns IPv6 and physical IPv4 recv addresses are mapped
    /// to IPv4-mapped IPv6 so the endpoint operates in dual-stack IPv6 mode).
    endpoint_is_v6: bool,
    primary_local_addr: SocketAddr,
    cached_local_addrs: Vec<SocketAddr>,
    poll_sources: Vec<PollSource>,
    poll_cursor: AtomicUsize,
    virtual_routes: Arc<RwLock<VirtualRouteTable>>,
    virtual_recv: Arc<VirtualRecvQueue>,
    stats: Arc<MultiplexedSocketStats>,
}

impl fmt::Debug for MultiplexedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiplexedUdpSocket")
            .field("primary_local_addr", &self.primary_local_addr)
            .field("physical_slots", &self.physical_slots.len())
            .field("cached_local_addrs", &self.cached_local_addrs)
            .field("stats", &self.stats)
            .finish()
    }
}

impl MultiplexedUdpSocket {
    /// Construct a [`MultiplexedUdpSocket`] over `1..=MAX_PHYSICAL_SLOTS`
    /// physical slots with the default virtual receive queue capacity.
    pub fn new(physical_slots: Vec<PhysicalBindSlot>) -> io::Result<Self> {
        Self::with_virtual_queue_capacity(physical_slots, DEFAULT_VIRTUAL_RECV_QUEUE_CAPACITY)
    }

    /// Construct a [`MultiplexedUdpSocket`] with an explicit bounded virtual
    /// receive queue capacity (useful for testing backpressure).
    pub fn with_virtual_queue_capacity(
        physical_slots: Vec<PhysicalBindSlot>,
        virtual_recv_capacity: usize,
    ) -> io::Result<Self> {
        if physical_slots.is_empty() || physical_slots.len() > MAX_PHYSICAL_SLOTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "MultiplexedUdpSocket requires 1..={MAX_PHYSICAL_SLOTS} physical slots, got {}",
                    physical_slots.len()
                ),
            ));
        }

        for (idx, slot) in physical_slots.iter().enumerate() {
            let Some(expected) = SocketSlotId::physical(idx) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "physical slot index {idx} exceeds MAX_PHYSICAL_SLOTS ({MAX_PHYSICAL_SLOTS})"
                    ),
                ));
            };
            if slot.slot_id != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "physical slot at index {idx} must have slot_id {expected:?}, got {:?}",
                        slot.slot_id
                    ),
                ));
            }
        }

        let mut cached_local_addrs = Vec::with_capacity(physical_slots.len() * 2);
        let mut poll_sources = Vec::with_capacity(physical_slots.len() * 2 + 1);
        let mut first_v6 = None;
        let mut first_v4 = None;

        for (idx, slot) in physical_slots.iter().enumerate() {
            if slot.abstract_socket.is_some() {
                if let Some(v4_addr) = slot.v4_addr {
                    cached_local_addrs.push(v4_addr);
                    if first_v4.is_none() {
                        first_v4 = Some(v4_addr);
                    }
                }
                if let Some(v6_addr) = slot.v6_addr {
                    cached_local_addrs.push(v6_addr);
                    if first_v6.is_none() {
                        first_v6 = Some(v6_addr);
                    }
                }
                poll_sources.push(PollSource::PhysicalAbstract { slot_idx: idx });
                continue;
            }
            if let Some(v4_addr) = slot.v4_addr {
                cached_local_addrs.push(v4_addr);
                if first_v4.is_none() {
                    first_v4 = Some(v4_addr);
                }
                poll_sources.push(PollSource::Physical {
                    slot_idx: idx,
                    is_v6: false,
                });
            }
            if let Some(v6_addr) = slot.v6_addr {
                cached_local_addrs.push(v6_addr);
                if first_v6.is_none() {
                    first_v6 = Some(v6_addr);
                }
                poll_sources.push(PollSource::Physical {
                    slot_idx: idx,
                    is_v6: true,
                });
            }
        }
        poll_sources.push(PollSource::Virtual);

        let (endpoint_is_v6, primary_local_addr) = match (first_v6, first_v4) {
            (Some(v6), _) => (true, v6),
            (None, Some(v4)) => (false, v4),
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no physical UDP addresses bound",
                ));
            }
        };

        Ok(Self {
            physical_slots: Arc::from(physical_slots),
            endpoint_is_v6,
            primary_local_addr,
            cached_local_addrs,
            poll_sources,
            poll_cursor: AtomicUsize::new(0),
            virtual_routes: Arc::new(RwLock::new(VirtualRouteTable::new())),
            virtual_recv: Arc::new(VirtualRecvQueue::new(virtual_recv_capacity)),
            stats: Arc::new(MultiplexedSocketStats::default()),
        })
    }

    /// Convenience constructor for a single primary dual-stack slot.
    pub fn from_dual_stack(
        v4: Option<tokio::net::UdpSocket>,
        v6: Option<tokio::net::UdpSocket>,
    ) -> io::Result<Self> {
        let primary = PhysicalBindSlot::new(SocketSlotId::PRIMARY, v4, v6)?;
        Self::new(vec![primary])
    }

    /// Convenience constructor wrapping a single `std::net::UdpSocket` on
    /// [`SocketSlotId::PRIMARY`].
    pub fn from_std_socket(socket: std::net::UdpSocket) -> io::Result<Self> {
        let primary = PhysicalBindSlot::from_std(SocketSlotId::PRIMARY, socket)?;
        Self::new(vec![primary])
    }

    /// Convenience constructor wrapping an existing [`AsyncUdpSocket`] on
    /// [`SocketSlotId::PRIMARY`] so custom sockets gain the unified virtual
    /// MASQUE relay plane.
    pub fn from_abstract_socket(socket: Arc<dyn AsyncUdpSocket>) -> io::Result<Self> {
        let primary = PhysicalBindSlot::from_abstract(SocketSlotId::PRIMARY, socket)?;
        Self::new(vec![primary])
    }

    /// Number of bound physical slots (`1..=MAX_PHYSICAL_SLOTS`).
    #[must_use]
    pub fn physical_slot_count(&self) -> usize {
        self.physical_slots.len()
    }

    /// Return `(v4_addr, v6_addr)` for a physical slot, if bound.
    #[must_use]
    pub fn slot_addrs(
        &self,
        slot: SocketSlotId,
    ) -> Option<(Option<SocketAddr>, Option<SocketAddr>)> {
        let idx = slot.physical_index()?;
        let physical = self.physical_slots.get(idx)?;
        Some((physical.v4_addr, physical.v6_addr))
    }

    /// Return diagnostic counters for spoof drops, queue backpressure, and cap
    /// enforcement.
    #[must_use]
    pub fn stats(&self) -> &Arc<MultiplexedSocketStats> {
        &self.stats
    }

    /// Attach a live [`MasqueRelaySocket`] to the virtual plane (ADR-021 §1.1).
    ///
    /// Reuses all ADR-020 `DatagramMuxV1`, `COMPRESSION_ASSIGN`, 4-context ECN
    /// quad, stream-lane Initial, and `900 B` floor mechanics inside
    /// `MasqueRelaySocket` while bridging ingress and egress across a strictly
    /// non-re-entrant, bounded, non-blocking boundary.
    pub fn attach_relay_socket(
        &self,
        relay_addr: SocketAddr,
        relay_socket: Arc<MasqueRelaySocket>,
    ) -> io::Result<VirtualRelayHandle> {
        let public_addr = relay_socket.public_addr();
        let send_tx = relay_socket.egress_sender();
        let initial_virtual_mtu = relay_socket.recommended_inner_mtu().unwrap_or(0);
        let outer_connection = relay_socket.outer_connection().cloned();
        let mux_v1 = relay_socket.is_mux_v1();
        let relay_stats = Arc::clone(relay_socket.stats());

        let handle = self.attach_virtual_channel_inner(
            relay_addr,
            public_addr,
            send_tx,
            initial_virtual_mtu,
            outer_connection,
            mux_v1,
            Some(relay_stats),
            Some(Arc::clone(&relay_socket)),
        )?;

        // Capture a Weak reference to `virtual_routes` so `virtual_routes ->
        // MasqueRelaySocket -> ingress_hook -> virtual_routes` never forms a
        // strong reference cycle if the socket is dropped without explicitly
        // calling `detach_all_relays()`.
        let routes = Arc::downgrade(&self.virtual_routes);
        let recv_queue = Arc::clone(&self.virtual_recv);
        let stats = Arc::clone(&self.stats);
        let relay_slot = handle.relay_slot;
        let route_gen = handle.route_gen;

        relay_socket.set_ingress_hook(Some(Arc::new(move |payload, real_source, ecn| {
            let Some(routes) = routes.upgrade() else {
                return;
            };
            Self::enqueue_virtual_ingress(
                &routes,
                &recv_queue,
                &stats,
                relay_slot,
                route_gen,
                real_source,
                payload,
                ecn,
            );
        })));

        Ok(handle)
    }

    /// Attach a raw bounded egress channel as a virtual relay session.
    ///
    /// Useful for tests and custom virtual transports that feed inbound packets
    /// via [`Self::inject_virtual_datagram`].
    #[cfg(test)]
    pub(crate) fn attach_virtual_channel(
        &self,
        relay_addr: SocketAddr,
        public_addr: SocketAddr,
        send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
        initial_virtual_mtu: u16,
    ) -> io::Result<VirtualRelayHandle> {
        self.attach_virtual_channel_inner(
            relay_addr,
            public_addr,
            send_tx,
            initial_virtual_mtu,
            None,
            true,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn attach_virtual_channel_inner(
        &self,
        relay_addr: SocketAddr,
        public_addr: SocketAddr,
        send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
        initial_virtual_mtu: u16,
        outer_connection: Option<Connection>,
        mux_v1: bool,
        relay_stats: Option<Arc<MasqueRelaySocketStats>>,
        relay_socket: Option<Arc<MasqueRelaySocket>>,
    ) -> io::Result<VirtualRelayHandle> {
        let normalized_relay = normalize_socket_addr(relay_addr);
        let virtual_mtu = Arc::new(AtomicU16::new(initial_virtual_mtu));
        let outer_for_subscribe = outer_connection.clone();
        let (relay_slot, route_gen, replaced_socket) = {
            let mut table = self.virtual_routes.write();
            let (slot, next_gen) = table.allocate_slot_and_gen(normalized_relay)?;
            let old_sock = table.relays.remove(&slot).and_then(|old| old.relay_socket);
            table.relays.insert(
                slot,
                RelaySessionSlot {
                    relay_addr: normalized_relay,
                    relay_slot: slot,
                    route_gen: next_gen,
                    public_addr,
                    send_tx,
                    outer_connection,
                    mux_v1,
                    relay_stats,
                    virtual_mtu: Arc::clone(&virtual_mtu),
                    relay_socket,
                },
            );
            (slot, next_gen, old_sock)
        };

        // Detach ingress hook on any replaced relay socket AFTER releasing
        // `self.virtual_routes.write()` to avoid lock-order inversion with
        // `MasqueRelaySocket::enqueue_received` (which holds
        // `ingress_hook.read()` while acquiring `virtual_routes`).
        if let Some(old_sock) = replaced_socket {
            old_sock.set_ingress_hook(None);
        }

        // Subscribe to synchronous outer connection MTU updates so mid-session
        // outer PMTU shrinks publish into `virtual_mtu` BEFORE inner
        // `poll_transmit` builds its next packet (ADR-021 §1.4).
        if let Some(conn) = outer_for_subscribe {
            let overhead = if mux_v1 { 2 } else { 8 };
            conn.subscribe_virtual_path_mtu(Arc::clone(&virtual_mtu), overhead);
        }

        Ok(VirtualRelayHandle {
            relay_slot,
            route_gen,
            public_addr,
            virtual_mtu,
        })
    }

    /// Detach the relay session associated with `relay_addr`, invalidating all
    /// virtual routes for that relay slot.
    pub fn detach_relay(&self, relay_addr: SocketAddr) {
        let normalized = normalize_socket_addr(relay_addr);
        let old_socket = {
            let mut table = self.virtual_routes.write();
            let Some(&slot) = table.relay_addr_to_slot.get(&normalized) else {
                return;
            };
            table.purge_routes_for_slot(slot);
            table.relays.remove(&slot).and_then(|s| s.relay_socket)
        };
        if let Some(sock) = old_socket {
            sock.set_ingress_hook(None);
        }
    }

    /// Detach all virtual relay sessions (called during endpoint shutdown so no
    /// outer relay handles remain retained).
    pub fn detach_all_relays(&self) {
        let old_sockets: Vec<Arc<MasqueRelaySocket>> = {
            let mut table = self.virtual_routes.write();
            table.by_synthetic.clear();
            table.by_target.clear();
            table
                .relays
                .drain()
                .filter_map(|(_, s)| s.relay_socket)
                .collect()
        };
        for sock in old_sockets {
            sock.set_ingress_hook(None);
        }
    }

    /// Return the currently attached `relay_slot` for `relay_addr`, if active.
    #[must_use]
    pub fn relay_slot_for_addr(&self, relay_addr: SocketAddr) -> Option<u16> {
        let normalized = normalize_socket_addr(relay_addr);
        let table = self.virtual_routes.read();
        let &slot = table.relay_addr_to_slot.get(&normalized)?;
        table.relays.contains_key(&slot).then_some(slot)
    }

    /// Register (or reuse) a synthetic virtual ULA route for outbound dialing
    /// to `real_target` through `relay_slot`.
    pub fn register_virtual_route(
        &self,
        relay_slot: u16,
        real_target: SocketAddr,
    ) -> io::Result<SocketAddr> {
        if is_synthetic_virtual_addr(real_target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot nest a synthetic virtual address inside a virtual route",
            ));
        }
        let mut table = self.virtual_routes.write();
        table.get_or_insert_route(relay_slot, real_target, &self.stats)
    }

    /// Explicitly remove a synthetic virtual route (for example after all
    /// sessions to that peer have closed).
    pub fn remove_virtual_route(&self, synthetic_addr: SocketAddr) -> bool {
        self.virtual_routes.write().remove_route(synthetic_addr)
    }

    /// Override the virtual route idle timeout (for deterministic unit tests).
    #[cfg(test)]
    pub(crate) fn set_virtual_route_idle_timeout(&self, timeout: Duration) {
        self.virtual_routes.write().route_idle_timeout = timeout;
    }

    /// Resolve a synthetic virtual ULA address back to the real peer target
    /// address, if the route is active and matches the slot's current generation.
    #[must_use]
    pub fn resolve_virtual_target(&self, synthetic_addr: SocketAddr) -> Option<SocketAddr> {
        let (relay_slot, route_gen, _) = decode_synthetic_virtual_addr(synthetic_addr)?;
        let table = self.virtual_routes.read();
        let relay = table.relays.get(&relay_slot)?;
        if relay.route_gen != route_gen {
            return None;
        }
        let entry = table.by_synthetic.get(&synthetic_addr)?;
        (entry.relay_slot == relay_slot && entry.route_gen == route_gen)
            .then_some(entry.real_target)
    }

    /// Inject an inbound virtual packet from `(relay_slot, route_gen, real_source)`
    /// into the bounded virtual receive queue without blocking.
    ///
    /// Returns `true` if enqueued, or `false` if dropped (stale generation,
    /// route cap hit, or virtual receive queue full).
    pub fn inject_virtual_datagram(
        &self,
        relay_slot: u16,
        route_gen: u32,
        real_source: SocketAddr,
        payload: Vec<u8>,
        ecn: Option<EcnCodepoint>,
    ) -> bool {
        Self::enqueue_virtual_ingress(
            &self.virtual_routes,
            &self.virtual_recv,
            &self.stats,
            relay_slot,
            route_gen,
            real_source,
            payload,
            ecn,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_virtual_ingress(
        routes: &Arc<RwLock<VirtualRouteTable>>,
        recv_queue: &Arc<VirtualRecvQueue>,
        stats: &Arc<MultiplexedSocketStats>,
        relay_slot: u16,
        route_gen: u32,
        real_source: SocketAddr,
        payload: Vec<u8>,
        ecn: Option<EcnCodepoint>,
    ) -> bool {
        if is_synthetic_virtual_addr(real_source) {
            stats
                .synthetic_prefix_spoof_dropped
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let normalized_source = normalize_socket_addr(real_source);

        // Fast read-lock lookup before taking a write lock for a new peer.
        let synthetic_addr = {
            let table = routes.read();
            let Some(relay) = table.relays.get(&relay_slot) else {
                return false;
            };
            if relay.route_gen != route_gen {
                return false;
            }
            let _ = relay.refresh_virtual_mtu();
            let now_ms = table.elapsed_ms();
            table
                .by_target
                .get(&(relay_slot, normalized_source))
                .copied()
                .filter(|addr| {
                    table.by_synthetic.get(addr).is_some_and(|e| {
                        if e.route_gen == route_gen {
                            e.touch(now_ms);
                            true
                        } else {
                            false
                        }
                    })
                })
        };

        let synthetic_addr = match synthetic_addr {
            Some(addr) => addr,
            None => {
                let mut table = routes.write();
                let Some(relay) = table.relays.get(&relay_slot) else {
                    return false;
                };
                if relay.route_gen != route_gen {
                    return false;
                }
                match table.get_or_insert_route(relay_slot, normalized_source, stats) {
                    Ok(addr) => addr,
                    Err(e) => {
                        trace!(
                            relay_slot,
                            %normalized_source,
                            error = %e,
                            "dropping virtual ingress datagram: route allocation failed"
                        );
                        return false;
                    }
                }
            }
        };

        if recv_queue.try_push(payload, synthetic_addr, ecn) {
            true
        } else {
            stats
                .virtual_recv_queue_dropped
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn convert_dest(dest: SocketAddr, socket_is_v6: bool) -> io::Result<SocketAddr> {
        match dest {
            SocketAddr::V4(v4) if socket_is_v6 => Ok(SocketAddr::V6(to_mapped_v6(v4))),
            SocketAddr::V6(v6) if !socket_is_v6 => {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    Ok(SocketAddr::new(v4.into(), v6.port()))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "cannot send native IPv6 address through IPv4 socket",
                    ))
                }
            }
            other => Ok(other),
        }
    }

    fn convert_src_ip(src_ip: Option<IpAddr>, socket_is_v6: bool) -> Option<IpAddr> {
        match (src_ip?, socket_is_v6) {
            (IpAddr::V4(v4), true) => Some(IpAddr::V6(v4.to_ipv6_mapped())),
            (IpAddr::V6(v6), false) => v6.to_ipv4_mapped().map(IpAddr::V4),
            (other, _) => Some(other),
        }
    }

    /// Poll a single physical socket family, dropping any datagram whose source
    /// IP matches the synthetic virtual ULA prefix (`fd00:53a0:5251::/48`) and
    /// tagging every kept datagram with its exact `slot_id`.
    #[allow(clippy::too_many_arguments)]
    fn poll_physical_batch(
        socket: &tokio::net::UdpSocket,
        state: &UdpSocketState,
        slot_id: SocketSlotId,
        socket_is_v4: bool,
        map_v4_to_v6: bool,
        stats: &MultiplexedSocketStats,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        slots: &mut [SocketSlotId],
        max_burst: usize,
    ) -> Poll<io::Result<usize>> {
        let limit = bufs.len().min(meta.len()).min(slots.len()).min(max_burst);
        if limit == 0 {
            return Poll::Ready(Ok(0));
        }

        loop {
            match socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let res = socket.try_io(Interest::READABLE, || {
                state.recv(
                    UdpSockRef::from(socket),
                    &mut bufs[..limit],
                    &mut meta[..limit],
                )
            });

            match res {
                Ok(count) => {
                    let mut kept = 0usize;
                    for i in 0..count {
                        let mut m = meta[i];
                        // ADR-021 §1.2: drop spoofed packets from the reserved
                        // synthetic virtual ULA prefix on any physical interface.
                        if is_synthetic_virtual_ip(m.addr.ip()) {
                            stats
                                .synthetic_prefix_spoof_dropped
                                .fetch_add(1, Ordering::Relaxed);
                            warn!(
                                addr = %m.addr,
                                ?slot_id,
                                "dropped spoofed synthetic virtual ULA packet on physical UDP socket"
                            );
                            continue;
                        }
                        if socket_is_v4 && map_v4_to_v6 {
                            if let SocketAddr::V4(v4) = m.addr {
                                m.addr = SocketAddr::V6(to_mapped_v6(v4));
                            }
                            if let Some(IpAddr::V4(v4)) = m.dst_ip {
                                m.dst_ip = Some(IpAddr::V6(v4.to_ipv6_mapped()));
                            }
                        }
                        if kept != i {
                            let len = m.len.min(bufs[kept].len()).min(bufs[i].len());
                            // Copy payload down into compacted slot `kept` without
                            // aliasing slices.
                            let (left, right) = bufs.split_at_mut(i);
                            left[kept][..len].copy_from_slice(&right[0][..len]);
                        }
                        meta[kept] = m;
                        slots[kept] = slot_id;
                        kept += 1;
                    }
                    if kept > 0 {
                        return Poll::Ready(Ok(kept));
                    }
                    // Every datagram in this batch was a dropped spoof; keep polling.
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncUdpSocket for MultiplexedUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        let physical_senders = self
            .physical_slots
            .iter()
            .map(|slot| PhysicalSlotSender {
                v4: slot.v4.clone(),
                v6: slot.v6.clone(),
                v4_state: slot.v4_state.clone(),
                v6_state: slot.v6_state.clone(),
                v4_writable: slot.v4.as_ref().map(make_socket_poller),
                v6_writable: slot.v6.as_ref().map(make_socket_poller),
                abstract_sender: slot.abstract_socket.as_ref().map(|s| s.create_sender()),
            })
            .collect();

        Box::pin(MultiplexedUdpSender {
            physical_senders,
            virtual_routes: Arc::clone(&self.virtual_routes),
            stats: Arc::clone(&self.stats),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let len = bufs.len().min(meta.len());
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut scratch_slots = vec![SocketSlotId::PRIMARY; len];
        self.poll_recv_with_slots(cx, bufs, meta, &mut scratch_slots)
    }

    fn poll_recv_with_slots(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        slots: &mut [SocketSlotId],
    ) -> Poll<io::Result<usize>> {
        let limit = bufs.len().min(meta.len()).min(slots.len());
        if limit == 0 {
            return Poll::Ready(Ok(0));
        }

        let num_sources = self.poll_sources.len();
        if num_sources == 0 {
            return Poll::Pending;
        }

        let start = self.poll_cursor.fetch_add(1, Ordering::Relaxed) % num_sources;
        let mut last_err: Option<io::Error> = None;

        for offset in 0..num_sources {
            let source = self.poll_sources[(start + offset) % num_sources];
            match source {
                PollSource::Physical { slot_idx, is_v6 } => {
                    let slot = &self.physical_slots[slot_idx];
                    let (sock, state) = if is_v6 {
                        (&slot.v6, &slot.v6_state)
                    } else {
                        (&slot.v4, &slot.v4_state)
                    };
                    if let (Some(sock), Some(state)) = (sock, state) {
                        match Self::poll_physical_batch(
                            sock,
                            state,
                            slot.slot_id,
                            !is_v6,
                            self.endpoint_is_v6,
                            &self.stats,
                            cx,
                            &mut bufs[..limit],
                            &mut meta[..limit],
                            &mut slots[..limit],
                            MAX_RECV_BURST_PER_SOURCE,
                        ) {
                            Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                            Poll::Ready(Err(e)) => {
                                debug!(
                                    slot_id = ?slot.slot_id,
                                    is_v6,
                                    error = %e,
                                    "MultiplexedUdpSocket physical recv error"
                                );
                                last_err = Some(e);
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                PollSource::PhysicalAbstract { slot_idx } => {
                    let slot = &self.physical_slots[slot_idx];
                    if let Some(ref abs_sock) = slot.abstract_socket {
                        let burst = limit.min(MAX_RECV_BURST_PER_SOURCE);
                        loop {
                            match abs_sock.poll_recv(cx, &mut bufs[..burst], &mut meta[..burst]) {
                                Poll::Ready(Ok(0)) => break,
                                Poll::Ready(Ok(count)) => {
                                    let mut kept = 0usize;
                                    for i in 0..count {
                                        let m = meta[i];
                                        if is_synthetic_virtual_ip(m.addr.ip()) {
                                            self.stats
                                                .synthetic_prefix_spoof_dropped
                                                .fetch_add(1, Ordering::Relaxed);
                                            warn!(
                                                addr = %m.addr,
                                                slot_id = ?slot.slot_id,
                                                "dropped spoofed synthetic virtual ULA packet on abstract physical UDP socket"
                                            );
                                            continue;
                                        }
                                        if kept != i {
                                            let len =
                                                m.len.min(bufs[kept].len()).min(bufs[i].len());
                                            let (left, right) = bufs.split_at_mut(i);
                                            left[kept][..len].copy_from_slice(&right[0][..len]);
                                        }
                                        meta[kept] = m;
                                        slots[kept] = slot.slot_id;
                                        kept += 1;
                                    }
                                    if kept > 0 {
                                        return Poll::Ready(Ok(kept));
                                    }
                                    // Every datagram in this batch was a dropped spoof; keep
                                    // polling so the underlying socket registers our waker.
                                }
                                Poll::Ready(Err(e)) => {
                                    debug!(
                                        slot_id = ?slot.slot_id,
                                        error = %e,
                                        "MultiplexedUdpSocket abstract physical recv error"
                                    );
                                    last_err = Some(e);
                                    break;
                                }
                                Poll::Pending => break,
                            }
                        }
                    }
                }
                PollSource::Virtual => {
                    match self.virtual_recv.poll_pop(
                        cx,
                        &mut bufs[..limit],
                        &mut meta[..limit],
                        &mut slots[..limit],
                        MAX_RECV_BURST_PER_SOURCE,
                    ) {
                        Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                        Poll::Ready(Err(e)) => last_err = Some(e),
                        Poll::Pending => {}
                    }
                }
            }
        }

        if let Some(err) = last_err {
            return Poll::Ready(Err(err));
        }
        Poll::Pending
    }

    fn virtual_path_mtu(&self, remote: SocketAddr) -> Option<u16> {
        let (relay_slot, route_gen, _) = decode_synthetic_virtual_addr(remote)?;
        let table = self.virtual_routes.read();
        let relay = table.relays.get(&relay_slot)?;
        if relay.route_gen != route_gen {
            return None;
        }
        relay.refresh_virtual_mtu()
    }

    fn virtual_path_mtu_handle(&self, remote: SocketAddr) -> Option<Arc<AtomicU16>> {
        let (relay_slot, route_gen, _) = decode_synthetic_virtual_addr(remote)?;
        let table = self.virtual_routes.read();
        let relay = table.relays.get(&relay_slot)?;
        if relay.route_gen != route_gen {
            return None;
        }
        let _ = relay.refresh_virtual_mtu();
        Some(Arc::clone(&relay.virtual_mtu))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.primary_local_addr)
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        if self.cached_local_addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "multiplexed socket has no bound physical addresses",
            ));
        }
        Ok(self.cached_local_addrs.clone())
    }

    fn max_receive_segments(&self) -> usize {
        self.physical_slots
            .iter()
            .map(|slot| {
                let raw_max = [slot.v4_state.as_ref(), slot.v6_state.as_ref()]
                    .into_iter()
                    .flatten()
                    .map(|state| state.gro_segments())
                    .max()
                    .unwrap_or(1);
                let abs_max = slot
                    .abstract_socket
                    .as_ref()
                    .map(|s| s.max_receive_segments())
                    .unwrap_or(1);
                raw_max.max(abs_max)
            })
            .max()
            .unwrap_or(1)
            .max(1)
    }

    fn may_fragment(&self) -> bool {
        self.physical_slots.iter().any(|slot| {
            [slot.v4_state.as_ref(), slot.v6_state.as_ref()]
                .into_iter()
                .flatten()
                .any(|state| state.may_fragment())
                || slot
                    .abstract_socket
                    .as_ref()
                    .is_some_and(|s| s.may_fragment())
        })
    }
}

fn make_socket_poller(socket: &Arc<tokio::net::UdpSocket>) -> Pin<Box<dyn UdpPoller>> {
    let socket = Arc::clone(socket);
    Box::pin(UdpPollHelper::new(move || {
        let socket = Arc::clone(&socket);
        async move { socket.writable().await }
    }))
}

#[derive(Debug)]
struct PhysicalSlotSender {
    v4: Option<Arc<tokio::net::UdpSocket>>,
    v6: Option<Arc<tokio::net::UdpSocket>>,
    v4_state: Option<Arc<UdpSocketState>>,
    v6_state: Option<Arc<UdpSocketState>>,
    v4_writable: Option<Pin<Box<dyn UdpPoller>>>,
    v6_writable: Option<Pin<Box<dyn UdpPoller>>>,
    abstract_sender: Option<Pin<Box<dyn UdpSender>>>,
}

impl PhysicalSlotSender {
    fn select_family(&self, dest: &SocketAddr) -> Option<bool> {
        let has_v4 = self.v4.is_some();
        let has_v6 = self.v6.is_some();
        match dest {
            SocketAddr::V4(_) => {
                if has_v4 {
                    Some(false)
                } else {
                    has_v6.then_some(true)
                }
            }
            SocketAddr::V6(addr) if addr.ip().to_ipv4_mapped().is_some() => {
                if has_v4 {
                    Some(false)
                } else {
                    has_v6.then_some(true)
                }
            }
            SocketAddr::V6(_) => {
                if has_v6 {
                    Some(true)
                } else {
                    has_v4.then_some(false)
                }
            }
        }
    }

    fn poll_send_physical(
        &mut self,
        transmit: &Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // ADR-021 §1.2: physical send MUST reject synthetic virtual ULA addresses.
        if is_synthetic_virtual_addr(transmit.destination) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to transmit synthetic virtual ULA address on physical UDP slot",
            )));
        }

        if let Some(sender) = self.abstract_sender.as_mut() {
            return sender.as_mut().poll_send(transmit, cx);
        }

        let socket_is_v6 = self.select_family(&transmit.destination).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no physical socket available for destination address family",
            )
        })?;

        loop {
            let (socket, state, poller) = if socket_is_v6 {
                (
                    self.v6.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 socket unavailable")
                    })?,
                    self.v6_state.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 state unavailable")
                    })?,
                    self.v6_writable.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 poller unavailable")
                    })?,
                )
            } else {
                (
                    self.v4.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 socket unavailable")
                    })?,
                    self.v4_state.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 state unavailable")
                    })?,
                    self.v4_writable.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 poller unavailable")
                    })?,
                )
            };

            match poller.as_mut().poll_writable(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let dest = MultiplexedUdpSocket::convert_dest(transmit.destination, socket_is_v6)?;
            let converted = Transmit {
                destination: dest,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: MultiplexedUdpSocket::convert_src_ip(transmit.src_ip, socket_is_v6),
            };
            let res = socket.try_io(Interest::WRITABLE, || {
                state.send(UdpSockRef::from(&*socket), &converted)
            });
            match res {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn max_gso_segments(&self) -> usize {
        if let Some(ref sender) = self.abstract_sender {
            return sender.max_transmit_segments().max(1);
        }
        match (&self.v4_state, &self.v6_state) {
            (Some(v4), Some(v6)) => v4.max_gso_segments().min(v6.max_gso_segments()).max(1),
            (Some(v4), None) => v4.max_gso_segments().max(1),
            (None, Some(v6)) => v6.max_gso_segments().max(1),
            (None, None) => 1,
        }
    }
}

struct MultiplexedUdpSender {
    physical_senders: Vec<PhysicalSlotSender>,
    virtual_routes: Arc<RwLock<VirtualRouteTable>>,
    stats: Arc<MultiplexedSocketStats>,
}

impl fmt::Debug for MultiplexedUdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiplexedUdpSender")
            .field("physical_slots", &self.physical_senders.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl MultiplexedUdpSender {
    /// Non-re-entrant, non-blocking send onto the virtual MASQUE plane
    /// (ADR-021 §1.1). Never acquires any `Endpoint` lock and never blocks.
    fn send_virtual(&self, transmit: &Transmit) -> io::Result<()> {
        let Some((relay_slot, route_gen, _peer_id)) =
            decode_synthetic_virtual_addr(transmit.destination)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtual socket slot requires a synthetic virtual ULA destination",
            ));
        };

        let resolved = {
            let table = self.virtual_routes.read();
            let Some(relay) = table.relays.get(&relay_slot) else {
                self.stats
                    .virtual_stale_gen_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            if relay.route_gen != route_gen {
                self.stats
                    .virtual_stale_gen_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            let Some(entry) = table.by_synthetic.get(&transmit.destination) else {
                self.stats
                    .virtual_stale_gen_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            if entry.relay_slot != relay_slot || entry.route_gen != route_gen {
                self.stats
                    .virtual_stale_gen_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            entry.touch(table.elapsed_ms());
            let _ = relay.refresh_virtual_mtu();
            (
                entry.real_target,
                relay.send_tx.clone(),
                relay.relay_stats.clone(),
            )
        };

        let (real_target, send_tx, relay_stats) = resolved;
        let segment_size = transmit
            .segment_size
            .filter(|&s| s > 0 && s < transmit.contents.len())
            .unwrap_or(transmit.contents.len().max(1));

        for chunk in transmit.contents.chunks(segment_size) {
            let packet = OutboundRelayPacket {
                target: real_target,
                ecn: transmit.ecn,
                raw_payload: Bytes::copy_from_slice(chunk),
            };
            match send_tx.try_send(packet) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.stats
                        .virtual_tx_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(ref rs) = relay_stats {
                        rs.tx_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.stats
                        .virtual_stale_gen_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        Ok(())
    }
}

impl UdpSender for MultiplexedUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let slot = if is_synthetic_virtual_addr(transmit.destination) {
            SocketSlotId::VIRTUAL
        } else {
            SocketSlotId::PRIMARY
        };
        self.poll_send_on_slot(transmit, slot, cx)
    }

    fn poll_send_on_slot(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        local_slot: SocketSlotId,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if local_slot.is_virtual() {
            return Poll::Ready(this.send_virtual(transmit));
        }

        // ADR-021 §1.2: physical slot MUST reject synthetic virtual ULA targets.
        if is_synthetic_virtual_addr(transmit.destination) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to transmit synthetic virtual ULA address on physical UDP slot",
            )));
        }

        let Some(idx) = local_slot.physical_index() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid physical slot {local_slot:?}"),
            )));
        };
        let Some(sender) = this.physical_senders.get_mut(idx) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("physical slot {local_slot:?} is not bound"),
            )));
        };
        sender.poll_send_physical(transmit, cx)
    }

    fn max_transmit_segments(&self) -> usize {
        self.physical_senders
            .iter()
            .map(PhysicalSlotSender::max_gso_segments)
            .min()
            .unwrap_or(1)
            .max(1)
    }
}

fn to_mapped_v6(v4: SocketAddrV4) -> SocketAddrV6 {
    SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)
}
