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
//! Supports two forwarding modes per ADR-016:
//! - [`RelayForwardMode::Stream`] (default): all packets travel over the persistent
//!   bidirectional QUIC stream with `[4-byte BE length][UncompressedDatagram]` framing.
//! - [`RelayForwardMode::Hybrid`]: non-Initial packets that fit the negotiated QUIC
//!   `DATAGRAM` budget `P_max` travel as unreliable QUIC `DATAGRAM` frames (no
//!   head-of-line blocking, no nested retransmission), while QUIC Initial packets
//!   and packets larger than `P_max` stay on the length-prefixed stream lane.
//!
//! Hybrid is negotiated per relay session: the client sets
//! [`crate::masque::connect::REQUEST_FLAG_HYBRID_DATAGRAM_LANE`] in its CONNECT-UDP
//! request and the relay answers with
//! [`crate::masque::connect::RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`]. Without both
//! bits the session is stream-only in both directions. Advertising QUIC
//! `DATAGRAM` support in transport parameters is NOT a signal: every peer does
//! it, including peers that never read the datagram lane.
//!
//! QUIC `DATAGRAM` frames carry no relay demultiplexer (the context ID is always
//! `0`), so only one reader may consume a connection's datagrams. A hybrid
//! session therefore holds a [`DatagramLaneClaim`] on its outer connection for
//! its lifetime; a second hybrid session, or any other datagram reader on the
//! same connection, is refused instead of silently stealing packets.
//!
//! Implements [`AsyncUdpSocket`] so it can be plugged into a Quinn endpoint
//! as a transparent replacement for a real UDP socket.

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::{Context, Poll, Waker};

use quinn_udp::{RecvMeta, Transmit};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::VarInt;
use crate::high_level::{AsyncUdpSocket, Connection, SendDatagramError, UdpSender};
use crate::masque::UncompressedDatagram;

/// Minimum QUIC Initial packet size per RFC 9000 §14.1.
pub const QUIC_INITIAL_MIN_SIZE: usize = 1200;

/// Margin above [`QUIC_INITIAL_MIN_SIZE`] that the datagram budget `P_max`
/// must keep (ADR-016 Decision 3: never below 1200 B plus margin).
pub const RELAY_DATAGRAM_BUDGET_MARGIN: usize = 32;

/// Smallest inner payload budget `P_max` for which the datagram lane is used.
///
/// When the outer connection cannot carry this many inner bytes in one QUIC
/// `DATAGRAM` frame, [`compute_datagram_payload_budget`] returns `None` and
/// every packet uses the stream lane.
pub const MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET: usize =
    QUIC_INITIAL_MIN_SIZE + RELAY_DATAGRAM_BUDGET_MARGIN;

/// Maximum queued outbound packets before tail-drop engages.
///
/// Bounding the channel prevents inner QUIC PTO retransmissions from causing
/// unbounded memory growth and bufferbloat during outer-link congestion.
pub const DEFAULT_RELAY_SEND_QUEUE_CAPACITY: usize = 256;

/// Maximum queued inbound packets before oldest-drop engages (UDP ring semantics).
pub const DEFAULT_RELAY_RECV_QUEUE_CAPACITY: usize = 256;

/// Relay data-plane forwarding mode (ADR-016).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayForwardMode {
    /// Forward all packets over the length-prefixed reliable QUIC stream (ADR-009).
    #[default]
    Stream,
    /// Two-lane forwarding (ADR-016): unreliable QUIC `DATAGRAM` frames for
    /// non-Initial packets `<= P_max`, length-prefixed stream for Initials
    /// and oversized packets. Used for a session only when both ends signal
    /// it in the CONNECT-UDP exchange.
    Hybrid,
}

/// Forwarding lane selected for a single inner UDP packet (ADR-016).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayLane {
    /// Unreliable QUIC `DATAGRAM` frame on the outer relay connection.
    Datagram,
    /// Length-prefixed frame on the reliable outer relay bidirectional stream.
    Stream,
}

/// Overhead in bytes of an [`UncompressedDatagram`] header using Context ID `0`.
///
/// Layout: `1 B` context varint (`0`) + `1 B` IP version + `4 B` (IPv4) or
/// `16 B` (IPv6) address + `2 B` port.
#[must_use]
pub const fn uncompressed_datagram_header_overhead(target: SocketAddr) -> usize {
    match target {
        SocketAddr::V4(_) => 1 + 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 1 + 16 + 2,
    }
}

/// Returns `true` if `payload` looks like a QUIC Initial packet (v1 or v2).
///
/// Per RFC 9000 §17.2.2 and RFC 9369 §3.2:
/// - Long header bit (`0x80`) is set.
/// - For QUIC v1 (or unknown versions), long packet type bits `(b0 & 0x30) == 0x00`.
/// - For QUIC v2 (`version == 0x6b33_43cf`), Initial uses `(b0 & 0x30) == 0x10`.
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
/// QUIC `DATAGRAM` frame for `target`.
///
/// Returns `None` when outer datagrams are disabled/unsupported, or when the
/// budget after encapsulation overhead is below
/// [`MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET`] (ADR-016 Decision 3). `None` sends
/// every packet on the stream lane.
#[must_use]
pub fn compute_datagram_payload_budget(
    max_outer_datagram_size: Option<usize>,
    target: SocketAddr,
) -> Option<usize> {
    let outer = max_outer_datagram_size?;
    let overhead = uncompressed_datagram_header_overhead(target);
    outer
        .checked_sub(overhead)
        .filter(|&budget| budget >= MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET)
}

/// Select the forwarding lane for a single packet under `mode` (ADR-016).
///
/// Invariants:
/// - [`RelayForwardMode::Stream`] always selects [`RelayLane::Stream`].
/// - QUIC Initial packets always select [`RelayLane::Stream`].
/// - Without a budget of at least [`MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET`], every
///   packet selects [`RelayLane::Stream`].
/// - Otherwise, packets whose length is `<= P_max` select [`RelayLane::Datagram`].
#[must_use]
pub fn select_relay_lane(
    payload: &[u8],
    target: SocketAddr,
    max_outer_datagram_size: Option<usize>,
    mode: RelayForwardMode,
) -> RelayLane {
    if mode == RelayForwardMode::Stream || is_quic_initial_packet(payload) {
        return RelayLane::Stream;
    }
    match compute_datagram_payload_budget(max_outer_datagram_size, target) {
        Some(p_max) if payload.len() <= p_max => RelayLane::Datagram,
        _ => RelayLane::Stream,
    }
}

/// Why a [`DatagramLaneClaim`] could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramLaneError {
    /// The outer connection did not negotiate QUIC `DATAGRAM` frames.
    #[error("outer connection does not support QUIC datagrams")]
    Unsupported,
    /// Another hybrid relay session already reads this connection's datagrams.
    #[error("another hybrid relay session already reads this connection's datagrams")]
    ClaimedByRelaySession,
    /// A non-relay reader (for example `LinkConn::recv_datagrams`) already
    /// reads this connection's datagrams.
    #[error("another reader already consumes this connection's datagrams")]
    ClaimedByOtherReader,
}

#[derive(Debug, Default)]
struct DatagramReaders {
    hybrid_relay: bool,
    other_readers: usize,
}

/// Datagram readers per live connection, keyed by `Connection::stable_id`.
///
/// Every entry is owned by a guard that holds a clone of its connection, so
/// the key cannot be reused while the entry exists, and the guard's drop
/// removes the entry. The map therefore holds at most one entry per live
/// claimed connection.
static DATAGRAM_READERS: LazyLock<parking_lot::Mutex<HashMap<usize, DatagramReaders>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Exclusive right of one hybrid relay session to read (and send on) the
/// QUIC `DATAGRAM` lane of one outer connection.
///
/// Relay datagrams carry Context ID `0` and no session demultiplexer, so two
/// readers on one connection would take each other's packets. The claim makes
/// that impossible: while it exists, a second claim on the same connection and
/// any other datagram reader registered through this module are refused. It is
/// released on drop.
pub struct DatagramLaneClaim {
    connection: Connection,
    key: usize,
}

impl DatagramLaneClaim {
    /// Claim the datagram lane of `connection` for one hybrid relay session.
    pub fn try_claim(connection: &Connection) -> Result<Self, DatagramLaneError> {
        if connection.max_datagram_size().is_none() {
            return Err(DatagramLaneError::Unsupported);
        }
        let key = connection.stable_id();
        let mut readers = DATAGRAM_READERS.lock();
        let entry = readers.entry(key).or_default();
        if entry.hybrid_relay {
            return Err(DatagramLaneError::ClaimedByRelaySession);
        }
        if entry.other_readers > 0 {
            return Err(DatagramLaneError::ClaimedByOtherReader);
        }
        entry.hybrid_relay = true;
        Ok(Self {
            connection: connection.clone(),
            key,
        })
    }

    /// The outer connection whose datagram lane this claim holds.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl fmt::Debug for DatagramLaneClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramLaneClaim")
            .field("connection", &self.key)
            .finish()
    }
}

impl Drop for DatagramLaneClaim {
    fn drop(&mut self) {
        let mut readers = DATAGRAM_READERS.lock();
        if let Some(entry) = readers.get_mut(&self.key) {
            entry.hybrid_relay = false;
            if entry.other_readers == 0 {
                readers.remove(&self.key);
            }
        }
    }
}

/// Registration of a non-relay datagram reader (for example
/// `LinkConn::recv_datagrams`) on one connection. Released on drop.
pub(crate) struct OtherDatagramReaderGuard {
    _connection: Connection,
    key: usize,
}

impl Drop for OtherDatagramReaderGuard {
    fn drop(&mut self) {
        let mut readers = DATAGRAM_READERS.lock();
        if let Some(entry) = readers.get_mut(&self.key) {
            entry.other_readers = entry.other_readers.saturating_sub(1);
            if entry.other_readers == 0 && !entry.hybrid_relay {
                readers.remove(&self.key);
            }
        }
    }
}

/// Register a non-relay datagram reader on `connection`.
///
/// Returns `Err` when a hybrid relay session holds the connection's datagram
/// lane: the caller must not read datagrams then, or it would take relayed
/// packets (and the relay would take its datagrams).
pub(crate) fn register_other_datagram_reader(
    connection: &Connection,
) -> Result<OtherDatagramReaderGuard, DatagramLaneError> {
    let key = connection.stable_id();
    let mut readers = DATAGRAM_READERS.lock();
    let entry = readers.entry(key).or_default();
    if entry.hybrid_relay {
        return Err(DatagramLaneError::ClaimedByRelaySession);
    }
    entry.other_readers += 1;
    Ok(OtherDatagramReaderGuard {
        _connection: connection.clone(),
        key,
    })
}

/// Per-socket counters for relay lane usage and queue pressure.
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
    /// Outbound packets dropped because the bounded send queue was full.
    pub tx_dropped: AtomicU64,
    /// Inbound packets evicted because the bounded receive queue was full.
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
    raw_payload: Bytes,
    encoded: Bytes,
}

#[derive(Default)]
struct RecvState {
    queue: VecDeque<(Vec<u8>, SocketAddr)>,
    waker: Option<Waker>,
}

/// Bounded inbound packet ring with its waker under ONE lock.
///
/// The consumer stores its waker while it still holds the lock that showed
/// the queue empty, and a producer takes the waker under the same lock after
/// pushing. So no wake-up is lost, however many producers run (stream lane
/// and datagram lane).
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

    /// Push one packet, evicting the oldest when full. Returns `true` when a
    /// packet was evicted.
    fn push(&self, payload: Vec<u8>, source: SocketAddr) -> bool {
        let (evicted, waker) = match self.state.lock() {
            Ok(mut state) => {
                let evicted = if state.queue.len() >= self.capacity {
                    state.queue.pop_front().is_some()
                } else {
                    false
                };
                state.queue.push_back((payload, source));
                (evicted, state.waker.take())
            }
            Err(_) => (false, None),
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        evicted
    }

    /// Wake a pending receiver without queueing anything (lane closed).
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
            let Some((payload, source)) = state.queue.pop_front() else {
                break;
            };
            let len = payload.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&payload[..len]);

            let mut recv_meta = RecvMeta::default();
            recv_meta.len = len;
            recv_meta.stride = len;
            recv_meta.addr = source;
            recv_meta.ecn = None;
            recv_meta.dst_ip = None;
            meta[count] = recv_meta;
            count += 1;
        }
        if count > 0 {
            return Poll::Ready(Ok(count));
        }
        // Still under the lock that showed the queue empty: a producer that
        // pushes after this point finds the waker and wakes it.
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// A virtual UDP socket that tunnels packets through a MASQUE relay
/// via a persistent QUIC stream, optionally offloading regular packets
/// onto unreliable QUIC `DATAGRAM` frames (ADR-016).
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address)
    relay_public_addr: SocketAddr,
    /// Forwarding mode negotiated for this session
    forward_mode: RelayForwardMode,
    /// Bounded queue of received packets and the receiver's waker
    recv: RecvRing,
    /// Bounded channel for outbound packets (written to the relay by background task)
    send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
    /// Lane and queue statistics
    stats: Arc<MasqueRelaySocketStats>,
    /// Cancelled when the socket is dropped or the session's stream ends;
    /// stops the datagram-lane reader and releases its lane claim
    shutdown: CancellationToken,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field("forward_mode", &self.forward_mode)
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
    ///
    /// Spawns two background tasks:
    /// - Read from `recv_stream`, decode frames, queue for `poll_recv`
    /// - Read from bounded `send_tx` channel, write length-prefixed frames to `send_stream`
    pub fn new(
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::build(None, send_stream, recv_stream, relay_public_addr)
    }

    /// Create a hybrid relay socket (ADR-016) for a session whose CONNECT-UDP
    /// exchange negotiated the datagram lane in both directions.
    ///
    /// `lane` must be the claim the client took before it set the hybrid bit
    /// in its request, and the relay must have answered with the hybrid bit.
    /// - Outbound packets selected for [`RelayLane::Datagram`] are sent with
    ///   `send_datagram`, falling back to the stream lane when the outer
    ///   connection refuses them (too large, disabled, unsupported).
    /// - Inbound packets are read from both `recv_stream` and the claimed
    ///   connection's datagram lane.
    pub fn new_hybrid(
        lane: DatagramLaneClaim,
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::build(Some(lane), send_stream, recv_stream, relay_public_addr)
    }

    fn build(
        lane: Option<DatagramLaneClaim>,
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
        let shutdown = CancellationToken::new();

        let socket = Arc::new(Self {
            relay_public_addr,
            forward_mode,
            recv: RecvRing::new(DEFAULT_RELAY_RECV_QUEUE_CAPACITY),
            send_tx,
            stats: Arc::clone(&stats),
            shutdown: shutdown.clone(),
        });

        let writer_conn = lane.as_ref().map(|claim| claim.connection().clone());

        // Background task: read length-prefixed frames from relay stream → bounded queue.
        // The session ends with the stream; that also stops the datagram reader.
        let stream_reader_socket = Arc::clone(&socket);
        let stream_reader_stats = Arc::clone(&stats);
        let session_over = shutdown.clone();
        tokio::spawn(async move {
            loop {
                // Read 4-byte length prefix
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

                // Read frame data
                let mut frame_buf = vec![0u8; frame_len];
                if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (data)");
                    break;
                }

                // Decode as UncompressedDatagram
                let mut cursor = Bytes::from(frame_buf);
                match UncompressedDatagram::decode(&mut cursor) {
                    Ok(datagram) => {
                        stream_reader_stats
                            .stream_frames_received
                            .fetch_add(1, Ordering::Relaxed);
                        stream_reader_socket.enqueue_received(
                            datagram.payload.to_vec(),
                            datagram.target, // "target" in datagram = source from relay's perspective
                        );
                    }
                    Err(_) => {
                        tracing::trace!("MasqueRelaySocket: failed to decode stream frame");
                    }
                }
            }

            session_over.cancel();
            // Wake pending recv on stream close
            stream_reader_socket.recv.wake();
        });

        // Background task (hybrid): read QUIC DATAGRAM frames → bounded queue.
        // It owns the lane claim and holds only a weak socket reference, so it
        // ends (and releases the claim) when the session ends, the socket is
        // dropped, or the outer connection closes.
        if let Some(claim) = lane {
            let weak: Weak<Self> = Arc::downgrade(&socket);
            let dgram_stats = Arc::clone(&stats);
            let stop = shutdown.clone();
            tokio::spawn(async move {
                let conn = claim.connection().clone();
                loop {
                    let frame = tokio::select! {
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
                    };
                    let Some(socket) = weak.upgrade() else {
                        break;
                    };
                    let mut cursor = frame;
                    match UncompressedDatagram::decode(&mut cursor) {
                        Ok(datagram) => {
                            dgram_stats
                                .datagrams_received
                                .fetch_add(1, Ordering::Relaxed);
                            socket.enqueue_received(datagram.payload.to_vec(), datagram.target);
                        }
                        Err(_) => {
                            tracing::trace!("MasqueRelaySocket: failed to decode datagram frame");
                        }
                    }
                }
                if let Some(socket) = weak.upgrade() {
                    socket.recv.wake();
                }
                drop(claim);
            });
        }

        // Background task: write queued outbound packets via datagram lane (hybrid) or stream lane
        let writer_stats = Arc::clone(&stats);
        tokio::spawn(async move {
            loop {
                let Some(packet) = send_rx.recv().await else {
                    // Every sender is gone, i.e. the socket was dropped. Nothing is
                    // half-written, so finish gracefully: QUIC keeps retransmitting
                    // frames that are queued but not yet acknowledged, so packets
                    // already handed to the relay still arrive.
                    if let Err(e) = send_stream.finish() {
                        tracing::debug!(error = %e, "MasqueRelaySocket: stream finish error");
                    }
                    return;
                };

                if let Some(ref conn) = writer_conn {
                    let lane = select_relay_lane(
                        &packet.raw_payload,
                        packet.target,
                        conn.max_datagram_size(),
                        RelayForwardMode::Hybrid,
                    );
                    if lane == RelayLane::Datagram {
                        match conn.send_datagram(packet.encoded.clone()) {
                            Ok(()) => {
                                writer_stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            Err(
                                SendDatagramError::TooLarge
                                | SendDatagramError::UnsupportedByPeer
                                | SendDatagramError::Disabled,
                            ) => {
                                // Fall through to reliable stream lane for this packet.
                            }
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

                // A failed write may have left a partial frame on the wire. Return
                // without finishing so the drop resets the stream, and the relay's
                // length-prefixed reader sees a stream error rather than misparsing
                // a truncated frame.
                let frame_len = packet.encoded.len() as u32;
                if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (length)");
                    return;
                }
                if let Err(e) = send_stream.write_all(&packet.encoded).await {
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

    /// Return per-lane and queue-pressure statistics for this relay socket.
    #[must_use]
    pub fn stats(&self) -> &Arc<MasqueRelaySocketStats> {
        &self.stats
    }

    fn enqueue_received(&self, payload: Vec<u8>, source: SocketAddr) {
        if self.recv.push(payload, source) {
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
        let datagram = UncompressedDatagram::new(
            VarInt::from_u32(0),
            transmit.destination,
            raw_payload.clone(),
        );
        let encoded = datagram.encode();
        let packet = OutboundRelayPacket {
            target: transmit.destination,
            raw_payload,
            encoded,
        };

        match self.send_tx.try_send(packet) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // UDP tail-drop semantics under relay congestion: avoid
                // bufferbloat and let inner QUIC observe real packet loss.
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
        // QUIC v1 Initial: long header bit (0x80) | fixed bit (0x40) | type 00 (0x00)
        let v1_initial = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(is_quic_initial_packet(&v1_initial));

        // QUIC v2 Initial: version 0x6b3343cf, type 01 (0x10)
        let v2_initial = [0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00];
        assert!(is_quic_initial_packet(&v2_initial));

        // QUIC v1 Handshake: type 10 (0x20) -> not Initial
        let v1_handshake = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(!is_quic_initial_packet(&v1_handshake));

        // Short header 1-RTT packet: high bit 0
        let short_1rtt = [0x40, 0x11, 0x22, 0x33, 0x44];
        assert!(!is_quic_initial_packet(&short_1rtt));
    }

    /// ADR-016 Decision 3: `P_max` is never computed below 1200 B plus
    /// margin. An outer budget under the floor yields no datagram lane.
    #[test]
    fn datagram_budget_is_never_below_initial_size_plus_margin() {
        let v4 = v4_target();
        let v6 = v6_target();
        let v4_floor_outer = MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET + 8;
        let v6_floor_outer = MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET + 20;

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
        // A typical QUIC minimum-MTU outer budget (~1150 B) is below the floor.
        assert_eq!(compute_datagram_payload_budget(Some(1150), v4), None);
        assert_eq!(compute_datagram_payload_budget(None, v4), None);
        for outer in 0..4096 {
            if let Some(p_max) = compute_datagram_payload_budget(Some(outer), v6) {
                assert!(p_max >= QUIC_INITIAL_MIN_SIZE + RELAY_DATAGRAM_BUDGET_MARGIN);
            }
        }
    }

    #[test]
    fn lane_selection_respects_mode_budget_and_initial_invariant() {
        let target_v4 = v4_target();
        let target_v6 = v6_target();
        let outer = Some(1400);

        let short_pkt = vec![0x40u8; 600];

        // Stream mode ALWAYS selects Stream even when datagram budget fits.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, outer, RelayForwardMode::Stream),
            RelayLane::Stream
        );

        // Hybrid mode selects Datagram when payload <= P_max.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v6, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );

        // Exact P_max boundary: outer 1400 - 8 B (v4) = 1392 B fits; 1393 B spills to Stream.
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

        // IPv6 overhead is 20 B: outer 1400 - 20 = 1380 B.
        let p_max_v6 = compute_datagram_payload_budget(outer, target_v6).unwrap();
        assert_eq!(p_max_v6, 1380);

        // A full-size (1200 B) short-header packet rides the datagram lane
        // once the budget clears the floor.
        let full_short = vec![0x40u8; QUIC_INITIAL_MIN_SIZE];
        assert_eq!(
            select_relay_lane(&full_short, target_v4, outer, RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );

        // QUIC Initial packets ALWAYS take Stream even if small or outer budget is huge.
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

        // Budget below the floor, or no outer datagrams: every packet takes Stream.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Stream
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, None, RelayForwardMode::Hybrid),
            RelayLane::Stream
        );
    }

    /// Inbound ring: at most `capacity` packets; overflow evicts the oldest
    /// and reports each eviction (it feeds `rx_dropped`).
    #[test]
    fn recv_ring_is_bounded_and_evicts_oldest() {
        let ring = RecvRing::new(DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
        let src = v4_target();
        let total = DEFAULT_RELAY_RECV_QUEUE_CAPACITY + 44;
        let mut evicted = 0;
        for i in 0..total {
            if ring.push((i as u32).to_be_bytes().to_vec(), src) {
                evicted += 1;
            }
            assert!(ring.len() <= DEFAULT_RELAY_RECV_QUEUE_CAPACITY);
        }
        assert_eq!(evicted, 44);
        assert_eq!(ring.len(), DEFAULT_RELAY_RECV_QUEUE_CAPACITY);

        // The survivors are the newest packets, oldest first.
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
    }

    /// Outbound queue: a full channel tail-drops (counted in `tx_dropped`)
    /// and never grows past its capacity.
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

        // Closed channel: the sender reports the relay stream as gone.
        drop(send_rx);
        match sender
            .as_mut()
            .poll_send(&short_transmit(&payload), &mut cx)
        {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted),
            other => panic!("closed channel must error, got {other:?}"),
        }
    }

    /// `poll_recv` stores its waker under the lock that showed the queue
    /// empty, so a push from either of two producers always wakes it.
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
                        ring.push(vec![i], v4_target());
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
                        // Every Pending stored a waker; some producer must
                        // wake it. A lost wake-up would spin to the bound.
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
