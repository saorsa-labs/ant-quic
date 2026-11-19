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
//! - [`RelayForwardMode::Hybrid`]: post-handshake short-header packets fitting inside
//!   the negotiated QUIC `DATAGRAM` budget travel over unreliable QUIC `DATAGRAM` frames
//!   (avoiding head-of-line blocking and nested retransmission amplification), while
//!   QUIC Initial packets and packets exceeding `P_max` stay on the length-prefixed
//!   stream lane so 1200-byte Initials never truncate.
//!
//! Implements [`AsyncUdpSocket`] so it can be plugged into a Quinn endpoint
//! as a transparent replacement for a real UDP socket.

use bytes::Bytes;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use quinn_udp::{RecvMeta, Transmit};
use serde::{Deserialize, Serialize};

use crate::VarInt;
use crate::high_level::{AsyncUdpSocket, Connection, SendDatagramError, UdpSender};
use crate::masque::UncompressedDatagram;

/// Minimum QUIC Initial packet size per RFC 9000 §14.1.
///
/// Packets at or above this threshold always ride the length-prefixed stream
/// lane in [`RelayForwardMode::Hybrid`] so Initial packets survive regardless
/// of outer path MTU (ADR-016 §Decision 2).
pub const QUIC_INITIAL_MIN_SIZE: usize = 1200;

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
    /// short-header packets `<= P_max`, length-prefixed stream for Initials
    /// and oversized packets.
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
/// Returns `None` when outer datagrams are disabled/unsupported or the outer
/// budget cannot hold even a 1-byte inner payload after encapsulation overhead.
#[must_use]
pub fn compute_datagram_payload_budget(
    max_outer_datagram_size: Option<usize>,
    target: SocketAddr,
) -> Option<usize> {
    let outer = max_outer_datagram_size?;
    let overhead = uncompressed_datagram_header_overhead(target);
    outer.checked_sub(overhead).filter(|&budget| budget > 0)
}

/// Select the forwarding lane for a single packet under `mode` (ADR-016).
///
/// Invariants:
/// - [`RelayForwardMode::Stream`] always selects [`RelayLane::Stream`].
/// - QUIC Initial packets always select [`RelayLane::Stream`].
/// - Packets `>= QUIC_INITIAL_MIN_SIZE` (1200 B) always select [`RelayLane::Stream`]
///   so Initial-sized datagrams never risk outer truncation.
/// - Otherwise, packets whose payload length fits within
///   [`compute_datagram_payload_budget`] select [`RelayLane::Datagram`].
#[must_use]
pub fn select_relay_lane(
    payload: &[u8],
    target: SocketAddr,
    max_outer_datagram_size: Option<usize>,
    mode: RelayForwardMode,
) -> RelayLane {
    if mode == RelayForwardMode::Stream {
        return RelayLane::Stream;
    }
    if payload.len() >= QUIC_INITIAL_MIN_SIZE || is_quic_initial_packet(payload) {
        return RelayLane::Stream;
    }
    match compute_datagram_payload_budget(max_outer_datagram_size, target) {
        Some(p_max) if payload.len() <= p_max => RelayLane::Datagram,
        _ => RelayLane::Stream,
    }
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

/// A virtual UDP socket that tunnels packets through a MASQUE relay
/// via a persistent QUIC stream, optionally offloading regular packets
/// onto unreliable QUIC `DATAGRAM` frames (ADR-016).
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address)
    relay_public_addr: SocketAddr,
    /// Forwarding mode active on this socket
    forward_mode: RelayForwardMode,
    /// Bounded queue of received packets (payload, source_addr)
    recv_queue: std::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Waker to notify when new packets arrive
    recv_waker: std::sync::Mutex<Option<Waker>>,
    /// Bounded channel for outbound packets (written to the relay by background task)
    send_tx: tokio::sync::mpsc::Sender<OutboundRelayPacket>,
    /// Lane and queue statistics
    stats: Arc<MasqueRelaySocketStats>,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field("forward_mode", &self.forward_mode)
            .field(
                "recv_queue_len",
                &self.recv_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .field("stats", &self.stats)
            .finish()
    }
}

impl MasqueRelaySocket {
    /// Create a new stream-based relay socket (ADR-009 / default mode).
    ///
    /// Spawns two background tasks:
    /// - Read from `recv_stream`, decode frames, queue for `poll_recv`
    /// - Read from bounded `send_tx` channel, write length-prefixed frames to `send_stream`
    pub fn new(
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::new_with_mode(
            None,
            send_stream,
            recv_stream,
            relay_public_addr,
            RelayForwardMode::Stream,
        )
    }

    /// Create a relay socket configured with [`RelayForwardMode`] (ADR-016).
    ///
    /// When `mode` is [`RelayForwardMode::Hybrid`] and `connection` is provided:
    /// - Outbound packets selected for [`RelayLane::Datagram`] are transmitted
    ///   via `connection.send_datagram(...)`, falling back transparently to the
    ///   stream lane if outer datagrams are unavailable or the packet exceeds
    ///   the live path MTU.
    /// - Inbound packets are accepted concurrently from both `recv_stream` and
    ///   `connection.read_datagram()`, keeping backward compatibility with
    ///   stream-only peers.
    pub fn new_with_mode(
        connection: Option<Connection>,
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
        forward_mode: RelayForwardMode,
    ) -> Arc<Self> {
        let (send_tx, mut send_rx) =
            tokio::sync::mpsc::channel::<OutboundRelayPacket>(DEFAULT_RELAY_SEND_QUEUE_CAPACITY);
        let stats = Arc::new(MasqueRelaySocketStats::default());

        let socket = Arc::new(Self {
            relay_public_addr,
            forward_mode,
            recv_queue: std::sync::Mutex::new(VecDeque::with_capacity(
                DEFAULT_RELAY_RECV_QUEUE_CAPACITY.min(64),
            )),
            recv_waker: std::sync::Mutex::new(None),
            send_tx,
            stats: Arc::clone(&stats),
        });

        let stream_reader_socket = Arc::clone(&socket);
        let stream_reader_stats = Arc::clone(&stats);
        let datagram_conn = if forward_mode == RelayForwardMode::Hybrid {
            connection.clone()
        } else {
            None
        };

        // Background task: read length-prefixed frames from relay stream → bounded queue
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

            // Wake pending recv on stream close
            stream_reader_socket.wake_receiver();
        });

        // Background task (Hybrid mode): read unreliable QUIC DATAGRAM frames → bounded queue
        if let Some(dgram_conn) = datagram_conn {
            let dgram_reader_socket = Arc::clone(&socket);
            let dgram_reader_stats = Arc::clone(&stats);
            tokio::spawn(async move {
                loop {
                    match dgram_conn.read_datagram().await {
                        Ok(frame) => {
                            let mut cursor = frame;
                            match UncompressedDatagram::decode(&mut cursor) {
                                Ok(datagram) => {
                                    dgram_reader_stats
                                        .datagrams_received
                                        .fetch_add(1, Ordering::Relaxed);
                                    dgram_reader_socket.enqueue_received(
                                        datagram.payload.to_vec(),
                                        datagram.target,
                                    );
                                }
                                Err(_) => {
                                    tracing::trace!(
                                        "MasqueRelaySocket: failed to decode datagram frame"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                error = %e,
                                "MasqueRelaySocket: outer datagram read ended"
                            );
                            break;
                        }
                    }
                }
                dgram_reader_socket.wake_receiver();
            });
        }

        // Background task: write queued outbound packets via datagram lane (Hybrid) or stream lane
        let writer_stats = Arc::clone(&stats);
        let writer_conn = if forward_mode == RelayForwardMode::Hybrid {
            connection
        } else {
            None
        };
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
                        forward_mode,
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

    /// Return the configured forwarding mode for this relay socket.
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
        if let Ok(mut queue) = self.recv_queue.lock() {
            if queue.len() >= DEFAULT_RELAY_RECV_QUEUE_CAPACITY {
                let _ = queue.pop_front();
                self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back((payload, source));
        }
        self.wake_receiver();
    }

    fn wake_receiver(&self) {
        if let Ok(mut waker) = self.recv_waker.lock() {
            if let Some(w) = waker.take() {
                w.wake();
            }
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

        if let Ok(mut queue) = self.recv_queue.lock() {
            let max_batch = bufs.len().min(meta.len());
            let mut count = 0;
            while count < max_batch {
                let Some((payload, source)) = queue.pop_front() else {
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
        }

        // Register waker for when data arrives
        if let Ok(mut waker) = self.recv_waker.lock() {
            *waker = Some(cx.waker().clone());
        }

        Poll::Pending
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

    fn v4_target() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 9000)
    }

    fn v6_target() -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9000,
        )
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

    #[test]
    fn lane_selection_respects_mode_budget_and_initial_invariant() {
        let target_v4 = v4_target();
        let target_v6 = v6_target();

        // Short-header regular packet (600 B)
        let mut short_pkt = vec![0x40u8; 600];
        short_pkt[0] = 0x40;

        // Stream mode ALWAYS selects Stream even when datagram budget fits.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, Some(1150), RelayForwardMode::Stream),
            RelayLane::Stream
        );

        // Hybrid mode selects Datagram when payload <= P_max.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&short_pkt, target_v6, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );

        // Exact P_max boundary: outer 1150 - 8 B (v4) = 1142 B fits; 1143 B spills to Stream.
        let p_max_v4 = compute_datagram_payload_budget(Some(1150), target_v4).unwrap();
        assert_eq!(p_max_v4, 1142);
        let at_limit = vec![0x40u8; p_max_v4];
        let over_limit = vec![0x40u8; p_max_v4 + 1];
        assert_eq!(
            select_relay_lane(&at_limit, target_v4, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Datagram
        );
        assert_eq!(
            select_relay_lane(&over_limit, target_v4, Some(1150), RelayForwardMode::Hybrid),
            RelayLane::Stream
        );

        // IPv6 overhead is 20 B: outer 1150 - 20 = 1130 B.
        let p_max_v6 = compute_datagram_payload_budget(Some(1150), target_v6).unwrap();
        assert_eq!(p_max_v6, 1130);

        // QUIC Initial packets ALWAYS take Stream even if small or outer budget is huge.
        let mut small_initial = vec![0x00u8; 200];
        small_initial[0] = 0xc0;
        small_initial[4] = 0x01;
        assert_eq!(
            select_relay_lane(
                &small_initial,
                target_v4,
                Some(2000),
                RelayForwardMode::Hybrid
            ),
            RelayLane::Stream
        );

        // Any packet >= 1200 B ALWAYS takes Stream regardless of outer datagram budget.
        let large_short = vec![0x40u8; QUIC_INITIAL_MIN_SIZE];
        assert_eq!(
            select_relay_lane(
                &large_short,
                target_v4,
                Some(2000),
                RelayForwardMode::Hybrid
            ),
            RelayLane::Stream
        );

        // Disabled/unsupported outer datagrams (None) always fall back to Stream.
        assert_eq!(
            select_relay_lane(&short_pkt, target_v4, None, RelayForwardMode::Hybrid),
            RelayLane::Stream
        );
    }
}
