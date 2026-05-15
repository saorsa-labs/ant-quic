// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection statistics

use crate::{Dir, Duration, frame::Frame};

/// Statistics about UDP datagrams transmitted or received on a connection
#[derive(Default, Debug, Copy, Clone)]
#[non_exhaustive]
pub struct UdpStats {
    /// The amount of UDP datagrams observed
    pub datagrams: u64,
    /// The total amount of bytes which have been transferred inside UDP datagrams
    pub bytes: u64,
    /// The amount of I/O operations executed
    ///
    /// Can be less than `datagrams` when GSO, GRO, and/or batched system calls are in use.
    pub ios: u64,
}

impl UdpStats {
    pub(crate) fn on_sent(&mut self, datagrams: u64, bytes: usize) {
        self.datagrams += datagrams;
        self.bytes += bytes as u64;
        self.ios += 1;
    }
}

/// Number of frames transmitted of each frame type
#[derive(Default, Copy, Clone)]
#[non_exhaustive]
#[allow(missing_docs)]
pub struct FrameStats {
    pub acks: u64,
    pub ack_frequency: u64,
    pub crypto: u64,
    pub connection_close: u64,
    pub data_blocked: u64,
    pub datagram: u64,
    pub handshake_done: u8,
    pub immediate_ack: u64,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub new_connection_id: u64,
    pub new_token: u64,
    pub path_challenge: u64,
    pub path_response: u64,
    pub ping: u64,
    pub reset_stream: u64,
    pub retire_connection_id: u64,
    pub stream_data_blocked: u64,
    pub streams_blocked_bidi: u64,
    pub streams_blocked_uni: u64,
    pub stop_sending: u64,
    pub stream: u64,
    pub add_address: u64,
    pub punch_me_now: u64,
    pub remove_address: u64,
    pub observed_address: u64,
    pub try_connect_to: u64,
    pub try_connect_to_response: u64,
}

impl FrameStats {
    pub(crate) fn record(&mut self, frame: &Frame) {
        match frame {
            Frame::Padding => {}
            Frame::Ping => self.ping += 1,
            Frame::Ack(_) => self.acks += 1,
            Frame::ResetStream(_) => self.reset_stream += 1,
            Frame::StopSending(_) => self.stop_sending += 1,
            Frame::Crypto(_) => self.crypto += 1,
            Frame::Datagram(_) => self.datagram += 1,
            Frame::NewToken(_) => self.new_token += 1,
            Frame::MaxData(_) => self.max_data += 1,
            Frame::MaxStreamData { .. } => self.max_stream_data += 1,
            Frame::MaxStreams { dir, .. } => {
                if *dir == Dir::Bi {
                    self.max_streams_bidi += 1;
                } else {
                    self.max_streams_uni += 1;
                }
            }
            Frame::DataBlocked { .. } => self.data_blocked += 1,
            Frame::Stream(_) => self.stream += 1,
            Frame::StreamDataBlocked { .. } => self.stream_data_blocked += 1,
            Frame::StreamsBlocked { dir, .. } => {
                if *dir == Dir::Bi {
                    self.streams_blocked_bidi += 1;
                } else {
                    self.streams_blocked_uni += 1;
                }
            }
            Frame::NewConnectionId(_) => self.new_connection_id += 1,
            Frame::RetireConnectionId { .. } => self.retire_connection_id += 1,
            Frame::PathChallenge(_) => self.path_challenge += 1,
            Frame::PathResponse(_) => self.path_response += 1,
            Frame::Close(_) => self.connection_close += 1,
            Frame::AckFrequency(_) => self.ack_frequency += 1,
            Frame::ImmediateAck => self.immediate_ack += 1,
            Frame::HandshakeDone => self.handshake_done = self.handshake_done.saturating_add(1),
            Frame::AddAddress(_) => self.add_address += 1,
            Frame::PunchMeNow(_) => self.punch_me_now += 1,
            Frame::RemoveAddress(_) => self.remove_address += 1,
            Frame::ObservedAddress(_) => self.observed_address += 1,
            Frame::TryConnectTo(_) => self.try_connect_to += 1,
            Frame::TryConnectToResponse(_) => self.try_connect_to_response += 1,
        }
    }
}

impl std::fmt::Debug for FrameStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameStats")
            .field("ACK", &self.acks)
            .field("ACK_FREQUENCY", &self.ack_frequency)
            .field("CONNECTION_CLOSE", &self.connection_close)
            .field("CRYPTO", &self.crypto)
            .field("DATA_BLOCKED", &self.data_blocked)
            .field("DATAGRAM", &self.datagram)
            .field("HANDSHAKE_DONE", &self.handshake_done)
            .field("IMMEDIATE_ACK", &self.immediate_ack)
            .field("MAX_DATA", &self.max_data)
            .field("MAX_STREAM_DATA", &self.max_stream_data)
            .field("MAX_STREAMS_BIDI", &self.max_streams_bidi)
            .field("MAX_STREAMS_UNI", &self.max_streams_uni)
            .field("NEW_CONNECTION_ID", &self.new_connection_id)
            .field("NEW_TOKEN", &self.new_token)
            .field("PATH_CHALLENGE", &self.path_challenge)
            .field("PATH_RESPONSE", &self.path_response)
            .field("PING", &self.ping)
            .field("RESET_STREAM", &self.reset_stream)
            .field("RETIRE_CONNECTION_ID", &self.retire_connection_id)
            .field("STREAM_DATA_BLOCKED", &self.stream_data_blocked)
            .field("STREAMS_BLOCKED_BIDI", &self.streams_blocked_bidi)
            .field("STREAMS_BLOCKED_UNI", &self.streams_blocked_uni)
            .field("STOP_SENDING", &self.stop_sending)
            .field("STREAM", &self.stream)
            .field("ADD_ADDRESS", &self.add_address)
            .field("PUNCH_ME_NOW", &self.punch_me_now)
            .field("REMOVE_ADDRESS", &self.remove_address)
            .field("OBSERVED_ADDRESS", &self.observed_address)
            .finish()
    }
}

/// Statistics related to a transmission path
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct PathStats {
    /// Current best estimate of this connection's latency (round-trip-time)
    pub rtt: Duration,
    /// Current congestion window of the connection
    pub cwnd: u64,
    /// Congestion events on the connection
    pub congestion_events: u64,
    /// The amount of packets lost on this path
    pub lost_packets: u64,
    /// The amount of bytes lost on this path
    pub lost_bytes: u64,
    /// The amount of packets sent on this path
    pub sent_packets: u64,
    /// The amount of PLPMTUD probe packets sent on this path (also counted by `sent_packets`)
    pub sent_plpmtud_probes: u64,
    /// The amount of PLPMTUD probe packets lost on this path (ignored by `lost_packets` and
    /// `lost_bytes`)
    pub lost_plpmtud_probes: u64,
    /// The number of times a black hole was detected in the path
    pub black_holes_detected: u64,
    /// Largest UDP payload size the path currently supports
    pub current_mtu: u16,
}

/// Connection statistics
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// Statistics about UDP datagrams transmitted on a connection
    pub udp_tx: UdpStats,
    /// Statistics about UDP datagrams received on a connection
    pub udp_rx: UdpStats,
    /// Statistics about frames transmitted on a connection
    pub frame_tx: FrameStats,
    /// Statistics about frames received on a connection
    pub frame_rx: FrameStats,
    /// Statistics related to the current transmission path
    pub path: PathStats,
    /// Statistics about application datagrams dropped due to receive buffer overflow
    pub datagram_drops: DatagramDropStats,
}

/// Aggregated statistics about dropped application datagrams
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct DatagramDropStats {
    /// Number of datagrams dropped
    pub datagrams: u64,
    /// Total bytes dropped
    pub bytes: u64,
}

impl DatagramDropStats {
    pub(crate) fn record(&mut self, datagrams: u64, bytes: u64) {
        self.datagrams = self.datagrams.saturating_add(datagrams);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    // UdpStats tests

    #[test]
    fn udp_stats_default() {
        let s = UdpStats::default();
        assert_eq!(s.datagrams, 0);
        assert_eq!(s.bytes, 0);
        assert_eq!(s.ios, 0);
    }

    #[test]
    fn udp_stats_on_sent_increments() {
        let mut s = UdpStats::default();
        s.on_sent(5, 1200);
        assert_eq!(s.datagrams, 5);
        assert_eq!(s.bytes, 1200);
        assert_eq!(s.ios, 1);
    }

    #[test]
    fn udp_stats_on_sent_accumulates() {
        let mut s = UdpStats::default();
        s.on_sent(1, 100);
        s.on_sent(2, 200);
        assert_eq!(s.datagrams, 3);
        assert_eq!(s.bytes, 300);
        assert_eq!(s.ios, 2);
    }

    #[test]
    fn udp_stats_clone_copy() {
        let mut a = UdpStats::default();
        a.on_sent(10, 500);
        let b = a;
        assert_eq!(b.datagrams, 10);
    }

    // FrameStats tests

    #[test]
    fn frame_stats_default() {
        let s = FrameStats::default();
        assert_eq!(s.ping, 0);
        assert_eq!(s.acks, 0);
        assert_eq!(s.crypto, 0);
    }

    #[test]
    fn frame_stats_padding_record() {
        let mut s = FrameStats::default();
        s.record(&Frame::Padding);
        assert_eq!(s.ping, 0); // Padding doesn't increment anything
    }

    #[test]
    fn frame_stats_ping_record() {
        let mut s = FrameStats::default();
        s.record(&Frame::Ping);
        assert_eq!(s.ping, 1);
    }

    #[test]
    fn frame_stats_immediate_ack_record() {
        let mut s = FrameStats::default();
        s.record(&Frame::ImmediateAck);
        assert_eq!(s.immediate_ack, 1);
    }

    #[test]
    fn frame_stats_handshake_done_record() {
        let mut s = FrameStats::default();
        s.record(&Frame::HandshakeDone);
        assert_eq!(s.handshake_done, 1);
        s.record(&Frame::HandshakeDone);
        assert_eq!(s.handshake_done, 2); // uses saturating_add
    }

    #[test]
    fn frame_stats_increments_separate_counters() {
        let mut s = FrameStats::default();
        s.record(&Frame::Ping);
        s.record(&Frame::ImmediateAck);
        s.record(&Frame::HandshakeDone);
        assert_eq!(s.ping, 1);
        assert_eq!(s.immediate_ack, 1);
        assert_eq!(s.handshake_done, 1);
    }

    #[test]
    fn frame_stats_debug_format() {
        let s = FrameStats::default();
        let debug = format!("{s:?}");
        assert!(debug.contains("PING"));
        assert!(debug.contains("ACK"));
    }

    // DatagramDropStats tests

    #[test]
    fn datagram_drop_default_zero() {
        let d = DatagramDropStats::default();
        assert_eq!(d.datagrams, 0);
        assert_eq!(d.bytes, 0);
    }

    #[test]
    fn datagram_drop_record() {
        let mut d = DatagramDropStats::default();
        d.record(5, 1000);
        assert_eq!(d.datagrams, 5);
        assert_eq!(d.bytes, 1000);
    }

    #[test]
    fn datagram_drop_accumulates() {
        let mut d = DatagramDropStats::default();
        d.record(3, 300);
        d.record(2, 200);
        assert_eq!(d.datagrams, 5);
        assert_eq!(d.bytes, 500);
    }

    #[test]
    fn datagram_drop_saturating_add() {
        let mut d = DatagramDropStats::default();
        d.datagrams = u64::MAX;
        d.record(1, 0);
        // Should not overflow
        assert_eq!(d.datagrams, u64::MAX);
    }

    #[test]
    fn datagram_drop_equality() {
        let mut a = DatagramDropStats::default();
        a.record(10, 100);
        let b = a;
        assert_eq!(a, b);
    }

    // PathStats tests

    #[test]
    fn path_stats_default() {
        let p = PathStats::default();
        assert_eq!(p.rtt, Duration::default());
        assert_eq!(p.cwnd, 0);
        assert_eq!(p.lost_packets, 0);
        assert_eq!(p.current_mtu, 0);
    }

    #[test]
    fn path_stats_clone_copy() {
        let a = PathStats::default();
        let b = a;
        assert_eq!(a.rtt, b.rtt);
    }

    // ConnectionStats tests

    #[test]
    fn connection_stats_default() {
        let c = ConnectionStats::default();
        assert_eq!(c.udp_tx.datagrams, 0);
        assert_eq!(c.udp_rx.datagrams, 0);
        assert_eq!(c.frame_tx.ping, 0);
        assert_eq!(c.frame_rx.ping, 0);
        assert_eq!(c.path.cwnd, 0);
        assert_eq!(c.datagram_drops.datagrams, 0);
    }

    #[test]
    fn connection_stats_clone_copy() {
        let a = ConnectionStats::default();
        let b = a;
        assert_eq!(a.udp_tx.ios, b.udp_tx.ios);
    }
}
