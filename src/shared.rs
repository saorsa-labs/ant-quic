// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut, BytesMut};

use crate::{Instant, MAX_CID_SIZE, ResetToken, coding::BufExt, packet::PartialDecode};

/// Events sent from an Endpoint to a Connection
#[derive(Debug)]
pub struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram(DatagramConnectionEvent),
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>, Instant),
    /// Queue an ADD_ADDRESS frame for transmission
    QueueAddAddress(crate::frame::AddAddress),
    /// Queue a PUNCH_ME_NOW frame for transmission
    QueuePunchMeNow(crate::frame::PunchMeNow),
}

/// Variant of [`ConnectionEventInner`].
#[derive(Debug)]
pub(crate) struct DatagramConnectionEvent {
    pub(crate) now: Instant,
    pub(crate) remote: SocketAddr,
    pub(crate) ecn: Option<EcnCodepoint>,
    pub(crate) first_decode: PartialDecode,
    pub(crate) remaining: Option<BytesMut>,
}

/// Events sent from a Connection to an Endpoint
#[derive(Debug)]
pub struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]

pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// The reset token and/or address eligible for generating resets has been updated
    ResetToken(SocketAddr, ResetToken),
    /// The connection needs connection identifiers
    NeedIdentifiers(Instant, u64),
    /// Stop routing connection ID for this sequence number to the connection
    /// When `bool == true`, a new connection ID will be issued to peer
    RetireConnectionId(Instant, u64, bool),
    /// Request to send an AddAddress frame to the peer
    #[allow(dead_code)]
    SendAddressFrame(crate::frame::AddAddress),
    /// Request to relay a PUNCH_ME_NOW frame to a target peer
    #[allow(dead_code)]
    RelayPunchMeNow([u8; 32], crate::frame::PunchMeNow),
    /// NAT traversal candidate validation succeeded
    #[allow(dead_code)]
    NatCandidateValidated { address: SocketAddr, challenge: u64 },
    /// A peer advertised a new reachable address via ADD_ADDRESS.
    /// The endpoint should propagate this so the DHT routing table is updated.
    PeerAddressAdvertised {
        /// The peer's current connection address
        peer_addr: SocketAddr,
        /// The new address the peer is advertising
        advertised_addr: SocketAddr,
    },
    /// Request to attempt connection to a target address (NAT callback mechanism)
    TryConnectTo {
        request_id: crate::VarInt,
        target_address: SocketAddr,
        timeout_ms: u16,
        requester_connection: SocketAddr,
        requested_at: crate::Instant,
    },
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    /// Construct cid from byte array
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Constructs cid by reading `len` bytes from a `Buf`
    ///
    /// Callers need to assure that `buf.remaining() >= len`
    pub fn from_buf(buf: &mut (impl Buf + ?Sized), len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        match len > MAX_CID_SIZE || buf.remaining() < len {
            false => Some(Self::from_buf(buf, len)),
            true => None,
        }
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }

    /// Returns whether the codepoint is a CE, signalling that congestion was experienced
    pub fn is_ce(self) -> bool {
        matches!(self, Self::Ce)
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct IssuedCid {
    pub(crate) sequence: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}

/// Normalize a socket address by converting IPv4-mapped IPv6 addresses to pure IPv4.
///
/// This is critical for address comparison when connections may use either format.
/// For example, `[::ffff:192.168.1.1]:9000` normalizes to `192.168.1.1:9000`.
///
/// This normalization is essential for nodes bound to IPv4-only sockets (0.0.0.0:port)
/// that receive addresses in IPv4-mapped IPv6 format (::ffff:a.b.c.d). Without
/// normalization, attempting to connect to an IPv4-mapped address from an IPv4-only
/// socket fails with "Address family not supported by protocol" (EAFNOSUPPORT).
pub fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6_addr) => {
            // Check if this is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
            if let Some(ipv4) = v6_addr.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(ipv4), v6_addr.port())
            } else {
                addr
            }
        }
        SocketAddr::V4(_) => addr,
    }
}

/// Return the dual-stack alternate of a socket address.
///
/// For an IPv4 address, returns its IPv4-mapped IPv6 form (::ffff:a.b.c.d).
/// For an IPv4-mapped IPv6 address, returns the plain IPv4 form.
/// For a native IPv6 address, returns it unchanged.
pub fn dual_stack_alternate(addr: &SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                *addr
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ── ConnectionId tests ──

    #[test]
    fn connection_id_new_empty() {
        let cid = ConnectionId::new(&[]);
        assert!(cid.is_empty());
        assert_eq!(cid.len(), 0);
        assert_eq!(cid.as_ref(), &[] as &[u8]);
    }

    #[test]
    fn connection_id_new_short() {
        let cid = ConnectionId::new(&[0xAB, 0xCD]);
        assert_eq!(cid.len(), 2);
        assert_eq!(cid.as_ref(), &[0xAB, 0xCD]);
    }

    #[test]
    fn connection_id_new_max_size() {
        let bytes: Vec<u8> = (0..MAX_CID_SIZE as u8).collect();
        let cid = ConnectionId::new(&bytes);
        assert_eq!(cid.len(), MAX_CID_SIZE);
        assert_eq!(cid.as_ref(), bytes.as_slice());
    }

    #[test]
    fn connection_id_display_hex() {
        let cid = ConnectionId::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(format!("{cid}"), "deadbeef");
    }

    #[test]
    fn connection_id_display_empty() {
        let cid = ConnectionId::new(&[]);
        assert_eq!(format!("{cid}"), "");
    }

    #[test]
    fn connection_id_debug_uses_slice_fmt() {
        let cid = ConnectionId::new(&[0x01, 0x02]);
        let debug = format!("{cid:?}");
        // Debug formats the underlying slice which looks like [1, 2]
        assert!(debug.contains("1") || debug.contains("01"));
    }

    #[test]
    fn connection_id_clone() {
        let cid = ConnectionId::new(&[1, 2, 3]);
        let cloned = cid;
        assert_eq!(cid, cloned);
    }

    #[test]
    fn connection_id_equality() {
        let a = ConnectionId::new(&[1, 2, 3]);
        let b = ConnectionId::new(&[1, 2, 3]);
        let c = ConnectionId::new(&[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn connection_id_ordering() {
        let a = ConnectionId::new(&[1]);
        let b = ConnectionId::new(&[2]);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn connection_id_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = ConnectionId::new(&[1, 2, 3]);
        let b = ConnectionId::new(&[1, 2, 3]);
        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn connection_id_deref() {
        let cid = ConnectionId::new(&[0xAA, 0xBB]);
        let slice: &[u8] = &cid;
        assert_eq!(slice, &[0xAA, 0xBB]);
    }

    #[test]
    fn connection_id_deref_mut() {
        let mut cid = ConnectionId::new(&[0xAA, 0xBB]);
        cid[1] = 0xCC;
        assert_eq!(cid.as_ref(), &[0xAA, 0xCC]);
    }

    #[test]
    fn connection_id_from_buf() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0x11, 0x22, 0x33]);
        let mut read = buf.freeze();
        let cid = ConnectionId::from_buf(&mut read, 2);
        assert_eq!(cid.len(), 2);
        assert_eq!(cid.as_ref(), &[0x11, 0x22]);
    }

    #[test]
    fn connection_id_encode_long() {
        let cid = ConnectionId::new(&[0xAA, 0xBB, 0xCC]);
        let mut buf = BytesMut::new();
        cid.encode_long(&mut buf);
        let mut read = buf.freeze();
        assert_eq!(read.get_u8(), 3); // length byte
        assert_eq!(read.get_u8(), 0xAA);
        assert_eq!(read.get_u8(), 0xBB);
        assert_eq!(read.get_u8(), 0xCC);
    }

    #[test]
    fn connection_id_decode_long_roundtrip() {
        let original = ConnectionId::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut buf = BytesMut::new();
        original.encode_long(&mut buf);
        let mut read = buf.freeze();
        let decoded = ConnectionId::decode_long(&mut read).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn connection_id_decode_long_empty() {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // length 0, no bytes follow
        let mut read = buf.freeze();
        let decoded = ConnectionId::decode_long(&mut read).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn connection_id_decode_long_truncated_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_u8(5); // claims 5 bytes, but only has 0 bytes
        // Don't add any CID bytes
        let mut read = buf.freeze();
        assert!(ConnectionId::decode_long(&mut read).is_none());
    }

    #[test]
    fn connection_id_decode_long_oversized_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_u8(MAX_CID_SIZE as u8 + 1); // claims more than MAX
        let mut read = buf.freeze();
        assert!(ConnectionId::decode_long(&mut read).is_none());
    }

    // ── EcnCodepoint tests ──

    #[test]
    fn ecn_ect0_from_bits() {
        let ecn = EcnCodepoint::from_bits(0b10).unwrap();
        assert_eq!(ecn, EcnCodepoint::Ect0);
        assert!(!ecn.is_ce());
    }

    #[test]
    fn ecn_ect1_from_bits() {
        let ecn = EcnCodepoint::from_bits(0b01).unwrap();
        assert_eq!(ecn, EcnCodepoint::Ect1);
        assert!(!ecn.is_ce());
    }

    #[test]
    fn ecn_ce_from_bits() {
        let ecn = EcnCodepoint::from_bits(0b11).unwrap();
        assert_eq!(ecn, EcnCodepoint::Ce);
        assert!(ecn.is_ce());
    }

    #[test]
    fn ecn_from_bits_not_ect() {
        assert!(EcnCodepoint::from_bits(0b00).is_none());
    }

    #[test]
    fn ecn_from_bits_masked() {
        // Only bottom 2 bits matter
        let ecn = EcnCodepoint::from_bits(0b1110).unwrap();
        assert_eq!(ecn, EcnCodepoint::Ect0);
    }

    #[test]
    fn ecn_equality() {
        assert_eq!(EcnCodepoint::Ect0, EcnCodepoint::Ect0);
        assert_ne!(EcnCodepoint::Ect0, EcnCodepoint::Ce);
    }

    #[test]
    fn ecn_clone_copy() {
        let ecn = EcnCodepoint::Ce;
        let copied = ecn;
        assert_eq!(ecn, copied);
    }

    #[test]
    fn ecn_repr_values() {
        assert_eq!(EcnCodepoint::Ect0 as u8, 0b10);
        assert_eq!(EcnCodepoint::Ect1 as u8, 0b01);
        assert_eq!(EcnCodepoint::Ce as u8, 0b11);
    }

    // ── EndpointEvent tests ──

    #[test]
    fn endpoint_event_drained() {
        let event = EndpointEvent::drained();
        assert!(event.is_drained());
    }

    #[test]
    fn endpoint_event_debug() {
        let event = EndpointEvent::drained();
        let debug = format!("{event:?}");
        assert!(!debug.is_empty());
    }

    // ── normalize_socket_addr tests ──

    #[test]
    fn normalize_ipv4_stays_ipv4() {
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let normalized = normalize_socket_addr(addr);
        assert!(normalized.is_ipv4());
        assert_eq!(normalized, addr);
    }

    #[test]
    fn normalize_ipv4_mapped_to_ipv4() {
        // ::ffff:192.168.1.1:9000 should normalize to 192.168.1.1:9000
        let addr: SocketAddr = "[::ffff:192.168.1.1]:9000".parse().unwrap();
        assert!(addr.is_ipv6());
        let normalized = normalize_socket_addr(addr);
        assert!(normalized.is_ipv4());
        assert_eq!(normalized.port(), 9000);
        assert_eq!(normalized.ip().to_string(), "192.168.1.1");
    }

    #[test]
    fn normalize_native_ipv6_unchanged() {
        let addr: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();
        let normalized = normalize_socket_addr(addr);
        assert!(normalized.is_ipv6());
        assert_eq!(normalized, addr);
    }

    #[test]
    fn normalize_loopback_ipv6_unchanged() {
        let addr: SocketAddr = "[::1]:9000".parse().unwrap();
        let normalized = normalize_socket_addr(addr);
        assert!(normalized.is_ipv6());
        assert_eq!(normalized, addr);
    }

    // ── dual_stack_alternate tests ──

    #[test]
    fn dual_stack_ipv4_becomes_ipv6_mapped() {
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let alternate = dual_stack_alternate(&addr);
        assert!(alternate.is_ipv6());
        assert_eq!(alternate.port(), 9000);
        // Should be ::ffff:192.168.1.1
        assert!(alternate.ip().to_string().contains("ffff"));
    }

    #[test]
    fn dual_stack_ipv6_mapped_becomes_ipv4() {
        let addr: SocketAddr = "[::ffff:10.0.0.1]:443".parse().unwrap();
        let alternate = dual_stack_alternate(&addr);
        assert!(alternate.is_ipv4());
        assert_eq!(alternate.port(), 443);
        assert_eq!(alternate.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn dual_stack_native_ipv6_unchanged() {
        let addr: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();
        let alternate = dual_stack_alternate(&addr);
        assert!(alternate.is_ipv6());
        assert_eq!(alternate, addr);
    }

    #[test]
    fn dual_stack_roundtrip() {
        let original: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let v6 = dual_stack_alternate(&original);
        let v4 = dual_stack_alternate(&v6);
        assert_eq!(v4, original);
    }

    #[test]
    fn normalize_and_dual_stack_roundtrip() {
        let original: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        // IPv4 -> IPv6-mapped -> normalized (IPv4) -> should equal original
        let v6 = dual_stack_alternate(&original);
        let normalized = normalize_socket_addr(v6);
        assert_eq!(normalized, original);
    }
}
