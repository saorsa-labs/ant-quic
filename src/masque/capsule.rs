// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! HTTP Capsule Protocol types for MASQUE CONNECT-UDP Bind
//!
//! Implements capsules per draft-ietf-masque-connect-udp-listen-10:
//! - COMPRESSION_ASSIGN (0x11)
//! - COMPRESSION_ACK (0x12)
//! - COMPRESSION_CLOSE (0x13)
//!
//! These capsules enable header compression for HTTP Datagrams by registering
//! Context IDs that represent specific target addresses, reducing per-datagram
//! overhead for frequent communication with the same peers.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::VarInt;
use crate::coding::{self, Codec};

/// Capsule type identifier for COMPRESSION_ASSIGN
pub const CAPSULE_COMPRESSION_ASSIGN: u64 = 0x11;

/// Capsule type identifier for COMPRESSION_ACK
pub const CAPSULE_COMPRESSION_ACK: u64 = 0x12;

/// Capsule type identifier for COMPRESSION_CLOSE
pub const CAPSULE_COMPRESSION_CLOSE: u64 = 0x13;

/// Capsule type identifier for ECN_COMPRESSION_ASSIGN (ADR-020 /
/// `draft-seemann-masque-connect-udp-ecn-01`).
///
/// Uses the same body layout as [`CompressionAssign`] (`[base_context_id][ip_ver][ip][port]`),
/// registering 4 consecutive even Context IDs for one target:
/// - `base + 0`: `Not-ECT`
/// - `base + 2`: `ECT(0)`
/// - `base + 4`: `ECT(1)`
/// - `base + 6`: `CE`
///
/// Acknowledged by a single [`CompressionAck`] carrying `base_context_id` and
/// closed by a single [`CompressionClose`] carrying `base_context_id`.
pub const CAPSULE_ECN_COMPRESSION_ASSIGN: u64 = 0x14;

/// Leading marker byte distinguishing a control [`Capsule`] frame from an
/// [`crate::masque::UncompressedDatagram`] (which starts with Context ID `0x00`)
/// inside a length-prefixed relay bidirectional stream frame (`datagram_mux_v1`).
pub const STREAM_CAPSULE_MARKER: u8 = 0xFF;

/// COMPRESSION_ASSIGN Capsule
///
/// Registers a Context ID for either uncompressed or compressed operation.
/// - IP Version 0 = uncompressed (no IP/port follows)
/// - IP Version 4 = IPv4 compressed context
/// - IP Version 6 = IPv6 compressed context
///
/// Per the specification, clients allocate even Context IDs and servers
/// allocate odd Context IDs. Context ID 0 is reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAssign {
    /// Context ID (clients allocate even, servers allocate odd)
    pub context_id: VarInt,
    /// IP Version: 0 = uncompressed, 4 = IPv4, 6 = IPv6
    pub ip_version: u8,
    /// Target IP address (None if ip_version == 0)
    pub ip_address: Option<IpAddr>,
    /// Target UDP port in network byte order (None if ip_version == 0)
    pub udp_port: Option<u16>,
}

impl CompressionAssign {
    /// Create an uncompressed context registration
    ///
    /// An uncompressed context allows sending datagrams with inline
    /// IP address and port information, suitable for communicating
    /// with arbitrary targets.
    pub fn uncompressed(context_id: VarInt) -> Self {
        Self {
            context_id,
            ip_version: 0,
            ip_address: None,
            udp_port: None,
        }
    }

    /// Create a compressed context for an IPv4 target
    ///
    /// A compressed context registers a specific IPv4 address and port,
    /// allowing subsequent datagrams to omit the target information.
    pub fn compressed_v4(context_id: VarInt, addr: Ipv4Addr, port: u16) -> Self {
        Self {
            context_id,
            ip_version: 4,
            ip_address: Some(IpAddr::V4(addr)),
            udp_port: Some(port),
        }
    }

    /// Create a compressed context for an IPv6 target
    ///
    /// A compressed context registers a specific IPv6 address and port,
    /// allowing subsequent datagrams to omit the target information.
    pub fn compressed_v6(context_id: VarInt, addr: Ipv6Addr, port: u16) -> Self {
        Self {
            context_id,
            ip_version: 6,
            ip_address: Some(IpAddr::V6(addr)),
            udp_port: Some(port),
        }
    }

    /// Check if this is an uncompressed context
    pub fn is_uncompressed(&self) -> bool {
        self.ip_version == 0
    }

    /// Get the target socket address if this is a compressed context
    pub fn target(&self) -> Option<std::net::SocketAddr> {
        match (self.ip_address, self.udp_port) {
            (Some(ip), Some(port)) => Some(std::net::SocketAddr::new(ip, port)),
            _ => None,
        }
    }
}

impl Codec for CompressionAssign {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;

        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        let ip_version = buf.get_u8();

        let (ip_address, udp_port) = if ip_version == 0 {
            (None, None)
        } else {
            let ip = match ip_version {
                4 => {
                    if buf.remaining() < 4 {
                        return Err(coding::UnexpectedEnd);
                    }
                    let mut octets = [0u8; 4];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    if buf.remaining() < 16 {
                        return Err(coding::UnexpectedEnd);
                    }
                    let mut octets = [0u8; 16];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(coding::UnexpectedEnd),
            };

            if buf.remaining() < 2 {
                return Err(coding::UnexpectedEnd);
            }
            let port = buf.get_u16();

            (Some(ip), Some(port))
        };

        Ok(Self {
            context_id,
            ip_version,
            ip_address,
            udp_port,
        })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
        buf.put_u8(self.ip_version);

        if let (Some(ip), Some(port)) = (&self.ip_address, self.udp_port) {
            match ip {
                IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
                IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
            }
            buf.put_u16(port);
        }
    }
}

/// COMPRESSION_ACK Capsule
///
/// Confirms registration of a Context ID received via COMPRESSION_ASSIGN.
/// The receiver sends this capsule to acknowledge successful context setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAck {
    /// The Context ID being acknowledged
    pub context_id: VarInt,
}

impl CompressionAck {
    /// Create a new acknowledgment for the given context ID
    pub fn new(context_id: VarInt) -> Self {
        Self { context_id }
    }
}

impl Codec for CompressionAck {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        Ok(Self { context_id })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
    }
}

/// COMPRESSION_CLOSE Capsule
///
/// Rejects a registration or closes an existing context. This can be sent
/// in response to a COMPRESSION_ASSIGN to reject the registration, or at
/// any time to close an established context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionClose {
    /// The Context ID being closed or rejected
    pub context_id: VarInt,
}

impl CompressionClose {
    /// Create a new close for the given context ID
    pub fn new(context_id: VarInt) -> Self {
        Self { context_id }
    }
}

impl Codec for CompressionClose {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        Ok(Self { context_id })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
    }
}

/// Generic capsule wrapper for encoding/decoding any capsule type
///
/// This enum provides a unified interface for working with all MASQUE
/// capsule types, including handling unknown capsules gracefully.
#[derive(Debug, Clone)]
pub enum Capsule {
    /// COMPRESSION_ASSIGN capsule
    CompressionAssign(CompressionAssign),
    /// COMPRESSION_ACK capsule
    CompressionAck(CompressionAck),
    /// COMPRESSION_CLOSE capsule
    CompressionClose(CompressionClose),
    /// ECN_COMPRESSION_ASSIGN capsule (registers a 4-context ECN quad `{base, base+2, base+4, base+6}`)
    EcnCompressionAssign(CompressionAssign),
    /// Unknown capsule type (forward compatibility)
    Unknown {
        /// The capsule type identifier
        capsule_type: VarInt,
        /// The raw capsule data
        data: Vec<u8>,
    },
}

impl Capsule {
    /// Decode a capsule from a buffer
    ///
    /// The buffer should start with the capsule type VarInt followed by
    /// the length VarInt and then the capsule payload.
    pub fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let capsule_type = VarInt::decode(buf)?;
        let length = VarInt::decode(buf)?;
        let length_usize = length.into_inner() as usize;

        if buf.remaining() < length_usize {
            return Err(coding::UnexpectedEnd);
        }

        match capsule_type.into_inner() {
            CAPSULE_COMPRESSION_ASSIGN => {
                let capsule = CompressionAssign::decode(buf)?;
                Ok(Capsule::CompressionAssign(capsule))
            }
            CAPSULE_COMPRESSION_ACK => {
                let capsule = CompressionAck::decode(buf)?;
                Ok(Capsule::CompressionAck(capsule))
            }
            CAPSULE_COMPRESSION_CLOSE => {
                let capsule = CompressionClose::decode(buf)?;
                Ok(Capsule::CompressionClose(capsule))
            }
            CAPSULE_ECN_COMPRESSION_ASSIGN => {
                let capsule = CompressionAssign::decode(buf)?;
                Ok(Capsule::EcnCompressionAssign(capsule))
            }
            _ => {
                let mut data = vec![0u8; length_usize];
                buf.copy_to_slice(&mut data);
                Ok(Capsule::Unknown { capsule_type, data })
            }
        }
    }

    /// Encode a capsule to a buffer
    ///
    /// Returns the encoded bytes including capsule type and length prefix.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let mut payload = BytesMut::new();

        let capsule_type = match self {
            Capsule::CompressionAssign(c) => {
                c.encode(&mut payload);
                CAPSULE_COMPRESSION_ASSIGN
            }
            Capsule::CompressionAck(c) => {
                c.encode(&mut payload);
                CAPSULE_COMPRESSION_ACK
            }
            Capsule::CompressionClose(c) => {
                c.encode(&mut payload);
                CAPSULE_COMPRESSION_CLOSE
            }
            Capsule::EcnCompressionAssign(c) => {
                c.encode(&mut payload);
                CAPSULE_ECN_COMPRESSION_ASSIGN
            }
            Capsule::Unknown { capsule_type, data } => {
                payload.put_slice(data);
                capsule_type.into_inner()
            }
        };

        // Encode capsule type
        if let Ok(ct) = VarInt::from_u64(capsule_type) {
            ct.encode(&mut buf);
        }

        // Encode length
        if let Ok(len) = VarInt::from_u64(payload.len() as u64) {
            len.encode(&mut buf);
        }

        // Append payload
        buf.put(payload);

        buf.freeze()
    }

    /// Get the capsule type identifier
    pub fn capsule_type(&self) -> u64 {
        match self {
            Capsule::CompressionAssign(_) => CAPSULE_COMPRESSION_ASSIGN,
            Capsule::CompressionAck(_) => CAPSULE_COMPRESSION_ACK,
            Capsule::CompressionClose(_) => CAPSULE_COMPRESSION_CLOSE,
            Capsule::EcnCompressionAssign(_) => CAPSULE_ECN_COMPRESSION_ASSIGN,
            Capsule::Unknown { capsule_type, .. } => capsule_type.into_inner(),
        }
    }

    /// Encode this capsule as a relay-stream frame body prefixed with
    /// [`STREAM_CAPSULE_MARKER`] (`0xFF`).
    #[must_use]
    pub fn encode_stream_frame(&self) -> Bytes {
        let encoded = self.encode();
        let mut buf = BytesMut::with_capacity(1 + encoded.len());
        buf.put_u8(STREAM_CAPSULE_MARKER);
        buf.put_slice(&encoded);
        buf.freeze()
    }

    /// Decode a relay-stream frame body if it begins with [`STREAM_CAPSULE_MARKER`].
    ///
    /// Returns `None` if the frame does not start with `STREAM_CAPSULE_MARKER`
    /// (i.e. it is a regular data frame).
    pub fn decode_stream_frame(frame: &[u8]) -> Option<coding::Result<Self>> {
        if frame.first() != Some(&STREAM_CAPSULE_MARKER) {
            return None;
        }
        let mut slice = &frame[1..];
        Some(Self::decode(&mut slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_assign_uncompressed_roundtrip() {
        let original = CompressionAssign::uncompressed(VarInt::from_u32(2));
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = CompressionAssign::decode(&mut buf.freeze()).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.is_uncompressed());
        assert!(decoded.target().is_none());
    }

    #[test]
    fn test_compression_assign_ipv4_roundtrip() {
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let original = CompressionAssign::compressed_v4(VarInt::from_u32(4), addr, 8080);
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = CompressionAssign::decode(&mut buf.freeze()).unwrap();
        assert_eq!(original, decoded);
        assert!(!decoded.is_uncompressed());
        assert_eq!(
            decoded.target(),
            Some(std::net::SocketAddr::new(IpAddr::V4(addr), 8080))
        );
    }

    #[test]
    fn test_compression_assign_ipv6_roundtrip() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = CompressionAssign::compressed_v6(VarInt::from_u32(6), addr, 443);
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = CompressionAssign::decode(&mut buf.freeze()).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.ip_version, 6);
    }

    #[test]
    fn test_compression_ack_roundtrip() {
        let original = CompressionAck::new(VarInt::from_u32(42));
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = CompressionAck::decode(&mut buf.freeze()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_compression_close_roundtrip() {
        let original = CompressionClose::new(VarInt::from_u32(99));
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = CompressionClose::decode(&mut buf.freeze()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_capsule_wrapper_encoding() {
        let assign =
            CompressionAssign::compressed_v4(VarInt::from_u32(2), Ipv4Addr::new(10, 0, 0, 1), 9000);
        let capsule = Capsule::CompressionAssign(assign.clone());

        let encoded = capsule.encode();
        let mut buf = encoded;
        let decoded = Capsule::decode(&mut buf).unwrap();

        match decoded {
            Capsule::CompressionAssign(c) => assert_eq!(c, assign),
            _ => panic!("Expected CompressionAssign capsule"),
        }
    }

    #[test]
    fn test_capsule_type_identifiers() {
        assert_eq!(
            Capsule::CompressionAssign(CompressionAssign::uncompressed(VarInt::from_u32(1)))
                .capsule_type(),
            CAPSULE_COMPRESSION_ASSIGN
        );
        assert_eq!(
            Capsule::CompressionAck(CompressionAck::new(VarInt::from_u32(1))).capsule_type(),
            CAPSULE_COMPRESSION_ACK
        );
        assert_eq!(
            Capsule::CompressionClose(CompressionClose::new(VarInt::from_u32(1))).capsule_type(),
            CAPSULE_COMPRESSION_CLOSE
        );
        assert_eq!(
            Capsule::EcnCompressionAssign(CompressionAssign::compressed_v4(
                VarInt::from_u32(2),
                Ipv4Addr::LOCALHOST,
                9000,
            ))
            .capsule_type(),
            CAPSULE_ECN_COMPRESSION_ASSIGN
        );
    }

    #[test]
    fn ecn_compression_assign_capsule_roundtrips_v4_and_v6() {
        let v4 = CompressionAssign::compressed_v4(
            VarInt::from_u32(2),
            Ipv4Addr::new(198, 51, 100, 10),
            4433,
        );
        let framed_v4 = Capsule::EcnCompressionAssign(v4.clone()).encode_stream_frame();
        assert_eq!(framed_v4[0], STREAM_CAPSULE_MARKER);
        match Capsule::decode_stream_frame(&framed_v4)
            .expect("stream capsule")
            .expect("valid decode")
        {
            Capsule::EcnCompressionAssign(decoded) => assert_eq!(decoded, v4),
            other => panic!("expected EcnCompressionAssign, got {other:?}"),
        }

        let v6 = CompressionAssign::compressed_v6(
            VarInt::from_u32(10),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            8443,
        );
        let framed_v6 = Capsule::EcnCompressionAssign(v6.clone()).encode_stream_frame();
        match Capsule::decode_stream_frame(&framed_v6)
            .expect("stream capsule")
            .expect("valid decode")
        {
            Capsule::EcnCompressionAssign(decoded) => assert_eq!(decoded, v6),
            other => panic!("expected EcnCompressionAssign, got {other:?}"),
        }

        // Legacy UncompressedDatagram starts with 0x00, not STREAM_CAPSULE_MARKER.
        assert!(Capsule::decode_stream_frame(&[0x00, 0x04, 127, 0, 0, 1, 0, 80]).is_none());
    }
}
