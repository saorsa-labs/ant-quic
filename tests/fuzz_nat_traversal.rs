//! Fuzz testing for NAT traversal frame parsing
//!
//! This module provides fuzz targets to test NAT traversal frame parsing
//! with malformed and edge-case inputs to ensure robustness.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::VarInt;
use ant_quic::coding::{BufExt, UnexpectedEnd};
use ant_quic::frame::nat_traversal_unified::{AddAddress, PunchMeNow, RemoveAddress};
use bytes::BytesMut;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

// Frame type constants from the RFC
const FRAME_TYPE_ADD_ADDRESS_IPV4: u64 = 0x3d7e90;
const FRAME_TYPE_ADD_ADDRESS_IPV6: u64 = 0x3d7e91;
const FRAME_TYPE_PUNCH_ME_NOW_IPV4: u64 = 0x3d7e92;
const FRAME_TYPE_PUNCH_ME_NOW_IPV6: u64 = 0x3d7e93;
const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e94;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedNatTraversalFrame {
    AddAddress(AddAddress),
    PunchMeNow(PunchMeNow),
    RemoveAddress(RemoveAddress),
}

fn decode_nat_traversal_frame(
    data: &[u8],
) -> Result<Option<DecodedNatTraversalFrame>, UnexpectedEnd> {
    let mut buf = BytesMut::from(data);
    let frame_type = buf.get_var()?;

    match frame_type {
        FRAME_TYPE_ADD_ADDRESS_IPV4 => AddAddress::decode_auto(&mut buf, false)
            .map(DecodedNatTraversalFrame::AddAddress)
            .map(Some),
        FRAME_TYPE_ADD_ADDRESS_IPV6 => AddAddress::decode_auto(&mut buf, true)
            .map(DecodedNatTraversalFrame::AddAddress)
            .map(Some),
        FRAME_TYPE_PUNCH_ME_NOW_IPV4 => PunchMeNow::decode_auto(&mut buf, false)
            .map(DecodedNatTraversalFrame::PunchMeNow)
            .map(Some),
        FRAME_TYPE_PUNCH_ME_NOW_IPV6 => PunchMeNow::decode_auto(&mut buf, true)
            .map(DecodedNatTraversalFrame::PunchMeNow)
            .map(Some),
        FRAME_TYPE_REMOVE_ADDRESS => RemoveAddress::decode(&mut buf)
            .map(DecodedNatTraversalFrame::RemoveAddress)
            .map(Some),
        _ => Ok(None),
    }
}

/// Fuzz target for ADD_ADDRESS frame parsing
pub fn fuzz_add_address_frame(data: &[u8]) {
    let _ = decode_nat_traversal_frame(data);
}

/// Fuzz target for PUNCH_ME_NOW frame parsing
pub fn fuzz_punch_me_now_frame(data: &[u8]) {
    let _ = decode_nat_traversal_frame(data);
}

/// Fuzz target for REMOVE_ADDRESS frame parsing
pub fn fuzz_remove_address_frame(data: &[u8]) {
    let _ = decode_nat_traversal_frame(data);
}

/// Fuzz target for general frame parsing with arbitrary data
pub fn fuzz_frame_parsing(data: &[u8]) {
    let _ = decode_nat_traversal_frame(data);
}

/// Fuzz target for VarInt parsing (critical for frame parsing)
pub fn fuzz_varint_parsing(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut buf = BytesMut::from(data);

    // Try to parse VarInt - should not panic on any input
    let _ = buf.get_var();

    // Try to create VarInt from arbitrary u64 values
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[0..8]);
        let arbitrary_u64 = u64::from_le_bytes(bytes);

        let _ = VarInt::from_u64(arbitrary_u64);
    }
}

/// Fuzz target for address parsing
pub fn fuzz_address_parsing(data: &[u8]) {
    if data.len() < 6 {
        return;
    }

    // Try to parse IPv4 address and port
    if data.len() >= 6 {
        let mut ipv4_bytes = [0u8; 4];
        ipv4_bytes.copy_from_slice(&data[0..4]);
        let port = u16::from_le_bytes([data[4], data[5]]);

        let _ipv4_addr = Ipv4Addr::from(ipv4_bytes);
        let _socket_addr_v4 = SocketAddr::from((_ipv4_addr, port));
    }

    // Try to parse IPv6 address and port
    if data.len() >= 18 {
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes.copy_from_slice(&data[0..16]);
        let port = u16::from_le_bytes([data[16], data[17]]);

        let _ipv6_addr = Ipv6Addr::from(ipv6_bytes);
        let _socket_addr_v6 = SocketAddr::from((_ipv6_addr, port));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_frame(frame: &DecodedNatTraversalFrame) -> BytesMut {
        let mut buf = BytesMut::new();
        match frame {
            DecodedNatTraversalFrame::AddAddress(frame) => frame.encode_rfc(&mut buf),
            DecodedNatTraversalFrame::PunchMeNow(frame) => frame.encode_rfc(&mut buf),
            DecodedNatTraversalFrame::RemoveAddress(frame) => frame.encode(&mut buf),
        }
        buf
    }

    #[test]
    fn test_fuzz_targets_with_valid_data() {
        let valid_frames = [
            DecodedNatTraversalFrame::AddAddress(AddAddress::new(
                VarInt::from_u32(42),
                "192.168.1.100:8080".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::AddAddress(AddAddress::new(
                VarInt::from_u32(999),
                "[2001:db8::1]:9000".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::PunchMeNow(PunchMeNow::new(
                VarInt::from_u32(5),
                VarInt::from_u32(42),
                "10.0.0.1:1234".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::PunchMeNow(PunchMeNow::new(
                VarInt::from_u32(7),
                VarInt::from_u32(999),
                "[2001:db8::5]:9001".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::RemoveAddress(RemoveAddress::new(VarInt::from_u32(42))),
        ];

        for frame in valid_frames {
            let data = encoded_frame(&frame);

            assert_eq!(decode_nat_traversal_frame(&data), Ok(Some(frame.clone())));
            fuzz_frame_parsing(&data);
        }
    }

    #[test]
    fn test_fuzz_targets_with_invalid_data() {
        // Test with completely invalid data
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
        fuzz_frame_parsing(&invalid_data);

        // Test with truncated data
        let truncated_data = vec![0x80, 0x3d, 0x7e, 0x90]; // Just frame type
        fuzz_frame_parsing(&truncated_data);

        // Test with oversized VarInt
        let oversized_varint = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        fuzz_varint_parsing(&oversized_varint);
    }

    #[test]
    fn test_fuzz_targets_with_malformed_data() {
        // Test with malformed addresses
        let malformed_ipv4 = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        fuzz_address_parsing(&malformed_ipv4);

        // Test with oversized data
        let oversized_data = vec![0; 1000];
        fuzz_frame_parsing(&oversized_data);

        // Test with empty data
        let empty_data = vec![];
        fuzz_frame_parsing(&empty_data);
    }

    #[test]
    fn test_production_decoders_reject_truncated_frames() {
        let valid_frames = [
            DecodedNatTraversalFrame::AddAddress(AddAddress::new(
                VarInt::from_u32(42),
                "192.168.1.100:8080".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::PunchMeNow(PunchMeNow::new(
                VarInt::from_u32(5),
                VarInt::from_u32(42),
                "10.0.0.1:1234".parse().unwrap(),
            )),
            DecodedNatTraversalFrame::RemoveAddress(RemoveAddress::new(VarInt::from_u32(42))),
        ];

        for frame in valid_frames {
            let data = encoded_frame(&frame);

            for len in 0..data.len() {
                assert_eq!(decode_nat_traversal_frame(&data[..len]), Err(UnexpectedEnd));
                fuzz_frame_parsing(&data[..len]);
            }
        }
    }
}
