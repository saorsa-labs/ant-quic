//! Simple RFC compliance tests for NAT traversal.
//!
//! These tests verify draft-seemann-quic-nat-traversal-02 wire compatibility
//! through the crate's production NAT traversal frame codecs.

use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use ant_quic::{
    VarInt,
    coding::BufExt,
    frame::nat_traversal_unified::{AddAddress, PunchMeNow, RemoveAddress},
};
use bytes::{Buf, Bytes, BytesMut};

fn payload_after_frame_type(
    encoded: BytesMut,
    expected_frame_type: u64,
) -> Result<Bytes, Box<dyn Error>> {
    let mut payload = encoded.freeze();
    let actual_frame_type = payload.get_var()?;

    assert_eq!(actual_frame_type, expected_frame_type);

    Ok(payload)
}

#[test]
fn add_address_ipv4_uses_production_rfc_codec() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(42);
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 4433));
    let frame = AddAddress::new(sequence, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    let mut payload = payload_after_frame_type(encoded, 0x3d7e90)?;
    let decoded = AddAddress::decode_rfc(&mut payload, false)?;

    assert_eq!(decoded.sequence, sequence);
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn add_address_ipv6_uses_production_rfc_codec() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(43);
    let address = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 10),
        4434,
        0,
        0,
    ));
    let frame = AddAddress::new(sequence, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    let mut payload = payload_after_frame_type(encoded, 0x3d7e91)?;
    let decoded = AddAddress::decode_rfc(&mut payload, true)?;

    assert_eq!(decoded.sequence, sequence);
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn punch_me_now_ipv4_uses_production_rfc_codec() -> Result<(), Box<dyn Error>> {
    let round = VarInt::from_u32(7);
    let paired_with_sequence_number = VarInt::from_u32(42);
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 20), 9000));
    let frame = PunchMeNow::new(round, paired_with_sequence_number, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    let mut payload = payload_after_frame_type(encoded, 0x3d7e92)?;
    let decoded = PunchMeNow::decode_rfc(&mut payload, false)?;

    assert_eq!(decoded.round, round);
    assert_eq!(
        decoded.paired_with_sequence_number,
        paired_with_sequence_number
    );
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn punch_me_now_ipv6_uses_production_rfc_codec() -> Result<(), Box<dyn Error>> {
    let round = VarInt::from_u32(8);
    let paired_with_sequence_number = VarInt::from_u32(43);
    let address = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0x0db8, 0, 2, 0, 0, 0, 20),
        9001,
        0,
        0,
    ));
    let frame = PunchMeNow::new(round, paired_with_sequence_number, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    let mut payload = payload_after_frame_type(encoded, 0x3d7e93)?;
    let decoded = PunchMeNow::decode_rfc(&mut payload, true)?;

    assert_eq!(decoded.round, round);
    assert_eq!(
        decoded.paired_with_sequence_number,
        paired_with_sequence_number
    );
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn remove_address_uses_production_codec() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(42);
    let frame = RemoveAddress::new(sequence);

    let mut encoded = BytesMut::new();
    frame.try_encode(&mut encoded)?;

    let mut payload = payload_after_frame_type(encoded, 0x3d7e94)?;
    let decoded = RemoveAddress::decode(&mut payload)?;

    assert_eq!(decoded.sequence, sequence);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn punch_me_now_round_ordering_uses_decoded_frame_rounds() -> Result<(), Box<dyn Error>> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 30), 9002));
    let current = PunchMeNow::new(VarInt::from_u32(5), VarInt::from_u32(42), address);
    let newer = PunchMeNow::new(VarInt::from_u32(10), VarInt::from_u32(42), address);

    let mut encoded_current = BytesMut::new();
    current.try_encode_rfc(&mut encoded_current)?;
    let mut current_payload = payload_after_frame_type(encoded_current, 0x3d7e92)?;
    let decoded_current = PunchMeNow::decode_rfc(&mut current_payload, false)?;

    let mut encoded_newer = BytesMut::new();
    newer.try_encode_rfc(&mut encoded_newer)?;
    let mut newer_payload = payload_after_frame_type(encoded_newer, 0x3d7e92)?;
    let decoded_newer = PunchMeNow::decode_rfc(&mut newer_payload, false)?;

    assert!(decoded_newer.round > decoded_current.round);

    Ok(())
}
