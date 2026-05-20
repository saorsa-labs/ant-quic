// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use ant_quic::{
    VarInt,
    coding::{BufExt, BufMutExt},
    frame::nat_traversal_unified::{AddAddress, PunchMeNow, RemoveAddress},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

const ADD_ADDRESS_IPV4: u64 = 0x3d7e90;
const ADD_ADDRESS_IPV6: u64 = 0x3d7e91;
const PUNCH_ME_NOW_IPV4: u64 = 0x3d7e92;
const PUNCH_ME_NOW_IPV6: u64 = 0x3d7e93;
const REMOVE_ADDRESS: u64 = 0x3d7e94;

fn frame_type_bytes(frame_type: u64) -> Result<BytesMut, Box<dyn Error>> {
    let mut buf = BytesMut::new();
    buf.write_var(frame_type)?;
    Ok(buf)
}

fn payload_after_frame_type(
    encoded: BytesMut,
    expected_frame_type: u64,
) -> Result<Bytes, Box<dyn Error>> {
    let expected_prefix = frame_type_bytes(expected_frame_type)?;
    assert_eq!(&encoded[..expected_prefix.len()], expected_prefix.as_ref());

    let mut payload = encoded.freeze();
    let actual_frame_type = payload.get_var()?;
    assert_eq!(actual_frame_type, expected_frame_type);
    Ok(payload)
}

fn append_socket_addr(buf: &mut BytesMut, address: SocketAddr) {
    match address {
        SocketAddr::V4(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }
}

fn expected_add_address(
    frame_type: u64,
    sequence: VarInt,
    address: SocketAddr,
) -> Result<BytesMut, Box<dyn Error>> {
    let mut expected = frame_type_bytes(frame_type)?;
    expected.write_var(sequence.into_inner())?;
    append_socket_addr(&mut expected, address);
    Ok(expected)
}

fn expected_punch_me_now(
    frame_type: u64,
    round: VarInt,
    paired_with_sequence_number: VarInt,
    address: SocketAddr,
) -> Result<BytesMut, Box<dyn Error>> {
    let mut expected = frame_type_bytes(frame_type)?;
    expected.write_var(round.into_inner())?;
    expected.write_var(paired_with_sequence_number.into_inner())?;
    append_socket_addr(&mut expected, address);
    Ok(expected)
}

#[test]
fn add_address_ipv4_uses_production_rfc_wire_format() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(42);
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080));
    let frame = AddAddress::new(sequence, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    assert_eq!(
        encoded.as_ref(),
        expected_add_address(ADD_ADDRESS_IPV4, sequence, address)?.as_ref()
    );

    let mut payload = payload_after_frame_type(encoded, ADD_ADDRESS_IPV4)?;
    let decoded = AddAddress::decode_auto(&mut payload, false)?;

    assert_eq!(decoded.sequence, sequence);
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn add_address_ipv6_uses_production_rfc_wire_format() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(123);
    let address = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ),
        9000,
        0,
        0,
    ));
    let frame = AddAddress::new(sequence, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    assert_eq!(
        encoded.as_ref(),
        expected_add_address(ADD_ADDRESS_IPV6, sequence, address)?.as_ref()
    );

    let mut payload = payload_after_frame_type(encoded, ADD_ADDRESS_IPV6)?;
    let decoded = AddAddress::decode_auto(&mut payload, true)?;

    assert_eq!(decoded.sequence, sequence);
    assert_eq!(decoded.address, address);
    assert!(!payload.has_remaining());

    Ok(())
}

#[test]
fn punch_me_now_ipv4_uses_production_rfc_wire_format() -> Result<(), Box<dyn Error>> {
    let round = VarInt::from_u32(5);
    let paired_with_sequence_number = VarInt::from_u32(42);
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 12345));
    let frame = PunchMeNow::new(round, paired_with_sequence_number, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    assert_eq!(
        encoded.as_ref(),
        expected_punch_me_now(
            PUNCH_ME_NOW_IPV4,
            round,
            paired_with_sequence_number,
            address
        )?
        .as_ref()
    );

    let mut payload = payload_after_frame_type(encoded, PUNCH_ME_NOW_IPV4)?;
    let decoded = PunchMeNow::decode_auto(&mut payload, false)?;

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
fn punch_me_now_ipv6_uses_production_rfc_wire_format() -> Result<(), Box<dyn Error>> {
    let round = VarInt::from_u32(10);
    let paired_with_sequence_number = VarInt::from_u32(99);
    let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 54321, 0, 0));
    let frame = PunchMeNow::new(round, paired_with_sequence_number, address);

    let mut encoded = BytesMut::new();
    frame.try_encode_rfc(&mut encoded)?;

    assert_eq!(
        encoded.as_ref(),
        expected_punch_me_now(
            PUNCH_ME_NOW_IPV6,
            round,
            paired_with_sequence_number,
            address
        )?
        .as_ref()
    );

    let mut payload = payload_after_frame_type(encoded, PUNCH_ME_NOW_IPV6)?;
    let decoded = PunchMeNow::decode_auto(&mut payload, true)?;

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
fn remove_address_uses_production_wire_format() -> Result<(), Box<dyn Error>> {
    let sequence = VarInt::from_u32(777);
    let frame = RemoveAddress::new(sequence);

    let mut encoded = BytesMut::new();
    frame.try_encode(&mut encoded)?;

    let mut expected = frame_type_bytes(REMOVE_ADDRESS)?;
    expected.write_var(sequence.into_inner())?;
    assert_eq!(encoded.as_ref(), expected.as_ref());

    let mut payload = payload_after_frame_type(encoded, REMOVE_ADDRESS)?;
    let decoded = RemoveAddress::decode(&mut payload)?;

    assert_eq!(decoded.sequence, sequence);
    assert!(!payload.has_remaining());

    Ok(())
}
