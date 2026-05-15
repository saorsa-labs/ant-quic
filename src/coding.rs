// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Coding related traits.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};
use thiserror::Error;

use crate::{VarInt, VarIntBoundsExceeded};

/// Error indicating that the provided buffer was too small
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
#[error("unexpected end of buffer")]
pub struct UnexpectedEnd;

/// Coding result type
pub type Result<T> = ::std::result::Result<T, UnexpectedEnd>;

/// Infallible encoding and decoding of QUIC primitives
pub trait Codec: Sized {
    /// Decode a `Self` from the provided buffer, if the buffer is large enough
    fn decode<B: Buf>(buf: &mut B) -> Result<Self>;
    /// Append the encoding of `self` to the provided buffer
    fn encode<B: BufMut>(&self, buf: &mut B);
}

impl Codec for u8 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u8())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }
}

impl Codec for u16 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u16())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(*self);
    }
}

impl Codec for u32 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u32())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32(*self);
    }
}

impl Codec for u64 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u64())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u64(*self);
    }
}

impl Codec for Ipv4Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0; 4];
        buf.copy_to_slice(&mut octets);
        Ok(octets.into())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

impl Codec for Ipv6Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 16 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0; 16];
        buf.copy_to_slice(&mut octets);
        Ok(octets.into())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

/// Extension trait for reading from buffers
pub trait BufExt {
    /// Read and decode a value from the buffer
    fn get<T: Codec>(&mut self) -> Result<T>;
    /// Read a variable-length integer from the buffer
    fn get_var(&mut self) -> Result<u64>;
}

impl<T: Buf> BufExt for T {
    fn get<U: Codec>(&mut self) -> Result<U> {
        U::decode(self)
    }

    fn get_var(&mut self) -> Result<u64> {
        Ok(VarInt::decode(self)?.into_inner())
    }
}

/// Extension trait for writing to buffers
pub trait BufMutExt {
    /// Write and encode a value to the buffer
    fn write<T: Codec>(&mut self, x: T);
    /// Write a variable-length integer to the buffer
    fn write_var(&mut self, x: u64) -> std::result::Result<(), VarIntBoundsExceeded>;
    /// Write a variable-length integer, debug-asserting on overflow in debug builds
    fn write_var_or_debug_assert(&mut self, x: u64) {
        if self.write_var(x).is_err() {
            tracing::error!("VarInt overflow: {} exceeds maximum", x);
            debug_assert!(false, "VarInt overflow: {}", x);
        }
    }
}

impl<T: BufMut> BufMutExt for T {
    fn write<U: Codec>(&mut self, x: U) {
        x.encode(self);
    }

    fn write_var(&mut self, x: u64) -> std::result::Result<(), VarIntBoundsExceeded> {
        VarInt::encode_checked(x, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ── Round-trip tests for all primitive Codec impls ──

    #[test]
    fn u8_roundtrip() {
        let mut buf = BytesMut::new();
        let v: u8 = 0xAB;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u8 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u8_roundtrip_zero() {
        let mut buf = BytesMut::new();
        let v: u8 = 0;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u8 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u8_roundtrip_max() {
        let mut buf = BytesMut::new();
        let v: u8 = u8::MAX;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u8 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u16_roundtrip() {
        let mut buf = BytesMut::new();
        let v: u16 = 0xABCD;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u16 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u16_roundtrip_zero() {
        let mut buf = BytesMut::new();
        let v: u16 = 0;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u16 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u16_roundtrip_max() {
        let mut buf = BytesMut::new();
        let v: u16 = u16::MAX;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u16 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u32_roundtrip() {
        let mut buf = BytesMut::new();
        let v: u32 = 0xDEAD_BEEF;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u32 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u32_roundtrip_zero() {
        let mut buf = BytesMut::new();
        let v: u32 = 0;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u32 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u32_roundtrip_max() {
        let mut buf = BytesMut::new();
        let v: u32 = u32::MAX;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u32 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u64_roundtrip() {
        let mut buf = BytesMut::new();
        let v: u64 = 0x0123_4567_89AB_CDEF;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u64 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u64_roundtrip_zero() {
        let mut buf = BytesMut::new();
        let v: u64 = 0;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u64 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u64_roundtrip_max() {
        let mut buf = BytesMut::new();
        let v: u64 = u64::MAX;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u64 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv4_roundtrip() {
        let mut buf = BytesMut::new();
        let v: Ipv4Addr = "192.168.1.1".parse().unwrap();
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv4Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv4_zero() {
        let mut buf = BytesMut::new();
        let v: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv4Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv4_broadcast() {
        let mut buf = BytesMut::new();
        let v: Ipv4Addr = Ipv4Addr::BROADCAST;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv4Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv6_roundtrip() {
        let mut buf = BytesMut::new();
        let v: Ipv6Addr = "2001:db8::1".parse().unwrap();
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv6Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv6_loopback() {
        let mut buf = BytesMut::new();
        let v: Ipv6Addr = "::1".parse().unwrap();
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv6Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ipv6_unspecified() {
        let mut buf = BytesMut::new();
        let v: Ipv6Addr = "::".parse().unwrap();
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: Ipv6Addr = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    // ── Insufficient buffer tests ──

    #[test]
    fn u8_decode_empty_fails() {
        let buf = BytesMut::new();
        let mut read = buf.freeze();
        let result: Result<u8> = Codec::decode(&mut read);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UnexpectedEnd);
    }

    #[test]
    fn u16_decode_insufficient_fails() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xAB);
        let mut read = buf.freeze();
        let result: Result<u16> = Codec::decode(&mut read);
        assert!(result.is_err());
    }

    #[test]
    fn u32_decode_insufficient_fails() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0; 3]);
        let mut read = buf.freeze();
        let result: Result<u32> = Codec::decode(&mut read);
        assert!(result.is_err());
    }

    #[test]
    fn u64_decode_insufficient_fails() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0; 7]);
        let mut read = buf.freeze();
        let result: Result<u64> = Codec::decode(&mut read);
        assert!(result.is_err());
    }

    #[test]
    fn ipv4_decode_insufficient_fails() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0; 3]);
        let mut read = buf.freeze();
        let result: Result<Ipv4Addr> = Codec::decode(&mut read);
        assert!(result.is_err());
    }

    #[test]
    fn ipv6_decode_insufficient_fails() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0; 15]);
        let mut read = buf.freeze();
        let result: Result<Ipv6Addr> = Codec::decode(&mut read);
        assert!(result.is_err());
    }

    // ── BufExt tests ──

    #[test]
    fn buf_ext_get_u32() {
        let mut buf = BytesMut::new();
        buf.put_u32(0xAABB_CCDD);
        let mut read = buf.freeze();
        let val: u32 = read.get().unwrap();
        assert_eq!(val, 0xAABB_CCDD);
    }

    #[test]
    fn buf_ext_get_var() {
        let mut buf = BytesMut::new();
        VarInt::from_u32(16383).encode(&mut buf);
        let mut read = buf.freeze();
        let val: u64 = read.get_var().unwrap();
        assert_eq!(val, 16383);
    }

    #[test]
    fn buf_ext_get_var_zero() {
        let mut buf = BytesMut::new();
        VarInt::from_u32(0).encode(&mut buf);
        let mut read = buf.freeze();
        let val: u64 = read.get_var().unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn buf_ext_get_var_large() {
        let mut buf = BytesMut::new();
        let v = VarInt::MAX;
        v.encode(&mut buf);
        let mut read = buf.freeze();
        let val: u64 = read.get_var().unwrap();
        assert_eq!(val, v.into_inner());
    }

    // ── BufMutExt tests ──

    #[test]
    fn buf_mut_ext_write_u16() {
        let mut buf = BytesMut::new();
        let v: u16 = 0x1234;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u16 = Codec::decode(&mut read).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn buf_mut_ext_write_var_small() {
        let mut buf = BytesMut::new();
        buf.write_var(42u64).unwrap();
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 42);
    }

    #[test]
    fn buf_mut_ext_write_var_medium() {
        let mut buf = BytesMut::new();
        buf.write_var(16383u64).unwrap();
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 16383);
    }

    #[test]
    fn buf_mut_ext_write_var_large() {
        let mut buf = BytesMut::new();
        buf.write_var(1_073_741_823u64).unwrap();
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 1_073_741_823);
    }

    #[test]
    fn buf_mut_ext_write_var_max() {
        let mut buf = BytesMut::new();
        let v = VarInt::MAX.into_inner();
        buf.write_var(v).unwrap();
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), v);
    }

    #[test]
    fn buf_mut_ext_write_var_overflow() {
        let mut buf = BytesMut::new();
        let result = buf.write_var(1u64 << 62);
        assert!(result.is_err());
    }

    #[test]
    fn buf_mut_ext_write_var_or_debug_assert_valid() {
        let mut buf = BytesMut::new();
        buf.write_var_or_debug_assert(42u64);
        let mut read = buf.freeze();
        let val = VarInt::decode(&mut read).unwrap();
        assert_eq!(val.into_inner(), 42);
    }

    #[test]
    fn write_var_or_debug_assert_overflow_logs_error() {
        // write_var_or_debug_assert with a valid value should work fine
        let mut buf = BytesMut::new();
        buf.write_var_or_debug_assert(42u64);
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 42);
    }

    // ── Integration: BufExt + BufMutExt roundtrip ──

    #[test]
    fn ext_traits_roundtrip_u32() {
        let mut buf = BytesMut::new();
        let v: u32 = 42;
        buf.write(v);
        let mut read = buf.freeze();
        let decoded: u32 = read.get().unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn ext_traits_roundtrip_mixed_types() {
        let mut buf = BytesMut::new();
        buf.write(0xABu8);
        buf.write(0x1234u16);
        buf.write(0xDEAD_BEEFu32);
        buf.write(0x0123_4567_89AB_CDEFu64);

        let mut read = buf.freeze();
        assert_eq!(read.get::<u8>().unwrap(), 0xAB);
        assert_eq!(read.get::<u16>().unwrap(), 0x1234);
        assert_eq!(read.get::<u32>().unwrap(), 0xDEAD_BEEF);
        assert_eq!(read.get::<u64>().unwrap(), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn ext_traits_roundtrip_varint_mixed() {
        let mut buf = BytesMut::new();
        buf.write_var(0u64).unwrap();
        buf.write_var(63u64).unwrap();
        buf.write_var(64u64).unwrap();
        buf.write_var(16383u64).unwrap();
        buf.write_var(16384u64).unwrap();
        buf.write_var(1_073_741_823u64).unwrap();
        buf.write_var(1_073_741_824u64).unwrap();
        buf.write_var(VarInt::MAX.into_inner()).unwrap();

        let mut read = buf.freeze();
        assert_eq!(read.get_var().unwrap(), 0);
        assert_eq!(read.get_var().unwrap(), 63);
        assert_eq!(read.get_var().unwrap(), 64);
        assert_eq!(read.get_var().unwrap(), 16383);
        assert_eq!(read.get_var().unwrap(), 16384);
        assert_eq!(read.get_var().unwrap(), 1_073_741_823);
        assert_eq!(read.get_var().unwrap(), 1_073_741_824);
        assert_eq!(read.get_var().unwrap(), VarInt::MAX.into_inner());

        // Verify we consumed everything
        assert!(!read.has_remaining());
    }

    // ── Boundary: Decode from insufficiently-sized buffers ──

    #[test]
    fn varint_decode_empty_fails() {
        let buf = BytesMut::new();
        let mut read = buf.freeze();
        let result: Result<VarInt> = VarInt::decode(&mut read);
        assert_eq!(result.unwrap_err(), UnexpectedEnd);
    }

    #[test]
    fn varint_decode_partial_2byte_tag() {
        let mut buf = BytesMut::new();
        // 2-byte encoding: tag 0b01, need 2 bytes total, only provide 1
        buf.put_u8(0b01_000000 | 42); // First byte with tag, but no second byte
        let mut read = buf.freeze();
        let result: Result<VarInt> = VarInt::decode(&mut read);
        assert_eq!(result.unwrap_err(), UnexpectedEnd);
    }

    #[test]
    fn varint_decode_partial_4byte_tag() {
        let mut buf = BytesMut::new();
        // 4-byte encoding: tag 0b10, need 4 bytes total, only provide 1
        buf.put_u8(0b10_000000 | 42);
        let mut read = buf.freeze();
        let result: Result<VarInt> = VarInt::decode(&mut read);
        assert_eq!(result.unwrap_err(), UnexpectedEnd);
    }

    #[test]
    fn varint_decode_partial_8byte_tag() {
        let mut buf = BytesMut::new();
        // 8-byte encoding: tag 0b11, need 8 bytes total, only provide 1
        buf.put_u8(0b11_000000);
        let mut read = buf.freeze();
        let result: Result<VarInt> = VarInt::decode(&mut read);
        assert_eq!(result.unwrap_err(), UnexpectedEnd);
    }

    // ── VarInt size tests ──

    #[test]
    fn varint_size_1_byte() {
        assert_eq!(VarInt::from_u32(0).size(), 1);
        assert_eq!(VarInt::from_u32(63).size(), 1);
    }

    #[test]
    fn varint_size_2_bytes() {
        assert_eq!(VarInt::from_u32(64).size(), 2);
        assert_eq!(VarInt::from_u32(16383).size(), 2);
    }

    #[test]
    fn varint_size_4_bytes() {
        assert_eq!(VarInt::from_u32(16384).size(), 4);
        assert_eq!(VarInt::from_u32(1_073_741_823).size(), 4);
    }

    #[test]
    fn varint_size_8_bytes() {
        assert_eq!(VarInt::from_u64(1_073_741_824).unwrap().size(), 8);
        assert_eq!(VarInt::MAX.size(), 8);
    }

    // ── VarInt constructor tests ──

    #[test]
    fn varint_from_u64_valid() {
        let v = VarInt::from_u64(0).unwrap();
        assert_eq!(v.into_inner(), 0);

        let v = VarInt::from_u64(VarInt::MAX.into_inner()).unwrap();
        assert_eq!(v.into_inner(), VarInt::MAX.into_inner());
    }

    #[test]
    fn varint_from_u64_invalid() {
        let result = VarInt::from_u64(1u64 << 62);
        assert!(result.is_err());
    }

    #[test]
    fn varint_try_from_u64_valid() {
        use std::convert::TryFrom;
        let v = VarInt::try_from(42u64).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn varint_try_from_u64_invalid() {
        use std::convert::TryFrom;
        let result = VarInt::try_from(1u64 << 62);
        assert!(result.is_err());
    }

    #[test]
    fn varint_try_from_u128_valid() {
        use std::convert::TryFrom;
        let v = VarInt::try_from(42u128).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn varint_try_from_u128_invalid() {
        use std::convert::TryFrom;
        let result = VarInt::try_from((1u128 << 62) + 1);
        assert!(result.is_err());
    }

    #[test]
    fn varint_try_from_usize_valid() {
        use std::convert::TryFrom;
        let v = VarInt::try_from(42usize).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn varint_into_u64() {
        let v = VarInt::from_u32(42);
        let val: u64 = v.into();
        assert_eq!(val, 42);
    }

    #[test]
    fn varint_from_u8() {
        let v: VarInt = 42u8.into();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn varint_from_u16() {
        let v: VarInt = 16383u16.into();
        assert_eq!(v.into_inner(), 16383);
    }

    #[test]
    fn varint_from_u32() {
        let v: VarInt = 42u32.into();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn varint_display() {
        let v = VarInt::from_u32(42);
        assert_eq!(format!("{v}"), "42");
    }

    #[test]
    fn varint_debug() {
        let v = VarInt::from_u32(42);
        assert_eq!(format!("{v:?}"), "42");
    }

    #[test]
    fn varint_ord() {
        let small = VarInt::from_u32(10);
        let large = VarInt::from_u32(20);
        assert!(small < large);
        assert!(large > small);
        assert_eq!(small.min(large), small);
        assert_eq!(small.max(large), large);
    }

    #[test]
    fn varint_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let v1 = VarInt::from_u32(42);
        let v2 = VarInt::from_u32(42);
        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        v1.hash(&mut hasher1);
        v2.hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish());
    }
}
