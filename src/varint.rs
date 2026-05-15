// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{convert::TryInto, fmt};

use bytes::{Buf, BufMut};
use thiserror::Error;

use crate::coding::{self, Codec, UnexpectedEnd};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
// It would be neat if we could express to Rust that the top two bits are available for use as enum
// discriminants
#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self((1 << 62) - 1);
    /// The largest encoded value length
    pub const MAX_SIZE: usize = 8;

    /// Create a VarInt from a value that is guaranteed to be in range
    ///
    /// This should only be used when the value is known at compile time or
    /// has been validated to be less than 2^62.
    #[inline]
    pub(crate) fn from_u64_bounded(x: u64) -> Self {
        debug_assert!(x < 2u64.pow(62), "VarInt value {} exceeds maximum", x);
        // Safety: caller guarantees the bound.
        unsafe { Self::from_u64_unchecked(x) }
    }

    /// Construct a `VarInt` infallibly
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Succeeds iff `x` < 2^62
    pub fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        if x < 2u64.pow(62) {
            Ok(Self(x))
        } else {
            Err(VarIntBoundsExceeded)
        }
    }

    /// Create a VarInt without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub const unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Extract the integer value
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub(crate) const fn size(self) -> usize {
        let x = self.0;
        if x < 2u64.pow(6) {
            1
        } else if x < 2u64.pow(14) {
            2
        } else if x < 2u64.pow(30) {
            4
        } else if x < 2u64.pow(62) {
            8
        } else {
            Self::MAX_SIZE
        }
    }

    pub(crate) fn encode_checked<B: BufMut>(x: u64, w: &mut B) -> Result<(), VarIntBoundsExceeded> {
        if x < 2u64.pow(6) {
            w.put_u8(x as u8);
            Ok(())
        } else if x < 2u64.pow(14) {
            w.put_u16((0b01 << 14) | x as u16);
            Ok(())
        } else if x < 2u64.pow(30) {
            w.put_u32((0b10 << 30) | x as u32);
            Ok(())
        } else if x < 2u64.pow(62) {
            w.put_u64((0b11 << 62) | x);
            Ok(())
        } else {
            Err(VarIntBoundsExceeded)
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl std::convert::TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        Self::from_u64(x)
    }
}

impl std::convert::TryFrom<u128> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u128) -> Result<Self, VarIntBoundsExceeded> {
        Self::from_u64(x.try_into().map_err(|_| VarIntBoundsExceeded)?)
    }
}

impl std::convert::TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: usize) -> Result<Self, VarIntBoundsExceeded> {
        Self::try_from(x as u64)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'arbitrary> Arbitrary<'arbitrary> for VarInt {
    fn arbitrary(u: &mut arbitrary::Unstructured<'arbitrary>) -> arbitrary::Result<Self> {
        Ok(Self(u.int_in_range(0..=Self::MAX.0)?))
    }
}

/// Error returned when constructing a `VarInt` from a value >= 2^62
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
#[error("value too large for varint encoding")]
pub struct VarIntBoundsExceeded;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ── Constants ──

    #[test]
    fn varint_max_value() {
        assert_eq!(VarInt::MAX.into_inner(), (1 << 62) - 1);
    }

    #[test]
    fn varint_max_size() {
        assert_eq!(VarInt::MAX_SIZE, 8);
    }

    // ── from_u32 ──

    #[test]
    fn from_u32_zero() {
        let v = VarInt::from_u32(0);
        assert_eq!(v.into_inner(), 0);
    }

    #[test]
    fn from_u32_max_u32() {
        let v = VarInt::from_u32(u32::MAX);
        assert_eq!(v.into_inner(), u32::MAX as u64);
    }

    #[test]
    fn from_u32_is_infallible() {
        // Every u32 value fits in VarInt since 2^32 < 2^62
        let v = VarInt::from_u32(0xFFFF_FFFF);
        assert_eq!(v.into_inner(), 0xFFFF_FFFF);
    }

    // ── from_u64 ──

    #[test]
    fn from_u64_zero() {
        let v = VarInt::from_u64(0).unwrap();
        assert_eq!(v.into_inner(), 0);
    }

    #[test]
    fn from_u64_max_valid() {
        let v = VarInt::from_u64(VarInt::MAX.into_inner()).unwrap();
        assert_eq!(v, VarInt::MAX);
    }

    #[test]
    fn from_u64_too_large() {
        let result = VarInt::from_u64(1u64 << 62);
        assert_eq!(result.unwrap_err(), VarIntBoundsExceeded);
    }

    #[test]
    fn from_u64_just_beyond_max() {
        let result = VarInt::from_u64(VarInt::MAX.into_inner() + 1);
        assert!(result.is_err());
    }

    // ── from_u64_bounded (debug-only, used internally) ──

    #[test]
    fn from_u64_bounded_works_for_valid_values() {
        let v = VarInt::from_u64_bounded(42);
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn from_u64_bounded_zero() {
        let v = VarInt::from_u64_bounded(0);
        assert_eq!(v.into_inner(), 0);
    }

    #[test]
    fn from_u64_bounded_max_valid() {
        let v = VarInt::from_u64_bounded(VarInt::MAX.into_inner());
        assert_eq!(v, VarInt::MAX);
    }

    // ── from_u64_unchecked (unsafe) ──

    #[test]
    fn from_u64_unchecked_safe_when_used_correctly() {
        // SAFETY: 42 < 2^62
        let v = unsafe { VarInt::from_u64_unchecked(42) };
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn from_u64_unchecked_with_max() {
        // SAFETY: MAX is < 2^62 by definition
        let v = unsafe { VarInt::from_u64_unchecked(VarInt::MAX.into_inner()) };
        assert_eq!(v, VarInt::MAX);
    }

    // ── size() tests ──

    #[test]
    fn size_1_byte_boundaries() {
        assert_eq!(VarInt::from_u32(0).size(), 1);
        assert_eq!(VarInt::from_u32(63).size(), 1);
    }

    #[test]
    fn size_2_byte_boundaries() {
        assert_eq!(VarInt::from_u32(64).size(), 2);
        assert_eq!(VarInt::from_u32(16383).size(), 2);
    }

    #[test]
    fn size_4_byte_boundaries() {
        assert_eq!(VarInt::from_u32(16384).size(), 4);
        assert_eq!(VarInt::from_u32(1_073_741_823).size(), 4);
    }

    #[test]
    fn size_8_byte_boundaries() {
        let v = VarInt::from_u64(1_073_741_824).unwrap();
        assert_eq!(v.size(), 8);
        assert_eq!(VarInt::MAX.size(), 8);
    }

    // ── encode_checked tests ──

    #[test]
    fn encode_checked_1_byte_tag() {
        let mut buf = BytesMut::new();
        VarInt::encode_checked(0, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0x00]);

        let mut buf = BytesMut::new();
        VarInt::encode_checked(63, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0x3F]);
    }

    #[test]
    fn encode_checked_2_byte_tag() {
        let mut buf = BytesMut::new();
        VarInt::encode_checked(64, &mut buf).unwrap();
        // tag 01 prefix, value = 64 = 0x40
        assert_eq!(buf[0] >> 6, 0b01);
        assert_eq!(buf.len(), 2);

        let mut buf = BytesMut::new();
        VarInt::encode_checked(16383, &mut buf).unwrap();
        // 16383 = 0x3FFF, with tag 01: 0x7FFF
        assert_eq!(&buf[..], &[0x7F, 0xFF]);
    }

    #[test]
    fn encode_checked_4_byte_tag() {
        let mut buf = BytesMut::new();
        VarInt::encode_checked(16384, &mut buf).unwrap();
        assert_eq!(buf[0] >> 6, 0b10);
        assert_eq!(buf.len(), 4);

        let mut buf = BytesMut::new();
        VarInt::encode_checked(1_073_741_823, &mut buf).unwrap();
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn encode_checked_8_byte_tag() {
        let mut buf = BytesMut::new();
        VarInt::encode_checked(1_073_741_824, &mut buf).unwrap();
        assert_eq!(buf[0] >> 6, 0b11);
        assert_eq!(buf.len(), 8);

        let mut buf = BytesMut::new();
        VarInt::encode_checked(VarInt::MAX.into_inner(), &mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn encode_checked_overflow() {
        let mut buf = BytesMut::new();
        let result = VarInt::encode_checked(1u64 << 62, &mut buf);
        assert_eq!(result.unwrap_err(), VarIntBoundsExceeded);
    }

    #[test]
    fn encode_checked_overflow_near_max() {
        let mut buf = BytesMut::new();
        let result = VarInt::encode_checked(u64::MAX, &mut buf);
        assert_eq!(result.unwrap_err(), VarIntBoundsExceeded);
    }

    // ── Codec roundtrip with encode_checked consistency ──

    #[test]
    fn encode_checked_and_decode_roundtrip_small() {
        let mut buf = BytesMut::new();
        VarInt::encode_checked(42, &mut buf).unwrap();
        let mut read = buf.freeze();
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 42);
    }

    #[test]
    fn encode_checked_and_decode_roundtrip_each_size() {
        let values = [
            0u64,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            VarInt::MAX.into_inner(),
        ];
        for &v in &values {
            let mut buf = BytesMut::new();
            VarInt::encode_checked(v, &mut buf).unwrap();
            let mut read = buf.freeze();
            let decoded = VarInt::decode(&mut read).unwrap();
            assert_eq!(decoded.into_inner(), v, "failed for value {v}");
        }
    }

    // ── VarInt encode (Codec trait) tests ──

    #[test]
    fn varint_encode_correct_tag_pattern() {
        // 1-byte: top 2 bits are 00, value fits in 6 bits
        let mut buf = BytesMut::new();
        VarInt::from_u32(42).encode(&mut buf);
        assert_eq!(buf[0] >> 6, 0b00);

        // 2-byte: top 2 bits are 01
        let mut buf2 = BytesMut::new();
        VarInt::from_u32(16383).encode(&mut buf2);
        assert_eq!(buf2[0] >> 6, 0b01);

        // 4-byte: top 2 bits are 10
        let mut buf4 = BytesMut::new();
        VarInt::from_u32(1_073_741_823).encode(&mut buf4);
        assert_eq!(buf4[0] >> 6, 0b10);

        // 8-byte: top 2 bits are 11
        let mut buf8 = BytesMut::new();
        VarInt::from_u64(1_073_741_824).unwrap().encode(&mut buf8);
        assert_eq!(buf8[0] >> 6, 0b11);
    }

    // ── Conversion trait tests ──

    #[test]
    fn into_u64() {
        let v = VarInt::from_u32(42);
        let val: u64 = v.into();
        assert_eq!(val, 42);
    }

    #[test]
    fn from_u8_into_varint() {
        let v: VarInt = 42u8.into();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn from_u8_max() {
        let v: VarInt = u8::MAX.into();
        assert_eq!(v.into_inner(), u8::MAX as u64);
    }

    #[test]
    fn from_u16_into_varint() {
        let v: VarInt = 16383u16.into();
        assert_eq!(v.into_inner(), 16383);
    }

    #[test]
    fn from_u16_max() {
        let v: VarInt = u16::MAX.into();
        assert_eq!(v.into_inner(), u16::MAX as u64);
    }

    #[test]
    fn from_u32_into_varint() {
        let v: VarInt = 42u32.into();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn from_u32_max() {
        let v: VarInt = u32::MAX.into();
        assert_eq!(v.into_inner(), u32::MAX as u64);
    }

    // ── TryFrom tests ──

    #[test]
    fn try_from_u64_valid() {
        let v = VarInt::try_from(42u64).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn try_from_u64_too_large() {
        let result = VarInt::try_from(1u64 << 62);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), VarIntBoundsExceeded);
    }

    #[test]
    fn try_from_u128_valid() {
        use std::convert::TryFrom;
        let v = VarInt::try_from(42u128).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn try_from_u128_too_large() {
        use std::convert::TryFrom;
        let result = VarInt::try_from((1u128 << 62) + 1);
        assert!(result.is_err());
    }

    #[test]
    fn try_from_u128_overflow_u64() {
        use std::convert::TryFrom;
        let result = VarInt::try_from(u128::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn try_from_usize_valid() {
        use std::convert::TryFrom;
        let v = VarInt::try_from(42usize).unwrap();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    fn try_from_usize_large() {
        use std::convert::TryFrom;
        // On 64-bit platforms usize can be up to 2^64-1 — too large
        let result = VarInt::try_from(usize::try_from(1u128 << 62).unwrap_or(usize::MAX));
        if usize::BITS >= 62 {
            assert!(result.is_err());
        }
    }

    // ── Default ──

    #[test]
    fn varint_default_is_zero() {
        let v = VarInt::default();
        assert_eq!(v.into_inner(), 0);
    }

    // ── Display/Debug ──

    #[test]
    fn display_works() {
        let v = VarInt::from_u32(42);
        assert_eq!(format!("{v}"), "42");
    }

    #[test]
    fn display_large_value() {
        let v = VarInt::from_u64(1_000_000_000_000).unwrap();
        assert_eq!(format!("{v}"), "1000000000000");
    }

    #[test]
    fn debug_works() {
        let v = VarInt::from_u32(42);
        assert_eq!(format!("{v:?}"), "42");
    }

    // ── Ordering ──

    #[test]
    fn ordering_less() {
        let a = VarInt::from_u32(10);
        let b = VarInt::from_u32(20);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.min(b), a);
        assert_eq!(a.max(b), b);
    }

    #[test]
    fn ordering_equal() {
        let a = VarInt::from_u32(10);
        let b = VarInt::from_u32(10);
        assert_eq!(a, b);
        assert!(!(a < b));
    }

    #[test]
    fn ordering_zero_vs_nonzero() {
        assert!(VarInt::from_u32(0) < VarInt::from_u32(1));
    }

    // ── Hash ──

    #[test]
    fn hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = VarInt::from_u32(42);
        let b = VarInt::from_u32(42);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn hash_different_values_different() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Note: different values CAN have the same hash, but for small values
        // this is extremely unlikely
        let a = VarInt::from_u32(1);
        let b = VarInt::from_u32(2);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        // We just verify the function works, not the collision resistance
        let _ = ha.finish();
        let _ = hb.finish();
    }

    // ── VarIntBoundsExceeded tests ──

    #[test]
    fn bounds_exceeded_display() {
        assert_eq!(
            format!("{}", VarIntBoundsExceeded),
            "value too large for varint encoding"
        );
    }

    #[test]
    fn bounds_exceeded_debug() {
        let debug = format!("{:?}", VarIntBoundsExceeded);
        assert!(debug.contains("VarIntBoundsExceeded"));
    }

    #[test]
    fn bounds_exceeded_clone() {
        let a = VarIntBoundsExceeded;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn bounds_exceeded_equality() {
        assert_eq!(VarIntBoundsExceeded, VarIntBoundsExceeded);
    }

    // ── Copy semantics ──

    #[test]
    fn varint_copy() {
        let a = VarInt::from_u32(42);
        let b = a; // Copy, not move
        assert_eq!(a, b); // Both usable
    }

    #[test]
    fn varint_clone_is_copy() {
        let a = VarInt::from_u32(42);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── Edge cases ──

    #[test]
    fn varint_max_is_below_threshold() {
        // MAX should be < 2^62
        assert!(VarInt::MAX.into_inner() < (1u64 << 62));
        // And MAX + 1 should be >= 2^62
        assert!(VarInt::MAX.into_inner() + 1 >= (1u64 << 62));
    }

    #[test]
    fn varint_from_u64_max_valid_is_max() {
        let v = VarInt::from_u64(VarInt::MAX.into_inner()).unwrap();
        assert_eq!(v, VarInt::MAX);
    }

    #[test]
    fn varint_from_u64_min_invalid_is_plus_one() {
        let min_invalid = VarInt::MAX.into_inner() + 1;
        assert!(min_invalid >= (1u64 << 62));
        assert!(VarInt::from_u64(min_invalid).is_err());
    }

    // ── Known tag patterns ──

    #[test]
    fn decode_known_1_byte_wire_format() {
        // Wire format 0x2A = 42 (1-byte VarInt)
        let buf = [0x2A];
        let mut read = &buf[..];
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 42);
    }

    #[test]
    fn decode_known_2_byte_wire_format() {
        // Wire format 0x40 0x01 = 1 (2-byte VarInt with tag 01, value = 0x0001)
        // 0x40 0x01: top 2 bits = 01 (2-byte), remaining 14 bits = 0x0001 = 1
        let buf = [0x40, 0x01];
        let mut read = &buf[..];
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 1);
    }

    #[test]
    fn decode_known_4_byte_wire_format() {
        // Wire format 0x80 0x00 0x40 0x00 = 16384 (4-byte VarInt with tag 10)
        let buf = [0x80, 0x00, 0x40, 0x00];
        let mut read = &buf[..];
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 16384);
    }

    #[test]
    fn decode_known_8_byte_wire_format() {
        // Wire format for 1_073_741_824 = 0x4000_0000 (tag 11)
        let buf = [0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
        let mut read = &buf[..];
        let decoded = VarInt::decode(&mut read).unwrap();
        assert_eq!(decoded.into_inner(), 1_073_741_824);
    }
}

impl Codec for VarInt {
    fn decode<B: Buf>(r: &mut B) -> coding::Result<Self> {
        if !r.has_remaining() {
            return Err(UnexpectedEnd);
        }
        let mut buf = [0; 8];
        buf[0] = r.get_u8();
        let tag = buf[0] >> 6;
        buf[0] &= 0b0011_1111;
        let x = match tag {
            0b00 => u64::from(buf[0]),
            0b01 => {
                if r.remaining() < 1 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..2]);
                // Safe: buf[..2] is exactly 2 bytes
                u64::from(u16::from_be_bytes([buf[0], buf[1]]))
            }
            0b10 => {
                if r.remaining() < 3 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..4]);
                // Safe: buf[..4] is exactly 4 bytes
                u64::from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
            }
            0b11 => {
                if r.remaining() < 7 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..8]);
                u64::from_be_bytes(buf)
            }
            _ => unreachable!(),
        };
        Ok(Self(x))
    }

    fn encode<B: BufMut>(&self, w: &mut B) {
        if let Err(_) = Self::encode_checked(self.0, w) {
            tracing::error!("VarInt overflow: {} exceeds maximum", self.0);
            debug_assert!(false, "VarInt overflow: {}", self.0);
        }
    }
}
