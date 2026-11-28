// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Local UDP socket slot identity and process-internal synthetic ULA virtual-path
//! addressing (ADR-021 Wave 4 Phase 4A-2).
//!
//! # Path Identity
//!
//! A validated QUIC path on a unified [`crate::high_level::MultiplexedUdpSocket`]
//! is identified by `(remote_addr, local_slot)`, not `remote_addr` alone. Physical UDP
//! bind slots use `SocketSlotId(0..MAX_PHYSICAL_SLOTS)` while MASQUE virtual relay routes
//! use `SocketSlotId::VIRTUAL`.
//!
//! # Synthetic ULA Virtual-Path Address Space
//!
//! Every active virtual MASQUE route `(relay_slot, target_addr)` is assigned a unique
//! process-internal IPv6 `SocketAddr` inside `fd00:53a0:5251::/48`:
//!
//! ```text
//! [ 48 bits: fd00:53a0:5251 ][ 16 bits: relay_slot ][ 32 bits: route_gen ][ 32 bits: target_idx ]
//! port: target_addr.port().max(1)
//! ```
//!
//! Addresses matching [`is_synthetic_virtual_ip`] are strictly process-internal and MUST
//! NEVER be transmitted on any physical socket or admitted/emitted by any NAT traversal
//! frame or candidate discovery store.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// Maximum number of physical UDP bind slots per [`crate::high_level::MultiplexedUdpSocket`].
///
/// Slot `0` is the primary dual-stack bind (e.g. `:443` on a dual-port VPS, or an
/// ephemeral high port on a client). Additional opt-in bind ports (e.g. `:5483`) occupy
/// slots `1..MAX_PHYSICAL_SLOTS`.
pub const MAX_PHYSICAL_SLOTS: usize = 4;

/// Maximum number of active virtual MASQUE routes tracked by a single
/// `MultiplexedUdpSocket` (ADR-014 / ADR-021).
pub const MAX_VIRTUAL_ROUTES: usize = 4096;

/// Process-internal reserved ULA prefix (`fd00:53a0:5251::/48`, RFC 4193) for virtual
/// MASQUE relay paths inside `MultiplexedUdpSocket` (ADR-021).
///
/// Must NEVER leave the local process on any physical socket or protocol frame.
pub const SYNTHETIC_VIRTUAL_ULA_PREFIX: [u8; 6] = [0xfd, 0x00, 0x53, 0xa0, 0x52, 0x51];

/// Minimum inner 1-RTT virtual path MTU floor (bytes), matching ADR-020 / ADR-021.
pub const MIN_VIRTUAL_PATH_MTU: u16 = 900;

/// Maximum inner 1-RTT virtual path MTU ceiling (bytes), matching ADR-020 / ADR-021.
pub const MAX_VIRTUAL_PATH_MTU: u16 = 1380;

/// Identifies the local socket group (physical bind slot or virtual MASQUE route plane)
/// on which a QUIC datagram was received or must be transmitted (ADR-021).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SocketSlotId(pub u8);

impl SocketSlotId {
    /// Primary physical dual-stack bind slot (slot `0`).
    pub const PRIMARY: Self = Self(0);

    /// Virtual MASQUE relay route plane (`u8::MAX`).
    pub const VIRTUAL: Self = Self(u8::MAX);

    /// Create a physical slot identifier if `index < MAX_PHYSICAL_SLOTS`.
    #[inline]
    pub const fn physical(index: usize) -> Option<Self> {
        if index < MAX_PHYSICAL_SLOTS {
            Some(Self(index as u8))
        } else {
            None
        }
    }

    /// Returns `true` if this slot refers to a physical UDP bind slot.
    #[inline]
    pub const fn is_physical(self) -> bool {
        (self.0 as usize) < MAX_PHYSICAL_SLOTS
    }

    /// Returns `true` if this slot refers to the virtual MASQUE relay route plane.
    #[inline]
    pub const fn is_virtual(self) -> bool {
        self.0 == Self::VIRTUAL.0
    }

    /// Returns the physical slot index (`0..MAX_PHYSICAL_SLOTS`) if physical.
    #[inline]
    pub const fn physical_index(self) -> Option<usize> {
        if self.is_physical() {
            Some(self.0 as usize)
        } else {
            None
        }
    }
}

impl Default for SocketSlotId {
    #[inline]
    fn default() -> Self {
        Self::PRIMARY
    }
}

/// Returns `true` if `ip` belongs to the process-internal synthetic ULA virtual-path
/// prefix (`fd00:53a0:5251::/48`, ADR-021).
#[inline]
pub fn is_synthetic_virtual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.octets()[..6] == SYNTHETIC_VIRTUAL_ULA_PREFIX,
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` if `addr`'s IP belongs to the process-internal synthetic ULA
/// virtual-path prefix (`fd00:53a0:5251::/48`, ADR-021).
#[inline]
pub fn is_synthetic_virtual_addr(addr: SocketAddr) -> bool {
    is_synthetic_virtual_ip(addr.ip())
}

/// Construct a deterministic process-internal synthetic ULA `SocketAddr` for a virtual
/// MASQUE relay route (ADR-021).
///
/// Layout: `[ 48 bits: fd00:53a0:5251 ][ 16 bits: relay_slot ][ 32 bits: route_gen ][ 32 bits: target_idx ]`
/// with port `target_port.max(1)`.
#[inline]
pub fn make_synthetic_virtual_addr(
    relay_slot: u16,
    route_gen: u32,
    target_idx: u32,
    target_port: u16,
) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets[0..6].copy_from_slice(&SYNTHETIC_VIRTUAL_ULA_PREFIX);
    octets[6..8].copy_from_slice(&relay_slot.to_be_bytes());
    octets[8..12].copy_from_slice(&route_gen.to_be_bytes());
    octets[12..16].copy_from_slice(&target_idx.to_be_bytes());
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(octets),
        target_port.max(1),
        0,
        0,
    ))
}

/// Decode `(relay_slot, route_gen, target_idx)` from a process-internal synthetic ULA
/// `SocketAddr`. Returns `None` if `addr` is not inside `fd00:53a0:5251::/48`.
#[inline]
pub fn decode_synthetic_virtual_addr(addr: SocketAddr) -> Option<(u16, u32, u32)> {
    let SocketAddr::V6(v6) = addr else {
        return None;
    };
    let octets = v6.ip().octets();
    if octets[..6] != SYNTHETIC_VIRTUAL_ULA_PREFIX {
        return None;
    }
    let relay_slot = u16::from_be_bytes([octets[6], octets[7]]);
    let route_gen = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
    let target_idx = u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
    Some((relay_slot, route_gen, target_idx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn socket_slot_id_classification() {
        assert!(SocketSlotId::PRIMARY.is_physical());
        assert!(!SocketSlotId::PRIMARY.is_virtual());
        assert_eq!(SocketSlotId::PRIMARY.physical_index(), Some(0));

        for idx in 0..MAX_PHYSICAL_SLOTS {
            let slot = SocketSlotId::physical(idx).expect("valid physical slot");
            assert!(slot.is_physical());
            assert!(!slot.is_virtual());
            assert_eq!(slot.physical_index(), Some(idx));
        }
        assert!(SocketSlotId::physical(MAX_PHYSICAL_SLOTS).is_none());

        assert!(SocketSlotId::VIRTUAL.is_virtual());
        assert!(!SocketSlotId::VIRTUAL.is_physical());
        assert_eq!(SocketSlotId::VIRTUAL.physical_index(), None);
    }

    #[test]
    fn synthetic_ula_roundtrip_and_isolation() {
        let addr = make_synthetic_virtual_addr(7, 42, 1234, 443);
        assert!(is_synthetic_virtual_addr(addr));
        assert!(is_synthetic_virtual_ip(addr.ip()));
        assert_eq!(addr.port(), 443);
        assert_eq!(decode_synthetic_virtual_addr(addr), Some((7, 42, 1234)));

        // Port 0 clamps to 1 so QUIC connect() never rejects synthetic targets for port==0.
        let zero_port = make_synthetic_virtual_addr(0, 1, 2, 0);
        assert_eq!(zero_port.port(), 1);
        assert!(is_synthetic_virtual_addr(zero_port));

        // Real IPv4, IPv4-mapped IPv6, and unrelated ULA addresses must NOT match.
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mapped_v6 = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
            443,
        );
        let other_ula = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0, 0, 0, 0, 1)),
            443,
        );
        assert!(!is_synthetic_virtual_addr(v4));
        assert!(!is_synthetic_virtual_addr(mapped_v6));
        assert!(!is_synthetic_virtual_addr(other_ula));
        assert_eq!(decode_synthetic_virtual_addr(v4), None);
        assert_eq!(decode_synthetic_virtual_addr(other_ula), None);
    }
}
