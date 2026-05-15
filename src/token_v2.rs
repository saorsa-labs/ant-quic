// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Token v2: AEAD-protected address validation and binding tokens.
//!
//! This module provides the single token format used by the transport for
//! Retry and NEW_TOKEN address validation, plus optional binding tokens used
//! by trust-model tests. All tokens are encrypted and authenticated with
//! AES-256-GCM and carry a type tag in their plaintext payload.
//!
//! Security features:
//! - AES-256-GCM authenticated encryption
//! - 12-byte nonces for uniqueness
//! - Authentication tags to prevent tampering
//! - Type-tagged payloads for unambiguous decoding
#![allow(missing_docs)]

use std::net::{IpAddr, SocketAddr};

use bytes::{Buf, BufMut};
use rand::RngCore;
use thiserror::Error;

use crate::{Duration, SystemTime, UNIX_EPOCH};
use crate::{nat_traversal_api::PeerId, shared::ConnectionId};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

const NONCE_LEN: usize = 12;

/// A 256-bit key used for encrypting and authenticating tokens.
/// Used with AES-256-GCM for authenticated encryption of token contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenKey(pub [u8; 32]);

/// The decoded contents of a binding token after successful decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingTokenDecoded {
    /// The peer ID that the token was issued for.
    pub peer_id: PeerId,
    /// The connection ID associated with this token.
    pub cid: ConnectionId,
    /// A unique nonce to prevent replay attacks.
    pub nonce: u128,
}

/// The decoded contents of a retry token after successful decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTokenDecoded {
    /// The client's address the token was issued for.
    pub address: SocketAddr,
    /// The destination connection ID from the initial packet.
    pub orig_dst_cid: ConnectionId,
    /// The time the token was issued.
    pub issued: SystemTime,
    /// A unique nonce to prevent replay attacks.
    pub nonce: u128,
}

/// The decoded contents of a validation token after successful decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationTokenDecoded {
    /// The client's IP address the token was issued for.
    pub ip: IpAddr,
    /// The time the token was issued.
    pub issued: SystemTime,
    /// A unique nonce to prevent replay attacks.
    pub nonce: u128,
}

/// Decoded token variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedToken {
    Binding(BindingTokenDecoded),
    Retry(RetryTokenDecoded),
    Validation(ValidationTokenDecoded),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum TokenType {
    Binding = 0,
    Retry = 1,
    Validation = 2,
}

impl TokenType {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(TokenType::Binding),
            1 => Some(TokenType::Retry),
            2 => Some(TokenType::Validation),
            _ => None,
        }
    }
}

/// Errors that can occur while encoding tokens.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Key length was invalid for AES-256-GCM.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// Nonce length was invalid for AES-256-GCM.
    #[error("invalid nonce length")]
    InvalidNonceLength,
    /// Encryption failed.
    #[error("token encryption failed")]
    EncryptionFailed,
}

/// Generate a random token key for testing purposes.
/// Fills a 32-byte array with random data from the provided RNG.
pub fn test_key_from_rng(rng: &mut dyn RngCore) -> TokenKey {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    TokenKey(k)
}

/// Encode a binding token containing peer ID and connection ID.
pub fn encode_binding_token_with_rng<R: RngCore>(
    key: &TokenKey,
    peer_id: &PeerId,
    cid: &ConnectionId,
    rng: &mut R,
) -> Result<Vec<u8>, TokenError> {
    let mut pt = Vec::with_capacity(1 + 32 + 1 + cid.len());
    pt.push(TokenType::Binding as u8);
    pt.extend_from_slice(&peer_id.0);
    pt.push(cid.len() as u8);
    pt.extend_from_slice(&cid[..]);
    seal_with_rng(&key.0, &pt, rng)
}

/// Encode a binding token using the thread RNG.
pub fn encode_binding_token(
    key: &TokenKey,
    peer_id: &PeerId,
    cid: &ConnectionId,
) -> Result<Vec<u8>, TokenError> {
    encode_binding_token_with_rng(key, peer_id, cid, &mut rand::thread_rng())
}

/// Encode a retry token containing the client address, original destination CID, and issue time.
pub fn encode_retry_token_with_rng<R: RngCore>(
    key: &TokenKey,
    address: SocketAddr,
    orig_dst_cid: &ConnectionId,
    issued: SystemTime,
    rng: &mut R,
) -> Result<Vec<u8>, TokenError> {
    let mut pt = Vec::new();
    pt.push(TokenType::Retry as u8);
    encode_addr(&mut pt, address);
    orig_dst_cid.encode_long(&mut pt);
    encode_unix_secs(&mut pt, issued);
    seal_with_rng(&key.0, &pt, rng)
}

/// Encode a retry token using the thread RNG.
pub fn encode_retry_token(
    key: &TokenKey,
    address: SocketAddr,
    orig_dst_cid: &ConnectionId,
    issued: SystemTime,
) -> Result<Vec<u8>, TokenError> {
    encode_retry_token_with_rng(key, address, orig_dst_cid, issued, &mut rand::thread_rng())
}

/// Encode a validation token containing the client IP and issue time.
pub fn encode_validation_token_with_rng<R: RngCore>(
    key: &TokenKey,
    ip: IpAddr,
    issued: SystemTime,
    rng: &mut R,
) -> Result<Vec<u8>, TokenError> {
    let mut pt = Vec::new();
    pt.push(TokenType::Validation as u8);
    encode_ip(&mut pt, ip);
    encode_unix_secs(&mut pt, issued);
    seal_with_rng(&key.0, &pt, rng)
}

/// Encode a validation token using the thread RNG.
pub fn encode_validation_token(
    key: &TokenKey,
    ip: IpAddr,
    issued: SystemTime,
) -> Result<Vec<u8>, TokenError> {
    encode_validation_token_with_rng(key, ip, issued, &mut rand::thread_rng())
}

/// Decode any token variant.
pub fn decode_token(key: &TokenKey, token: &[u8]) -> Option<DecodedToken> {
    let (plaintext, nonce) = open_with_nonce(&key.0, token)?;
    let mut reader = &plaintext[..];
    if !reader.has_remaining() {
        return None;
    }
    let token_type = TokenType::from_byte(reader.get_u8())?;

    let decoded = match token_type {
        TokenType::Binding => {
            if reader.remaining() < 32 + 1 {
                return None;
            }
            let mut pid = [0u8; 32];
            reader.copy_to_slice(&mut pid);
            let cid_len = reader.get_u8() as usize;
            if cid_len > crate::MAX_CID_SIZE || reader.remaining() < cid_len {
                return None;
            }
            let cid = ConnectionId::new(&reader.chunk()[..cid_len]);
            reader.advance(cid_len);
            DecodedToken::Binding(BindingTokenDecoded {
                peer_id: PeerId(pid),
                cid,
                nonce,
            })
        }
        TokenType::Retry => {
            let address = decode_addr(&mut reader)?;
            let orig_dst_cid = ConnectionId::decode_long(&mut reader)?;
            let issued = decode_unix_secs(&mut reader)?;
            DecodedToken::Retry(RetryTokenDecoded {
                address,
                orig_dst_cid,
                issued,
                nonce,
            })
        }
        TokenType::Validation => {
            let ip = decode_ip(&mut reader)?;
            let issued = decode_unix_secs(&mut reader)?;
            DecodedToken::Validation(ValidationTokenDecoded { ip, issued, nonce })
        }
    };

    if reader.has_remaining() {
        return None;
    }

    Some(decoded)
}

/// Decode and validate a binding token, returning the contained peer information.
pub fn decode_binding_token(key: &TokenKey, token: &[u8]) -> Option<BindingTokenDecoded> {
    match decode_token(key, token) {
        Some(DecodedToken::Binding(dec)) => Some(dec),
        _ => None,
    }
}

/// Decode a retry token, returning the contained retry information.
pub fn decode_retry_token(key: &TokenKey, token: &[u8]) -> Option<RetryTokenDecoded> {
    match decode_token(key, token) {
        Some(DecodedToken::Retry(dec)) => Some(dec),
        _ => None,
    }
}

/// Decode a validation token, returning the contained validation information.
pub fn decode_validation_token(key: &TokenKey, token: &[u8]) -> Option<ValidationTokenDecoded> {
    match decode_token(key, token) {
        Some(DecodedToken::Validation(dec)) => Some(dec),
        _ => None,
    }
}

/// Validate a binding token against the expected peer and connection ID.
pub fn validate_binding_token(
    key: &TokenKey,
    token: &[u8],
    expected_peer: &PeerId,
    expected_cid: &ConnectionId,
) -> bool {
    match decode_binding_token(key, token) {
        Some(dec) => dec.peer_id == *expected_peer && dec.cid == *expected_cid,
        None => false,
    }
}

fn nonce_u128_from_bytes(nonce12: [u8; NONCE_LEN]) -> u128 {
    let mut nonce_bytes_16 = [0u8; 16];
    nonce_bytes_16[..NONCE_LEN].copy_from_slice(&nonce12);
    u128::from_le_bytes(nonce_bytes_16)
}

fn open_with_nonce(key: &[u8; 32], token: &[u8]) -> Option<(Vec<u8>, u128)> {
    let (ct, nonce_suffix) = token.split_at(token.len().checked_sub(NONCE_LEN)?);
    let mut nonce12 = [0u8; NONCE_LEN];
    nonce12.copy_from_slice(nonce_suffix);
    let plaintext = open(key, &nonce12, ct).ok()?;
    let nonce = nonce_u128_from_bytes(nonce12);
    Some((plaintext, nonce))
}

/// Encrypt plaintext using AES-256-GCM with a fresh nonce.
fn seal_with_rng<R: RngCore>(
    key: &[u8; 32],
    pt: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, TokenError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    seal(key, &nonce_bytes, pt)
}

/// Encrypt plaintext using AES-256-GCM with the provided key and nonce.
/// Returns the ciphertext with authentication tag and nonce suffix.
#[allow(clippy::let_unit_value)]
fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], pt: &[u8]) -> Result<Vec<u8>, TokenError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| TokenError::InvalidKeyLength)?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_bytes = *nonce;
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| TokenError::InvalidNonceLength)?;

    let mut in_out = pt.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| TokenError::EncryptionFailed)?;

    in_out.extend_from_slice(&nonce_bytes);
    Ok(in_out)
}

/// Decrypt ciphertext using AES-256-GCM with the provided key and nonce suffix.
fn open(
    key: &[u8; 32],
    nonce12: &[u8; NONCE_LEN],
    ct_without_suffix: &[u8],
) -> Result<Vec<u8>, ()> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| ())?;
    let key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::try_assume_unique_for_key(nonce12).map_err(|_| ())?;

    let mut in_out = ct_without_suffix.to_vec();
    let plaintext_len = {
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| ())?;
        plaintext.len()
    };
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

fn encode_addr(buf: &mut Vec<u8>, address: SocketAddr) {
    encode_ip(buf, address.ip());
    buf.put_u16(address.port());
}

fn decode_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip(buf)?;
    if buf.remaining() < 2 {
        return None;
    }
    let port = buf.get_u16();
    Some(SocketAddr::new(ip, port))
}

fn encode_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
}

fn decode_ip<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    if !buf.has_remaining() {
        return None;
    }
    match buf.get_u8() {
        0 => {
            if buf.remaining() < 4 {
                return None;
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Some(IpAddr::V4(octets.into()))
        }
        1 => {
            if buf.remaining() < 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Some(IpAddr::V6(octets.into()))
        }
        _ => None,
    }
}

fn encode_unix_secs(buf: &mut Vec<u8>, time: SystemTime) {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    buf.put_u64(secs);
}

fn decode_unix_secs<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    if buf.remaining() < 8 {
        return None;
    }
    let secs = buf.get_u64();
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TokenType tests ──

    #[test]
    fn token_type_binding_from_byte() {
        assert_eq!(TokenType::from_byte(0), Some(TokenType::Binding));
    }

    #[test]
    fn token_type_retry_from_byte() {
        assert_eq!(TokenType::from_byte(1), Some(TokenType::Retry));
    }

    #[test]
    fn token_type_validation_from_byte() {
        assert_eq!(TokenType::from_byte(2), Some(TokenType::Validation));
    }

    #[test]
    fn token_type_from_invalid_byte() {
        assert_eq!(TokenType::from_byte(3), None);
        assert_eq!(TokenType::from_byte(0xFF), None);
    }

    #[test]
    fn token_type_repr_values() {
        assert_eq!(TokenType::Binding as u8, 0);
        assert_eq!(TokenType::Retry as u8, 1);
        assert_eq!(TokenType::Validation as u8, 2);
    }

    // ── TokenKey tests ──

    #[test]
    fn token_key_clone_copy_eq() {
        let key = TokenKey([0xAB; 32]);
        let copied = key;
        assert_eq!(key, copied);
        assert_eq!(key.0[0], 0xAB);
    }

    #[test]
    fn token_key_debug_does_not_leak_key() {
        let key = TokenKey([0xDE; 32]);
        let debug = format!("{key:?}");
        // Should show the array, not leak through redaction
        assert!(debug.contains("TokenKey"));
    }

    #[test]
    fn token_key_inequality() {
        let a = TokenKey([0; 32]);
        let b = TokenKey([1; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_key_from_rng_produces_random_key() {
        let mut rng = rand::thread_rng();
        let key = test_key_from_rng(&mut rng);
        // Key should be 32 bytes and not all zeros
        assert_eq!(key.0.len(), 32);
        assert!(key.0.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_key_from_rng_deterministic() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);
        let key1 = test_key_from_rng(&mut rng);
        let mut rng = Pcg64Mcg::seed_from_u64(42);
        let key2 = test_key_from_rng(&mut rng);
        assert_eq!(key1, key2);
    }

    // ── IP encode/decode tests ──

    #[test]
    fn encode_decode_ipv4_roundtrip() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut buf = Vec::new();
        encode_ip(&mut buf, ip);
        assert_eq!(buf[0], 0); // v4 tag
        assert_eq!(buf.len(), 5); // tag + 4 octets
        let decoded = decode_ip(&mut &buf[..]).unwrap();
        assert_eq!(decoded, ip);
    }

    #[test]
    fn encode_decode_ipv6_roundtrip() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let mut buf = Vec::new();
        encode_ip(&mut buf, ip);
        assert_eq!(buf[0], 1); // v6 tag
        assert_eq!(buf.len(), 17); // tag + 16 octets
        let decoded = decode_ip(&mut &buf[..]).unwrap();
        assert_eq!(decoded, ip);
    }

    #[test]
    fn decode_ip_v4_truncated() {
        let buf = [0, 192, 168]; // only 2 of 4 octets
        assert!(decode_ip(&mut &buf[..]).is_none());
    }

    #[test]
    fn decode_ip_v6_truncated() {
        let mut buf = vec![1u8];
        buf.extend_from_slice(&[0u8; 15]); // 15 of 16 octets
        assert!(decode_ip(&mut &buf[..]).is_none());
    }

    #[test]
    fn decode_ip_empty_buffer() {
        let buf: &[u8] = &[];
        assert!(decode_ip(&mut &buf[..]).is_none());
    }

    #[test]
    fn decode_ip_invalid_tag() {
        let buf = [0x02, 0, 0, 0, 0]; // tag 2 is invalid
        assert!(decode_ip(&mut &buf[..]).is_none());
    }

    // ── Address encode/decode tests ──

    #[test]
    fn encode_decode_addr_v4_roundtrip() {
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let mut buf = Vec::new();
        encode_addr(&mut buf, addr);
        let decoded = decode_addr(&mut &buf[..]).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn encode_decode_addr_v6_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut buf = Vec::new();
        encode_addr(&mut buf, addr);
        let decoded = decode_addr(&mut &buf[..]).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn decode_addr_truncated_port() {
        let buf = vec![0u8, 192, 168, 1, 1]; // IP tag + 4 octets, no port
        assert!(decode_addr(&mut &buf[..]).is_none());
    }

    #[test]
    fn encode_decode_addr_roundtrip_loopback() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut buf = Vec::new();
        encode_addr(&mut buf, addr);
        let decoded = decode_addr(&mut &buf[..]).unwrap();
        assert_eq!(decoded, addr);
    }

    // ── Unix time encode/decode tests ──

    #[test]
    fn encode_decode_unix_secs_roundtrip() {
        let time = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut buf = Vec::new();
        encode_unix_secs(&mut buf, time);
        assert_eq!(buf.len(), 8);
        let decoded = decode_unix_secs(&mut &buf[..]).unwrap();
        assert_eq!(decoded, time);
    }

    #[test]
    fn encode_decode_unix_epoch() {
        let time = UNIX_EPOCH;
        let mut buf = Vec::new();
        encode_unix_secs(&mut buf, time);
        let decoded = decode_unix_secs(&mut &buf[..]).unwrap();
        assert_eq!(decoded, time);
    }

    #[test]
    fn decode_unix_secs_truncated() {
        let buf = [0u8; 7]; // need 8
        assert!(decode_unix_secs(&mut &buf[..]).is_none());
    }

    #[test]
    fn decode_unix_secs_empty() {
        let buf: &[u8] = &[];
        assert!(decode_unix_secs(&mut &buf[..]).is_none());
    }

    #[test]
    fn encode_decode_unix_secs_far_future() {
        let time = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let mut buf = Vec::new();
        encode_unix_secs(&mut buf, time);
        let decoded = decode_unix_secs(&mut &buf[..]).unwrap();
        assert_eq!(decoded, time);
    }

    // ── Encrypt/decrypt roundtrip tests (requires real AES-GCM) ──

    #[test]
    fn seal_open_roundtrip() {
        let key_bytes = [0x42u8; 32];
        let pt = b"hello token world";
        let nonce = [0x01u8; 12];
        let ct = seal(&key_bytes, &nonce, pt).unwrap();
        // Ciphertext should be longer than plaintext (includes auth tag + nonce suffix)
        assert!(ct.len() > pt.len() + 12);
        // Nonce should be appended
        assert_eq!(&ct[ct.len() - 12..], &nonce[..]);

        // Open by splitting off nonce suffix
        let ct_body = &ct[..ct.len() - 12];
        let opened = open(&key_bytes, &nonce, ct_body).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn seal_open_wrong_key_fails() {
        let key_a = [0x42u8; 32];
        let key_b = [0xFFu8; 32];
        let pt = b"secret";
        let nonce = [0x01u8; 12];
        let ct = seal(&key_a, &nonce, pt).unwrap();
        let ct_body = &ct[..ct.len() - 12];
        assert!(open(&key_b, &nonce, ct_body).is_err());
    }

    #[test]
    fn seal_open_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let pt = b"secret";
        let nonce_a = [0x01u8; 12];
        let nonce_b = [0x02u8; 12];
        let ct = seal(&key, &nonce_a, pt).unwrap();
        let ct_body = &ct[..ct.len() - 12];
        assert!(open(&key, &nonce_b, ct_body).is_err());
    }

    #[test]
    fn seal_open_different_plaintexts() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let pt1 = b"message one";
        let pt2 = b"message two";

        let ct1 = seal(&key, &nonce, pt1).unwrap();
        let ct1_body = &ct1[..ct1.len() - 12];

        // Using same nonce with same key produces same ciphertext (deterministic)
        let ct2 = seal(&key, &nonce, pt2).unwrap();
        let ct2_body = &ct2[..ct2.len() - 12];

        assert_ne!(ct1_body, ct2_body);
    }

    #[test]
    fn seal_open_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let pt: &[u8] = &[];
        let ct = seal(&key, &nonce, pt).unwrap();
        let ct_body = &ct[..ct.len() - 12];
        let opened = open(&key, &nonce, ct_body).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn seal_short_ct_fails_open() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        // Too short to contain a valid GCM tag
        let too_short = [0u8; 1];
        assert!(open(&key, &nonce, &too_short).is_err());
    }

    // ── Full binding token roundtrip ──

    #[test]
    fn binding_token_roundtrip() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xAA; 32]);
        let cid = ConnectionId::new(&[0xAB, 0xCD, 0xEF]);

        let token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();
        assert!(!token.is_empty());

        // Decode
        let decoded = decode_binding_token(&key, &token).unwrap();
        assert_eq!(decoded.peer_id, peer_id);
        assert_eq!(decoded.cid, cid);
    }

    #[test]
    fn binding_token_wrong_key_fails() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key_a = test_key_from_rng(&mut rng);
        let key_b = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xBB; 32]);
        let cid = ConnectionId::new(&[0x01, 0x02]);

        let token = encode_binding_token_with_rng(&key_a, &peer_id, &cid, &mut rng).unwrap();
        assert!(decode_binding_token(&key_b, &token).is_none());
    }

    #[test]
    fn binding_token_validate_matches() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xCC; 32]);
        let cid = ConnectionId::new(&[0x01, 0x02, 0x03]);

        let token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();
        assert!(validate_binding_token(&key, &token, &peer_id, &cid));
    }

    #[test]
    fn binding_token_validate_wrong_peer_fails() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xDD; 32]);
        let cid = ConnectionId::new(&[0x01, 0x02]);
        let wrong_peer = PeerId([0xEE; 32]);

        let token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();
        assert!(!validate_binding_token(&key, &token, &wrong_peer, &cid));
    }

    #[test]
    fn binding_token_validate_wrong_cid_fails() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xDD; 32]);
        let cid = ConnectionId::new(&[0x01, 0x02]);
        let wrong_cid = ConnectionId::new(&[0xFF]);

        let token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();
        assert!(!validate_binding_token(&key, &token, &peer_id, &wrong_cid));
    }

    #[test]
    fn binding_token_garbled_data_fails_decode() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0xDD; 32]);
        let cid = ConnectionId::new(&[0x01, 0x02]);

        let mut token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();
        // Corrupt the ciphertext body
        token[5] ^= 0xFF;
        assert!(decode_binding_token(&key, &token).is_none());
    }

    // ── Full retry token roundtrip ──

    #[test]
    fn retry_token_roundtrip() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let addr: SocketAddr = "203.0.113.1:9000".parse().unwrap();
        let cid = ConnectionId::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let issued = UNIX_EPOCH + Duration::from_secs(1_000_000);

        let token = encode_retry_token_with_rng(&key, addr, &cid, issued, &mut rng).unwrap();
        let decoded = decode_retry_token(&key, &token).unwrap();
        assert_eq!(decoded.address, addr);
        assert_eq!(decoded.orig_dst_cid, cid);
        assert_eq!(decoded.issued, issued);
    }

    #[test]
    fn retry_token_wrong_key_fails() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key_a = test_key_from_rng(&mut rng);
        let key_b = test_key_from_rng(&mut rng);
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let cid = ConnectionId::new(&[0x01]);
        let issued = UNIX_EPOCH;

        let token = encode_retry_token_with_rng(&key_a, addr, &cid, issued, &mut rng).unwrap();
        assert!(decode_retry_token(&key_b, &token).is_none());
    }

    // ── Full validation token roundtrip ──

    #[test]
    fn validation_token_roundtrip() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let issued = UNIX_EPOCH + Duration::from_secs(2_000_000);

        let token = encode_validation_token_with_rng(&key, ip, issued, &mut rng).unwrap();
        let decoded = decode_validation_token(&key, &token).unwrap();
        assert_eq!(decoded.ip, ip);
        assert_eq!(decoded.issued, issued);
    }

    #[test]
    fn validation_token_roundtrip_ipv6() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let issued = UNIX_EPOCH;

        let token = encode_validation_token_with_rng(&key, ip, issued, &mut rng).unwrap();
        let decoded = decode_validation_token(&key, &token).unwrap();
        assert_eq!(decoded.ip, ip);
    }

    // ── decode_token dispatch tests ──

    #[test]
    fn decode_token_dispatches_binding() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let peer_id = PeerId([0x11; 32]);
        let cid = ConnectionId::new(&[0x22]);
        let token = encode_binding_token_with_rng(&key, &peer_id, &cid, &mut rng).unwrap();

        let decoded = decode_token(&key, &token).unwrap();
        assert!(matches!(decoded, DecodedToken::Binding(_)));
    }

    #[test]
    fn decode_token_dispatches_retry() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let cid = ConnectionId::new(&[0x33]);
        let issued = UNIX_EPOCH;
        let token = encode_retry_token_with_rng(&key, addr, &cid, issued, &mut rng).unwrap();

        let decoded = decode_token(&key, &token).unwrap();
        assert!(matches!(decoded, DecodedToken::Retry(_)));
    }

    #[test]
    fn decode_token_dispatches_validation() {
        use rand::SeedableRng;
        use rand_pcg::Pcg64Mcg;
        let mut rng = Pcg64Mcg::seed_from_u64(42);

        let key = test_key_from_rng(&mut rng);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let issued = UNIX_EPOCH;
        let token = encode_validation_token_with_rng(&key, ip, issued, &mut rng).unwrap();

        let decoded = decode_token(&key, &token).unwrap();
        assert!(matches!(decoded, DecodedToken::Validation(_)));
    }

    #[test]
    fn decode_token_empty_returns_none() {
        let key = TokenKey([0; 32]);
        assert!(decode_token(&key, &[]).is_none());
    }

    #[test]
    fn decode_token_garbage_returns_none() {
        let key = TokenKey([0; 32]);
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        assert!(decode_token(&key, &garbage).is_none());
    }

    // ── Nonce helper tests ──

    #[test]
    fn nonce_u128_from_bytes_properly_pads() {
        let nonce12 = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let val = nonce_u128_from_bytes(nonce12);
        // The top 32 bits should be zero (since we only copied 12 bytes into 16)
        let restored = val.to_le_bytes();
        assert_eq!(&restored[..12], &nonce12[..]);
        assert_eq!(&restored[12..], &[0, 0, 0, 0]);
    }

    #[test]
    fn nonce_u128_from_bytes_different_values() {
        let a = nonce_u128_from_bytes([0x01u8; 12]);
        let b = nonce_u128_from_bytes([0x02u8; 12]);
        assert_ne!(a, b);
    }

    // ── TokenError tests ──

    #[test]
    fn token_error_display() {
        assert_eq!(
            format!("{}", TokenError::InvalidKeyLength),
            "invalid key length"
        );
        assert_eq!(
            format!("{}", TokenError::InvalidNonceLength),
            "invalid nonce length"
        );
        assert_eq!(
            format!("{}", TokenError::EncryptionFailed),
            "token encryption failed"
        );
    }

    #[test]
    fn token_error_debug() {
        let err = TokenError::EncryptionFailed;
        let debug = format!("{err:?}");
        assert!(debug.contains("EncryptionFailed"));
    }

    #[test]
    fn token_error_equality() {
        assert_eq!(TokenError::InvalidKeyLength, TokenError::InvalidKeyLength);
        assert_ne!(TokenError::InvalidKeyLength, TokenError::EncryptionFailed);
    }

    #[test]
    fn token_error_clone() {
        let err = TokenError::EncryptionFailed;
        assert_eq!(err.clone(), err);
    }

    // ── DecodedToken value extraction tests ──

    #[test]
    fn decoded_token_binding_accessors() {
        let decoded = DecodedToken::Binding(BindingTokenDecoded {
            peer_id: PeerId([0x11; 32]),
            cid: ConnectionId::new(&[0x22, 0x33]),
            nonce: 42,
        });
        if let DecodedToken::Binding(b) = &decoded {
            assert_eq!(b.peer_id.0[0], 0x11);
            assert_eq!(b.cid.len(), 2);
            assert_eq!(b.nonce, 42);
        } else {
            panic!("expected Binding variant");
        }
    }

    #[test]
    fn decoded_token_equality() {
        let a = DecodedToken::Binding(BindingTokenDecoded {
            peer_id: PeerId([0; 32]),
            cid: ConnectionId::new(&[1]),
            nonce: 0,
        });
        let b = DecodedToken::Binding(BindingTokenDecoded {
            peer_id: PeerId([0; 32]),
            cid: ConnectionId::new(&[1]),
            nonce: 0,
        });
        assert_eq!(a, b);
    }

    #[test]
    fn decoded_token_variant_inequality() {
        let binding = DecodedToken::Binding(BindingTokenDecoded {
            peer_id: PeerId([0; 32]),
            cid: ConnectionId::new(&[1]),
            nonce: 0,
        });
        let retry = DecodedToken::Retry(RetryTokenDecoded {
            address: "127.0.0.1:9000".parse().unwrap(),
            orig_dst_cid: ConnectionId::new(&[1]),
            issued: UNIX_EPOCH,
            nonce: 0,
        });
        assert_ne!(binding, retry);
    }
}
