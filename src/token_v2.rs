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

#[derive(Copy, Clone)]
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
