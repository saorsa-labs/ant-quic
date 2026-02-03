// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{fmt, net::SocketAddr};

use bytes::Bytes;

use crate::{
    Duration, RESET_TOKEN_SIZE, ServerConfig, SystemTime, crypto::HmacKey, packet::InitialHeader,
    shared::ConnectionId,
};

/// Responsible for limiting clients' ability to reuse validation tokens
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
///
/// `TokenLog` pertains only to tokens provided in NEW_TOKEN frames.
pub trait TokenLog: Send + Sync {
    /// Record that the token was used and, ideally, return a token reuse error if the token may
    /// have been already used previously
    ///
    /// False negatives and false positives are both permissible. Called when a client uses an
    /// address validation token.
    ///
    /// Parameters:
    /// - `nonce`: A server-generated random unique value for the token.
    /// - `issued`: The time the server issued the token.
    /// - `lifetime`: The expiration time of address validation tokens sent via NEW_TOKEN frames,
    ///   as configured by [`ValidationTokenConfig::lifetime`][1].
    ///
    /// [1]: crate::config::ValidationTokenConfig::lifetime
    ///
    /// ## Security & Performance
    ///
    /// To the extent that it is possible to repeatedly trigger false negatives (returning `Ok` for
    /// a token which has been reused), an attacker could use the server to perform [amplification
    /// attacks][2]. The QUIC specification requires that this be limited, if not prevented fully.
    ///
    /// A false positive (returning `Err` for a token which has never been used) is not a security
    /// vulnerability; it is permissible for a `TokenLog` to always return `Err`. A false positive
    /// causes the token to be ignored, which may cause the transmission of some 0.5-RTT data to be
    /// delayed until the handshake completes, if a sufficient amount of 0.5-RTT data it sent.
    ///
    /// [2]: https://en.wikipedia.org/wiki/Denial-of-service_attack#Amplification
    fn check_and_insert(
        &self,
        nonce: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// Error for when a validation token may have been reused
pub struct TokenReuseError;

/// Null implementation of [`TokenLog`], which never accepts tokens
pub(crate) struct NoneTokenLog;

impl TokenLog for NoneTokenLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        Err(TokenReuseError)
    }
}

/// Responsible for storing validation tokens received from servers and retrieving them for use in
/// subsequent connections
pub trait TokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn insert(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// Null implementation of [`TokenStore`], which does not store any tokens
#[allow(dead_code)]
pub(crate) struct NoneTokenStore;

impl TokenStore for NoneTokenStore {
    fn insert(&self, _: &str, _: Bytes) {}
    fn take(&self, _: &str) -> Option<Bytes> {
        None
    }
}

/// State in an `Incoming` determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingToken {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
    pub(crate) validated: bool,
}

impl IncomingToken {
    /// Construct for an `Incoming` given the first packet header, or error if the connection
    /// cannot be established
    pub(crate) fn from_header(
        header: &InitialHeader,
        server_config: &ServerConfig,
        remote_address: SocketAddr,
    ) -> Result<Self, InvalidRetryTokenError> {
        let unvalidated = Self {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
            validated: false,
        };

        // Decode token or short-circuit
        if header.token.is_empty() {
            return Ok(unvalidated);
        }

        // In cases where a token cannot be decrypted/decoded, we must allow for the possibility
        // that this is caused not by client malfeasance, but by the token having been generated by
        // an incompatible endpoint, e.g. a different version or a neighbor behind the same load
        // balancer. In such cases we proceed as if there was no token.
        //
        // [_RFC 9000 § 8.1.3:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3-10)
        //
        // > If the token is invalid, then the server SHOULD proceed as if the client did not have
        // > a validated address, including potentially sending a Retry packet.

        let Some(decoded) = crate::token_v2::decode_token(&server_config.token_key, &header.token)
        else {
            return Ok(unvalidated);
        };

        match decoded {
            crate::token_v2::DecodedToken::Retry(retry) => {
                if retry.address != remote_address {
                    return Err(InvalidRetryTokenError);
                }
                if retry.issued + server_config.retry_token_lifetime
                    < server_config.time_source.now()
                {
                    return Err(InvalidRetryTokenError);
                }

                Ok(Self {
                    retry_src_cid: Some(header.dst_cid),
                    orig_dst_cid: retry.orig_dst_cid,
                    validated: true,
                })
            }
            crate::token_v2::DecodedToken::Validation(validation) => {
                if validation.ip != remote_address.ip() {
                    return Ok(unvalidated);
                }
                if validation.issued + server_config.validation_token.lifetime
                    < server_config.time_source.now()
                {
                    return Ok(unvalidated);
                }
                if server_config
                    .validation_token
                    .log
                    .check_and_insert(
                        validation.nonce,
                        validation.issued,
                        server_config.validation_token.lifetime,
                    )
                    .is_err()
                {
                    return Ok(unvalidated);
                }

                Ok(Self {
                    retry_src_cid: None,
                    orig_dst_cid: header.dst_cid,
                    validated: true,
                })
            }
            crate::token_v2::DecodedToken::Binding(_) => Ok(unvalidated),
        }
    }
}

/// Error for a token being unambiguously from a Retry packet, and not valid
///
/// The connection cannot be established.
pub(crate) struct InvalidRetryTokenError;

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derived_hash_with_manual_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(&id, &mut signature);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn retry_token_sanity() {
        use crate::MAX_CID_SIZE;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let mut rng = rand::thread_rng();
        let key = crate::token_v2::test_key_from_rng(&mut rng);
        let address_1 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let orig_dst_cid_1 = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost
        let token = crate::token_v2::encode_retry_token_with_rng(
            &key,
            address_1,
            &orig_dst_cid_1,
            issued_1,
            &mut rng,
        )
        .expect("encode retry token");
        let decoded = crate::token_v2::decode_retry_token(&key, &token).expect("decode retry");

        assert_eq!(address_1, decoded.address);
        assert_eq!(orig_dst_cid_1, decoded.orig_dst_cid);
        assert_eq!(issued_1, decoded.issued);
    }

    #[test]
    fn validation_token_sanity() {
        use crate::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let mut rng = rand::thread_rng();
        let key = crate::token_v2::test_key_from_rng(&mut rng);
        let ip_1 = Ipv6Addr::LOCALHOST.into();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost
        let token =
            crate::token_v2::encode_validation_token_with_rng(&key, ip_1, issued_1, &mut rng)
                .expect("encode validation token");
        let decoded = crate::token_v2::decode_validation_token(&key, &token)
            .expect("decode validation token");

        assert_eq!(ip_1, decoded.ip);
        assert_eq!(issued_1, decoded.issued);
    }

    #[test]
    fn invalid_token_returns_err() {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let key = crate::token_v2::test_key_from_rng(&mut rng);

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(crate::token_v2::decode_token(&key, &invalid_token).is_none());
    }
}
