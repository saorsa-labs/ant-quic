// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! HTTP CONNECT-UDP Bind Request/Response Types
//!
//! Implements the HTTP Extended CONNECT mechanism for establishing MASQUE relay
//! connections per RFC 9298 (CONNECT-UDP) and draft-ietf-masque-connect-udp-listen-10.
//!
//! # Protocol Overview
//!
//! CONNECT-UDP uses HTTP Extended CONNECT (RFC 8441) over HTTP/3:
//!
//! ```text
//! Client                                          Relay
//!   |                                               |
//!   |  HEADERS (Extended CONNECT with :protocol)    |
//!   |---------------------------------------------->|
//!   |                                               |
//!   |  HEADERS (200 OK + Proxy-Public-Address)      |
//!   |<----------------------------------------------|
//!   |                                               |
//!   |  <-- Capsules and Datagrams flow -->          |
//! ```
//!
//! # CONNECT-UDP Bind Extension
//!
//! The bind extension allows requesting a public address for inbound connections:
//! - Target host `"::"` indicates bind-any (IPv4 and IPv6)
//! - Target port `0` indicates let the relay choose a port
//! - The relay responds with the public address it allocated
//!
//! # Example
//!
//! ```rust
//! use ant_quic::masque::connect::{ConnectUdpRequest, ConnectUdpResponse};
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//!
//! // Create a bind request
//! let request = ConnectUdpRequest::bind_any();
//! assert!(request.is_bind_request());
//!
//! // Create a targeted request
//! let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
//! let request = ConnectUdpRequest::target(target);
//! assert!(!request.is_bind_request());
//!
//! // Parse a successful response
//! let response = ConnectUdpResponse::success(
//!     Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 9000))
//! );
//! assert!(response.is_success());
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

use crate::VarInt;
use crate::coding::Codec;

/// The protocol identifier for Extended CONNECT
pub const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

/// The protocol identifier for CONNECT-UDP Bind extension
pub const CONNECT_UDP_BIND_PROTOCOL: &str = "connect-udp-bind";

/// Bind-any host (indicates relay should choose)
pub const BIND_ANY_HOST: &str = "::";

/// Bind-any port (indicates relay should choose)
pub const BIND_ANY_PORT: u16 = 0;

/// Request flag bit: this is a CONNECT-UDP Bind request.
pub const REQUEST_FLAG_BIND: u8 = 0x01;

/// Request flag bit (ADR-016 hybrid signal): the client reads the QUIC
/// `DATAGRAM` lane for this relay session and asks the relay to use it.
///
/// Decoders before 0.29.0 ignore unknown flag bits, so an old relay treats
/// the request as stream-only and never sets
/// [`RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`] in its answer.
pub const REQUEST_FLAG_HYBRID_DATAGRAM_LANE: u8 = 0x02;

/// Request flag bit (ADR-020 / ant-quic 0.30.0): the client supports RFC 9297
/// Context-ID datagram demultiplexing (`DatagramMux`), stream-carried
/// `COMPRESSION_ASSIGN` / `ECN_COMPRESSION_ASSIGN` capsules, and 4-context ECN
/// mapping (`draft-seemann-masque-connect-udp-ecn-01`).
///
/// Decoders before 0.30.0 ignore this bit. When another datagram reader (e.g.
/// `LinkConn::recv_datagrams`) is already active on the outer connection, a
/// 0.30.0+ client sets this bit WITHOUT [`REQUEST_FLAG_HYBRID_DATAGRAM_LANE`]
/// so a 0.29.0 relay falls back cleanly to stream-only while a 0.30.0+ relay
/// accepts muxed hybrid.
pub const REQUEST_FLAG_DATAGRAM_MUX_V1: u8 = 0x04;

/// Response flag bit: a public address follows.
pub const RESPONSE_FLAG_HAS_ADDRESS: u8 = 0x01;

/// Response flag bit: a reason phrase follows.
pub const RESPONSE_FLAG_HAS_REASON: u8 = 0x02;

/// Response flag bit (ADR-016 hybrid signal): the relay accepted the
/// client's [`REQUEST_FLAG_HYBRID_DATAGRAM_LANE`] (or
/// [`REQUEST_FLAG_DATAGRAM_MUX_V1`]) for this session. Both ends then read and
/// may send on the QUIC `DATAGRAM` lane.
///
/// A relay sets it only in answer to a request that carried a hybrid bit, so a
/// client before 0.29.0 never receives it.
pub const RESPONSE_FLAG_HYBRID_DATAGRAM_LANE: u8 = 0x04;

/// Response flag bit (ADR-020 / ant-quic 0.30.0): the relay accepted
/// [`REQUEST_FLAG_DATAGRAM_MUX_V1`] for this session (RFC 9297 Context-ID
/// demultiplexing, compressed datagrams, and ECN propagation).
///
/// Only set in answer to a request carrying [`REQUEST_FLAG_DATAGRAM_MUX_V1`].
pub const RESPONSE_FLAG_DATAGRAM_MUX_V1: u8 = 0x08;

/// Errors that can occur during CONNECT-UDP processing
#[derive(Debug, Error)]
pub enum ConnectError {
    /// Invalid request format
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Invalid response format
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Request was rejected by relay
    #[error("rejected: status {status}, reason: {reason}")]
    Rejected {
        /// HTTP status code
        status: u16,
        /// Human-readable reason
        reason: String,
    },

    /// Encoding/decoding error
    #[error("codec error")]
    Codec,

    /// Connection failed
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

/// HTTP CONNECT-UDP Request
///
/// Represents an Extended CONNECT request for establishing a UDP proxy session.
/// Can be either a targeted request (proxy to specific destination) or a bind
/// request (request public address for inbound connections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    /// Target host ("::" for bind-any)
    pub target_host: String,
    /// Target port (0 for bind-any)
    pub target_port: u16,
    /// Whether this is a bind request (vs. targeted proxy)
    pub connect_udp_bind: bool,
    /// ADR-016 per-session hybrid signal: the client reads the QUIC
    /// `DATAGRAM` lane for this session and asks the relay to use it.
    ///
    /// Encoded as request flag bit [`REQUEST_FLAG_HYBRID_DATAGRAM_LANE`].
    /// Peers before 0.29.0 never set it, and their decoders ignore it.
    pub hybrid_datagram_lane: bool,
    /// ADR-020 per-session RFC 9297 Context-ID `DatagramMux` + compression +
    /// ECN signal (ant-quic 0.30.0+).
    ///
    /// Encoded as request flag bit [`REQUEST_FLAG_DATAGRAM_MUX_V1`].
    /// Peers before 0.30.0 never set it, and their decoders ignore it.
    pub datagram_mux_v1: bool,
}

impl ConnectUdpRequest {
    /// Create a bind-any request
    ///
    /// Requests the relay allocate a public address for receiving inbound
    /// connections. The relay will choose both the IP and port.
    pub fn bind_any() -> Self {
        Self {
            target_host: BIND_ANY_HOST.to_string(),
            target_port: BIND_ANY_PORT,
            connect_udp_bind: true,
            hybrid_datagram_lane: false,
            datagram_mux_v1: false,
        }
    }

    /// Create a bind request for a specific port
    ///
    /// Requests the relay allocate a public address with a specific port.
    /// The relay may reject this if the port is unavailable.
    pub fn bind_port(port: u16) -> Self {
        Self {
            target_host: BIND_ANY_HOST.to_string(),
            target_port: port,
            connect_udp_bind: true,
            hybrid_datagram_lane: false,
            datagram_mux_v1: false,
        }
    }

    /// Create a targeted proxy request
    ///
    /// Requests the relay forward UDP traffic to a specific destination.
    /// This is the standard CONNECT-UDP mode (not bind).
    pub fn target(addr: SocketAddr) -> Self {
        Self {
            target_host: addr.ip().to_string(),
            target_port: addr.port(),
            connect_udp_bind: false,
            hybrid_datagram_lane: false,
            datagram_mux_v1: false,
        }
    }

    /// Set the ADR-016 hybrid signal on this request (see
    /// [`Self::hybrid_datagram_lane`]).
    #[must_use]
    pub fn with_hybrid_datagram_lane(mut self, hybrid: bool) -> Self {
        self.hybrid_datagram_lane = hybrid;
        self
    }

    /// Set the ADR-020 Context-ID `DatagramMux` + compression + ECN signal on
    /// this request (see [`Self::datagram_mux_v1`]).
    #[must_use]
    pub fn with_datagram_mux_v1(mut self, mux_v1: bool) -> Self {
        self.datagram_mux_v1 = mux_v1;
        self
    }

    /// Check if this is a bind request
    pub fn is_bind_request(&self) -> bool {
        self.connect_udp_bind
    }

    /// Check if this is a bind-any request (both host and port unspecified)
    pub fn is_bind_any(&self) -> bool {
        self.connect_udp_bind
            && (self.target_host == BIND_ANY_HOST || self.target_host == "0.0.0.0")
            && self.target_port == BIND_ANY_PORT
    }

    /// Get the target socket address if this is a targeted request
    pub fn target_addr(&self) -> Option<SocketAddr> {
        if self.is_bind_request() {
            return None;
        }

        let ip: IpAddr = self.target_host.parse().ok()?;
        Some(SocketAddr::new(ip, self.target_port))
    }

    /// Alias for target_addr for consistency
    pub fn target_address(&self) -> Option<SocketAddr> {
        self.target_addr()
    }

    /// Get the protocol string for HTTP headers
    pub fn protocol(&self) -> &'static str {
        if self.connect_udp_bind {
            CONNECT_UDP_BIND_PROTOCOL
        } else {
            CONNECT_UDP_PROTOCOL
        }
    }

    /// Encode the request as a wire format message
    ///
    /// Format: `[flags (1)] [host_len (varint)] [host] [port (2)]`
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Flags byte: bit 0 = connect_udp_bind, bit 1 = ADR-016 hybrid signal,
        // bit 2 = ADR-020 datagram_mux_v1
        let mut flags: u8 = 0;
        if self.connect_udp_bind {
            flags |= REQUEST_FLAG_BIND;
        }
        if self.hybrid_datagram_lane {
            flags |= REQUEST_FLAG_HYBRID_DATAGRAM_LANE;
        }
        if self.datagram_mux_v1 {
            flags |= REQUEST_FLAG_DATAGRAM_MUX_V1;
        }
        buf.put_u8(flags);

        // Host length and host
        let host_bytes = self.target_host.as_bytes();
        if let Ok(len) = VarInt::from_u64(host_bytes.len() as u64) {
            len.encode(&mut buf);
        }
        buf.put_slice(host_bytes);

        // Port (network byte order)
        buf.put_u16(self.target_port);

        buf.freeze()
    }

    /// Decode a request from wire format
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ConnectError> {
        if buf.remaining() < 1 {
            return Err(ConnectError::InvalidRequest("buffer too short".into()));
        }

        let flags = buf.get_u8();
        let connect_udp_bind = (flags & REQUEST_FLAG_BIND) != 0;
        let hybrid_datagram_lane = (flags & REQUEST_FLAG_HYBRID_DATAGRAM_LANE) != 0;
        let datagram_mux_v1 = (flags & REQUEST_FLAG_DATAGRAM_MUX_V1) != 0;

        let host_len = VarInt::decode(buf)
            .map_err(|_| ConnectError::InvalidRequest("invalid host length".into()))?;
        let host_len = host_len.into_inner() as usize;

        if buf.remaining() < host_len + 2 {
            return Err(ConnectError::InvalidRequest(
                "buffer too short for host".into(),
            ));
        }

        let mut host_bytes = vec![0u8; host_len];
        buf.copy_to_slice(&mut host_bytes);
        let target_host = String::from_utf8(host_bytes)
            .map_err(|_| ConnectError::InvalidRequest("invalid UTF-8 in host".into()))?;

        let target_port = buf.get_u16();

        Ok(Self {
            target_host,
            target_port,
            connect_udp_bind,
            hybrid_datagram_lane,
            datagram_mux_v1,
        })
    }
}

impl fmt::Display for ConnectUdpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_bind_request() {
            write!(
                f,
                "CONNECT-UDP-BIND {}:{}",
                self.target_host, self.target_port
            )
        } else {
            write!(f, "CONNECT-UDP {}:{}", self.target_host, self.target_port)
        }
    }
}

/// HTTP CONNECT-UDP Response
///
/// Represents the relay's response to a CONNECT-UDP request.
/// Includes the allocated public address for bind requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpResponse {
    /// HTTP status code (200 = success, 4xx/5xx = error)
    pub status: u16,
    /// Public address allocated by relay (for bind requests)
    pub proxy_public_address: Option<SocketAddr>,
    /// Human-readable reason phrase
    pub reason: Option<String>,
    /// ADR-016 per-session hybrid signal: the relay accepted the client's
    /// request to use the QUIC `DATAGRAM` lane for this session.
    ///
    /// Encoded as response flag bit [`RESPONSE_FLAG_HYBRID_DATAGRAM_LANE`].
    pub hybrid_datagram_lane: bool,
    /// ADR-020 per-session RFC 9297 Context-ID `DatagramMux` + compression +
    /// ECN acceptance (ant-quic 0.30.0+).
    ///
    /// Encoded as response flag bit [`RESPONSE_FLAG_DATAGRAM_MUX_V1`].
    pub datagram_mux_v1: bool,
}

impl ConnectUdpResponse {
    /// HTTP status code for success
    pub const STATUS_OK: u16 = 200;
    /// HTTP status code for bad request
    pub const STATUS_BAD_REQUEST: u16 = 400;
    /// HTTP status code for forbidden
    pub const STATUS_FORBIDDEN: u16 = 403;
    /// HTTP status code for not found
    pub const STATUS_NOT_FOUND: u16 = 404;
    /// HTTP status code for service unavailable
    pub const STATUS_UNAVAILABLE: u16 = 503;

    /// Create a successful response with an allocated public address
    pub fn success(public_addr: Option<SocketAddr>) -> Self {
        Self {
            status: Self::STATUS_OK,
            proxy_public_address: public_addr,
            reason: None,
            hybrid_datagram_lane: false,
            datagram_mux_v1: false,
        }
    }

    /// Set the ADR-016 hybrid signal on this response (see
    /// [`Self::hybrid_datagram_lane`]).
    #[must_use]
    pub fn with_hybrid_datagram_lane(mut self, hybrid: bool) -> Self {
        self.hybrid_datagram_lane = hybrid;
        self
    }

    /// Set the ADR-020 Context-ID `DatagramMux` + compression + ECN acceptance
    /// on this response (see [`Self::datagram_mux_v1`]).
    #[must_use]
    pub fn with_datagram_mux_v1(mut self, mux_v1: bool) -> Self {
        self.datagram_mux_v1 = mux_v1;
        self
    }

    /// Create an error response
    pub fn error(status: u16, reason: impl Into<String>) -> Self {
        Self {
            status,
            proxy_public_address: None,
            reason: Some(reason.into()),
            hybrid_datagram_lane: false,
            datagram_mux_v1: false,
        }
    }

    /// Create a bad request response
    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::error(Self::STATUS_BAD_REQUEST, reason)
    }

    /// Create a forbidden response
    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::error(Self::STATUS_FORBIDDEN, reason)
    }

    /// Create a service unavailable response
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::error(Self::STATUS_UNAVAILABLE, reason)
    }

    /// Reason phrase a node with relay serving turned off sends with its
    /// `403` answer (ADR-019).
    pub const REASON_RELAY_SERVICE_DISABLED: &'static str = "relay service disabled";

    /// The answer of a node whose relay serving is turned off (ADR-019):
    /// status `403` with reason [`Self::REASON_RELAY_SERVICE_DISABLED`].
    pub fn relay_service_disabled() -> Self {
        Self::forbidden(Self::REASON_RELAY_SERVICE_DISABLED)
    }

    /// Whether this is the ADR-019 policy refusal: status `403` AND reason
    /// [`Self::REASON_RELAY_SERVICE_DISABLED`]. Other `403` answers (for
    /// example `"Authentication required"`) do not match.
    pub fn is_relay_service_disabled(&self) -> bool {
        self.status == Self::STATUS_FORBIDDEN
            && self.reason.as_deref() == Some(Self::REASON_RELAY_SERVICE_DISABLED)
    }

    /// Check if this is a successful response
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.status >= 400
    }

    /// Convert to a Result, extracting the public address on success
    pub fn into_result(self) -> Result<Option<SocketAddr>, ConnectError> {
        if self.is_success() {
            Ok(self.proxy_public_address)
        } else {
            Err(ConnectError::Rejected {
                status: self.status,
                reason: self.reason.unwrap_or_else(|| "unknown".into()),
            })
        }
    }

    /// Encode the response as wire format
    ///
    /// Format: [status (2)] [flags (1)] [addr if present]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Status code
        buf.put_u16(self.status);

        // Flags: bit 0 = has address, bit 1 = has reason,
        // bit 2 = ADR-016 hybrid signal accepted,
        // bit 3 = ADR-020 datagram_mux_v1 accepted
        let mut flags: u8 = 0;
        if self.proxy_public_address.is_some() {
            flags |= RESPONSE_FLAG_HAS_ADDRESS;
        }
        if self.reason.is_some() {
            flags |= RESPONSE_FLAG_HAS_REASON;
        }
        if self.hybrid_datagram_lane {
            flags |= RESPONSE_FLAG_HYBRID_DATAGRAM_LANE;
        }
        if self.datagram_mux_v1 {
            flags |= RESPONSE_FLAG_DATAGRAM_MUX_V1;
        }
        buf.put_u8(flags);

        // Public address if present
        if let Some(addr) = &self.proxy_public_address {
            match addr.ip() {
                IpAddr::V4(v4) => {
                    buf.put_u8(4);
                    buf.put_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.put_u8(6);
                    buf.put_slice(&v6.octets());
                }
            }
            buf.put_u16(addr.port());
        }

        // Reason if present
        if let Some(reason) = &self.reason {
            let reason_bytes = reason.as_bytes();
            if let Ok(len) = VarInt::from_u64(reason_bytes.len() as u64) {
                len.encode(&mut buf);
            }
            buf.put_slice(reason_bytes);
        }

        buf.freeze()
    }

    /// Decode a response from wire format
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ConnectError> {
        if buf.remaining() < 3 {
            return Err(ConnectError::InvalidResponse("buffer too short".into()));
        }

        let status = buf.get_u16();
        let flags = buf.get_u8();
        let has_addr = (flags & RESPONSE_FLAG_HAS_ADDRESS) != 0;
        let has_reason = (flags & RESPONSE_FLAG_HAS_REASON) != 0;
        let hybrid_datagram_lane = (flags & RESPONSE_FLAG_HYBRID_DATAGRAM_LANE) != 0;
        let datagram_mux_v1 = (flags & RESPONSE_FLAG_DATAGRAM_MUX_V1) != 0;

        let proxy_public_address = if has_addr {
            if buf.remaining() < 1 {
                return Err(ConnectError::InvalidResponse("missing IP version".into()));
            }
            let ip_version = buf.get_u8();
            let ip = match ip_version {
                4 => {
                    if buf.remaining() < 6 {
                        return Err(ConnectError::InvalidResponse("missing IPv4 address".into()));
                    }
                    let mut octets = [0u8; 4];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    if buf.remaining() < 18 {
                        return Err(ConnectError::InvalidResponse("missing IPv6 address".into()));
                    }
                    let mut octets = [0u8; 16];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(ConnectError::InvalidResponse("invalid IP version".into())),
            };
            let port = buf.get_u16();
            Some(SocketAddr::new(ip, port))
        } else {
            None
        };

        let reason = if has_reason {
            let reason_len = VarInt::decode(buf)
                .map_err(|_| ConnectError::InvalidResponse("invalid reason length".into()))?;
            let reason_len = reason_len.into_inner() as usize;

            if buf.remaining() < reason_len {
                return Err(ConnectError::InvalidResponse("missing reason text".into()));
            }

            let mut reason_bytes = vec![0u8; reason_len];
            buf.copy_to_slice(&mut reason_bytes);
            Some(
                String::from_utf8(reason_bytes)
                    .map_err(|_| ConnectError::InvalidResponse("invalid UTF-8 in reason".into()))?,
            )
        } else {
            None
        };

        Ok(Self {
            status,
            proxy_public_address,
            reason,
            hybrid_datagram_lane,
            datagram_mux_v1,
        })
    }
}

impl fmt::Display for ConnectUdpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status)?;
        if let Some(addr) = &self.proxy_public_address {
            write!(f, " (public: {})", addr)?;
        }
        if let Some(reason) = &self.reason {
            write!(f, " - {}", reason)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_any_request() {
        let request = ConnectUdpRequest::bind_any();
        assert!(request.is_bind_request());
        assert!(request.is_bind_any());
        assert_eq!(request.target_host, "::");
        assert_eq!(request.target_port, 0);
        assert!(request.target_addr().is_none());
        assert_eq!(request.protocol(), CONNECT_UDP_BIND_PROTOCOL);
    }

    #[test]
    fn test_bind_port_request() {
        let request = ConnectUdpRequest::bind_port(9000);
        assert!(request.is_bind_request());
        assert!(!request.is_bind_any()); // Has specific port
        assert_eq!(request.target_port, 9000);
    }

    #[test]
    fn test_target_request() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
        let request = ConnectUdpRequest::target(addr);
        assert!(!request.is_bind_request());
        assert!(!request.is_bind_any());
        assert_eq!(request.target_addr(), Some(addr));
        assert_eq!(request.protocol(), CONNECT_UDP_PROTOCOL);
    }

    #[test]
    fn test_request_roundtrip() {
        let original = ConnectUdpRequest::bind_any();
        let encoded = original.encode();
        let decoded = ConnectUdpRequest::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);

        let original =
            ConnectUdpRequest::target(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443));
        let encoded = original.encode();
        let decoded = ConnectUdpRequest::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_request_display() {
        let bind = ConnectUdpRequest::bind_any();
        assert!(bind.to_string().contains("CONNECT-UDP-BIND"));

        let target = ConnectUdpRequest::target(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
        ));
        assert!(target.to_string().contains("CONNECT-UDP"));
        assert!(target.to_string().contains("192.168.1.1:80"));
    }

    #[test]
    fn test_success_response() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 9000);
        let response = ConnectUdpResponse::success(Some(addr));
        assert!(response.is_success());
        assert!(!response.is_error());
        assert_eq!(response.proxy_public_address, Some(addr));
        assert!(response.reason.is_none());
    }

    #[test]
    fn test_error_response() {
        let response = ConnectUdpResponse::bad_request("invalid target");
        assert!(!response.is_success());
        assert!(response.is_error());
        assert_eq!(response.status, 400);
        assert_eq!(response.reason, Some("invalid target".to_string()));
    }

    #[test]
    fn test_response_roundtrip_success() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 9000);
        let original = ConnectUdpResponse::success(Some(addr));
        let encoded = original.encode();
        let decoded = ConnectUdpResponse::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_response_roundtrip_success_no_addr() {
        let original = ConnectUdpResponse::success(None);
        let encoded = original.encode();
        let decoded = ConnectUdpResponse::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_response_roundtrip_error() {
        let original = ConnectUdpResponse::forbidden("rate limited");
        let encoded = original.encode();
        let decoded = ConnectUdpResponse::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_response_roundtrip_ipv6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8443,
        );
        let original = ConnectUdpResponse::success(Some(addr));
        let encoded = original.encode();
        let decoded = ConnectUdpResponse::decode(&mut encoded.clone()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_into_result_success() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234);
        let response = ConnectUdpResponse::success(Some(addr));
        let result = response.into_result();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(addr));
    }

    #[test]
    fn test_into_result_error() {
        let response = ConnectUdpResponse::unavailable("no capacity");
        let result = response.into_result();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectError::Rejected { status, reason } => {
                assert_eq!(status, 503);
                assert_eq!(reason, "no capacity");
            }
            _ => panic!("Expected Rejected error"),
        }
    }

    #[test]
    fn test_response_display() {
        let success = ConnectUdpResponse::success(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            5678,
        )));
        let display = success.to_string();
        assert!(display.contains("200"));
        assert!(display.contains("1.2.3.4:5678"));

        let error = ConnectUdpResponse::forbidden("rate limit exceeded");
        let display = error.to_string();
        assert!(display.contains("403"));
        assert!(display.contains("rate limit exceeded"));
    }

    /// ADR-016 hybrid signal: a request without the signal encodes to the
    /// exact bytes a 0.28.0 client sends, and the signal only adds flag bit
    /// 0x02, which a 0.28.0 relay's decoder ignores (it reads bit 0 only).
    #[test]
    fn hybrid_request_signal_is_one_flag_bit_and_backward_compatible() {
        let legacy = ConnectUdpRequest::bind_any();
        assert!(!legacy.hybrid_datagram_lane);
        let legacy_bytes = legacy.encode();
        // 0.28.0 wire bytes: flags 0x01, varint host len 2, "::", port 0.
        assert_eq!(legacy_bytes.as_ref(), &[0x01, 0x02, b':', b':', 0x00, 0x00]);

        let hybrid = ConnectUdpRequest::bind_any().with_hybrid_datagram_lane(true);
        let hybrid_bytes = hybrid.encode();
        assert_eq!(
            hybrid_bytes[0],
            REQUEST_FLAG_BIND | REQUEST_FLAG_HYBRID_DATAGRAM_LANE
        );
        assert_eq!(&hybrid_bytes[1..], &legacy_bytes[1..]);

        let decoded = ConnectUdpRequest::decode(&mut hybrid_bytes.clone()).unwrap();
        assert_eq!(decoded, hybrid);
        assert!(decoded.is_bind_any());
        let decoded_legacy = ConnectUdpRequest::decode(&mut legacy_bytes.clone()).unwrap();
        assert!(!decoded_legacy.hybrid_datagram_lane);
    }

    /// ADR-016 hybrid signal on the response: bit 0x04, independent of the
    /// address and reason bits, so a 0.28.0 client decoding it still reads
    /// the address and reason correctly.
    #[test]
    fn hybrid_response_signal_roundtrips_and_keeps_layout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4433);
        let legacy = ConnectUdpResponse::success(Some(addr));
        let accepted = ConnectUdpResponse::success(Some(addr)).with_hybrid_datagram_lane(true);
        let legacy_bytes = legacy.encode();
        let accepted_bytes = accepted.encode();
        assert_eq!(legacy_bytes[2], RESPONSE_FLAG_HAS_ADDRESS);
        assert_eq!(
            accepted_bytes[2],
            RESPONSE_FLAG_HAS_ADDRESS | RESPONSE_FLAG_HYBRID_DATAGRAM_LANE
        );
        assert_eq!(&accepted_bytes[..2], &legacy_bytes[..2]);
        assert_eq!(&accepted_bytes[3..], &legacy_bytes[3..]);

        let decoded = ConnectUdpResponse::decode(&mut accepted_bytes.clone()).unwrap();
        assert_eq!(decoded, accepted);
        assert!(decoded.hybrid_datagram_lane);
        assert_eq!(decoded.proxy_public_address, Some(addr));
        let decoded_legacy = ConnectUdpResponse::decode(&mut legacy_bytes.clone()).unwrap();
        assert!(!decoded_legacy.hybrid_datagram_lane);
        assert!(!decoded_legacy.datagram_mux_v1);
    }

    /// ADR-020 `datagram_mux_v1` flag bits (request 0x04, response 0x08) keep
    /// layout identical to 0.28.0/0.29.0 and can be set independently of 0x02.
    #[test]
    fn datagram_mux_v1_flag_bits_roundtrip_and_stay_backward_compatible() {
        let base_req = ConnectUdpRequest::bind_any();
        let mux_only = ConnectUdpRequest::bind_any().with_datagram_mux_v1(true);
        let both = ConnectUdpRequest::bind_any()
            .with_hybrid_datagram_lane(true)
            .with_datagram_mux_v1(true);

        let base_bytes = base_req.encode();
        let mux_only_bytes = mux_only.encode();
        let both_bytes = both.encode();

        assert_eq!(
            mux_only_bytes[0],
            REQUEST_FLAG_BIND | REQUEST_FLAG_DATAGRAM_MUX_V1
        );
        assert_eq!(
            both_bytes[0],
            REQUEST_FLAG_BIND | REQUEST_FLAG_HYBRID_DATAGRAM_LANE | REQUEST_FLAG_DATAGRAM_MUX_V1
        );
        assert_eq!(&mux_only_bytes[1..], &base_bytes[1..]);
        assert_eq!(&both_bytes[1..], &base_bytes[1..]);

        let dec_mux_only = ConnectUdpRequest::decode(&mut mux_only_bytes.clone()).unwrap();
        assert!(!dec_mux_only.hybrid_datagram_lane);
        assert!(dec_mux_only.datagram_mux_v1);
        let dec_both = ConnectUdpRequest::decode(&mut both_bytes.clone()).unwrap();
        assert!(dec_both.hybrid_datagram_lane);
        assert!(dec_both.datagram_mux_v1);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 4433);
        let base_resp = ConnectUdpResponse::success(Some(addr));
        let mux_resp = ConnectUdpResponse::success(Some(addr))
            .with_hybrid_datagram_lane(true)
            .with_datagram_mux_v1(true);
        let base_resp_bytes = base_resp.encode();
        let mux_resp_bytes = mux_resp.encode();
        assert_eq!(
            mux_resp_bytes[2],
            RESPONSE_FLAG_HAS_ADDRESS
                | RESPONSE_FLAG_HYBRID_DATAGRAM_LANE
                | RESPONSE_FLAG_DATAGRAM_MUX_V1
        );
        assert_eq!(&mux_resp_bytes[..2], &base_resp_bytes[..2]);
        assert_eq!(&mux_resp_bytes[3..], &base_resp_bytes[3..]);

        let dec_resp = ConnectUdpResponse::decode(&mut mux_resp_bytes.clone()).unwrap();
        assert_eq!(dec_resp, mux_resp);
        assert!(dec_resp.hybrid_datagram_lane);
        assert!(dec_resp.datagram_mux_v1);
    }
}
