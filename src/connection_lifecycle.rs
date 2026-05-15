use std::fmt;

use crate::{ConnectionError, VarInt};

/// Reserved application close-code range for ant-quic lifecycle signaling.
///
/// `0x4E5B00..=0x4E5BFF` encodes ASCII `N[` in the upper bytes.
pub const ANT_QUIC_CLOSE_CODE_BASE: u32 = 0x4E5B00;
const CLOSE_CODE_SUPERSEDED: u32 = ANT_QUIC_CLOSE_CODE_BASE;
const CLOSE_CODE_READER_EXIT: u32 = ANT_QUIC_CLOSE_CODE_BASE + 0x01;
const CLOSE_CODE_PEER_SHUTDOWN: u32 = ANT_QUIC_CLOSE_CODE_BASE + 0x02;
const CLOSE_CODE_BANNED: u32 = ANT_QUIC_CLOSE_CODE_BASE + 0x03;
const CLOSE_CODE_LIFECYCLE_CLEANUP: u32 = ANT_QUIC_CLOSE_CODE_BASE + 0x04;
const CLOSE_CODE_LIVENESS_TIMEOUT: u32 = ANT_QUIC_CLOSE_CODE_BASE + 0x05;

/// ant-quic lifecycle-aware connection close reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionCloseReason {
    /// A newer connection superseded this one.
    Superseded,
    /// The reader task exited and the endpoint actively closed the connection.
    ReaderExit,
    /// The remote endpoint is shutting down.
    PeerShutdown,
    /// Trust or policy enforcement rejected the peer.
    Banned,
    /// Generic lifecycle cleanup.
    LifecycleCleanup,
    /// X0X-0062: the local endpoint detected the application data path is
    /// dead (repeated `send_with_receive_ack` retries failed within a short
    /// window) while the underlying QUIC connection still reports as `Live`.
    /// Used to force-close half-dead connections so callers can re-dial.
    LivenessTimeout,
    /// The peer sent a non-lifecycle application close.
    ApplicationClosed,
    /// The peer or transport closed the connection without an application code.
    ConnectionClosed,
    /// The connection timed out.
    TimedOut,
    /// The peer reset the connection.
    Reset,
    /// A transport error closed the connection.
    TransportError,
    /// The local side closed the connection.
    LocallyClosed,
    /// Version or capability mismatch closed the connection.
    VersionMismatch,
    /// CID exhaustion closed the connection.
    CidsExhausted,
    /// Unknown or unmapped close reason.
    Unknown,
}

impl ConnectionCloseReason {
    /// Return the reserved QUIC application error code, if this reason has one.
    pub fn app_error_code(self) -> Option<VarInt> {
        let code = match self {
            Self::Superseded => CLOSE_CODE_SUPERSEDED,
            Self::ReaderExit => CLOSE_CODE_READER_EXIT,
            Self::PeerShutdown => CLOSE_CODE_PEER_SHUTDOWN,
            Self::Banned => CLOSE_CODE_BANNED,
            Self::LifecycleCleanup => CLOSE_CODE_LIFECYCLE_CLEANUP,
            Self::LivenessTimeout => CLOSE_CODE_LIVENESS_TIMEOUT,
            Self::ApplicationClosed
            | Self::ConnectionClosed
            | Self::TimedOut
            | Self::Reset
            | Self::TransportError
            | Self::LocallyClosed
            | Self::VersionMismatch
            | Self::CidsExhausted
            | Self::Unknown => return None,
        };
        Some(VarInt::from_u32(code))
    }

    /// Human-readable identifier for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Superseded => "Superseded",
            Self::ReaderExit => "ReaderExit",
            Self::PeerShutdown => "PeerShutdown",
            Self::Banned => "Banned",
            Self::LifecycleCleanup => "LifecycleCleanup",
            Self::LivenessTimeout => "LivenessTimeout",
            Self::ApplicationClosed => "ApplicationClosed",
            Self::ConnectionClosed => "ConnectionClosed",
            Self::TimedOut => "TimedOut",
            Self::Reset => "Reset",
            Self::TransportError => "TransportError",
            Self::LocallyClosed => "LocallyClosed",
            Self::VersionMismatch => "VersionMismatch",
            Self::CidsExhausted => "CidsExhausted",
            Self::Unknown => "Unknown",
        }
    }

    /// Static reason bytes used in CONNECTION_CLOSE frames.
    pub fn reason_bytes(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// Map a QUIC application close code into a lifecycle reason.
    pub fn from_app_error_code(code: VarInt) -> Option<Self> {
        match code.into_inner() as u32 {
            CLOSE_CODE_SUPERSEDED => Some(Self::Superseded),
            CLOSE_CODE_READER_EXIT => Some(Self::ReaderExit),
            CLOSE_CODE_PEER_SHUTDOWN => Some(Self::PeerShutdown),
            CLOSE_CODE_BANNED => Some(Self::Banned),
            CLOSE_CODE_LIFECYCLE_CLEANUP => Some(Self::LifecycleCleanup),
            CLOSE_CODE_LIVENESS_TIMEOUT => Some(Self::LivenessTimeout),
            _ => None,
        }
    }

    /// Map a transport connection error into a lifecycle reason.
    pub fn from_connection_error(error: &ConnectionError) -> Self {
        match error {
            ConnectionError::ApplicationClosed(frame) => {
                Self::from_app_error_code(frame.error_code).unwrap_or(Self::ApplicationClosed)
            }
            ConnectionError::ConnectionClosed(_) => Self::ConnectionClosed,
            ConnectionError::TransportError(_) => Self::TransportError,
            ConnectionError::VersionMismatch => Self::VersionMismatch,
            ConnectionError::Reset => Self::Reset,
            ConnectionError::TimedOut => Self::TimedOut,
            ConnectionError::LocallyClosed => Self::LocallyClosed,
            ConnectionError::CidsExhausted => Self::CidsExhausted,
        }
    }
}

impl fmt::Display for ConnectionCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionLifecycleState {
    Live,
    Superseded {
        replaced_by_generation: u64,
    },
    Closing {
        reason: ConnectionCloseReason,
    },
    Closed {
        reason: ConnectionCloseReason,
        closed_at_unix_ms: u64,
    },
}

impl ConnectionLifecycleState {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Live => "Live",
            Self::Superseded { .. } => "Superseded",
            Self::Closing { .. } => "Closing",
            Self::Closed { .. } => "Closed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    // ── ConnectionCloseReason tests ──

    #[test]
    fn reason_as_str_all_variants() {
        let cases = [
            (ConnectionCloseReason::Superseded, "Superseded"),
            (ConnectionCloseReason::ReaderExit, "ReaderExit"),
            (ConnectionCloseReason::PeerShutdown, "PeerShutdown"),
            (ConnectionCloseReason::Banned, "Banned"),
            (ConnectionCloseReason::LifecycleCleanup, "LifecycleCleanup"),
            (ConnectionCloseReason::LivenessTimeout, "LivenessTimeout"),
            (
                ConnectionCloseReason::ApplicationClosed,
                "ApplicationClosed",
            ),
            (ConnectionCloseReason::ConnectionClosed, "ConnectionClosed"),
            (ConnectionCloseReason::TimedOut, "TimedOut"),
            (ConnectionCloseReason::Reset, "Reset"),
            (ConnectionCloseReason::TransportError, "TransportError"),
            (ConnectionCloseReason::LocallyClosed, "LocallyClosed"),
            (ConnectionCloseReason::VersionMismatch, "VersionMismatch"),
            (ConnectionCloseReason::CidsExhausted, "CidsExhausted"),
            (ConnectionCloseReason::Unknown, "Unknown"),
        ];

        for (reason, expected) in &cases {
            assert_eq!(reason.as_str(), *expected);
        }
    }

    #[test]
    fn reason_display_matches_as_str() {
        let reasons = [
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::ReaderExit,
            ConnectionCloseReason::PeerShutdown,
            ConnectionCloseReason::Banned,
            ConnectionCloseReason::LifecycleCleanup,
            ConnectionCloseReason::LivenessTimeout,
            ConnectionCloseReason::ApplicationClosed,
            ConnectionCloseReason::ConnectionClosed,
            ConnectionCloseReason::TimedOut,
            ConnectionCloseReason::Reset,
            ConnectionCloseReason::TransportError,
            ConnectionCloseReason::LocallyClosed,
            ConnectionCloseReason::VersionMismatch,
            ConnectionCloseReason::CidsExhausted,
            ConnectionCloseReason::Unknown,
        ];

        for reason in &reasons {
            assert_eq!(format!("{reason}"), reason.as_str());
        }
    }

    #[test]
    fn reason_reason_bytes_equals_as_str_bytes() {
        let reasons = [
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::ReaderExit,
            ConnectionCloseReason::LivenessTimeout,
            ConnectionCloseReason::Unknown,
        ];

        for reason in &reasons {
            assert_eq!(reason.reason_bytes(), reason.as_str().as_bytes());
        }
    }

    #[test]
    fn reason_equality() {
        assert_eq!(
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::Superseded
        );
        assert_ne!(
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::ReaderExit
        );
    }

    #[test]
    fn reason_clone() {
        let r = ConnectionCloseReason::Superseded;
        assert_eq!(r.clone(), r);
    }

    // ── app_error_code tests ──

    #[test]
    fn lifecycle_reasons_have_app_error_codes() {
        let has_code = [
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::ReaderExit,
            ConnectionCloseReason::PeerShutdown,
            ConnectionCloseReason::Banned,
            ConnectionCloseReason::LifecycleCleanup,
            ConnectionCloseReason::LivenessTimeout,
        ];

        for reason in &has_code {
            assert!(
                reason.app_error_code().is_some(),
                "{reason:?} should have an app_error_code"
            );
        }
    }

    #[test]
    fn non_lifecycle_reasons_have_no_app_error_code() {
        let no_code = [
            ConnectionCloseReason::ApplicationClosed,
            ConnectionCloseReason::ConnectionClosed,
            ConnectionCloseReason::TimedOut,
            ConnectionCloseReason::Reset,
            ConnectionCloseReason::TransportError,
            ConnectionCloseReason::LocallyClosed,
            ConnectionCloseReason::VersionMismatch,
            ConnectionCloseReason::CidsExhausted,
            ConnectionCloseReason::Unknown,
        ];

        for reason in &no_code {
            assert!(
                reason.app_error_code().is_none(),
                "{reason:?} should NOT have an app_error_code"
            );
        }
    }

    #[test]
    fn lifecycle_error_codes_start_at_base() {
        let superseded_code = ConnectionCloseReason::Superseded
            .app_error_code()
            .unwrap()
            .into_inner() as u32;
        assert_eq!(superseded_code, ANT_QUIC_CLOSE_CODE_BASE);

        let liveness_code = ConnectionCloseReason::LivenessTimeout
            .app_error_code()
            .unwrap()
            .into_inner() as u32;
        assert_eq!(liveness_code, ANT_QUIC_CLOSE_CODE_BASE + 5);
    }

    // ── from_app_error_code tests ──

    #[test]
    fn from_app_error_code_roundtrip() {
        let lifecycle_reasons = [
            ConnectionCloseReason::Superseded,
            ConnectionCloseReason::ReaderExit,
            ConnectionCloseReason::PeerShutdown,
            ConnectionCloseReason::Banned,
            ConnectionCloseReason::LifecycleCleanup,
            ConnectionCloseReason::LivenessTimeout,
        ];

        for reason in &lifecycle_reasons {
            let code = reason.app_error_code().unwrap();
            let mapped = ConnectionCloseReason::from_app_error_code(code);
            assert_eq!(mapped, Some(*reason));
        }
    }

    #[test]
    fn from_app_error_code_unknown_code() {
        let code = VarInt::from_u32(0x1234);
        let result = ConnectionCloseReason::from_app_error_code(code);
        assert_eq!(result, None);
    }

    #[test]
    fn from_app_error_code_zero() {
        // Standard QUIC no-error should not map to a lifecycle reason
        let code = VarInt::from_u32(0);
        let result = ConnectionCloseReason::from_app_error_code(code);
        assert_eq!(result, None);
    }

    // ── from_connection_error tests ──

    #[test]
    fn from_connection_error_application_closed_maps_to_lifecycle() {
        let code = VarInt::from_u32(CLOSE_CODE_SUPERSEDED);
        let app_close = crate::frame::ApplicationClose {
            error_code: code,
            reason: Bytes::new(),
        };
        let frame = crate::ConnectionError::ApplicationClosed(app_close);
        let reason = ConnectionCloseReason::from_connection_error(&frame);
        assert_eq!(reason, ConnectionCloseReason::Superseded);
    }

    #[test]
    fn from_connection_error_application_closed_falls_back() {
        let code = VarInt::from_u32(0x1234);
        let app_close = crate::frame::ApplicationClose {
            error_code: code,
            reason: Bytes::new(),
        };
        let frame = crate::ConnectionError::ApplicationClosed(app_close);
        let reason = ConnectionCloseReason::from_connection_error(&frame);
        assert_eq!(reason, ConnectionCloseReason::ApplicationClosed);
    }

    // ── ConnectionLifecycleState tests ──

    #[test]
    fn lifecycle_state_name_live() {
        assert_eq!(ConnectionLifecycleState::Live.name(), "Live");
    }

    #[test]
    fn lifecycle_state_name_superseded() {
        let state = ConnectionLifecycleState::Superseded {
            replaced_by_generation: 42,
        };
        assert_eq!(state.name(), "Superseded");
    }

    #[test]
    fn lifecycle_state_name_closing() {
        let state = ConnectionLifecycleState::Closing {
            reason: ConnectionCloseReason::PeerShutdown,
        };
        assert_eq!(state.name(), "Closing");
    }

    #[test]
    fn lifecycle_state_name_closed() {
        let state = ConnectionLifecycleState::Closed {
            reason: ConnectionCloseReason::LivenessTimeout,
            closed_at_unix_ms: 1000,
        };
        assert_eq!(state.name(), "Closed");
    }

    #[test]
    fn lifecycle_state_equality() {
        assert_eq!(
            ConnectionLifecycleState::Live,
            ConnectionLifecycleState::Live
        );
        assert_ne!(
            ConnectionLifecycleState::Live,
            ConnectionLifecycleState::Superseded {
                replaced_by_generation: 1,
            }
        );
    }

    #[test]
    fn lifecycle_state_debug() {
        let state = ConnectionLifecycleState::Live;
        let debug = format!("{state:?}");
        assert!(debug.contains("Live"));
    }
}
