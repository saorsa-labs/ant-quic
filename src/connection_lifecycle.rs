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
