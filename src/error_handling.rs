// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Standardized Error Handling Patterns for ant-quic
//!
//! This module provides consistent error handling patterns and utilities
//! to ensure uniform error propagation and handling across the codebase.

use thiserror::Error;

/// Comprehensive error type for ant-quic operations
#[derive(Error, Debug)]
pub enum AntQuicError {
    /// Transport-level errors (connection issues, protocol violations)
    #[error("Transport error: {0}")]
    Transport(#[from] crate::transport_error::Error),

    /// Connection establishment errors
    #[error("Connection error: {0}")]
    Connection(#[from] crate::connection::ConnectionError),

    /// Network address discovery errors
    #[error("Discovery error: {0}")]
    Discovery(#[from] crate::candidate_discovery::DiscoveryError),

    /// NAT traversal errors
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] crate::nat_traversal_api::NatTraversalError),

    /// Configuration validation errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// I/O operation errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation errors
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Post-Quantum Cryptography errors
    #[error("PQC error: {0}")]
    Pqc(#[from] crate::crypto::pqc::types::PqcError),

    /// Timeout errors
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Resource exhaustion errors
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Invalid input parameters
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Internal errors (should not happen in production)
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for ant-quic operations
pub type Result<T> = std::result::Result<T, AntQuicError>;

/// Error handling utilities
pub mod utils {
    use super::*;
    use tracing::{debug, error, info, warn};

    /// Log an error with appropriate level based on severity
    pub fn log_error(error: &(dyn std::error::Error + 'static), context: &str) {
        let error_msg = format!("{}: {}", context, error);
        match error.downcast_ref::<AntQuicError>() {
            Some(AntQuicError::Internal(_)) => error!("{}", error_msg),
            Some(AntQuicError::Transport(_)) => warn!("{}", error_msg),
            Some(AntQuicError::Connection(_)) => warn!("{}", error_msg),
            Some(AntQuicError::Timeout(_)) => info!("{}", error_msg),
            Some(AntQuicError::InvalidParameter(_)) => debug!("{}", error_msg),
            _ => warn!("{}", error_msg),
        }
    }

    /// Convert an error to a user-friendly message
    pub fn to_user_message(error: &(dyn std::error::Error + 'static)) -> String {
        match error.downcast_ref::<AntQuicError>() {
            Some(AntQuicError::Transport(_)) => {
                "Network connection error. Please check your internet connection.".to_string()
            }
            Some(AntQuicError::Connection(_)) => {
                "Failed to establish connection. The remote peer may be unreachable.".to_string()
            }
            Some(AntQuicError::Discovery(_)) => {
                "Failed to discover network configuration. Please check your network settings."
                    .to_string()
            }
            Some(AntQuicError::NatTraversal(_)) => {
                "NAT traversal failed. This may be due to restrictive network policies.".to_string()
            }
            Some(AntQuicError::Timeout(_)) => "Operation timed out. Please try again.".to_string(),
            Some(AntQuicError::Config(_)) => {
                "Configuration error. Please check your settings.".to_string()
            }
            Some(AntQuicError::Io(_)) => {
                "System I/O error. Please check file permissions and disk space.".to_string()
            }
            Some(AntQuicError::Crypto(_)) => {
                "Cryptographic operation failed. This may indicate a security issue.".to_string()
            }
            Some(AntQuicError::Pqc(_)) => {
                "Post-quantum cryptographic operation failed.".to_string()
            }
            Some(AntQuicError::ResourceExhausted(_)) => {
                "System resources exhausted. Please close some applications and try again."
                    .to_string()
            }
            Some(AntQuicError::InvalidParameter(_)) => {
                "Invalid input parameters provided.".to_string()
            }
            Some(AntQuicError::Internal(_)) => {
                "An internal error occurred. Please report this issue.".to_string()
            }
            _ => format!("An unexpected error occurred: {}", error),
        }
    }

    /// Check if an error is recoverable
    pub fn is_recoverable(error: &(dyn std::error::Error + 'static)) -> bool {
        match error.downcast_ref::<AntQuicError>() {
            Some(AntQuicError::Timeout(_)) => true,
            Some(AntQuicError::Connection(_)) => true,
            Some(AntQuicError::Discovery(_)) => true,
            Some(AntQuicError::NatTraversal(_)) => true,
            Some(AntQuicError::Io(io_err)) => {
                // Some I/O errors are recoverable
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                )
            }
            _ => false,
        }
    }

    /// Get recommended retry delay for an error
    pub fn get_retry_delay(
        error: &(dyn std::error::Error + 'static),
    ) -> Option<std::time::Duration> {
        match error.downcast_ref::<AntQuicError>() {
            Some(AntQuicError::Timeout(_)) => Some(std::time::Duration::from_millis(100)),
            Some(AntQuicError::Connection(_)) => Some(std::time::Duration::from_millis(500)),
            Some(AntQuicError::Discovery(_)) => Some(std::time::Duration::from_secs(1)),
            Some(AntQuicError::NatTraversal(_)) => Some(std::time::Duration::from_secs(2)),
            Some(AntQuicError::Io(io_err)) => match io_err.kind() {
                std::io::ErrorKind::TimedOut => Some(std::time::Duration::from_millis(100)),
                std::io::ErrorKind::Interrupted => Some(std::time::Duration::from_millis(10)),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Checks a condition and returns an error (converted via `.into()`) if it's false.
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $error:expr) => {
        if !($condition) {
            return Err($error.into());
        }
    };
}

/// Returns an error immediately, converting via .
/// Returns an error immediately, converting via `.into()`.
#[macro_export]
macro_rules! bail {
    ($error:expr) => {
        return Err($error.into());
    };
}

/// Wraps a Result's error with additional context, converting to [].
/// Wraps a Result's error with additional context, converting to [`AntQuicError::Internal`].
#[macro_export]
macro_rules! context {
    ($result:expr, $context:expr) => {
        $result.map_err(|e| AntQuicError::Internal(format!("{}: {}", $context, e)))
    };
}

/// Best practices for error handling:
///
/// 1. **Use Result<T, E> everywhere**: Never use unwrap() or expect() in production code
/// 2. **Chain errors with ? operator**: Let errors bubble up naturally
/// 3. **Add context when needed**: Use context! macro to add context to errors
/// 4. **Handle recoverable errors**: Use is_recoverable() to determine if retry is appropriate
/// 5. **Log errors appropriately**: Use log_error() for consistent error logging
/// 6. **Provide user-friendly messages**: Use to_user_message() for end-user communication
/// 7. **Use specific error types**: Prefer specific error variants over generic ones
/// 8. **Document error conditions**: Document when and why errors can occur
/// 9. **Test error paths**: Ensure error conditions are tested
/// 10. **Fail securely**: Don't leak sensitive information in error messages
#[cfg(test)]
mod tests {
    use super::*;

    // ── AntQuicError construction and display ──

    #[test]
    fn error_transport_display() {
        let err = AntQuicError::Transport(crate::transport_error::Error::INTERNAL_ERROR("test"));
        let display = format!("{err}");
        assert!(display.contains("Transport error"));
    }

    #[test]
    fn error_connection_display() {
        let err = AntQuicError::Connection(crate::connection::ConnectionError::LocallyClosed);
        let display = format!("{err}");
        assert!(display.contains("Connection error"));
    }

    #[test]
    fn error_config_display() {
        let err = AntQuicError::Config("bad config".to_string());
        let display = format!("{err}");
        assert!(display.contains("Configuration error"));
        assert!(display.contains("bad config"));
    }

    #[test]
    fn error_crypto_display() {
        let err = AntQuicError::Crypto("key error".to_string());
        let display = format!("{err}");
        assert!(display.contains("Crypto error"));
    }

    #[test]
    fn error_timeout_display() {
        let err = AntQuicError::Timeout("timed out".to_string());
        let display = format!("{err}");
        assert!(display.contains("timed out"));
    }

    #[test]
    fn error_resource_exhausted_display() {
        let err = AntQuicError::ResourceExhausted("no mem".to_string());
        let display = format!("{err}");
        assert!(display.contains("Resource exhausted"));
    }

    #[test]
    fn error_invalid_parameter_display() {
        let err = AntQuicError::InvalidParameter("bad param".to_string());
        let display = format!("{err}");
        assert!(display.contains("Invalid parameter"));
    }

    #[test]
    fn error_internal_display() {
        let err = AntQuicError::Internal("bug".to_string());
        let display = format!("{err}");
        assert!(display.contains("Internal error"));
    }

    #[test]
    fn error_debug_format() {
        let err = AntQuicError::Internal("test".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("Internal"));
    }

    #[test]
    fn error_from_invalid_parameter() {
        let s = "bad".to_string();
        let err: AntQuicError = AntQuicError::InvalidParameter(s);
        assert!(format!("{err}").contains("Invalid parameter"));
    }

    #[test]
    fn error_io_into() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: AntQuicError = io_err.into();
        assert!(matches!(err, AntQuicError::Io(_)));
    }

    // ── utils::log_error tests ──

    #[test]
    fn log_error_internal() {
        let err = AntQuicError::Internal("test internal".to_string());
        // Should not panic
        utils::log_error(&err, "test context");
    }

    #[test]
    fn log_error_transport() {
        let err = AntQuicError::Transport(crate::transport_error::Error::INTERNAL_ERROR("x"));
        utils::log_error(&err, "transport");
    }

    #[test]
    fn log_error_generic() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "generic");
        utils::log_error(&err, "generic context");
    }

    // ── utils::to_user_message tests ──

    #[test]
    fn user_message_transport() {
        let err = AntQuicError::Transport(crate::transport_error::Error::INTERNAL_ERROR(""));
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Network connection error"));
    }

    #[test]
    fn user_message_connection() {
        let err = AntQuicError::Connection(crate::connection::ConnectionError::LocallyClosed);
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Failed to establish connection"));
    }

    #[test]
    fn user_message_timeout() {
        let err = AntQuicError::Timeout("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn user_message_crypto() {
        let err = AntQuicError::Crypto("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Cryptographic operation failed"));
    }

    #[test]
    fn user_message_internal() {
        let err = AntQuicError::Internal("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("internal error"));
    }

    #[test]
    fn user_message_config() {
        let err = AntQuicError::Config("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Configuration error"));
    }

    #[test]
    fn user_message_discovery() {
        // DiscoveryError is in candidate_discovery module — use a generic fallback
        let err = std::io::Error::new(std::io::ErrorKind::Other, "weird");
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("unexpected error"));
    }

    #[test]
    fn user_message_io() {
        let err = AntQuicError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("I/O error"));
    }

    #[test]
    fn user_message_invalid_parameter() {
        let err = AntQuicError::InvalidParameter("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Invalid input"));
    }

    #[test]
    fn user_message_resource_exhausted() {
        let err = AntQuicError::ResourceExhausted("x".to_string());
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("resources exhausted"));
    }

    #[test]
    fn user_message_pqc() {
        use crate::crypto::pqc::types::PqcError;
        let err = AntQuicError::Pqc(PqcError::KeyGenerationFailed("test".to_string()));
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("Post-quantum"));
    }

    #[test]
    fn user_message_nat_traversal() {
        use crate::nat_traversal_api::NatTraversalError;
        let err = AntQuicError::NatTraversal(NatTraversalError::HolePunchingFailed);
        let msg = utils::to_user_message(&err);
        assert!(msg.contains("NAT traversal failed"));
    }

    // ── utils::is_recoverable tests ──

    #[test]
    fn timeout_is_recoverable() {
        let err = AntQuicError::Timeout("x".to_string());
        assert!(utils::is_recoverable(&err));
    }

    #[test]
    fn connection_error_is_recoverable() {
        let err = AntQuicError::Connection(crate::connection::ConnectionError::LocallyClosed);
        assert!(utils::is_recoverable(&err));
    }

    #[test]
    fn internal_error_is_not_recoverable() {
        let err = AntQuicError::Internal("x".to_string());
        assert!(!utils::is_recoverable(&err));
    }

    #[test]
    fn config_error_is_not_recoverable() {
        let err = AntQuicError::Config("x".to_string());
        assert!(!utils::is_recoverable(&err));
    }

    #[test]
    fn io_timeout_is_recoverable() {
        let err = AntQuicError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        assert!(utils::is_recoverable(&err));
    }

    #[test]
    fn io_interrupted_is_recoverable() {
        let err = AntQuicError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "interrupted",
        ));
        assert!(utils::is_recoverable(&err));
    }

    #[test]
    fn io_permission_denied_is_not_recoverable() {
        let err = AntQuicError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert!(!utils::is_recoverable(&err));
    }

    #[test]
    fn generic_error_is_not_recoverable() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "other");
        assert!(!utils::is_recoverable(&err));
    }

    #[test]
    fn crypto_error_is_not_recoverable() {
        let err = AntQuicError::Crypto("x".to_string());
        assert!(!utils::is_recoverable(&err));
    }

    // ── utils::get_retry_delay tests ──

    #[test]
    fn timeout_has_retry_delay() {
        let err = AntQuicError::Timeout("x".to_string());
        let delay = utils::get_retry_delay(&err);
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), std::time::Duration::from_millis(100));
    }

    #[test]
    fn connection_has_retry_delay() {
        let err = AntQuicError::Connection(crate::connection::ConnectionError::LocallyClosed);
        let delay = utils::get_retry_delay(&err);
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), std::time::Duration::from_millis(500));
    }

    #[test]
    fn discovery_has_retry_delay() {
        use crate::candidate_discovery::DiscoveryError;
        let err = AntQuicError::Discovery(DiscoveryError::NoLocalInterfaces);
        let delay = utils::get_retry_delay(&err);
        assert!(delay.is_some());
    }

    #[test]
    fn internal_has_no_retry_delay() {
        let err = AntQuicError::Internal("x".to_string());
        assert!(utils::get_retry_delay(&err).is_none());
    }

    #[test]
    fn generic_error_has_no_retry_delay() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "other");
        assert!(utils::get_retry_delay(&err).is_none());
    }

    #[test]
    fn io_timeout_has_retry_delay() {
        let err = AntQuicError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        let delay = utils::get_retry_delay(&err);
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), std::time::Duration::from_millis(100));
    }

    #[test]
    fn io_interrupted_has_retry_delay() {
        let err = AntQuicError::Io(std::io::Error::new(std::io::ErrorKind::Interrupted, "int"));
        let delay = utils::get_retry_delay(&err);
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), std::time::Duration::from_millis(10));
    }

    // ── Macro tests ──

    #[test]
    fn ensure_passes_when_true() {
        let result: Result<()> = (|| {
            ensure!(
                true,
                AntQuicError::Internal("should not happen".to_string())
            );
            Ok(())
        })();
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_fails_when_false() {
        let result: Result<()> = (|| {
            ensure!(false, AntQuicError::InvalidParameter("bad".to_string()));
            Ok(())
        })();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AntQuicError::InvalidParameter(_)
        ));
    }

    #[test]
    fn bail_returns_error() {
        let result: Result<()> = (|| {
            bail!(AntQuicError::Internal("bailed".to_string()));
        })();
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("bailed"));
    }

    #[test]
    fn bail_with_type_conversion() {
        // bail! can convert via .into()
        let result: Result<()> = (|| {
            let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
            bail!(io_err);
        })();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AntQuicError::Io(_)));
    }

    // ── Error source chain ──

    #[test]
    fn error_source_chain_transport() {
        let err = AntQuicError::Transport(crate::transport_error::Error::INTERNAL_ERROR("chain"));
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }
}
