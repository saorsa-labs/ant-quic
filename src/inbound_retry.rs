// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Stateless QUIC Retry for inbound connections (#374 Wave 3).
//!
//! A pure-PQC server flight is about 7 KiB and costs an ML-KEM-768
//! decapsulation. Sent toward a spoofed source address, it turns a VPS
//! relay/bootstrap node into an amplifier and burns its CPU. A stateless QUIC
//! Retry (RFC 9000 §8.1.2) costs about 100 B and no crypto beyond an AEAD
//! tag: the client must echo the Retry token from the address it claims
//! before the server spends anything on it.
//!
//! The gate follows the upstream quinn pattern: the accept loop inspects each
//! [`crate::high_level::Incoming`] and calls `retry()` while the source address
//! is unvalidated. A client whose Initial carries a valid address-validation
//! token is exempt. The default [`crate::config::ValidationTokenConfig`] issues no
//! `NEW_TOKEN` tokens (`sent = 0`, `NoneTokenLog`), so under
//! [`StatelessRetryPolicy::Always`] every inbound connection currently pays
//! one Retry round trip. Enabling `NEW_TOKEN` issuance is a follow-up.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

/// When an inbound endpoint answers a new connection with a stateless Retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StatelessRetryPolicy {
    /// Never send Retry (the default; no behaviour change).
    #[default]
    Disabled,
    /// Retry every connection whose source address is not yet validated.
    ///
    /// Under the current defaults (no `NEW_TOKEN` issuance) this costs one
    /// extra round trip on every inbound connection.
    Always,
    /// Retry unvalidated sources only while at least `pending_handshakes`
    /// inbound handshakes are already in flight on this endpoint.
    ///
    /// Normal load pays no extra round trip; a flood of Initials (spoofed or
    /// not) quickly pushes the endpoint into Retry mode.
    UnderLoad {
        /// In-flight inbound handshakes at or above which Retry is used.
        pending_handshakes: usize,
    },
}

impl StatelessRetryPolicy {
    /// Default `UnderLoad` threshold: 64 inbound handshakes in flight.
    pub const DEFAULT_UNDER_LOAD_THRESHOLD: usize = 64;

    /// `UnderLoad` with [`Self::DEFAULT_UNDER_LOAD_THRESHOLD`].
    pub fn under_load() -> Self {
        Self::UnderLoad {
            pending_handshakes: Self::DEFAULT_UNDER_LOAD_THRESHOLD,
        }
    }

    /// Whether an incoming connection should get a Retry.
    ///
    /// * `remote_address_validated` — the Initial carried a valid Retry or
    ///   `NEW_TOKEN` token.
    /// * `may_retry` — no Retry has been sent for this attempt yet (RFC 9000
    ///   allows only one).
    /// * `pending_handshakes` — inbound handshakes in flight now.
    pub fn should_retry(
        self,
        remote_address_validated: bool,
        may_retry: bool,
        pending_handshakes: usize,
    ) -> bool {
        if remote_address_validated || !may_retry {
            return false;
        }
        match self {
            Self::Disabled => false,
            Self::Always => true,
            Self::UnderLoad {
                pending_handshakes: threshold,
            } => pending_handshakes >= threshold,
        }
    }
}

/// Shared state for one accept loop's Retry decisions.
#[derive(Debug, Clone, Default)]
pub(crate) struct InboundRetryGate {
    policy: StatelessRetryPolicy,
    pending_handshakes: Arc<AtomicUsize>,
    retries_sent: Arc<AtomicU64>,
}

/// Counts one inbound handshake as in flight until dropped.
#[derive(Debug)]
pub(crate) struct PendingHandshakeGuard(Arc<AtomicUsize>);

impl Drop for PendingHandshakeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl InboundRetryGate {
    pub(crate) fn new(policy: StatelessRetryPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Decide for one incoming connection. When this returns `true` the
    /// caller must send the Retry and then call [`Self::record_retry`].
    pub(crate) fn should_retry(&self, remote_address_validated: bool, may_retry: bool) -> bool {
        self.policy.should_retry(
            remote_address_validated,
            may_retry,
            self.pending_handshakes.load(Ordering::Acquire),
        )
    }

    pub(crate) fn record_retry(&self) {
        self.retries_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Count an accepted handshake as in flight until the guard drops.
    pub(crate) fn begin_handshake(&self) -> PendingHandshakeGuard {
        self.pending_handshakes.fetch_add(1, Ordering::AcqRel);
        PendingHandshakeGuard(Arc::clone(&self.pending_handshakes))
    }

    /// Retry packets sent by this accept loop.
    pub(crate) fn retries_sent(&self) -> u64 {
        self.retries_sent.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_never_retries() {
        let policy = StatelessRetryPolicy::Disabled;
        assert!(!policy.should_retry(false, true, 0));
        assert!(!policy.should_retry(false, true, usize::MAX));
    }

    #[test]
    fn always_retries_only_unvalidated_first_attempts() {
        let policy = StatelessRetryPolicy::Always;
        assert!(policy.should_retry(false, true, 0));
        assert!(!policy.should_retry(true, true, 0), "validated by token");
        assert!(!policy.should_retry(false, false, 0), "Retry already sent");
    }

    #[test]
    fn under_load_retries_at_threshold() {
        let policy = StatelessRetryPolicy::UnderLoad {
            pending_handshakes: 3,
        };
        assert!(!policy.should_retry(false, true, 2));
        assert!(policy.should_retry(false, true, 3));
        assert!(policy.should_retry(false, true, 4));
        assert!(!policy.should_retry(true, true, 100));
    }

    #[test]
    fn gate_tracks_pending_handshakes() {
        let gate = InboundRetryGate::new(StatelessRetryPolicy::UnderLoad {
            pending_handshakes: 2,
        });
        assert!(!gate.should_retry(false, true));
        let first = gate.begin_handshake();
        assert!(!gate.should_retry(false, true));
        let second = gate.begin_handshake();
        assert!(gate.should_retry(false, true));
        drop(first);
        assert!(!gate.should_retry(false, true));
        drop(second);
        gate.record_retry();
        assert_eq!(gate.retries_sent(), 1);
    }
}
