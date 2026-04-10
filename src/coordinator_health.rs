//! Circuit-breaker for NAT traversal coordinators.
//!
//! Tracks consecutive coordinator failures and applies exponential-backoff
//! cooldowns so that dead coordinators are temporarily skipped rather than
//! retried on every connection attempt.
//!
//! # Backoff Strategy
//!
//! | Failures | Cooldown |
//! |----------|----------|
//! | 1        | 30 s     |
//! | 2        | 60 s     |
//! | 3        | 120 s    |
//! | 4        | 240 s    |
//! | 5+       | 600 s    |

use std::net::SocketAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Base cooldown duration in seconds after the first failure.
const BASE_COOLDOWN_SECS: u64 = 30;

/// Maximum cooldown duration in seconds, regardless of failure count.
const MAX_COOLDOWN_SECS: u64 = 600;

/// Per-coordinator health state.
#[derive(Debug, Clone)]
struct HealthEntry {
    /// Number of consecutive failures without an intervening success.
    consecutive_failures: u32,
    /// The coordinator is considered unavailable until this instant.
    cooldown_until: Instant,
}

/// Thread-safe circuit-breaker for coordinator peers.
///
/// Shared via `Arc` across the endpoint and NAT-traversal code paths.
/// Uses [`DashMap`] for lock-free concurrent access.
#[derive(Debug)]
pub struct CoordinatorHealth {
    entries: DashMap<SocketAddr, HealthEntry>,
}

impl CoordinatorHealth {
    /// Create a new, empty health tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Record a coordinator failure.
    ///
    /// Increments the consecutive-failure counter and sets the cooldown
    /// using exponential backoff: `min(30 * 2^(failures-1), 600)` seconds.
    pub fn record_failure(&self, addr: SocketAddr) {
        let now = Instant::now();
        let mut entry = self.entries.entry(addr).or_insert_with(|| HealthEntry {
            consecutive_failures: 0,
            cooldown_until: now,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.cooldown_until = now + cooldown_duration(entry.consecutive_failures);
    }

    /// Record a coordinator success, fully resetting its health state.
    pub fn record_success(&self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    /// Check whether a coordinator is available for use.
    ///
    /// Returns `true` if the coordinator has no recorded failures **or** its
    /// cooldown period has expired.
    pub fn is_available(&self, addr: &SocketAddr) -> bool {
        let should_remove = {
            match self.entries.get(addr) {
                None => return true,
                Some(entry) => Instant::now() >= entry.cooldown_until,
            }
        };
        if should_remove {
            self.entries.remove(addr);
        }
        should_remove
    }

    /// Return only the coordinators whose cooldown has expired.
    pub fn filter_available(&self, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
        candidates
            .iter()
            .filter(|addr| self.is_available(addr))
            .copied()
            .collect()
    }
}

impl Default for CoordinatorHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the cooldown duration for a given failure count.
fn cooldown_duration(failures: u32) -> std::time::Duration {
    let exponent = failures.saturating_sub(1);
    let secs = BASE_COOLDOWN_SECS.saturating_mul(1u64.checked_shl(exponent).unwrap_or(u64::MAX));
    std::time::Duration::from_secs(secs.min(MAX_COOLDOWN_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn test_new_coordinator_is_available() {
        let h = CoordinatorHealth::new();
        assert!(h.is_available(&addr(1)));
    }

    #[test]
    fn test_single_failure_cooldown() {
        let h = CoordinatorHealth::new();
        h.record_failure(addr(1));
        assert!(!h.is_available(&addr(1)));
        assert_eq!(cooldown_duration(1), std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_exponential_backoff() {
        assert_eq!(cooldown_duration(1), std::time::Duration::from_secs(30));
        assert_eq!(cooldown_duration(2), std::time::Duration::from_secs(60));
        assert_eq!(cooldown_duration(3), std::time::Duration::from_secs(120));
        assert_eq!(cooldown_duration(4), std::time::Duration::from_secs(240));
    }

    #[test]
    fn test_max_cooldown_cap() {
        assert_eq!(cooldown_duration(10), std::time::Duration::from_secs(600));
        assert_eq!(
            cooldown_duration(u32::MAX),
            std::time::Duration::from_secs(600)
        );
    }

    #[test]
    fn test_success_resets() {
        let h = CoordinatorHealth::new();
        h.record_failure(addr(1));
        h.record_failure(addr(1));
        assert!(!h.is_available(&addr(1)));
        h.record_success(&addr(1));
        assert!(h.is_available(&addr(1)));
    }

    #[test]
    fn test_filter_available() {
        let h = CoordinatorHealth::new();
        h.record_failure(addr(2));
        h.record_failure(addr(4));
        let candidates = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        let available = h.filter_available(&candidates);
        assert!(available.contains(&addr(1)));
        assert!(!available.contains(&addr(2)));
        assert!(available.contains(&addr(3)));
        assert!(!available.contains(&addr(4)));
        assert!(available.contains(&addr(5)));
    }

    #[test]
    fn test_expired_cooldown_cleans_up() {
        let h = CoordinatorHealth::new();
        h.entries.insert(
            addr(1),
            HealthEntry {
                consecutive_failures: 1,
                cooldown_until: Instant::now() - std::time::Duration::from_secs(1),
            },
        );
        assert!(h.is_available(&addr(1)));
        assert!(!h.entries.contains_key(&addr(1)));
    }

    #[test]
    fn test_independent_addrs() {
        let h = CoordinatorHealth::new();
        h.record_failure(addr(1));
        assert!(!h.is_available(&addr(1)));
        assert!(h.is_available(&addr(2)));
    }
}
