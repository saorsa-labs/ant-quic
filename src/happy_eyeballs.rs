// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! RFC 8305 Happy Eyeballs v2 implementation for parallel IPv4/IPv6 connection racing.
//!
//! This module implements the Happy Eyeballs algorithm (RFC 8305) which races connection
//! attempts across multiple addresses with staggered timing. This is used to provide fast
//! and reliable connectivity in dual-stack environments where either IPv4 or IPv6 might be
//! faster or more reliable.
//!
//! # Algorithm Overview
//!
//! Per RFC 8305 Section 5:
//! 1. Addresses are sorted to interleave address families (starting with the preferred family)
//! 2. The first connection attempt starts immediately
//! 3. After a configurable delay (default 250ms), if no connection has succeeded, the next
//!    attempt starts in parallel
//! 4. On any failure, the next attempt starts immediately without waiting for the delay
//! 5. The first successful connection wins; all other pending attempts are cancelled
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::happy_eyeballs::{race_connect, HappyEyeballsConfig};
//! use std::net::SocketAddr;
//!
//! let addresses: Vec<SocketAddr> = vec![
//!     "192.168.1.1:9000".parse().unwrap(),
//!     "[::1]:9000".parse().unwrap(),
//! ];
//!
//! let config = HappyEyeballsConfig::default();
//! let (connection, addr) = race_connect(&addresses, &config, |addr| async move {
//!     // Your connection logic here
//!     Ok::<_, String>("connected")
//! }).await?;
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Which address family to prefer when interleaving connection attempts.
///
/// RFC 8305 recommends preferring IPv6 by default to encourage IPv6 adoption,
/// but applications may override this based on local network conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// Prefer IPv6 addresses first (RFC 8305 default)
    IPv6Preferred,
    /// Prefer IPv4 addresses first
    IPv4Preferred,
}

/// Configuration for the RFC 8305 Happy Eyeballs algorithm.
///
/// Controls timing and address family preferences for parallel connection racing.
///
/// # Defaults
///
/// - `connection_attempt_delay`: 250ms (RFC 8305 Section 5 recommendation)
/// - `first_address_family_count`: 1 (start with one address from the preferred family)
/// - `preferred_family`: [`AddressFamily::IPv6Preferred`]
#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    /// Delay before starting the next connection attempt (RFC 8305 recommends 250ms).
    ///
    /// If a connection attempt fails before this delay elapses, the next attempt
    /// starts immediately without waiting.
    pub connection_attempt_delay: Duration,

    /// Maximum number of addresses from the preferred family to try first.
    ///
    /// After this many addresses from the preferred family, addresses are interleaved
    /// between families.
    pub first_address_family_count: usize,

    /// Which address family to prefer when ordering connection attempts.
    pub preferred_family: AddressFamily,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            connection_attempt_delay: Duration::from_millis(250),
            first_address_family_count: 1,
            preferred_family: AddressFamily::IPv6Preferred,
        }
    }
}

/// Errors that can occur during the Happy Eyeballs connection racing algorithm.
#[derive(Debug, Error)]
pub enum HappyEyeballsError {
    /// No addresses were provided to attempt connections to.
    #[error("no addresses provided for connection attempts")]
    NoAddresses,

    /// All connection attempts failed.
    ///
    /// Contains the list of addresses attempted and their corresponding error messages.
    #[error(
        "all {count} connection attempts failed: {summary}",
        count = errors.len(),
        summary = format_error_summary(errors)
    )]
    AllAttemptsFailed {
        /// Each failed attempt's address and error description.
        errors: Vec<(SocketAddr, String)>,
    },

    /// The connection racing timed out before any attempt succeeded.
    #[error("connection racing timed out")]
    Timeout,
}

/// Formats a summary of connection errors for display.
fn format_error_summary(errors: &[(SocketAddr, String)]) -> String {
    errors
        .iter()
        .map(|(addr, err)| format!("{addr}: {err}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Sort addresses according to RFC 8305 Section 4 address interleaving.
///
/// The sorted order:
/// 1. Start with `config.first_address_family_count` addresses from the preferred family
/// 2. Then alternate between the non-preferred family and the preferred family
/// 3. Original order within each family is preserved
///
/// # Arguments
///
/// * `addresses` - The list of socket addresses to sort
/// * `config` - Configuration controlling preferred family and first-family count
///
/// # Returns
///
/// A new `Vec<SocketAddr>` with addresses interleaved per the algorithm.
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::happy_eyeballs::{sort_addresses, HappyEyeballsConfig, AddressFamily};
///
/// let addrs: Vec<SocketAddr> = vec![
///     "192.168.1.1:80".parse().unwrap(),  // v4_a
///     "[::1]:80".parse().unwrap(),         // v6_a
///     "192.168.1.2:80".parse().unwrap(),   // v4_b
///     "[::2]:80".parse().unwrap(),         // v6_b
///     "192.168.1.3:80".parse().unwrap(),   // v4_c
/// ];
///
/// let config = HappyEyeballsConfig {
///     preferred_family: AddressFamily::IPv6Preferred,
///     first_address_family_count: 1,
///     ..Default::default()
/// };
///
/// let sorted = sort_addresses(&addrs, &config);
/// // Result: [v6_a, v4_a, v6_b, v4_b, v4_c]
/// ```
pub fn sort_addresses(addresses: &[SocketAddr], config: &HappyEyeballsConfig) -> Vec<SocketAddr> {
    if addresses.is_empty() {
        return Vec::new();
    }

    let is_preferred = |addr: &SocketAddr| -> bool {
        match config.preferred_family {
            AddressFamily::IPv6Preferred => addr.is_ipv6(),
            AddressFamily::IPv4Preferred => addr.is_ipv4(),
        }
    };

    // Separate addresses into preferred and non-preferred families, preserving order
    let preferred: Vec<SocketAddr> = addresses.iter().copied().filter(is_preferred).collect();
    let non_preferred: Vec<SocketAddr> = addresses
        .iter()
        .copied()
        .filter(|a| !is_preferred(a))
        .collect();

    let mut result = Vec::with_capacity(addresses.len());

    // Phase 1: Add first_address_family_count addresses from preferred family
    let first_count = config.first_address_family_count.min(preferred.len());
    result.extend_from_slice(&preferred[..first_count]);

    // Phase 2: Interleave remaining addresses, starting with non-preferred
    let mut pref_iter = preferred[first_count..].iter();
    let mut non_pref_iter = non_preferred.iter();

    loop {
        let non_pref_next = non_pref_iter.next();
        let pref_next = pref_iter.next();

        match (non_pref_next, pref_next) {
            (Some(np), Some(p)) => {
                result.push(*np);
                result.push(*p);
            }
            (Some(np), None) => {
                result.push(*np);
            }
            (None, Some(p)) => {
                result.push(*p);
            }
            (None, None) => break,
        }
    }

    result
}

/// Message sent from a spawned connection attempt back to the coordinator.
enum AttemptResult<C> {
    /// Connection succeeded with the connection value and the address used.
    Success(C, SocketAddr),
    /// Connection failed with the address and error description.
    Failure(SocketAddr, String),
}

/// Spawn a single connection attempt as a tokio task.
///
/// The task sends its result (success or failure) through the provided channel sender.
fn spawn_attempt<F, Fut, C, E>(
    addr: SocketAddr,
    attempt_num: usize,
    connect_fn: &F,
    tx: &tokio::sync::mpsc::UnboundedSender<AttemptResult<C>>,
) -> JoinHandle<()>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<C, E>> + Send + 'static,
    C: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    debug!(addr = %addr, attempt = attempt_num, "Starting connection attempt");
    let fut = connect_fn(addr);
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        match fut.await {
            Ok(conn) => {
                // Ignore send errors - receiver may have been dropped if another attempt won
                let _ = tx_clone.send(AttemptResult::Success(conn, addr));
            }
            Err(e) => {
                let _ = tx_clone.send(AttemptResult::Failure(addr, e.to_string()));
            }
        }
    })
}

/// Race multiple connection attempts using the RFC 8305 Happy Eyeballs algorithm.
///
/// Attempts connections to the given addresses with staggered timing, returning the
/// first successful connection. Failed attempts trigger the next attempt immediately;
/// otherwise, the next attempt starts after `config.connection_attempt_delay`.
///
/// The function is generic over the connection function, making it testable without
/// requiring a real QUIC endpoint.
///
/// # Arguments
///
/// * `addresses` - List of socket addresses to try connecting to
/// * `config` - Happy Eyeballs configuration (timing, address family preferences)
/// * `connect_fn` - A function that takes a `SocketAddr` and returns a future resolving
///   to either a successful connection or an error
///
/// # Returns
///
/// A tuple of the successful connection and the address it connected to, or
/// a [`HappyEyeballsError`] if all attempts failed.
///
/// # Errors
///
/// Returns [`HappyEyeballsError::NoAddresses`] if the address list is empty.
/// Returns [`HappyEyeballsError::AllAttemptsFailed`] if every attempt fails.
///
/// # Algorithm
///
/// Per RFC 8305 Section 5:
/// 1. Sort addresses using [`sort_addresses`]
/// 2. Start the first connection attempt immediately
/// 3. Wait for `connection_attempt_delay` or for the attempt to complete
/// 4. If the attempt succeeded, return it (cancel remaining attempts)
/// 5. If the attempt failed, start the next attempt immediately
/// 6. If the delay elapsed, start the next attempt in parallel
/// 7. Repeat until one succeeds or all fail
pub async fn race_connect<F, Fut, C, E>(
    addresses: &[SocketAddr],
    config: &HappyEyeballsConfig,
    connect_fn: F,
) -> Result<(C, SocketAddr), HappyEyeballsError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<C, E>> + Send + 'static,
    C: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    if addresses.is_empty() {
        return Err(HappyEyeballsError::NoAddresses);
    }

    let sorted = sort_addresses(addresses, config);
    debug!(
        addresses = ?sorted,
        delay_ms = config.connection_attempt_delay.as_millis(),
        "Starting Happy Eyeballs connection racing"
    );

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AttemptResult<C>>();
    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(sorted.len());
    let mut errors: Vec<(SocketAddr, String)> = Vec::new();
    let mut next_index: usize = 0;
    let total = sorted.len();
    let mut in_flight: usize = 0;

    // Spawn the first attempt immediately
    handles.push(spawn_attempt(
        sorted[next_index],
        next_index + 1,
        &connect_fn,
        &tx,
    ));
    next_index += 1;
    in_flight += 1;

    // Main event loop
    loop {
        if next_index < total {
            // We have more addresses to try. Race between delay timer and results.
            tokio::select! {
                biased;

                // Prefer checking results over starting new attempts
                result = rx.recv() => {
                    match result {
                        Some(AttemptResult::Success(conn, addr)) => {
                            info!(addr = %addr, "Happy Eyeballs: connection succeeded");
                            abort_all(&handles);
                            return Ok((conn, addr));
                        }
                        Some(AttemptResult::Failure(addr, err)) => {
                            warn!(addr = %addr, error = %err, "Connection attempt failed");
                            errors.push((addr, err));
                            in_flight -= 1;

                            // On failure, start next attempt immediately (RFC 8305 Section 5)
                            if next_index < total {
                                handles.push(spawn_attempt(
                                    sorted[next_index],
                                    next_index + 1,
                                    &connect_fn,
                                    &tx,
                                ));
                                next_index += 1;
                                in_flight += 1;
                            }
                        }
                        None => {
                            // Channel closed unexpectedly
                            break;
                        }
                    }
                }

                // Timer fires: start next attempt in parallel
                _ = tokio::time::sleep(config.connection_attempt_delay) => {
                    if next_index < total {
                        debug!(
                            addr = %sorted[next_index],
                            attempt = next_index + 1,
                            "Starting parallel attempt after delay"
                        );
                        handles.push(spawn_attempt(
                            sorted[next_index],
                            next_index + 1,
                            &connect_fn,
                            &tx,
                        ));
                        next_index += 1;
                        in_flight += 1;
                    }
                }
            }
        } else {
            // No more addresses to try - wait for all pending results
            if in_flight == 0 {
                break;
            }

            match rx.recv().await {
                Some(AttemptResult::Success(conn, addr)) => {
                    info!(addr = %addr, "Happy Eyeballs: connection succeeded");
                    abort_all(&handles);
                    return Ok((conn, addr));
                }
                Some(AttemptResult::Failure(addr, err)) => {
                    warn!(addr = %addr, error = %err, "Connection attempt failed");
                    errors.push((addr, err));
                    in_flight -= 1;
                }
                None => {
                    // Channel closed
                    break;
                }
            }
        }
    }

    Err(HappyEyeballsError::AllAttemptsFailed { errors })
}

/// Abort all spawned task handles.
fn abort_all(handles: &[JoinHandle<()>]) {
    for handle in handles {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Parse a v4 socket address from a string.
    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Parse a v6 socket address from a string.
    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // ========================================================================
    // sort_addresses tests
    // ========================================================================

    #[test]
    fn test_sort_ipv6_preferred() {
        let addrs = vec![
            v4("192.168.1.1:80"), // v4_a
            v6("[::1]:80"),       // v6_a
            v4("192.168.1.2:80"), // v4_b
            v6("[::2]:80"),       // v6_b
            v4("192.168.1.3:80"), // v4_c
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv6Preferred,
            first_address_family_count: 1,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Expected: [v6_a, v4_a, v6_b, v4_b, v4_c]
        assert_eq!(sorted.len(), 5);
        assert_eq!(sorted[0], v6("[::1]:80")); // first preferred
        assert_eq!(sorted[1], v4("192.168.1.1:80")); // first non-preferred
        assert_eq!(sorted[2], v6("[::2]:80")); // second preferred
        assert_eq!(sorted[3], v4("192.168.1.2:80")); // second non-preferred
        assert_eq!(sorted[4], v4("192.168.1.3:80")); // remaining non-preferred
    }

    #[test]
    fn test_sort_ipv4_preferred() {
        let addrs = vec![
            v6("[::1]:80"),
            v4("10.0.0.1:80"),
            v6("[::2]:80"),
            v4("10.0.0.2:80"),
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv4Preferred,
            first_address_family_count: 1,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Expected: [v4_a, v6_a, v4_b, v6_b]
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0], v4("10.0.0.1:80")); // first preferred (v4)
        assert_eq!(sorted[1], v6("[::1]:80")); // first non-preferred (v6)
        assert_eq!(sorted[2], v4("10.0.0.2:80")); // second preferred (v4)
        assert_eq!(sorted[3], v6("[::2]:80")); // second non-preferred (v6)
    }

    #[test]
    fn test_sort_single_family() {
        // All IPv4 - should preserve original order
        let addrs = vec![v4("10.0.0.1:80"), v4("10.0.0.2:80"), v4("10.0.0.3:80")];

        let config = HappyEyeballsConfig::default(); // IPv6 preferred

        let sorted = sort_addresses(&addrs, &config);

        // No preferred addresses exist, so all go into non-preferred
        // Phase 1 adds 0 preferred (none exist), Phase 2 interleaves the rest
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0], v4("10.0.0.1:80"));
        assert_eq!(sorted[1], v4("10.0.0.2:80"));
        assert_eq!(sorted[2], v4("10.0.0.3:80"));
    }

    #[test]
    fn test_sort_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let config = HappyEyeballsConfig::default();
        let sorted = sort_addresses(&addrs, &config);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_sort_first_count_two() {
        let addrs = vec![
            v4("10.0.0.1:80"),
            v6("[::1]:80"),
            v4("10.0.0.2:80"),
            v6("[::2]:80"),
            v6("[::3]:80"),
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv6Preferred,
            first_address_family_count: 2,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Phase 1: [v6_a, v6_b] (first 2 preferred)
        // Phase 2: interleave remaining - non-preferred [v4_a, v4_b] with preferred [v6_c]
        // => [v4_a, v6_c, v4_b]
        assert_eq!(sorted.len(), 5);
        assert_eq!(sorted[0], v6("[::1]:80"));
        assert_eq!(sorted[1], v6("[::2]:80"));
        assert_eq!(sorted[2], v4("10.0.0.1:80"));
        assert_eq!(sorted[3], v6("[::3]:80"));
        assert_eq!(sorted[4], v4("10.0.0.2:80"));
    }

    // ========================================================================
    // race_connect tests
    // ========================================================================

    #[tokio::test]
    async fn test_race_single_address_success() {
        let addrs = vec![v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig::default();

        let result = race_connect(&addrs, &config, |addr| async move {
            Ok::<_, String>(format!("connected to {addr}"))
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_first_succeeds_fast() {
        // First attempt succeeds before delay, second should never start
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_count_clone = Arc::clone(&attempt_count);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(500),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, move |addr| {
            let count = Arc::clone(&attempt_count_clone);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                // Succeed immediately
                Ok::<_, String>(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to [::1]:80");
        assert_eq!(addr, v6("[::1]:80"));

        // Only one attempt should have been made (the first one succeeded immediately)
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_race_first_fails_second_succeeds() {
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_secs(10), // Long delay, won't fire
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            if addr == v6("[::1]:80") {
                Err("connection refused".to_string())
            } else {
                Ok(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_slow_first_fast_second() {
        // First attempt is slow (> delay), second attempt succeeds quickly
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(50),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            if addr == v6("[::1]:80") {
                // Slow: takes 2 seconds
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok::<_, String>(format!("connected to {addr}"))
            } else {
                // Fast: succeeds quickly
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        // The fast second attempt should win
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_all_fail() {
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80"), v4("10.0.0.2:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            Err::<String, _>(format!("failed to connect to {addr}"))
        })
        .await;

        match result {
            Err(HappyEyeballsError::AllAttemptsFailed { errors }) => {
                assert_eq!(errors.len(), 3, "Expected 3 errors, got {}", errors.len());
                // All three addresses should appear in the errors
                let addrs_in_errors: Vec<SocketAddr> =
                    errors.iter().map(|(addr, _)| *addr).collect();
                assert!(addrs_in_errors.contains(&v6("[::1]:80")));
                assert!(addrs_in_errors.contains(&v4("10.0.0.1:80")));
                assert!(addrs_in_errors.contains(&v4("10.0.0.2:80")));
            }
            other => panic!("Expected AllAttemptsFailed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_race_empty_addresses() {
        let addrs: Vec<SocketAddr> = vec![];
        let config = HappyEyeballsConfig::default();

        let result = race_connect(&addrs, &config, |addr| async move {
            Ok::<_, String>(format!("connected to {addr}"))
        })
        .await;

        match result {
            Err(HappyEyeballsError::NoAddresses) => {} // Expected
            other => panic!("Expected NoAddresses, got: {other:?}"),
        }
    }

    #[test]
    fn test_default_config() {
        let config = HappyEyeballsConfig::default();
        assert_eq!(config.connection_attempt_delay, Duration::from_millis(250));
        assert_eq!(config.preferred_family, AddressFamily::IPv6Preferred);
        assert_eq!(config.first_address_family_count, 1);
    }

    #[tokio::test]
    async fn test_race_immediate_failure_triggers_next() {
        // Verify that an immediate failure starts the next attempt without waiting
        // for the delay timer
        let attempt_times = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let attempt_times_clone = Arc::clone(&attempt_times);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            // Very long delay - if the second attempt starts quickly despite this,
            // it means the failure triggered it immediately
            connection_attempt_delay: Duration::from_secs(60),
            ..Default::default()
        };

        let start = tokio::time::Instant::now();
        let result = race_connect(&addrs, &config, move |addr| {
            let times = Arc::clone(&attempt_times_clone);
            let start_time = start;
            async move {
                {
                    let mut t = times.lock().await;
                    t.push((addr, start_time.elapsed()));
                }
                if addr == v6("[::1]:80") {
                    // Fail immediately
                    Err("connection refused".to_string())
                } else {
                    // Second attempt succeeds
                    Ok(format!("connected to {addr}"))
                }
            }
        })
        .await;

        let (conn, _addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");

        // Check that the second attempt started much sooner than the 60s delay
        let times = attempt_times.lock().await;
        assert_eq!(times.len(), 2);
        // The second attempt should start within a few ms, certainly not 60 seconds
        let second_start = times[1].1;
        assert!(
            second_start < Duration::from_millis(500),
            "Second attempt took too long to start: {second_start:?} (expected < 500ms, \
             indicating failure-triggered immediate start)"
        );
    }

    #[tokio::test]
    async fn test_race_cancels_remaining_on_success() {
        // Verify that remaining tasks are aborted when one succeeds
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_clone = Arc::clone(&completed);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80"), v4("10.0.0.2:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, move |addr| {
            let done = Arc::clone(&completed_clone);
            async move {
                if addr == v4("10.0.0.1:80") {
                    // This one succeeds after a short delay
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, String>(format!("connected to {addr}"))
                } else {
                    // Others take very long
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok(format!("connected to {addr}"))
                }
            }
        })
        .await;

        let (_conn, addr) = result.unwrap();
        assert_eq!(addr, v4("10.0.0.1:80"));

        // Give a moment for abort to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Only one task should have completed (the fast successful one).
        // The others should have been aborted.
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_error_display() {
        let err = HappyEyeballsError::NoAddresses;
        assert_eq!(
            err.to_string(),
            "no addresses provided for connection attempts"
        );

        let err = HappyEyeballsError::Timeout;
        assert_eq!(err.to_string(), "connection racing timed out");

        let err = HappyEyeballsError::AllAttemptsFailed {
            errors: vec![
                (v4("10.0.0.1:80"), "refused".to_string()),
                (v6("[::1]:80"), "timeout".to_string()),
            ],
        };
        let display = err.to_string();
        assert!(display.contains("10.0.0.1:80: refused"));
        assert!(display.contains("[::1]:80: timeout"));
    }
}
