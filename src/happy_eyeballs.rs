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
//! 5. The first successful connection wins; all other pending attempts are aborted
//!    before the winner is returned (see `race_connect` for the exact guarantee)
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

use std::any::Any;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures_util::FutureExt;
use thiserror::Error;
use tokio::task::JoinSet;
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

/// What one spawned attempt returns: the address it dialled and its result.
type AttemptOutcome<C> = (SocketAddr, Result<C, AttemptFailure>);

/// The payload of a caught panic. Its destructor is arbitrary code, so the
/// coordinator never drops one; the race hands it to the cleanup task (#294).
type PanicPayload = Box<dyn Any + Send>;

/// Why one attempt failed.
struct AttemptFailure {
    /// The error text that `AllAttemptsFailed` reports.
    message: String,
    /// The payload when the attempt (or the formatting of its error)
    /// panicked. It is kept as a value so that it is not dropped in the
    /// attempt task or on the coordinator.
    panic_payload: Option<PanicPayload>,
}

/// Longest time the winner waits for the aborted losers to end.
///
/// A loser that yields normally ends soon after it is aborted, so the wait is
/// normally short; scheduling does not guarantee it. A loser in a non-yielding
/// section (blocking code) cannot be stopped from outside. This bound keeps
/// such a loser from holding a ready winner; what is left after the bound goes
/// to a detached cleanup task (#294).
const LOSER_SHUTDOWN_GRACE: Duration = Duration::from_millis(50);

/// Spawn a single connection attempt into the race's [`JoinSet`].
///
/// The set owns the task: dropping or shutting down the set stops the
/// attempt. A panic in the attempt future, or in the formatting of its error,
/// becomes a failed attempt, so the coordinator always gets one outcome per
/// attempt. The panic payload is returned, not dropped.
fn spawn_attempt<F, Fut, C, E>(
    attempts: &mut JoinSet<AttemptOutcome<C>>,
    addr: SocketAddr,
    attempt_num: usize,
    connect_fn: &F,
) where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<C, E>> + Send + 'static,
    C: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    debug!(addr = %addr, attempt = attempt_num, "Starting connection attempt");
    let fut = connect_fn(addr);
    attempts.spawn(async move {
        // Format the error inside the catch: a panicking `Display` is a failed
        // attempt too.
        let attempt = async move { fut.await.map_err(|e| e.to_string()) };
        let outcome = match AssertUnwindSafe(attempt).catch_unwind().await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(message)) => Err(AttemptFailure {
                message,
                panic_payload: None,
            }),
            Err(payload) => Err(AttemptFailure {
                message: "connection attempt panicked".to_string(),
                panic_payload: Some(payload),
            }),
        };
        (addr, outcome)
    });
}

/// Keep the parts of a join result that have an arbitrary destructor, and
/// drop the rest here.
///
/// A connected loser's value goes to `loser_values` and a panic payload goes
/// to `panic_payloads`. What is dropped here has a trivial destructor: an
/// error `String`, or a join error for a cancelled task (it carries no
/// payload).
fn keep_leftovers<C>(
    joined: Result<AttemptOutcome<C>, tokio::task::JoinError>,
    loser_values: &mut Vec<C>,
    panic_payloads: &mut Vec<PanicPayload>,
) {
    match joined {
        Ok((_, Ok(value))) => loser_values.push(value),
        Ok((_, Err(failure))) => panic_payloads.extend(failure.panic_payload),
        Err(join_error) => {
            if let Ok(payload) = join_error.try_into_panic() {
                panic_payloads.push(payload);
            }
        }
    }
}

/// Hand what is left of a race to a detached cleanup task, so that the
/// coordinator never drops a loser's value or a panic payload (#294).
///
/// The task drops the values that losers already returned (losers that also
/// connected) and the panic payloads, then joins and drops the aborted losers
/// that have not ended yet. It ends when the last loser ends. When nothing is
/// left, no task is spawned.
fn release_losers<C: Send + 'static>(
    mut attempts: JoinSet<AttemptOutcome<C>>,
    loser_values: Vec<C>,
    panic_payloads: Vec<PanicPayload>,
) {
    if attempts.is_empty() && loser_values.is_empty() && panic_payloads.is_empty() {
        return;
    }
    debug!(
        still_running = attempts.len(),
        connected_losers = loser_values.len(),
        panic_payloads = panic_payloads.len(),
        "Happy Eyeballs: a cleanup task releases the losing attempts"
    );
    tokio::spawn(async move {
        drop(loser_values);
        drop(panic_payloads);
        // This task is the place where leftovers are dropped.
        while attempts.join_next().await.is_some() {}
    });
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
///
/// # Cancellation
///
/// One [`JoinSet`] owns every spawned attempt (#294).
/// - When an attempt wins, every other attempt is aborted before the winner
///   is returned. The race then waits at most 50 ms for the aborted attempts
///   to end. The race never drops a loser's value or a panic payload on the
///   coordinator: the value of a loser that also connected, every panic
///   payload (from an attempt, from the formatting of its error, or from a
///   destructor that panicked when an aborted attempt was dropped) and any
///   loser that has not ended yet go to a detached cleanup task. That task
///   drops them and ends when the last loser ends. So neither a blocking poll
///   nor a blocking destructor of a loser can hold the winner for more than
///   the bound. Of the attempt outcomes, the coordinator itself drops only
///   error strings and cancellation results, which have trivial destructors.
/// - The race owns `connect_fn` (it takes `F` by value). It drops the
///   callback, with everything that the callback captures, when
///   `race_connect` returns or when its future is dropped. That drop runs on
///   the caller's task, on the return path. `F` has no `Send + 'static`
///   bound, so the race cannot move this drop to another task. A caller must
///   therefore not let `connect_fn` capture anything whose drop blocks, or
///   must keep the last reference to such a value elsewhere (for example,
///   capture an `Arc` clone and keep another clone outside the race).
/// - When the caller drops the returned future (for example an outer
///   timeout), the set is dropped and every attempt is aborted. Results that
///   are already complete are dropped in that drop, on the caller's thread.
/// - An attempt that panics counts as a failed attempt; it does not stall the
///   race. Its payload goes to the cleanup task when the race ends.
///
/// Assumptions. Tokio cancellation is cooperative: an aborted attempt ends at
/// its next poll (its next `.await`), and the runtime then drops its future.
/// A normal async dial ends within the bound, but scheduling does not
/// guarantee it. An attempt in a non-yielding section, or a value with a
/// blocking destructor, keeps what it holds until that code ends; the race
/// cannot release it sooner. On a current-thread runtime the runtime drops
/// aborted attempts on the same thread, so blocking code there blocks the
/// whole runtime. An error value of `connect_fn` is formatted and dropped in
/// its own attempt task. `connect_fn` must therefore not hold resources that
/// the winner needs across blocking code, and its values and its captures
/// should drop without blocking.
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

    let mut attempts: JoinSet<AttemptOutcome<C>> = JoinSet::new();
    let mut errors: Vec<(SocketAddr, String)> = Vec::new();
    // Payloads of attempts that panicked before the race ended. They go to
    // the cleanup task at the end; the coordinator never drops them.
    let mut panic_payloads: Vec<PanicPayload> = Vec::new();
    let mut pending = sorted.iter().copied().enumerate().peekable();

    // Spawn the first attempt immediately
    if let Some((index, addr)) = pending.next() {
        spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
    }

    // Main event loop
    loop {
        let joined = if pending.peek().is_some() {
            // More addresses to try: race the next result against the delay timer.
            tokio::select! {
                biased;

                // Prefer checking results over starting new attempts
                joined = attempts.join_next() => joined,

                // Timer fires: start next attempt in parallel
                () = tokio::time::sleep(config.connection_attempt_delay) => {
                    if let Some((index, addr)) = pending.next() {
                        debug!(
                            addr = %addr,
                            attempt = index + 1,
                            "Starting parallel attempt after delay"
                        );
                        spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
                    }
                    continue;
                }
            }
        } else {
            // No more addresses to try - wait for the attempts in flight
            attempts.join_next().await
        };

        match joined {
            Some(Ok((addr, Ok(conn)))) => {
                info!(addr = %addr, "Happy Eyeballs: connection succeeded");
                // Abort every losing attempt, then give the aborted attempts a
                // bounded time to end. A loser that also connected returns a
                // value; move it out, never drop it here: its destructor can
                // block, and a timeout cannot interrupt a synchronous drop.
                // The same applies to a panic payload.
                attempts.abort_all();
                let mut loser_values = Vec::new();
                let _ = tokio::time::timeout(LOSER_SHUTDOWN_GRACE, async {
                    while let Some(joined) = attempts.join_next().await {
                        keep_leftovers(joined, &mut loser_values, &mut panic_payloads);
                    }
                })
                .await;
                release_losers(attempts, loser_values, panic_payloads);
                return Ok((conn, addr));
            }
            Some(Ok((addr, Err(failure)))) => {
                warn!(addr = %addr, error = %failure.message, "Connection attempt failed");
                panic_payloads.extend(failure.panic_payload);
                errors.push((addr, failure.message));
            }
            Some(Err(join_error)) => {
                // Panics in an attempt are caught inside it, so this arm sees
                // an external cancellation (runtime shutdown), or a panic in a
                // destructor while the runtime dropped the task.
                warn!(error = %join_error, "Connection attempt ended without a result");
                if let Ok(payload) = join_error.try_into_panic() {
                    panic_payloads.push(payload);
                }
            }
            None => {
                // No attempt in flight.
                if pending.peek().is_none() {
                    break;
                }
            }
        }

        // An attempt ended without a winner: start the next attempt
        // immediately (RFC 8305 Section 5).
        if let Some((index, addr)) = pending.next() {
            spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
        }
    }

    // Every attempt has ended; only panic payloads can be left.
    release_losers(attempts, Vec::new(), panic_payloads);
    Err(HappyEyeballsError::AllAttemptsFailed { errors })
}

// ============================================================================
// Happy Eyeballs v3 per-interface family-health cache (#374)
// ============================================================================

/// IPv4-preferred races on one network before the cache re-tests IPv6 first.
pub const DEFAULT_FAMILY_HEALTH_TTL: Duration = Duration::from_secs(10 * 60);

/// Dual-stack races that IPv4 must win, with IPv6 dialled first, before the
/// cache marks IPv6 as broken on the current network.
pub const DEFAULT_IPV6_FAILURE_THRESHOLD: u32 = 2;

/// Identifies the local network attachment for the family-health cache.
///
/// It holds the source address the host would use for an IPv4 and for an
/// IPv6 destination on the default route. A new interface, a new DHCP lease
/// or a new IPv6 prefix changes it, and a changed fingerprint flushes what
/// the cache learned (draft-ietf-happy-happyeyeballs-v3: remember per
/// network, forget on network change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkFingerprint {
    ipv4_source: Option<std::net::Ipv4Addr>,
    ipv6_source: Option<std::net::Ipv6Addr>,
}

impl NetworkFingerprint {
    /// Build a fingerprint from known source addresses.
    pub fn new(
        ipv4_source: Option<std::net::Ipv4Addr>,
        ipv6_source: Option<std::net::Ipv6Addr>,
    ) -> Self {
        Self {
            ipv4_source,
            ipv6_source,
        }
    }

    /// The fingerprint of the current default routes.
    ///
    /// Each family is resolved by `connect()`ing an unbound UDP socket to a
    /// documentation address (RFC 5737 `192.0.2.1`, RFC 3849 `2001:db8::1`)
    /// and reading the local address the kernel picked. A UDP `connect()`
    /// sends no packet. A family without a route resolves to `None`.
    pub fn current() -> Self {
        fn route_source(target: SocketAddr) -> Option<std::net::IpAddr> {
            let bind: SocketAddr = match target {
                SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
                SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
            };
            let socket = std::net::UdpSocket::bind(bind).ok()?;
            socket.connect(target).ok()?;
            let ip = socket.local_addr().ok()?.ip();
            (!ip.is_unspecified()).then_some(ip)
        }
        let ipv4_source = match route_source((std::net::Ipv4Addr::new(192, 0, 2, 1), 9).into()) {
            Some(std::net::IpAddr::V4(ip)) => Some(ip),
            _ => None,
        };
        let ipv6_source = match route_source(
            (std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9).into(),
        ) {
            Some(std::net::IpAddr::V6(ip)) => Some(ip),
            _ => None,
        };
        Self {
            ipv4_source,
            ipv6_source,
        }
    }
}

#[derive(Debug, Default)]
struct FamilyHealthState {
    fingerprint: Option<NetworkFingerprint>,
    ipv6_strikes: u32,
    ipv6_broken_until: Option<std::time::Instant>,
}

impl FamilyHealthState {
    /// Switch to `fingerprint`, forgetting everything learned on another network.
    fn observe(&mut self, fingerprint: NetworkFingerprint) {
        if self.fingerprint != Some(fingerprint) {
            if self.fingerprint.is_some() {
                debug!("Happy Eyeballs: network changed; flushing family-health cache");
            }
            *self = Self {
                fingerprint: Some(fingerprint),
                ..Self::default()
            };
        }
    }

    fn ipv6_broken(&mut self, now: std::time::Instant) -> bool {
        match self.ipv6_broken_until {
            Some(until) if now < until => true,
            Some(_) => {
                // Expired: re-test IPv6 first from a clean slate.
                self.ipv6_broken_until = None;
                self.ipv6_strikes = 0;
                false
            }
            None => false,
        }
    }
}

/// Per-network memory of a broken IPv6 path (Happy Eyeballs v3).
///
/// RFC 8305 dials IPv6 first and waits 250 ms before IPv4. On a network whose
/// IPv6 is broken or black-holed, every dual-stack connect pays that stall
/// and sends a wasted ~1.2 KiB pure-PQC Initial (plus retransmits) on IPv6.
/// The cache remembers, for the current [`NetworkFingerprint`] only, that
/// IPv4 kept winning races that IPv6 started first, and then starts IPv4
/// first; IPv6 still races after the stagger, so nothing is lost if IPv4 is
/// the broken family instead.
///
/// The cache is bounded (one network's state) and in memory only. A changed
/// fingerprint flushes it, an IPv6 win clears it, and the learned state
/// expires after the TTL so IPv6 is re-tested.
#[derive(Debug)]
pub struct FamilyHealthCache {
    state: parking_lot::Mutex<FamilyHealthState>,
    ipv6_failure_threshold: u32,
    ttl: Duration,
}

impl Default for FamilyHealthCache {
    fn default() -> Self {
        Self::new(DEFAULT_IPV6_FAILURE_THRESHOLD, DEFAULT_FAMILY_HEALTH_TTL)
    }
}

/// Whether the candidate list holds both address families.
pub fn is_dual_stack(candidates: &[SocketAddr]) -> bool {
    candidates.iter().any(SocketAddr::is_ipv4) && candidates.iter().any(SocketAddr::is_ipv6)
}

impl FamilyHealthCache {
    /// A cache that marks IPv6 broken after `ipv6_failure_threshold` (at least
    /// 1) lost races and keeps that state for `ttl`.
    pub fn new(ipv6_failure_threshold: u32, ttl: Duration) -> Self {
        Self {
            state: parking_lot::Mutex::new(FamilyHealthState::default()),
            ipv6_failure_threshold: ipv6_failure_threshold.max(1),
            ttl,
        }
    }

    /// The race configuration to use on `fingerprint`'s network.
    ///
    /// Returns `base` unchanged unless IPv6 is currently marked broken on this
    /// network and `base` prefers IPv6; then IPv4 is dialled first.
    pub fn config_for(
        &self,
        fingerprint: NetworkFingerprint,
        base: &HappyEyeballsConfig,
        now: std::time::Instant,
    ) -> HappyEyeballsConfig {
        let mut config = base.clone();
        if base.preferred_family == AddressFamily::IPv6Preferred
            && self.ipv6_suppressed(fingerprint, now)
        {
            debug!("Happy Eyeballs: IPv6 marked broken on this network; dialling IPv4 first");
            config.preferred_family = AddressFamily::IPv4Preferred;
        }
        config
    }

    /// Whether IPv6-first racing is currently suppressed on `fingerprint`'s network.
    pub fn ipv6_suppressed(
        &self,
        fingerprint: NetworkFingerprint,
        now: std::time::Instant,
    ) -> bool {
        let mut state = self.state.lock();
        state.observe(fingerprint);
        state.ipv6_broken(now)
    }

    /// Learn from one finished race.
    ///
    /// * `candidates` — the addresses raced; races with one family teach nothing.
    /// * `config` — the configuration the race used (from [`Self::config_for`]).
    /// * `winner` — the winning address, or `None` when every attempt failed
    ///   (the peer may simply be down, so that teaches nothing either).
    ///
    /// An IPv4 win in a race that dialled IPv6 first counts as an IPv6
    /// failure: IPv6 did not complete within the stagger plus a whole IPv4
    /// handshake. An IPv6 win clears all IPv6 failures.
    pub fn record_race(
        &self,
        fingerprint: NetworkFingerprint,
        candidates: &[SocketAddr],
        config: &HappyEyeballsConfig,
        winner: Option<SocketAddr>,
        now: std::time::Instant,
    ) {
        if !is_dual_stack(candidates) {
            return;
        }
        let Some(winner) = winner else {
            return;
        };
        let mut state = self.state.lock();
        state.observe(fingerprint);
        if winner.is_ipv6() {
            state.ipv6_strikes = 0;
            state.ipv6_broken_until = None;
            return;
        }
        if config.preferred_family != AddressFamily::IPv6Preferred {
            // IPv4 went first; the race says nothing about IPv6.
            return;
        }
        state.ipv6_strikes = state.ipv6_strikes.saturating_add(1);
        if state.ipv6_strikes >= self.ipv6_failure_threshold && state.ipv6_broken_until.is_none() {
            info!(
                strikes = state.ipv6_strikes,
                ttl_secs = self.ttl.as_secs(),
                "Happy Eyeballs: IPv6 keeps losing to IPv4 on this network; dialling IPv4 first"
            );
            // `checked_add` keeps a huge configured TTL from panicking; an
            // unrepresentable deadline falls back to one day.
            state.ipv6_broken_until = now
                .checked_add(self.ttl)
                .or_else(|| now.checked_add(Duration::from_secs(24 * 60 * 60)));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropWitness {
        count: Arc<AtomicUsize>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.dropped.notify_one();
        }
    }

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

    #[tokio::test]
    async fn dropping_race_cancels_entered_attempt() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_event = Arc::new(tokio::sync::Notify::new());
        let entered_for_attempt = Arc::clone(&entered);
        let dropped_for_attempt = Arc::clone(&dropped);
        let drop_event_for_attempt = Arc::clone(&drop_event);
        let addrs = vec![v6("[::1]:80")];

        let race = tokio::spawn(async move {
            race_connect(&addrs, &HappyEyeballsConfig::default(), move |_| {
                let entered = Arc::clone(&entered_for_attempt);
                let dropped = Arc::clone(&dropped_for_attempt);
                let drop_event = Arc::clone(&drop_event_for_attempt);
                async move {
                    let _witness = DropWitness {
                        count: dropped,
                        dropped: drop_event,
                    };
                    entered.notify_one();
                    std::future::pending::<Result<String, String>>().await
                }
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        race.abort();
        let _ = race.await;

        tokio::time::timeout(Duration::from_secs(1), drop_event.notified())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timing_out_race_cancels_entered_attempt() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_event = Arc::new(tokio::sync::Notify::new());
        let entered_for_attempt = Arc::clone(&entered);
        let dropped_for_attempt = Arc::clone(&dropped);
        let drop_event_for_attempt = Arc::clone(&drop_event);
        let addrs = vec![v6("[::1]:80")];

        let mut race = Box::pin(async {
            race_connect(&addrs, &HappyEyeballsConfig::default(), move |_| {
                let entered = Arc::clone(&entered_for_attempt);
                let dropped = Arc::clone(&dropped_for_attempt);
                let drop_event = Arc::clone(&drop_event_for_attempt);
                async move {
                    let _witness = DropWitness {
                        count: dropped,
                        dropped: drop_event,
                    };
                    entered.notify_one();
                    std::future::pending::<Result<String, String>>().await
                }
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                () = entered.notified() => {}
                result = &mut race => panic!("race ended before attempt entered: {result:?}"),
            }
        })
        .await
        .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(50), &mut race).await;

        assert!(result.is_err());
        drop(race);
        tokio::time::timeout(Duration::from_secs(1), drop_event.notified())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    /// #294: when a winner is found, a losing attempt that yields must
    /// already be stopped when `race_connect` returns. An abort that is only
    /// scheduled leaves the losing dial running (and holding its resources)
    /// after the caller has the winner. The winner itself must not be dropped.
    /// (A loser that does not yield is covered by
    /// `blocking_loser_does_not_hold_ready_winner`.)
    ///
    /// Deterministic: explicit gates on the current-thread runtime. The
    /// winning attempt waits until the losing dial has entered, and the check
    /// runs with no yield after the race returns, so a loser that is only
    /// scheduled for cancellation is still alive at the check.
    #[tokio::test]
    async fn winner_return_stops_losing_attempts_before_handoff() {
        let loser_entered = Arc::new(tokio::sync::Notify::new());
        let loser_dropped = Arc::new(AtomicUsize::new(0));
        let winner_dropped = Arc::new(AtomicUsize::new(0));
        let loser_entered_for_attempt = Arc::clone(&loser_entered);
        let loser_dropped_for_attempt = Arc::clone(&loser_dropped);
        let winner_dropped_for_attempt = Arc::clone(&winner_dropped);
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let race = race_connect(&addrs, &config, move |addr| {
            let loser_entered = Arc::clone(&loser_entered_for_attempt);
            let loser_dropped = Arc::clone(&loser_dropped_for_attempt);
            let winner_dropped = Arc::clone(&winner_dropped_for_attempt);
            async move {
                if addr == v6("[::1]:80") {
                    let _witness = DropWitness {
                        count: loser_dropped,
                        dropped: Arc::new(tokio::sync::Notify::new()),
                    };
                    loser_entered.notify_one();
                    std::future::pending::<Result<DropWitness, String>>().await
                } else {
                    // Gate: win only after the losing dial is in flight.
                    loser_entered.notified().await;
                    Ok(DropWitness {
                        count: winner_dropped,
                        dropped: Arc::new(tokio::sync::Notify::new()),
                    })
                }
            }
        });
        let (winner, addr) = tokio::time::timeout(Duration::from_secs(5), race)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(addr, v4("10.0.0.1:80"));
        assert_eq!(
            loser_dropped.load(Ordering::SeqCst),
            1,
            "the losing attempt must be stopped before the winner is returned"
        );
        assert_eq!(
            winner_dropped.load(Ordering::SeqCst),
            0,
            "stopping the losers must not drop the winning connection"
        );
        drop(winner);
        assert_eq!(winner_dropped.load(Ordering::SeqCst), 1);
    }

    /// #294: an attempt task that panics must count as a failed attempt.
    /// Before the fix the coordinator kept its own channel sender, so it
    /// waited for a result that never came and the race hung until an outer
    /// timeout cancelled it.
    ///
    /// Deterministic in outcome: the race uses no timer (one address), so a
    /// correct race ends on the attempt's first poll and a broken race never
    /// ends. The guard only bounds how long the failure takes to report.
    #[tokio::test]
    async fn panicking_attempt_is_a_failed_attempt_not_a_hang() {
        let addrs = vec![v6("[::1]:80")];

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            race_connect(&addrs, &HappyEyeballsConfig::default(), |addr| async move {
                if addr.is_ipv6() {
                    // `resume_unwind` skips the panic hook, so the test log stays clean.
                    std::panic::resume_unwind(Box::new("injected attempt panic"));
                }
                Ok::<String, String>(format!("connected to {addr}"))
            }),
        )
        .await;

        match outcome {
            Ok(Err(HappyEyeballsError::AllAttemptsFailed { errors })) => {
                assert_eq!(errors.len(), 1, "one failed attempt expected: {errors:?}");
                assert_eq!(errors[0].0, v6("[::1]:80"));
                assert!(
                    errors[0].1.contains("panicked"),
                    "failure must name the panic: {}",
                    errors[0].1
                );
            }
            Ok(other) => panic!("expected AllAttemptsFailed, got: {other:?}"),
            Err(_) => panic!("race hung after its only attempt panicked"),
        }
    }

    /// #294 round 2: a losing attempt that blocks in a non-yielding section
    /// (here `block_in_place`) cannot be stopped from outside, because tokio
    /// cancellation is cooperative. The race must still hand over a ready
    /// winner after a bounded wait. It must not wait until the blocked loser
    /// ends.
    ///
    /// Deterministic in outcome: the gate keeps the loser blocked until the
    /// test releases it, so a race that waits for the loser cannot return
    /// before the release. A race with a bounded wait returns long before the
    /// 5 s guard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_loser_does_not_hold_ready_winner() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut race = tokio::spawn(async move {
            race_connect(&addrs, &config, move |addr| {
                let entered = Arc::clone(&entered);
                let release_rx = Arc::clone(&release_rx);
                async move {
                    if addr.is_ipv6() {
                        entered.notify_one();
                        // Blocking section: an abort cannot interrupt it.
                        tokio::task::block_in_place(|| {
                            let _ = release_rx.lock().unwrap().recv();
                        });
                        std::future::pending::<Result<u8, String>>().await
                    } else {
                        // Gate: win only after the loser is blocked.
                        entered.notified().await;
                        Ok(42)
                    }
                }
            })
            .await
        });

        let before_release = tokio::time::timeout(Duration::from_secs(5), &mut race).await;
        // Release the blocked worker before any assertion, so that a failure
        // cannot leave a blocked thread behind.
        let _ = release_tx.send(());
        let joined = match before_release {
            Ok(joined) => joined,
            Err(_) => {
                let _ = tokio::time::timeout(Duration::from_secs(5), race).await;
                panic!("the ready winner was held until the blocked loser was released");
            }
        };
        let (winner, addr) = joined.unwrap().unwrap();
        assert_eq!(winner, 42);
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    /// A connection stand-in whose destructor can block until a gate opens.
    struct GatedDrop {
        gate: Option<Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Drop for GatedDrop {
        fn drop(&mut self) {
            if let Some(gate) = self.gate.take() {
                let _ = gate.lock().unwrap().recv();
            }
            self.dropped.notify_one();
        }
    }

    /// #294 round 3: a loser that also connected returns a value, and that
    /// value can have a blocking destructor. The race must not drop it on the
    /// winner's handoff path: a timeout cannot interrupt a synchronous drop,
    /// so an inline drop holds a ready winner without a bound. The value must
    /// still be dropped later (no leak).
    ///
    /// Deterministic: current-thread runtime and explicit gates. The winner
    /// completes first and wakes the loser, which completes in the same
    /// scheduler pass, so both results are ready when the race resumes. A
    /// separate thread opens the destructor gate only after the race returns
    /// (or after a 5 s guard). A race that drops the loser value inline can
    /// therefore return only after the gate opens.
    #[tokio::test]
    async fn blocking_loser_result_drop_does_not_hold_ready_winner() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate_rx = Arc::new(std::sync::Mutex::new(gate_rx));
        let (returned_tx, returned_rx) = std::sync::mpsc::channel::<()>();
        let gate_opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_opened_by_thread = Arc::clone(&gate_opened);
        let releaser = std::thread::spawn(move || {
            let _ = returned_rx.recv_timeout(Duration::from_secs(5));
            gate_opened_by_thread.store(true, Ordering::SeqCst);
            let _ = gate_tx.send(());
        });

        let loser_may_finish = Arc::new(tokio::sync::Notify::new());
        let loser_dropped = Arc::new(tokio::sync::Notify::new());
        let winner_dropped = Arc::new(tokio::sync::Notify::new());
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let loser_dropped_for_attempt = Arc::clone(&loser_dropped);
        let winner_dropped_for_attempt = Arc::clone(&winner_dropped);
        let loser_may_finish_for_attempt = Arc::clone(&loser_may_finish);

        let (winner, addr) = race_connect(&addrs, &config, move |addr| {
            let gate_rx = Arc::clone(&gate_rx);
            let loser_may_finish = Arc::clone(&loser_may_finish_for_attempt);
            let loser_dropped = Arc::clone(&loser_dropped_for_attempt);
            let winner_dropped = Arc::clone(&winner_dropped_for_attempt);
            async move {
                if addr.is_ipv6() {
                    // Loser: also connects, right after the winner.
                    loser_may_finish.notified().await;
                    Ok::<GatedDrop, String>(GatedDrop {
                        gate: Some(gate_rx),
                        dropped: loser_dropped,
                    })
                } else {
                    // Winner: wake the loser, then win.
                    loser_may_finish.notify_one();
                    Ok(GatedDrop {
                        gate: None,
                        dropped: winner_dropped,
                    })
                }
            }
        })
        .await
        .unwrap();

        let gate_was_open_at_return = gate_opened.load(Ordering::SeqCst);
        let _ = returned_tx.send(());
        releaser.join().unwrap();
        assert_eq!(addr, v4("10.0.0.1:80"));
        assert!(
            !gate_was_open_at_return,
            "the ready winner was held until the loser's destructor was released"
        );

        // No leak: the loser value is dropped after the handoff.
        tokio::time::timeout(Duration::from_secs(5), loser_dropped.notified())
            .await
            .unwrap();
        drop(winner);
        tokio::time::timeout(Duration::from_secs(1), winner_dropped.notified())
            .await
            .unwrap();
    }

    /// A panic payload whose destructor blocks until a gate opens.
    struct BlockingPayload {
        gate: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Drop for BlockingPayload {
        fn drop(&mut self) {
            let _ = self.gate.lock().unwrap().recv();
            self.dropped.notify_one();
        }
    }

    /// A dial error whose `Display` panics with a [`BlockingPayload`].
    struct PanickingDisplayError(std::sync::Mutex<Option<BlockingPayload>>);

    impl std::fmt::Display for PanickingDisplayError {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let payload = self.0.lock().unwrap().take();
            // `resume_unwind` skips the panic hook, so the test log stays clean.
            std::panic::resume_unwind(Box::new(payload))
        }
    }

    /// A future local that panics with a [`BlockingPayload`] when the
    /// aborted future is dropped.
    struct PanicOnCancel(Option<BlockingPayload>);

    impl Drop for PanicOnCancel {
        fn drop(&mut self) {
            if let Some(payload) = self.0.take() {
                std::panic::resume_unwind(Box::new(payload));
            }
        }
    }

    /// A gate that a separate thread opens only after the test reports that
    /// the race returned, or after a 5 s guard.
    struct ReleaseGate {
        gate: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
        opened: Arc<std::sync::atomic::AtomicBool>,
        returned: std::sync::mpsc::Sender<()>,
        thread: std::thread::JoinHandle<()>,
    }

    impl ReleaseGate {
        fn new() -> Self {
            let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
            let (returned, returned_rx) = std::sync::mpsc::channel::<()>();
            let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let opened_by_thread = Arc::clone(&opened);
            let thread = std::thread::spawn(move || {
                let _ = returned_rx.recv_timeout(Duration::from_secs(5));
                opened_by_thread.store(true, Ordering::SeqCst);
                let _ = gate_tx.send(());
            });
            Self {
                gate: Arc::new(std::sync::Mutex::new(gate_rx)),
                opened,
                returned,
                thread,
            }
        }

        /// Report that the race returned; return whether the gate was
        /// already open at that time.
        fn race_returned(self) -> bool {
            let was_open = self.opened.load(Ordering::SeqCst);
            let _ = self.returned.send(());
            self.thread.join().unwrap();
            was_open
        }
    }

    /// #294 round 4 (Codex probe 1): a losing dial error whose `Display`
    /// panics yields a panic payload. The race must not drop that payload on
    /// the coordinator: its destructor can block, and a timeout cannot
    /// interrupt a synchronous drop. The payload must still be dropped later.
    ///
    /// Deterministic: current-thread runtime and explicit gates. The winner
    /// completes first and wakes the loser, which fails in the same scheduler
    /// pass. A race that drops the payload inline can return only after the
    /// gate thread opens the gate (5 s guard).
    #[tokio::test]
    async fn losing_error_display_panic_payload_does_not_hold_ready_winner() {
        let gate = ReleaseGate::new();
        let payload_gate = Arc::clone(&gate.gate);
        let payload_dropped = Arc::new(tokio::sync::Notify::new());
        let payload_dropped_for_attempt = Arc::clone(&payload_dropped);
        let loser_may_finish = Arc::new(tokio::sync::Notify::new());
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let (winner, addr) = race_connect(&addrs, &config, move |addr| {
            let loser_may_finish = Arc::clone(&loser_may_finish);
            let gate = Arc::clone(&payload_gate);
            let dropped = Arc::clone(&payload_dropped_for_attempt);
            async move {
                if addr.is_ipv6() {
                    // Loser: fails right after the winner; formatting the
                    // error panics.
                    loser_may_finish.notified().await;
                    let payload = BlockingPayload { gate, dropped };
                    Err(PanickingDisplayError(std::sync::Mutex::new(Some(payload))))
                } else {
                    // Winner: wake the loser, then win.
                    loser_may_finish.notify_one();
                    Ok(42u8)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!((winner, addr), (42, v4("10.0.0.1:80")));
        assert!(
            !gate.race_returned(),
            "the ready winner was held until the loser's panic payload was released"
        );
        // No leak: the payload is dropped after the handoff.
        tokio::time::timeout(Duration::from_secs(5), payload_dropped.notified())
            .await
            .unwrap();
    }

    /// #294 round 4 (Codex probe 2): aborting a pending loser drops its
    /// future, and a destructor in that future can panic. Tokio then returns
    /// a panic-bearing join error. The race must not drop that error's
    /// payload on the coordinator either. The payload must still be dropped
    /// later.
    ///
    /// Deterministic: current-thread runtime and explicit gates, as above.
    #[tokio::test]
    async fn aborted_loser_panic_payload_does_not_hold_ready_winner() {
        let gate = ReleaseGate::new();
        let payload_gate = Arc::clone(&gate.gate);
        let payload_dropped = Arc::new(tokio::sync::Notify::new());
        let payload_dropped_for_attempt = Arc::clone(&payload_dropped);
        let loser_entered = Arc::new(tokio::sync::Notify::new());
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let (winner, addr) = race_connect(&addrs, &config, move |addr| {
            let loser_entered = Arc::clone(&loser_entered);
            let gate = Arc::clone(&payload_gate);
            let dropped = Arc::clone(&payload_dropped_for_attempt);
            async move {
                if addr.is_ipv6() {
                    // Loser: pending until aborted; the abort drops the bomb.
                    let _bomb = PanicOnCancel(Some(BlockingPayload { gate, dropped }));
                    loser_entered.notify_one();
                    std::future::pending::<Result<u8, String>>().await
                } else {
                    // Winner: win after the loser is pending.
                    loser_entered.notified().await;
                    Ok(42u8)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!((winner, addr), (42, v4("10.0.0.1:80")));
        assert!(
            !gate.race_returned(),
            "the ready winner was held until the aborted loser's panic payload was released"
        );
        // No leak: the payload is dropped after the handoff.
        tokio::time::timeout(Duration::from_secs(5), payload_dropped.notified())
            .await
            .unwrap();
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

#[cfg(test)]
mod family_health_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    fn home() -> NetworkFingerprint {
        NetworkFingerprint::new(
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            Some(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10)),
        )
    }

    fn cafe() -> NetworkFingerprint {
        NetworkFingerprint::new(Some(Ipv4Addr::new(10, 0, 0, 7)), None)
    }

    fn v4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 9000))
    }

    fn v6() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1), 9000))
    }

    /// Record `n` races that IPv4 won after IPv6 was dialled first.
    fn lose_ipv6(cache: &FamilyHealthCache, fp: NetworkFingerprint, n: u32, now: Instant) {
        for _ in 0..n {
            let config = cache.config_for(fp, &HappyEyeballsConfig::default(), now);
            cache.record_race(fp, &[v6(), v4()], &config, Some(v4()), now);
        }
    }

    #[test]
    fn learns_broken_ipv6_after_threshold() {
        let cache = FamilyHealthCache::default();
        let now = Instant::now();
        lose_ipv6(&cache, home(), DEFAULT_IPV6_FAILURE_THRESHOLD - 1, now);
        assert!(
            !cache.ipv6_suppressed(home(), now),
            "one loss is not enough"
        );
        lose_ipv6(&cache, home(), 1, now);
        assert!(cache.ipv6_suppressed(home(), now));
        let config = cache.config_for(home(), &HappyEyeballsConfig::default(), now);
        assert_eq!(config.preferred_family, AddressFamily::IPv4Preferred);
        assert_eq!(
            sort_addresses(&[v6(), v4()], &config),
            vec![v4(), v6()],
            "IPv4 is dialled first; IPv6 still races after the stagger"
        );
    }

    #[test]
    fn failures_and_single_family_races_teach_nothing() {
        let cache = FamilyHealthCache::new(1, DEFAULT_FAMILY_HEALTH_TTL);
        let now = Instant::now();
        let config = HappyEyeballsConfig::default();
        cache.record_race(home(), &[v6(), v4()], &config, None, now);
        cache.record_race(home(), &[v4()], &config, Some(v4()), now);
        let v4_first = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv4Preferred,
            ..HappyEyeballsConfig::default()
        };
        cache.record_race(home(), &[v6(), v4()], &v4_first, Some(v4()), now);
        assert!(!cache.ipv6_suppressed(home(), now));
    }

    #[test]
    fn ipv6_win_clears_learned_state() {
        let cache = FamilyHealthCache::default();
        let now = Instant::now();
        lose_ipv6(&cache, home(), DEFAULT_IPV6_FAILURE_THRESHOLD, now);
        assert!(cache.ipv6_suppressed(home(), now));
        let config = cache.config_for(home(), &HappyEyeballsConfig::default(), now);
        cache.record_race(home(), &[v6(), v4()], &config, Some(v6()), now);
        assert!(!cache.ipv6_suppressed(home(), now));
    }

    #[test]
    fn learned_state_expires_after_ttl() {
        let ttl = Duration::from_secs(60);
        let cache = FamilyHealthCache::new(1, ttl);
        let now = Instant::now();
        lose_ipv6(&cache, home(), 1, now);
        assert!(cache.ipv6_suppressed(home(), now + ttl - Duration::from_secs(1)));
        assert!(!cache.ipv6_suppressed(home(), now + ttl));
        // Expiry also reset the strike count: one more loss is needed.
        lose_ipv6(&cache, home(), 1, now + ttl);
        assert!(cache.ipv6_suppressed(home(), now + ttl));
    }

    #[test]
    fn interface_change_flushes_cache() {
        let cache = FamilyHealthCache::default();
        let now = Instant::now();
        lose_ipv6(&cache, home(), DEFAULT_IPV6_FAILURE_THRESHOLD, now);
        assert!(cache.ipv6_suppressed(home(), now));
        // Moving to another network forgets what was learned at home ...
        assert!(!cache.ipv6_suppressed(cafe(), now));
        // ... and coming back starts from scratch too.
        assert!(!cache.ipv6_suppressed(home(), now));
        // Strikes from one network do not add up with another's.
        lose_ipv6(&cache, home(), DEFAULT_IPV6_FAILURE_THRESHOLD - 1, now);
        lose_ipv6(&cache, cafe(), 1, now);
        assert!(!cache.ipv6_suppressed(cafe(), now));
    }

    #[test]
    fn ipv4_preferred_base_config_is_left_alone() {
        let cache = FamilyHealthCache::new(1, DEFAULT_FAMILY_HEALTH_TTL);
        let now = Instant::now();
        let base = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv4Preferred,
            connection_attempt_delay: Duration::from_millis(100),
            ..HappyEyeballsConfig::default()
        };
        let config = cache.config_for(home(), &base, now);
        assert_eq!(config.preferred_family, AddressFamily::IPv4Preferred);
        assert_eq!(config.connection_attempt_delay, Duration::from_millis(100));
    }

    #[test]
    fn current_fingerprint_is_stable() {
        // No packets are sent; on a host without routes both families are None.
        assert_eq!(NetworkFingerprint::current(), NetworkFingerprint::current());
    }

    /// A black-holed IPv6 dial: never completes.
    async fn dial(addr: SocketAddr) -> Result<SocketAddr, String> {
        if addr.is_ipv6() {
            std::future::pending::<()>().await;
        }
        Ok(addr)
    }

    #[tokio::test(start_paused = true)]
    async fn learned_cache_skips_the_ipv6_stall() {
        let cache = FamilyHealthCache::default();
        let fp = home();
        let candidates = [v6(), v4()];

        // Cold cache: IPv6 goes first and IPv4 only starts after the 250 ms stagger.
        for _ in 0..DEFAULT_IPV6_FAILURE_THRESHOLD {
            let config = cache.config_for(fp, &HappyEyeballsConfig::default(), Instant::now());
            let started = tokio::time::Instant::now();
            let (winner, _) = race_connect(&candidates, &config, dial)
                .await
                .unwrap_or_else(|e| panic!("race must succeed over IPv4: {e}"));
            assert_eq!(winner, v4());
            assert!(started.elapsed() >= Duration::from_millis(250));
            cache.record_race(fp, &candidates, &config, Some(winner), Instant::now());
        }

        // Learned: IPv4 goes first and wins with no stall.
        let config = cache.config_for(fp, &HappyEyeballsConfig::default(), Instant::now());
        let started = tokio::time::Instant::now();
        let (winner, _) = race_connect(&candidates, &config, dial)
            .await
            .unwrap_or_else(|e| panic!("race must succeed over IPv4: {e}"));
        assert_eq!(winner, v4());
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "learned IPv6 breakage must remove the stagger, took {:?}",
            started.elapsed()
        );
    }
}
