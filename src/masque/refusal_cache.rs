// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Client-side relay refusal cache (ADR-019).
//!
//! When a relay answers a CONNECT-UDP request with the ADR-019 policy
//! refusal (`403 "relay service disabled"`), the client records the relay's
//! peer ID here with an expiry. While the entry is live, relay selection
//! skips that peer. The cache is in memory only and bounded in size; it is
//! never persisted, so the bootstrap-cache file format does not change.
//!
//! A `503` (capacity) answer never creates an entry: it means "try later",
//! not "never". Both kinds of refusal are counted for metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::masque::ConnectUdpResponse;
use crate::nat_traversal_api::PeerId;
use crate::shared::normalize_socket_addr;

/// How long a relay that refused with `403 "relay service disabled"` is
/// skipped. ADR-019 leaves the value open (open question 2); one hour keeps a
/// leaf from being retried on every dial while still letting an operator who
/// turns serving back on be picked up within the hour.
pub(crate) const RELAY_REFUSAL_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Upper bound on the number of refused relays remembered at once.
pub(crate) const RELAY_REFUSAL_CACHE_MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, Copy)]
struct Entry {
    expires: Instant,
    /// The address the refusal came from, so address-only relay sources
    /// (known peers, static relay nodes) can skip the relay once its
    /// authenticated peer ID has refused us.
    addr: Option<SocketAddr>,
}

/// In-memory, bounded, expiring set of relays that refused us by policy.
#[derive(Debug)]
pub(crate) struct RelayRefusalCache {
    /// Relay peer ID -> entry.
    entries: Mutex<HashMap<PeerId, Entry>>,
    ttl: Duration,
    max_entries: usize,
    /// Count of ADR-019 policy refusals (`403 "relay service disabled"`).
    refusals_forbidden: AtomicU64,
    /// Count of capacity refusals (`503`).
    refusals_capacity: AtomicU64,
    /// Test-only clock offset, so expiry can be tested without sleeping.
    #[cfg(test)]
    clock_offset: Mutex<Duration>,
}

impl Default for RelayRefusalCache {
    fn default() -> Self {
        Self::new(RELAY_REFUSAL_CACHE_TTL, RELAY_REFUSAL_CACHE_MAX_ENTRIES)
    }
}

impl RelayRefusalCache {
    pub(crate) fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries: max_entries.max(1),
            refusals_forbidden: AtomicU64::new(0),
            refusals_capacity: AtomicU64::new(0),
            #[cfg(test)]
            clock_offset: Mutex::new(Duration::ZERO),
        }
    }

    /// The cache's clock: `Instant::now()`, shifted in tests by
    /// `advance_clock`.
    pub(crate) fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now.checked_add(*self.clock_offset.lock()).unwrap_or(now);
        now
    }

    /// Move the cache's clock forward (tests only).
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, by: Duration) {
        let mut offset = self.clock_offset.lock();
        *offset = offset.saturating_add(by);
    }

    /// The expiry applied to new entries.
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Record a non-success CONNECT-UDP answer from `relay` at `relay_addr`.
    ///
    /// Only the ADR-019 policy refusal (status `403` and reason
    /// `"relay service disabled"`) creates a cache entry. A `503` is counted
    /// but never cached. Returns `true` when an entry was recorded.
    pub(crate) fn observe_response(
        &self,
        relay: Option<PeerId>,
        relay_addr: Option<SocketAddr>,
        response: &ConnectUdpResponse,
        now: Instant,
    ) -> bool {
        if response.status == ConnectUdpResponse::STATUS_UNAVAILABLE {
            self.refusals_capacity.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if !response.is_relay_service_disabled() {
            return false;
        }
        self.refusals_forbidden.fetch_add(1, Ordering::Relaxed);
        let Some(peer) = relay else {
            return false;
        };
        self.record(peer, relay_addr, now);
        true
    }

    /// Record a policy refusal from `relay`, valid until `now + ttl`.
    pub(crate) fn record(&self, relay: PeerId, addr: Option<SocketAddr>, now: Instant) {
        let expires = now.checked_add(self.ttl).unwrap_or(now);
        let addr = addr.map(normalize_socket_addr);
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires > now);
        if !entries.contains_key(&relay) && entries.len() >= self.max_entries {
            // Evict the entry closest to expiry to stay within the bound.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(peer, _)| *peer)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(relay, Entry { expires, addr });
    }

    /// Whether `relay` refused us by policy and the entry has not expired.
    pub(crate) fn is_refused(&self, relay: &PeerId, now: Instant) -> bool {
        let mut entries = self.entries.lock();
        match entries.get(relay) {
            Some(entry) if entry.expires > now => true,
            Some(_) => {
                entries.remove(relay);
                false
            }
            None => false,
        }
    }

    /// Whether a live refusal was recorded from `addr`.
    pub(crate) fn is_addr_refused(&self, addr: SocketAddr, now: Instant) -> bool {
        let addr = normalize_socket_addr(addr);
        self.entries
            .lock()
            .values()
            .any(|entry| entry.expires > now && entry.addr == Some(addr))
    }

    /// Number of live entries.
    pub(crate) fn len(&self, now: Instant) -> usize {
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires > now);
        entries.len()
    }

    /// Count of `403 "relay service disabled"` answers received.
    pub(crate) fn refusals_forbidden(&self) -> u64 {
        self.refusals_forbidden.load(Ordering::Relaxed)
    }

    /// Count of `503` (capacity) answers received.
    pub(crate) fn refusals_capacity(&self) -> u64 {
        self.refusals_capacity.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn relay_refusal_cache_records_policy_403_until_expiry() {
        let cache = RelayRefusalCache::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        let addr: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        assert!(cache.observe_response(
            Some(peer(1)),
            Some(addr),
            &ConnectUdpResponse::relay_service_disabled(),
            now
        ));
        assert!(cache.is_addr_refused(addr, now));
        assert!(!cache.is_addr_refused(addr, now + Duration::from_secs(60)));
        assert!(cache.is_refused(&peer(1), now));
        assert!(cache.is_refused(&peer(1), now + Duration::from_secs(59)));
        assert!(!cache.is_refused(&peer(1), now + Duration::from_secs(60)));
        assert_eq!(cache.len(now + Duration::from_secs(61)), 0);
        assert_eq!(cache.refusals_forbidden(), 1);
        assert_eq!(cache.refusals_capacity(), 0);
    }

    #[test]
    fn relay_refusal_cache_ignores_503_and_other_403_reasons() {
        let cache = RelayRefusalCache::default();
        let now = Instant::now();
        assert!(!cache.observe_response(
            Some(peer(2)),
            None,
            &ConnectUdpResponse::error(503, "Server at capacity"),
            now
        ));
        assert!(!cache.observe_response(
            Some(peer(3)),
            None,
            &ConnectUdpResponse::forbidden("Authentication required"),
            now
        ));
        assert!(!cache.is_refused(&peer(2), now));
        assert!(!cache.is_refused(&peer(3), now));
        assert_eq!(cache.len(now), 0);
        assert_eq!(cache.refusals_capacity(), 1);
        assert_eq!(cache.refusals_forbidden(), 0);
    }

    #[test]
    fn relay_refusal_cache_is_bounded() {
        let cache = RelayRefusalCache::new(Duration::from_secs(60), 3);
        let now = Instant::now();
        for i in 0..10u8 {
            cache.record(peer(i), None, now + Duration::from_millis(u64::from(i)));
        }
        let later = now + Duration::from_millis(20);
        assert_eq!(cache.len(later), 3);
        // The most recent entries survive.
        assert!(cache.is_refused(&peer(9), later));
        assert!(!cache.is_refused(&peer(0), later));
    }

    #[test]
    fn relay_refusal_cache_default_ttl_is_one_hour() {
        assert_eq!(RELAY_REFUSAL_CACHE_TTL, Duration::from_secs(3600));
        assert_eq!(RelayRefusalCache::default().ttl(), RELAY_REFUSAL_CACHE_TTL);
    }

    #[test]
    fn relay_refusal_cache_injected_clock_expires_entries() {
        let cache = RelayRefusalCache::default();
        cache.record(peer(4), None, cache.now());
        assert!(cache.is_refused(&peer(4), cache.now()));
        cache.advance_clock(RELAY_REFUSAL_CACHE_TTL);
        assert!(!cache.is_refused(&peer(4), cache.now()));
    }
}
