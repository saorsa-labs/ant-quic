// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Cached peer entry types.

use crate::nat_traversal_api::PeerId;
use crate::reachability::{ReachabilityScope, socket_addr_scope};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

/// A cached peer entry with quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPeer {
    /// Unique peer identifier (serialized as bytes)
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,

    /// Known socket addresses for this peer
    pub addresses: Vec<SocketAddr>,

    /// Peer capabilities and features
    pub capabilities: PeerCapabilities,

    /// When we first discovered this peer
    pub first_seen: SystemTime,

    /// When we last successfully communicated with this peer
    pub last_seen: SystemTime,

    /// When we last attempted to connect (success or failure)
    pub last_attempt: Option<SystemTime>,

    /// Connection statistics
    pub stats: ConnectionStats,

    /// Computed quality score (0.0 to 1.0)
    #[serde(default = "default_quality_score")]
    pub quality_score: f64,

    /// Source that added this peer
    pub source: PeerSource,

    /// Known relay paths for reaching this peer when direct connection fails
    #[serde(default)]
    pub relay_paths: Vec<RelayPathHint>,

    /// Persistent QUIC address validation token
    #[serde(default)]
    pub token: Option<Vec<u8>>,
}

fn default_quality_score() -> f64 {
    0.5
}

/// Peer-verified directly reachable address evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachableAddressRecord {
    /// Address that was directly reachable.
    pub address: SocketAddr,
    /// Scope in which the address was verified.
    pub scope: ReachabilityScope,
    /// Most recent successful direct observation time.
    pub verified_at: SystemTime,
}

/// Peer capabilities and features
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Peer is suitable as a generally reusable relay helper.
    ///
    /// This is the **effective** relay signal used by cache selection. It is
    /// true when we have either fresh global-scope direct evidence or an
    /// explicit higher-layer assist hint persisted into the bootstrap cache.
    /// Scoped local/loopback direct evidence is preserved separately in
    /// `reachable_addresses` / `direct_reachability_scope` for callers that
    /// need to reason about reachability quality.
    pub supports_relay: bool,

    /// Peer is suitable as a generally reusable NAT traversal coordinator.
    ///
    /// Like `supports_relay`, this is an effective capability signal that may
    /// come from fresh global direct evidence or an explicit higher-layer hint.
    pub supports_coordination: bool,

    /// Whether a higher layer explicitly hinted that this peer can relay.
    ///
    /// This survives bootstrap-cache persistence and is combined with direct
    /// evidence to derive `supports_relay`.
    #[serde(default)]
    pub hinted_supports_relay: bool,

    /// Whether a higher layer explicitly hinted that this peer can coordinate.
    ///
    /// This survives bootstrap-cache persistence and is combined with direct
    /// evidence to derive `supports_coordination`.
    #[serde(default)]
    pub hinted_supports_coordination: bool,

    /// Protocol identifiers advertised by this peer (as hex strings for serialization)
    #[serde(default)]
    pub protocols: HashSet<String>,

    /// Observed NAT type hint
    pub nat_type: Option<NatType>,

    /// External addresses reported by peer
    #[serde(default)]
    pub external_addresses: Vec<SocketAddr>,

    /// Directly reachable addresses observed by this node.
    ///
    /// Unlike `external_addresses`, these addresses have been verified by an
    /// actual direct connection without coordinator or relay assistance. They
    /// may be global, LAN, or loopback addresses depending on the observer.
    #[serde(default)]
    pub reachable_addresses: Vec<ReachableAddressRecord>,

    /// Broadest scope among currently fresh direct reachability evidence.
    pub direct_reachability_scope: Option<ReachabilityScope>,
}

impl PeerCapabilities {
    fn refresh_effective_helper_flags(&mut self) {
        let globally_reachable = self.has_global_direct_reachability();
        self.supports_relay = globally_reachable || self.hinted_supports_relay;
        self.supports_coordination = globally_reachable || self.hinted_supports_coordination;
    }

    /// Record explicit higher-layer assist-role hints.
    pub fn record_assist_hints(&mut self, supports_relay: bool, supports_coordination: bool) {
        if supports_relay {
            self.hinted_supports_relay = true;
        }
        if supports_coordination {
            self.hinted_supports_coordination = true;
        }
        self.refresh_effective_helper_flags();
    }

    /// Record an externally observed address if we have not seen it before.
    pub fn record_external_address(&mut self, addr: SocketAddr) {
        if !self.external_addresses.contains(&addr) {
            self.external_addresses.push(addr);
        }
    }

    /// Record a fresh, peer-verified direct observation.
    pub fn record_direct_observation(&mut self, addr: SocketAddr, observed_at: SystemTime) {
        let scope = socket_addr_scope(addr).unwrap_or(ReachabilityScope::LocalNetwork);
        if let Some(existing) = self
            .reachable_addresses
            .iter_mut()
            .find(|entry| entry.address == addr)
        {
            existing.verified_at = observed_at;
            existing.scope = scope;
        } else {
            self.reachable_addresses.push(ReachableAddressRecord {
                address: addr,
                scope,
                verified_at: observed_at,
            });
        }
        self.direct_reachability_scope = self
            .reachable_addresses
            .iter()
            .map(|entry| entry.scope)
            .max();

        self.refresh_effective_helper_flags();
    }

    /// Whether peer-verified direct reachability evidence is still fresh.
    pub fn has_fresh_direct_reachability(&self, ttl: Duration, now: SystemTime) -> bool {
        self.reachable_addresses.iter().any(|entry| {
            now.duration_since(entry.verified_at)
                .map(|age| age <= ttl)
                .unwrap_or(false)
        })
    }

    /// Whether we have fresh global-scope direct evidence for this peer.
    pub fn has_global_direct_reachability(&self) -> bool {
        self.reachable_addresses
            .iter()
            .any(|entry| entry.scope == ReachabilityScope::Global)
    }

    /// Refresh derived relay/coordinator flags from fresh direct evidence.
    pub fn refresh_direct_capabilities(&mut self, ttl: Duration, now: SystemTime) {
        self.reachable_addresses.retain(|entry| {
            now.duration_since(entry.verified_at)
                .map(|age| age <= ttl)
                .unwrap_or(false)
        });

        self.direct_reachability_scope = self
            .reachable_addresses
            .iter()
            .map(|entry| entry.scope)
            .max();

        self.refresh_effective_helper_flags();
    }

    /// Return all known addresses, preferring peer-verified reachable addresses.
    pub fn known_addresses(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .reachable_addresses
            .iter()
            .map(|entry| entry.address)
            .collect();
        for addr in &self.external_addresses {
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
        }
        addrs
    }

    /// Check if this peer has any IPv4 addresses
    pub fn has_ipv4(&self) -> bool {
        self.known_addresses().iter().any(|addr| addr.is_ipv4())
    }

    /// Check if this peer has any IPv6 addresses
    pub fn has_ipv6(&self) -> bool {
        self.known_addresses().iter().any(|addr| addr.is_ipv6())
    }

    /// Check if this peer supports dual-stack (both IPv4 and IPv6)
    ///
    /// A dual-stack peer can bridge traffic between IPv4 and IPv6 networks
    /// when acting as a relay.
    pub fn supports_dual_stack(&self) -> bool {
        self.has_ipv4() && self.has_ipv6()
    }

    /// Get addresses filtered by IP version
    pub fn addresses_by_version(&self, ipv4: bool) -> Vec<SocketAddr> {
        self.known_addresses()
            .into_iter()
            .filter(|addr| addr.is_ipv4() == ipv4)
            .collect()
    }

    /// Check if this peer can bridge between source and target IP versions
    pub fn can_bridge(&self, source: &SocketAddr, target: &SocketAddr) -> bool {
        let source_v4 = source.is_ipv4();
        let target_v4 = target.is_ipv4();

        // Same version - any peer can handle
        if source_v4 == target_v4 {
            return true;
        }

        // Different versions - need dual-stack
        self.supports_dual_stack()
    }
}

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Address-restricted cone NAT
    AddressRestrictedCone,
    /// Port-restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown NAT type
    Unknown,
}

/// Connection statistics for quality scoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Total successful connections
    pub success_count: u32,

    /// Total failed connection attempts
    pub failure_count: u32,

    /// Exponential moving average RTT in milliseconds
    pub avg_rtt_ms: u32,

    /// Minimum observed RTT
    pub min_rtt_ms: u32,

    /// Maximum observed RTT
    pub max_rtt_ms: u32,

    /// Total bytes relayed through this peer (if relay)
    pub bytes_relayed: u64,

    /// Number of NAT traversals coordinated (if coordinator)
    pub coordinations_completed: u32,
}

/// How we discovered this peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PeerSource {
    /// User-provided bootstrap seed
    Seed,
    /// Discovered via active connection
    Connection,
    /// Discovered via relay traffic
    Relay,
    /// Discovered via NAT coordination
    Coordination,
    /// Merged from another cache instance
    Merge,
    /// Unknown source (legacy entries)
    #[default]
    Unknown,
}

/// Result of a connection attempt
#[derive(Debug, Clone)]
pub struct ConnectionOutcome {
    /// Whether the connection succeeded
    pub success: bool,
    /// RTT in milliseconds if available
    pub rtt_ms: Option<u32>,
    /// Capabilities discovered during connection
    pub capabilities_discovered: Option<PeerCapabilities>,
}

/// A relay path hint for reaching a peer through an intermediary
///
/// When direct connections fail, relay paths provide alternative routes.
/// This tracks known relays that can reach a given peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPathHint {
    /// EndpointId of the relay peer
    #[serde(with = "peer_id_serde")]
    pub relay_endpoint_id: PeerId,

    /// Known socket addresses for the relay
    pub relay_locators: Vec<SocketAddr>,

    /// Observed round-trip latency through this relay in milliseconds
    pub observed_latency_ms: Option<u32>,

    /// When this relay path was last successfully used
    pub last_used: SystemTime,
}

impl CachedPeer {
    /// Create a new peer entry
    pub fn new(peer_id: PeerId, addresses: Vec<SocketAddr>, source: PeerSource) -> Self {
        let now = SystemTime::now();
        Self {
            peer_id,
            addresses,
            capabilities: PeerCapabilities::default(),
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            stats: ConnectionStats::default(),
            quality_score: 0.5, // Neutral starting score
            source,
            relay_paths: Vec::new(),
            token: None,
        }
    }

    /// Record a successful connection
    pub fn record_success(&mut self, rtt_ms: u32, caps: Option<PeerCapabilities>) {
        self.last_seen = SystemTime::now();
        self.last_attempt = Some(SystemTime::now());
        self.stats.success_count = self.stats.success_count.saturating_add(1);

        // Update RTT with exponential moving average (alpha = 0.125)
        if self.stats.avg_rtt_ms == 0 {
            self.stats.avg_rtt_ms = rtt_ms;
            self.stats.min_rtt_ms = rtt_ms;
            self.stats.max_rtt_ms = rtt_ms;
        } else {
            self.stats.avg_rtt_ms = (self.stats.avg_rtt_ms * 7 + rtt_ms) / 8;
            self.stats.min_rtt_ms = self.stats.min_rtt_ms.min(rtt_ms);
            self.stats.max_rtt_ms = self.stats.max_rtt_ms.max(rtt_ms);
        }

        if let Some(caps) = caps {
            self.capabilities = caps;
        }
    }

    /// Record a failed connection attempt
    pub fn record_failure(&mut self) {
        self.last_attempt = Some(SystemTime::now());
        self.stats.failure_count = self.stats.failure_count.saturating_add(1);
    }

    /// Calculate quality score based on metrics
    pub fn calculate_quality(&mut self, weights: &super::config::QualityWeights) {
        let total_attempts = self.stats.success_count + self.stats.failure_count;

        // Success rate component (0.0 to 1.0)
        let success_rate = if total_attempts > 0 {
            self.stats.success_count as f64 / total_attempts as f64
        } else {
            0.5 // Neutral for untested peers
        };

        // RTT component (lower is better, normalized to 0.0-1.0)
        // 50ms = 1.0, 500ms = 0.5, 1000ms+ = 0.0
        let rtt_score = if self.stats.avg_rtt_ms > 0 {
            1.0 - (self.stats.avg_rtt_ms as f64 / 1000.0).min(1.0)
        } else {
            0.5 // Neutral for unknown RTT
        };

        // Freshness component (exponential decay with 24-hour half-life)
        let age_secs = self
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|last_seen_epoch| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|now_epoch| {
                        now_epoch
                            .as_secs()
                            .saturating_sub(last_seen_epoch.as_secs())
                    })
            })
            .unwrap_or(0) as f64;

        // Half-life of 24 hours = decay constant ln(2)/86400
        let freshness = (-age_secs * 0.693 / 86400.0).exp();

        // Capability bonuses
        let mut cap_bonus: f64 = 0.0;
        if self.capabilities.supports_relay {
            cap_bonus += 0.25;
        }
        if self.capabilities.supports_coordination {
            cap_bonus += 0.25;
        }
        if self.capabilities.supports_dual_stack() {
            cap_bonus += 0.2; // Dual-stack relays are valuable for bridging
        }
        let cap_score = cap_bonus.min(1.0);

        // Weighted combination
        self.quality_score = (success_rate * weights.success_rate
            + rtt_score * weights.rtt
            + freshness * weights.freshness
            + cap_score * weights.capabilities)
            .clamp(0.0, 1.0);
    }

    /// Check if this peer is stale
    pub fn is_stale(&self, threshold: Duration) -> bool {
        self.last_seen
            .elapsed()
            .map(|age| age > threshold)
            .unwrap_or(true)
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.stats.success_count + self.stats.failure_count;
        if total == 0 {
            0.5
        } else {
            self.stats.success_count as f64 / total as f64
        }
    }

    /// Return candidate addresses ordered by freshest reachability evidence first.
    ///
    /// This prefers peer-verified reachable and externally observed addresses,
    /// but still falls back to the persisted `addresses` list so unverified peers
    /// remain dialable.
    pub fn preferred_addresses(&self) -> Vec<SocketAddr> {
        let mut addrs = self.capabilities.known_addresses();
        for addr in &self.addresses {
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
        }
        addrs
    }

    /// Merge addresses from another peer entry
    pub fn merge_addresses(&mut self, other: &CachedPeer) {
        for addr in &other.addresses {
            if !self.addresses.contains(addr) {
                self.addresses.push(*addr);
            }
        }
        // Keep reasonable limit
        if self.addresses.len() > 10 {
            self.addresses.truncate(10);
        }
    }
}

/// Serde helper for PeerId serialization
mod peer_id_serde {
    use super::PeerId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(peer_id.0).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("PeerId must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PeerId(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_peer_new() {
        let peer_id = PeerId([1u8; 32]);
        let peer = CachedPeer::new(
            peer_id,
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.addresses.len(), 1);
        assert_eq!(peer.source, PeerSource::Seed);
        assert!((peer.quality_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_success() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        peer.record_success(100, None);
        assert_eq!(peer.stats.success_count, 1);
        assert_eq!(peer.stats.avg_rtt_ms, 100);
        assert_eq!(peer.stats.min_rtt_ms, 100);
        assert_eq!(peer.stats.max_rtt_ms, 100);

        peer.record_success(200, None);
        assert_eq!(peer.stats.success_count, 2);
        // EMA: (100*7 + 200) / 8 = 112
        assert_eq!(peer.stats.avg_rtt_ms, 112);
        assert_eq!(peer.stats.min_rtt_ms, 100);
        assert_eq!(peer.stats.max_rtt_ms, 200);
    }

    #[test]
    fn test_record_failure() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        peer.record_failure();
        assert_eq!(peer.stats.failure_count, 1);
        assert!(peer.last_attempt.is_some());
    }

    #[test]
    fn test_success_rate() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        // No attempts = 0.5
        assert!((peer.success_rate() - 0.5).abs() < f64::EPSILON);

        peer.record_success(100, None);
        assert!((peer.success_rate() - 1.0).abs() < f64::EPSILON);

        peer.record_failure();
        assert!((peer.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quality_calculation() {
        let weights = super::super::config::QualityWeights::default();
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        // Initial quality should be moderate (untested peer)
        peer.calculate_quality(&weights);
        assert!(peer.quality_score > 0.3 && peer.quality_score < 0.7);

        // Good performance should increase quality
        for _ in 0..5 {
            peer.record_success(50, None); // Low RTT
        }
        peer.calculate_quality(&weights);
        assert!(peer.quality_score > 0.6);
    }

    #[test]
    fn test_peer_serialization() {
        let peer = CachedPeer::new(
            PeerId([0xab; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: CachedPeer = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.peer_id, peer.peer_id);
        assert_eq!(deserialized.addresses, peer.addresses);
        assert_eq!(deserialized.source, peer.source);
    }

    #[test]
    fn test_peer_capabilities_dual_stack() {
        let mut caps = PeerCapabilities::default();

        // Default - no addresses
        assert!(!caps.supports_dual_stack());
        assert!(!caps.has_ipv4());
        assert!(!caps.has_ipv6());

        // Add IPv4 only
        caps.external_addresses
            .push("127.0.0.1:9000".parse().unwrap());
        assert!(!caps.supports_dual_stack());
        assert!(caps.has_ipv4());
        assert!(!caps.has_ipv6());

        // Add IPv6 - now dual-stack
        caps.external_addresses.push("[::1]:9001".parse().unwrap());
        assert!(caps.supports_dual_stack());
        assert!(caps.has_ipv4());
        assert!(caps.has_ipv6());
    }

    #[test]
    fn test_peer_capabilities_ipv6_only() {
        let mut caps = PeerCapabilities::default();
        caps.external_addresses.push("[::1]:9000".parse().unwrap());
        caps.external_addresses.push("[::1]:9001".parse().unwrap());

        assert!(!caps.supports_dual_stack());
        assert!(!caps.has_ipv4());
        assert!(caps.has_ipv6());
    }

    #[test]
    fn test_peer_capabilities_can_bridge() {
        let mut caps = PeerCapabilities::default();
        caps.external_addresses
            .push("127.0.0.1:9000".parse().unwrap());
        caps.external_addresses.push("[::1]:9001".parse().unwrap());

        let v4_src: SocketAddr = "192.168.1.1:1000".parse().unwrap();
        let v4_dst: SocketAddr = "192.168.1.2:2000".parse().unwrap();
        let v6_src: SocketAddr = "[2001:db8::1]:1000".parse().unwrap();
        let v6_dst: SocketAddr = "[2001:db8::2]:2000".parse().unwrap();

        // Same version - always OK
        assert!(caps.can_bridge(&v4_src, &v4_dst));
        assert!(caps.can_bridge(&v6_src, &v6_dst));

        // Cross version - OK for dual-stack
        assert!(caps.can_bridge(&v4_src, &v6_dst));
        assert!(caps.can_bridge(&v6_src, &v4_dst));
    }

    #[test]
    fn test_peer_capabilities_cannot_bridge_ipv4_only() {
        let mut caps = PeerCapabilities::default();
        caps.external_addresses
            .push("127.0.0.1:9000".parse().unwrap());

        let v4_addr: SocketAddr = "192.168.1.1:1000".parse().unwrap();
        let v6_addr: SocketAddr = "[2001:db8::1]:1000".parse().unwrap();

        // Same version - OK
        assert!(caps.can_bridge(&v4_addr, &v4_addr));

        // Cross version - NOT OK for IPv4-only
        assert!(!caps.can_bridge(&v4_addr, &v6_addr));
        assert!(!caps.can_bridge(&v6_addr, &v4_addr));
    }

    #[test]
    fn test_addresses_by_version() {
        let mut caps = PeerCapabilities::default();
        caps.external_addresses
            .push("127.0.0.1:9000".parse().unwrap());
        caps.external_addresses
            .push("10.0.0.1:9001".parse().unwrap());
        caps.external_addresses.push("[::1]:9002".parse().unwrap());

        let v4_addrs = caps.addresses_by_version(true);
        assert_eq!(v4_addrs.len(), 2);

        let v6_addrs = caps.addresses_by_version(false);
        assert_eq!(v6_addrs.len(), 1);
    }

    #[test]
    fn test_known_addresses_prefer_directly_reachable_addresses() {
        let mut caps = PeerCapabilities::default();
        let direct: SocketAddr = "192.168.1.20:9000".parse().unwrap();
        let external: SocketAddr = "203.0.113.10:9000".parse().unwrap();

        caps.record_direct_observation(direct, SystemTime::now());
        caps.record_external_address(external);
        caps.record_external_address(direct);

        let known = caps.known_addresses();
        assert_eq!(known[0], direct);
        assert!(known.contains(&external));
        assert_eq!(known.iter().filter(|addr| **addr == direct).count(), 1);
    }

    #[test]
    fn test_local_direct_observation_does_not_claim_global_helper_capability() {
        let mut caps = PeerCapabilities::default();
        let direct: SocketAddr = "192.168.1.20:9000".parse().unwrap();

        caps.record_direct_observation(direct, SystemTime::now());
        caps.refresh_direct_capabilities(Duration::from_secs(60), SystemTime::now());

        assert_eq!(
            caps.direct_reachability_scope,
            Some(ReachabilityScope::LocalNetwork)
        );
        assert!(!caps.supports_relay);
        assert!(!caps.supports_coordination);
    }

    #[test]
    fn test_preferred_addresses_include_cached_fallbacks() {
        let mut peer = CachedPeer::new(
            PeerId([7; 32]),
            vec!["198.51.100.7:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        peer.capabilities
            .record_direct_observation("192.168.1.20:9000".parse().unwrap(), SystemTime::now());
        peer.capabilities
            .record_external_address("203.0.113.20:9000".parse().unwrap());

        let preferred = peer.preferred_addresses();
        assert_eq!(preferred[0], "192.168.1.20:9000".parse().unwrap());
        assert!(preferred.contains(&"203.0.113.20:9000".parse().unwrap()));
        assert!(preferred.contains(&"198.51.100.7:9000".parse().unwrap()));
    }

    #[test]
    fn test_explicit_assist_hints_survive_direct_refresh() {
        let mut caps = PeerCapabilities::default();
        let now = SystemTime::now();

        caps.record_assist_hints(true, true);
        caps.record_direct_observation("203.0.113.20:9000".parse().unwrap(), now);
        caps.refresh_direct_capabilities(Duration::from_secs(60), now + Duration::from_secs(120));

        assert!(caps.reachable_addresses.is_empty());
        assert!(caps.hinted_supports_relay);
        assert!(caps.hinted_supports_coordination);
        assert!(caps.supports_relay);
        assert!(caps.supports_coordination);
        assert_eq!(caps.direct_reachability_scope, None);
    }

    #[test]
    fn test_refresh_direct_capabilities_prunes_stale_addresses() {
        let mut caps = PeerCapabilities::default();
        let direct: SocketAddr = "192.168.1.20:9000".parse().unwrap();
        let now = SystemTime::now();

        caps.record_direct_observation(direct, now - Duration::from_secs(120));
        caps.refresh_direct_capabilities(Duration::from_secs(60), now);

        assert!(caps.reachable_addresses.is_empty());
        assert!(!caps.supports_relay);
        assert!(!caps.supports_coordination);
        assert_eq!(caps.direct_reachability_scope, None);
    }
}
