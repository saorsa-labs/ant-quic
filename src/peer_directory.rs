use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

use crate::bootstrap_cache::{CachedPeer, PeerCapabilities};
use crate::mdns::MdnsPeerRecord;
use crate::nat_traversal_api::PeerId;

/// Provider-neutral discovery source for peer directory records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PeerDiscoverySource {
    StaticKnownPeer,
    ManualKnownPeer,
    RuntimeKnownPeer,
    BootstrapCache,
    PeerHints,
    Mdns,
}

/// Durable authenticated peer view keyed by `PeerId`.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedPeerRecord {
    pub addresses: Vec<SocketAddr>,
    pub capabilities: PeerCapabilities,
    pub sources: BTreeSet<PeerDiscoverySource>,
}

impl AuthenticatedPeerRecord {
    pub fn merge_addr(&mut self, addr: SocketAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    pub fn merge_cached_peer(&mut self, peer: &CachedPeer, source: PeerDiscoverySource) {
        self.sources.insert(source);
        for addr in peer.preferred_addresses() {
            self.merge_addr(addr);
        }
        self.capabilities = peer.capabilities.clone();
    }

    pub fn merge_capabilities(&mut self, capabilities: &PeerCapabilities) {
        self.capabilities.supports_relay |= capabilities.supports_relay;
        self.capabilities.supports_coordination |= capabilities.supports_coordination;
        self.capabilities.hinted_supports_relay |= capabilities.hinted_supports_relay;
        self.capabilities.hinted_supports_coordination |= capabilities.hinted_supports_coordination;
        self.capabilities
            .protocols
            .extend(capabilities.protocols.clone());
        if capabilities.nat_type.is_some() {
            self.capabilities.nat_type = capabilities.nat_type;
        }
        for addr in &capabilities.external_addresses {
            self.capabilities.record_external_address(*addr);
        }
        for reachable in &capabilities.reachable_addresses {
            self.capabilities
                .record_direct_observation(reachable.address, reachable.verified_at);
        }
        if self.capabilities.direct_reachability_scope.is_none() {
            self.capabilities.direct_reachability_scope = capabilities.direct_reachability_scope;
        }
    }
}

/// Pre-auth locator claims kept separate from authenticated peer truth.
#[derive(Debug, Clone, Default)]
pub(crate) struct LocatorClaimRecord {
    pub claimed_peer_id: Option<PeerId>,
    pub addresses: Vec<SocketAddr>,
    pub sources: BTreeSet<PeerDiscoverySource>,
    pub mdns_peer: Option<MdnsPeerRecord>,
}

impl LocatorClaimRecord {
    pub fn merge_addr(&mut self, addr: SocketAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }
}

/// Aggregated provider-neutral peer directory view.
#[derive(Debug, Clone, Default)]
pub(crate) struct PeerDirectorySnapshot {
    authenticated: HashMap<PeerId, AuthenticatedPeerRecord>,
    locator_claims: Vec<LocatorClaimRecord>,
}

impl PeerDirectorySnapshot {
    pub fn authenticated_record_mut(&mut self, peer_id: PeerId) -> &mut AuthenticatedPeerRecord {
        self.authenticated
            .entry(peer_id)
            .or_insert_with(|| AuthenticatedPeerRecord {
                addresses: Vec::new(),
                capabilities: PeerCapabilities::default(),
                sources: BTreeSet::new(),
            })
    }

    pub fn add_authenticated_addr(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        source: PeerDiscoverySource,
    ) {
        let record = self.authenticated_record_mut(peer_id);
        record.sources.insert(source);
        record.merge_addr(addr);
    }

    pub fn add_authenticated_capabilities(
        &mut self,
        peer_id: PeerId,
        capabilities: &PeerCapabilities,
        source: PeerDiscoverySource,
    ) {
        let record = self.authenticated_record_mut(peer_id);
        record.sources.insert(source);
        record.merge_capabilities(capabilities);
    }

    pub fn add_cached_peer(&mut self, peer: &CachedPeer) {
        let record = self.authenticated_record_mut(peer.peer_id);
        record.merge_cached_peer(peer, PeerDiscoverySource::BootstrapCache);
    }

    pub fn add_locator_claim(
        &mut self,
        claimed_peer_id: Option<PeerId>,
        addresses: Vec<SocketAddr>,
        source: PeerDiscoverySource,
        mdns_peer: Option<MdnsPeerRecord>,
    ) {
        if let Some(claimed_peer_id) = claimed_peer_id
            && let Some(existing) = self
                .locator_claims
                .iter_mut()
                .find(|record| record.claimed_peer_id == Some(claimed_peer_id))
        {
            existing.sources.insert(source);
            for addr in addresses {
                existing.merge_addr(addr);
            }
            if mdns_peer.is_some() {
                existing.mdns_peer = mdns_peer;
            }
            return;
        }

        if let Some(existing) = self
            .locator_claims
            .iter_mut()
            .find(|record| record.claimed_peer_id.is_none() && record.addresses == addresses)
        {
            existing.sources.insert(source);
            if mdns_peer.is_some() {
                existing.mdns_peer = mdns_peer;
            }
            return;
        }

        let mut record = LocatorClaimRecord {
            claimed_peer_id,
            mdns_peer,
            ..LocatorClaimRecord::default()
        };
        record.sources.insert(source);
        for addr in addresses {
            record.merge_addr(addr);
        }
        self.locator_claims.push(record);
    }

    pub fn candidate_addrs_for_peer(&self, peer_id: PeerId) -> Vec<SocketAddr> {
        let mut addrs = self
            .authenticated
            .get(&peer_id)
            .map(|record| record.addresses.clone())
            .unwrap_or_default();

        for claim in self
            .locator_claims
            .iter()
            .filter(|record| record.claimed_peer_id == Some(peer_id))
        {
            for addr in &claim.addresses {
                if !addrs.contains(addr) {
                    addrs.push(*addr);
                }
            }
        }

        addrs
    }

    #[cfg(test)]
    pub fn authenticated_records(&self) -> impl Iterator<Item = &AuthenticatedPeerRecord> {
        self.authenticated.values()
    }

    pub fn locator_claims(&self) -> impl Iterator<Item = &LocatorClaimRecord> {
        self.locator_claims.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::MdnsPeerRecord;

    fn peer_id(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    fn make_mdns(pid: PeerId, addrs: Vec<SocketAddr>) -> MdnsPeerRecord {
        MdnsPeerRecord {
            service: "ant-quic".to_string(),
            fullname: "peer._ant-quic._udp.local.".to_string(),
            hostname: "peer.local.".to_string(),
            namespace: None,
            claimed_peer_id: Some(pid),
            addresses: addrs,
            metadata: std::collections::BTreeMap::new(),
            eligible: true,
            ineligible_reason: None,
        }
    }

    fn make_cached_peer(pid: PeerId, addrs: Vec<SocketAddr>) -> CachedPeer {
        CachedPeer::new(pid, addrs, crate::PeerSource::Unknown)
    }

    // ── AuthenticatedPeerRecord tests ──

    #[test]
    fn authenticated_record_new_is_empty() {
        let record = AuthenticatedPeerRecord {
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            sources: BTreeSet::new(),
        };
        assert!(record.addresses.is_empty());
        assert!(record.sources.is_empty());
    }

    #[test]
    fn authenticated_record_merge_addr() {
        let mut record = AuthenticatedPeerRecord {
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            sources: BTreeSet::new(),
        };
        record.merge_addr(addr(9000));
        assert_eq!(record.addresses.len(), 1);
        // Duplicate should not be added
        record.merge_addr(addr(9000));
        assert_eq!(record.addresses.len(), 1);
        // Different address should be added
        record.merge_addr(addr(9001));
        assert_eq!(record.addresses.len(), 2);
    }

    #[test]
    fn authenticated_record_merge_capabilities() {
        let mut record = AuthenticatedPeerRecord {
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            sources: BTreeSet::new(),
        };
        let mut caps = PeerCapabilities::default();
        caps.supports_relay = true;
        record.merge_capabilities(&caps);
        assert!(record.capabilities.supports_relay);
    }

    // ── LocatorClaimRecord tests ──

    #[test]
    fn locator_claim_default() {
        let claim = LocatorClaimRecord::default();
        assert!(claim.claimed_peer_id.is_none());
        assert!(claim.addresses.is_empty());
        assert!(claim.sources.is_empty());
        assert!(claim.mdns_peer.is_none());
    }

    #[test]
    fn locator_claim_merge_addr() {
        let mut claim = LocatorClaimRecord::default();
        claim.merge_addr(addr(9000));
        assert_eq!(claim.addresses.len(), 1);
        claim.merge_addr(addr(9000));
        assert_eq!(claim.addresses.len(), 1);
        claim.merge_addr(addr(9001));
        assert_eq!(claim.addresses.len(), 2);
    }

    // ── PeerDirectorySnapshot tests ──

    #[test]
    fn snapshot_default_is_empty() {
        let snapshot = PeerDirectorySnapshot::default();
        assert_eq!(snapshot.authenticated_records().count(), 0);
        assert_eq!(snapshot.locator_claims().count(), 0);
    }

    #[test]
    fn snapshot_add_authenticated_addr() {
        let pid = peer_id(1);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_authenticated_addr(pid, addr(9000), PeerDiscoverySource::PeerHints);
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert_eq!(addrs, vec![addr(9000)]);
    }

    #[test]
    fn snapshot_add_authenticated_addr_multiple_sources() {
        let pid = peer_id(1);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_authenticated_addr(pid, addr(9000), PeerDiscoverySource::PeerHints);
        snapshot.add_authenticated_addr(pid, addr(9001), PeerDiscoverySource::BootstrapCache);
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr(9000)));
        assert!(addrs.contains(&addr(9001)));
    }

    #[test]
    fn snapshot_add_authenticated_capabilities() {
        let pid = peer_id(2);
        let mut caps = PeerCapabilities::default();
        caps.supports_relay = true;
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_authenticated_capabilities(pid, &caps, PeerDiscoverySource::BootstrapCache);
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert!(addrs.is_empty());
    }

    #[test]
    fn snapshot_add_cached_peer() {
        let pid = peer_id(3);
        let cached = make_cached_peer(pid, vec![addr(9000), addr(9001)]);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_cached_peer(&cached);
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn snapshot_add_locator_claim_new() {
        let pid = peer_id(4);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(9002)],
            PeerDiscoverySource::Mdns,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 1);
    }

    #[test]
    fn snapshot_add_locator_claim_merges_existing() {
        let pid = peer_id(5);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(9000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        // Same peer with different address should merge into existing record
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(9001)],
            PeerDiscoverySource::StaticKnownPeer,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 1);
        // Both addresses should be in the merged record
        let claim = snapshot.locator_claims().next().unwrap();
        assert_eq!(claim.addresses.len(), 2);
        assert!(claim.addresses.contains(&addr(9000)));
        assert!(claim.addresses.contains(&addr(9001)));
    }

    #[test]
    fn snapshot_locator_claim_anonymous_not_merged_with_named() {
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(
            None,
            vec![addr(9000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        // A named claim for a different peer should create separate record
        let pid = peer_id(7);
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(9001)],
            PeerDiscoverySource::StaticKnownPeer,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 2);
    }

    #[test]
    fn snapshot_candidate_addrs_for_unknown_peer_returns_empty() {
        let snapshot = PeerDirectorySnapshot::default();
        let addrs = snapshot.candidate_addrs_for_peer(peer_id(99));
        assert!(addrs.is_empty());
    }

    #[test]
    fn snapshot_candidate_addrs_includes_locator_claims() {
        let pid = peer_id(6);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_authenticated_addr(pid, addr(1000), PeerDiscoverySource::PeerHints);
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(2000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr(1000)));
        assert!(addrs.contains(&addr(2000)));
    }

    #[test]
    fn snapshot_add_locator_claim_mdns_peer() {
        let pid = peer_id(8);
        let mdns = make_mdns(pid, vec![addr(3000)]);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(3000)],
            PeerDiscoverySource::Mdns,
            Some(mdns),
        );
        let claim = snapshot.locator_claims().next().unwrap();
        assert!(claim.mdns_peer.is_some());
        assert!(claim.sources.contains(&PeerDiscoverySource::Mdns));
    }

    #[test]
    fn snapshot_locator_claim_both_named_and_anonymous() {
        let mut snapshot = PeerDirectorySnapshot::default();
        // An anonymous claim
        snapshot.add_locator_claim(
            None,
            vec![addr(4000)],
            PeerDiscoverySource::StaticKnownPeer,
            None,
        );
        // A named claim
        snapshot.add_locator_claim(
            Some(peer_id(10)),
            vec![addr(4001)],
            PeerDiscoverySource::PeerHints,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 2);
    }

    #[test]
    fn snapshot_authenticated_record_mut_creates_new() {
        let pid = peer_id(9);
        let mut snapshot = PeerDirectorySnapshot::default();
        let record = snapshot.authenticated_record_mut(pid);
        assert!(record.addresses.is_empty());
        record.merge_addr(addr(5000));
        let record = snapshot.authenticated_record_mut(pid);
        assert_eq!(record.addresses.len(), 1);
    }

    #[test]
    fn snapshot_add_locator_claim_anonymous_same_addrs_merges() {
        let mut snapshot = PeerDirectorySnapshot::default();
        // Two anonymous claims with same addresses should merge
        snapshot.add_locator_claim(
            None,
            vec![addr(6000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        snapshot.add_locator_claim(
            None,
            vec![addr(6000)],
            PeerDiscoverySource::StaticKnownPeer,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 1);
        let claim = snapshot.locator_claims().next().unwrap();
        assert_eq!(claim.sources.len(), 2);
        assert!(claim.sources.contains(&PeerDiscoverySource::Mdns));
        assert!(claim.sources.contains(&PeerDiscoverySource::StaticKnownPeer));
    }

    #[test]
    fn snapshot_add_locator_claim_anonymous_different_addrs_no_merge() {
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(
            None,
            vec![addr(7000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        snapshot.add_locator_claim(
            None,
            vec![addr(7001)],
            PeerDiscoverySource::StaticKnownPeer,
            None,
        );
        assert_eq!(snapshot.locator_claims().count(), 2);
    }

    #[test]
    fn snapshot_candidate_addrs_deduplicates() {
        let pid = peer_id(11);
        let mut snapshot = PeerDirectorySnapshot::default();
        // Same address from both sources
        snapshot.add_authenticated_addr(pid, addr(8000), PeerDiscoverySource::PeerHints);
        snapshot.add_locator_claim(
            Some(pid),
            vec![addr(8000)],
            PeerDiscoverySource::Mdns,
            None,
        );
        let addrs = snapshot.candidate_addrs_for_peer(pid);
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn authenticated_record_merge_cached_peer_sets_sources() {
        let pid = peer_id(12);
        let cached = make_cached_peer(pid, vec![addr(9000)]);
        let mut record = AuthenticatedPeerRecord {
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            sources: BTreeSet::new(),
        };
        record.merge_cached_peer(&cached, PeerDiscoverySource::BootstrapCache);
        assert!(record.sources.contains(&PeerDiscoverySource::BootstrapCache));
    }

    #[test]
    fn authenticated_record_merge_capabilities_or_nat_type() {
        let mut record = AuthenticatedPeerRecord {
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            sources: BTreeSet::new(),
        };
        let mut caps = PeerCapabilities::default();
        caps.nat_type = Some(crate::CacheNatType::FullCone);
        caps.supports_coordination = true;
        record.merge_capabilities(&caps);
        assert_eq!(record.capabilities.nat_type, Some(crate::CacheNatType::FullCone));
        assert!(record.capabilities.supports_coordination);
    }

    #[test]
    fn snapshot_add_cached_peer_creates_authenticated() {
        let pid = peer_id(13);
        let cached = make_cached_peer(pid, vec![addr(1000)]);
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_cached_peer(&cached);
        let record = snapshot.authenticated_record_mut(pid);
        assert!(record.sources.contains(&PeerDiscoverySource::BootstrapCache));
    }
}
