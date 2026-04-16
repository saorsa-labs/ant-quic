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

    #[test]
    fn candidate_addrs_merge_authenticated_and_locator_claims() {
        let peer_id = PeerId([0x11; 32]);
        let addr_a: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let addr_b: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");

        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_authenticated_addr(peer_id, addr_a, PeerDiscoverySource::PeerHints);
        snapshot.add_locator_claim(
            Some(peer_id),
            vec![addr_b],
            PeerDiscoverySource::Mdns,
            Some(MdnsPeerRecord {
                service: "ant-quic".to_string(),
                fullname: "peer._ant-quic._udp.local.".to_string(),
                hostname: "peer.local.".to_string(),
                namespace: Some("workspace-a".to_string()),
                claimed_peer_id: Some(peer_id),
                addresses: vec![addr_b],
                metadata: std::collections::BTreeMap::new(),
                eligible: true,
                ineligible_reason: None,
            }),
        );

        let addrs = snapshot.candidate_addrs_for_peer(peer_id);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr_a));
        assert!(addrs.contains(&addr_b));
    }

    #[test]
    fn anonymous_locator_claims_stay_separate() {
        let addr: SocketAddr = "127.0.0.1:9002".parse().expect("valid addr");
        let mut snapshot = PeerDirectorySnapshot::default();
        snapshot.add_locator_claim(None, vec![addr], PeerDiscoverySource::StaticKnownPeer, None);

        assert_eq!(snapshot.locator_claims().count(), 1);
        assert_eq!(snapshot.authenticated_records().count(), 0);
    }
}
