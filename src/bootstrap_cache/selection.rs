// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Epsilon-greedy peer selection.

use super::entry::CachedPeer;
use crate::reachability::{ReachabilityScope, socket_addr_scope};
use rand::Rng;
use std::collections::HashSet;

/// Peer selection strategy
#[derive(Debug, Clone, Copy)]
pub enum SelectionStrategy {
    /// Always select highest quality peers
    BestFirst,
    /// Epsilon-greedy: explore with probability epsilon
    EpsilonGreedy {
        /// Exploration rate (0.0 = pure exploitation, 1.0 = pure exploration)
        epsilon: f64,
    },
    /// Purely random selection
    Random,
}

impl Default for SelectionStrategy {
    fn default() -> Self {
        Self::EpsilonGreedy { epsilon: 0.1 }
    }
}

const fn scope_rank(scope: Option<ReachabilityScope>) -> u8 {
    match scope {
        Some(ReachabilityScope::Loopback) => 1,
        Some(ReachabilityScope::LocalNetwork) => 2,
        Some(ReachabilityScope::Global) => 3,
        None => 0,
    }
}

fn helper_preference_score(
    peer: &CachedPeer,
    require_relay: bool,
    require_coordination: bool,
) -> u8 {
    if !require_relay && !require_coordination {
        return 0;
    }

    let scope_score = scope_rank(peer.capabilities.direct_reachability_scope);
    let global_bonus = u8::from(
        (require_relay && peer.capabilities.supports_relay)
            || (require_coordination && peer.capabilities.supports_coordination),
    );

    scope_score.saturating_mul(2).saturating_add(global_bonus)
}

fn scope_match_score(observed: ReachabilityScope, target_scope: Option<ReachabilityScope>) -> u8 {
    match target_scope {
        Some(ReachabilityScope::Global) => u8::from(observed == ReachabilityScope::Global) * 3,
        Some(ReachabilityScope::LocalNetwork) => match observed {
            ReachabilityScope::LocalNetwork => 3,
            ReachabilityScope::Global => 2,
            ReachabilityScope::Loopback => 0,
        },
        Some(ReachabilityScope::Loopback) => u8::from(observed == ReachabilityScope::Loopback) * 3,
        None => scope_rank(Some(observed)),
    }
}

fn best_relay_score(peer: &CachedPeer, target: std::net::SocketAddr) -> u8 {
    let target_scope = socket_addr_scope(target);
    let target_is_ipv4 = target.is_ipv4();

    let direct_score = peer
        .capabilities
        .reachable_addresses
        .iter()
        .filter(|entry| entry.address.is_ipv4() == target_is_ipv4)
        .filter_map(|entry| {
            let scope_score = scope_match_score(entry.scope, target_scope);
            (scope_score > 0).then_some(scope_score.saturating_add(4))
        })
        .max()
        .unwrap_or(0);

    let observed_score = peer
        .capabilities
        .external_addresses
        .iter()
        .filter(|addr| addr.is_ipv4() == target_is_ipv4)
        .filter_map(|addr| {
            let scope_score = socket_addr_scope(*addr)
                .map(|scope| scope_match_score(scope, target_scope))
                .unwrap_or(0);
            (scope_score > 0).then_some(scope_score.saturating_add(2))
        })
        .max()
        .unwrap_or(0);

    let stored_score = peer
        .addresses
        .iter()
        .filter(|addr| addr.is_ipv4() == target_is_ipv4)
        .filter_map(|addr| {
            let scope_score = socket_addr_scope(*addr)
                .map(|scope| scope_match_score(scope, target_scope))
                .unwrap_or(0);
            (scope_score > 0).then_some(scope_score)
        })
        .max()
        .unwrap_or(0);

    direct_score.max(observed_score).max(stored_score)
}

/// Select peers using epsilon-greedy strategy
///
/// This balances exploitation (selecting known-good peers) with
/// exploration (trying unknown peers to discover potentially better ones).
///
/// # Arguments
/// * `peers` - Slice of cached peers to select from
/// * `count` - Number of peers to select
/// * `epsilon` - Exploration rate (0.0 = pure exploitation, 1.0 = pure exploration)
///
/// # Returns
/// References to selected peers, up to `count` items
pub fn select_epsilon_greedy(peers: &[CachedPeer], count: usize, epsilon: f64) -> Vec<&CachedPeer> {
    if peers.is_empty() || count == 0 {
        return Vec::new();
    }

    let mut rng = rand::thread_rng();
    let mut selected = Vec::with_capacity(count.min(peers.len()));
    let mut used_indices = HashSet::new();

    // Sort indices by quality for exploitation
    let mut sorted_indices: Vec<usize> = (0..peers.len()).collect();
    sorted_indices.sort_by(|&a, &b| {
        peers[b]
            .quality_score
            .partial_cmp(&peers[a].quality_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Calculate how many to explore vs exploit
    let target_count = count.min(peers.len());
    let explore_count = ((target_count as f64) * epsilon).ceil() as usize;
    let exploit_count = target_count.saturating_sub(explore_count);

    // Exploit: select top quality peers
    for &idx in sorted_indices.iter().take(exploit_count) {
        if used_indices.insert(idx) && selected.len() < target_count {
            selected.push(&peers[idx]);
        }
    }

    // Explore: randomly select from remaining peers
    // Preferentially select untested peers (those with neutral quality)
    let remaining: Vec<usize> = (0..peers.len())
        .filter(|idx| !used_indices.contains(idx))
        .collect();

    if !remaining.is_empty() && selected.len() < target_count {
        // Separate untested and tested peers
        let (untested, tested): (Vec<_>, Vec<_>) = remaining.iter().partition(|&&idx| {
            peers[idx].stats.success_count + peers[idx].stats.failure_count == 0
        });

        // Prefer untested peers for exploration
        let explore_pool = if !untested.is_empty() {
            untested
        } else {
            tested
        };

        // Randomly select from exploration pool
        let mut explore_indices: Vec<usize> = explore_pool.into_iter().copied().collect();
        // Shuffle for randomness
        for i in (1..explore_indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            explore_indices.swap(i, j);
        }

        for &idx in explore_indices.iter() {
            if selected.len() >= target_count {
                break;
            }
            if used_indices.insert(idx) {
                selected.push(&peers[idx]);
            }
        }
    }

    // Fill any remaining slots with best available
    for &idx in &sorted_indices {
        if selected.len() >= target_count {
            break;
        }
        if used_indices.insert(idx) {
            selected.push(&peers[idx]);
        }
    }

    selected
}

/// Select peers with specific capability preferences.
///
/// Prefers peers with stronger fresh direct-evidence scope first, using the
/// conservative global helper flags as an additional bonus, but does not
/// exclude unverified peers. This supports "measure, don't trust" selection.
#[allow(dead_code)]
pub fn select_with_capabilities(
    peers: &[CachedPeer],
    count: usize,
    require_relay: bool,
    require_coordination: bool,
) -> Vec<&CachedPeer> {
    if peers.is_empty() || count == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<&CachedPeer> = peers.iter().collect();

    // Prefer stronger fresh direct-evidence scope first, with conservative
    // global helper flags as an additional bonus. Do not exclude unverified peers.
    candidates.sort_by(|a, b| {
        let a_pref = helper_preference_score(a, require_relay, require_coordination);
        let b_pref = helper_preference_score(b, require_relay, require_coordination);
        b_pref
            .cmp(&a_pref)
            .then_with(|| {
                b.capabilities
                    .direct_reachability_scope
                    .cmp(&a.capabilities.direct_reachability_scope)
            })
            .then_with(|| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    candidates.into_iter().take(count).collect()
}

/// Select relay peers that can reach a target address.
///
/// Returns relays sorted by how well their fresh/address-specific evidence fits
/// the target scope and address family. Dual-stack support is an additional
/// preference, not the primary signal.
///
/// # Arguments
/// * `peers` - Slice of cached peers to select from
/// * `count` - Maximum number of relays to return
/// * `target` - The target address we want a relay path toward
/// * `prefer_dual_stack` - If true, prioritize dual-stack relays as a tie-breaker
pub fn select_relays_for_target(
    peers: &[CachedPeer],
    count: usize,
    target: std::net::SocketAddr,
    prefer_dual_stack: bool,
) -> Vec<&CachedPeer> {
    if peers.is_empty() || count == 0 {
        return Vec::new();
    }

    let target_is_ipv4 = target.is_ipv4();

    let mut candidates: Vec<&CachedPeer> = peers
        .iter()
        .filter(|p| {
            let preferred = p.preferred_addresses();
            preferred.is_empty()
                || preferred
                    .iter()
                    .any(|addr| addr.is_ipv4() == target_is_ipv4)
        })
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    candidates.sort_by(|a, b| {
        let a_pref = best_relay_score(a, target);
        let b_pref = best_relay_score(b, target);

        b_pref
            .cmp(&a_pref)
            .then_with(|| {
                if prefer_dual_stack {
                    b.capabilities
                        .supports_dual_stack()
                        .cmp(&a.capabilities.supports_dual_stack())
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| {
                b.capabilities
                    .direct_reachability_scope
                    .cmp(&a.capabilities.direct_reachability_scope)
            })
            .then_with(|| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    candidates.into_iter().take(count).collect()
}

/// Select peers that support dual-stack (IPv4 + IPv6) bridging.
///
/// These peers are valuable for bridging between IPv4-only and IPv6-only networks.
pub fn select_dual_stack_relays(peers: &[CachedPeer], count: usize) -> Vec<&CachedPeer> {
    let mut filtered: Vec<&CachedPeer> = peers
        .iter()
        .filter(|p| p.capabilities.supports_dual_stack())
        .collect();

    if filtered.is_empty() {
        return Vec::new();
    }

    filtered.sort_by(|a, b| {
        let a_pref = helper_preference_score(a, true, false);
        let b_pref = helper_preference_score(b, true, false);
        b_pref
            .cmp(&a_pref)
            .then_with(|| {
                b.capabilities
                    .direct_reachability_scope
                    .cmp(&a.capabilities.direct_reachability_scope)
            })
            .then_with(|| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    filtered.into_iter().take(count).collect()
}

/// Select peers by strategy
#[allow(dead_code)]
pub fn select_by_strategy(
    peers: &[CachedPeer],
    count: usize,
    strategy: SelectionStrategy,
) -> Vec<&CachedPeer> {
    match strategy {
        SelectionStrategy::BestFirst => {
            let mut sorted: Vec<&CachedPeer> = peers.iter().collect();
            sorted.sort_by(|a, b| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            sorted.into_iter().take(count).collect()
        }
        SelectionStrategy::EpsilonGreedy { epsilon } => {
            select_epsilon_greedy(peers, count, epsilon)
        }
        SelectionStrategy::Random => {
            let mut rng = rand::thread_rng();
            let mut indices: Vec<usize> = (0..peers.len()).collect();
            // Fisher-Yates shuffle
            for i in (1..indices.len()).rev() {
                let j = rng.gen_range(0..=i);
                indices.swap(i, j);
            }
            indices.into_iter().take(count).map(|i| &peers[i]).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_cache::entry::PeerSource;
    use crate::nat_traversal_api::PeerId;

    fn create_test_peers(count: usize) -> Vec<CachedPeer> {
        (0..count)
            .map(|i| {
                let mut peer = CachedPeer::new(
                    PeerId([i as u8; 32]),
                    vec![format!("127.0.0.1:{}", 9000 + i).parse().unwrap()],
                    PeerSource::Seed,
                );
                // Higher index = higher quality
                peer.quality_score = i as f64 / count as f64;
                peer
            })
            .collect()
    }

    #[test]
    fn test_select_empty() {
        let peers: Vec<CachedPeer> = vec![];
        let selected = select_epsilon_greedy(&peers, 5, 0.1);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_select_pure_exploitation() {
        let peers = create_test_peers(10);
        // epsilon=0 means pure exploitation (best first)
        let selected = select_epsilon_greedy(&peers, 5, 0.0);

        assert_eq!(selected.len(), 5);
        // Should be sorted by quality descending
        for i in 0..4 {
            assert!(selected[i].quality_score >= selected[i + 1].quality_score);
        }
        // First selected should be highest quality
        assert!((selected[0].quality_score - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_select_with_exploration() {
        let peers = create_test_peers(20);
        // epsilon=0.5 means 50% exploration
        // Run multiple times to verify randomness
        let mut has_variation = false;
        let first_selection = select_epsilon_greedy(&peers, 10, 0.5);

        for _ in 0..10 {
            let selection = select_epsilon_greedy(&peers, 10, 0.5);
            if selection.iter().map(|p| p.peer_id).collect::<Vec<_>>()
                != first_selection
                    .iter()
                    .map(|p| p.peer_id)
                    .collect::<Vec<_>>()
            {
                has_variation = true;
                break;
            }
        }
        // With 50% exploration, we should see some variation
        assert!(has_variation, "Expected variation with epsilon=0.5");
    }

    #[test]
    fn test_select_more_than_available() {
        let peers = create_test_peers(3);
        let selected = select_epsilon_greedy(&peers, 10, 0.1);
        assert_eq!(selected.len(), 3); // Can't select more than available
    }

    #[test]
    fn test_select_with_capabilities_prefers_broader_scope() {
        let mut peers = create_test_peers(3);

        peers[0].capabilities.direct_reachability_scope = Some(ReachabilityScope::LocalNetwork);
        peers[1].capabilities.direct_reachability_scope = Some(ReachabilityScope::Global);
        peers[1].capabilities.supports_relay = true;
        peers[1].capabilities.supports_coordination = true;

        let relays = select_with_capabilities(&peers, 3, true, false);
        assert_eq!(relays.len(), 3);
        assert_eq!(
            relays[0].peer_id, peers[1].peer_id,
            "global evidence should rank first"
        );
        assert_eq!(
            relays[1].peer_id, peers[0].peer_id,
            "local evidence should outrank unknown peers"
        );
    }

    #[test]
    fn test_best_first_strategy() {
        let peers = create_test_peers(10);
        let selected = select_by_strategy(&peers, 5, SelectionStrategy::BestFirst);

        assert_eq!(selected.len(), 5);
        // Should be strictly sorted by quality
        for i in 0..4 {
            assert!(selected[i].quality_score >= selected[i + 1].quality_score);
        }
    }

    #[test]
    fn test_random_strategy() {
        let peers = create_test_peers(20);
        // Run multiple times to verify randomness
        let mut has_variation = false;
        let first_selection = select_by_strategy(&peers, 10, SelectionStrategy::Random);

        for _ in 0..10 {
            let selection = select_by_strategy(&peers, 10, SelectionStrategy::Random);
            if selection.iter().map(|p| p.peer_id).collect::<Vec<_>>()
                != first_selection
                    .iter()
                    .map(|p| p.peer_id)
                    .collect::<Vec<_>>()
            {
                has_variation = true;
                break;
            }
        }
        assert!(has_variation, "Random selection should vary");
    }

    fn create_relay_peer_with_addresses(
        id: u8,
        quality: f64,
        ipv4_addrs: Vec<&str>,
        ipv6_addrs: Vec<&str>,
    ) -> CachedPeer {
        let mut peer = CachedPeer::new(PeerId([id; 32]), vec![], PeerSource::Seed);
        peer.quality_score = quality;

        for addr in ipv4_addrs {
            peer.capabilities
                .external_addresses
                .push(addr.parse().unwrap());
        }
        for addr in ipv6_addrs {
            peer.capabilities
                .external_addresses
                .push(addr.parse().unwrap());
        }

        peer.capabilities.direct_reachability_scope = peer
            .capabilities
            .external_addresses
            .iter()
            .filter_map(|addr| socket_addr_scope(*addr))
            .max();
        let globally_reachable = peer
            .capabilities
            .external_addresses
            .iter()
            .filter_map(|addr| socket_addr_scope(*addr))
            .any(|scope| scope == ReachabilityScope::Global);
        peer.capabilities.supports_relay = globally_reachable;
        peer.capabilities.supports_coordination = globally_reachable;

        peer
    }

    #[test]
    fn test_select_relays_for_ipv4_target() {
        let peers = vec![
            // Dual-stack relay (high quality)
            create_relay_peer_with_addresses(
                1,
                0.9,
                vec!["1.2.3.4:9000"],
                vec!["[2001:db8::10]:9000"],
            ),
            // IPv4-only relay (medium quality)
            create_relay_peer_with_addresses(2, 0.7, vec!["5.6.7.8:9001"], vec![]),
            // IPv6-only relay (high quality - should NOT be selected for IPv4 target)
            create_relay_peer_with_addresses(3, 0.95, vec![], vec!["[2001:db8::1]:9002"]),
        ];

        let selected = select_relays_for_target(&peers, 10, "8.8.8.8:443".parse().unwrap(), false);
        assert_eq!(selected.len(), 2);

        // Should include dual-stack and IPv4-only, NOT IPv6-only
        let ids: Vec<u8> = selected.iter().map(|p| p.peer_id.0[0]).collect();
        assert!(ids.contains(&1)); // dual-stack
        assert!(ids.contains(&2)); // IPv4-only
        assert!(!ids.contains(&3)); // IPv6-only excluded
    }

    #[test]
    fn test_select_relays_for_ipv6_target() {
        let peers = vec![
            // Dual-stack relay
            create_relay_peer_with_addresses(
                1,
                0.9,
                vec!["1.2.3.4:9000"],
                vec!["[2001:db8::10]:9000"],
            ),
            // IPv4-only relay (should NOT be selected for IPv6 target)
            create_relay_peer_with_addresses(2, 0.95, vec!["5.6.7.8:9001"], vec![]),
            // IPv6-only relay
            create_relay_peer_with_addresses(3, 0.7, vec![], vec!["[2001:db8::1]:9002"]),
        ];

        let selected = select_relays_for_target(
            &peers,
            10,
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            false,
        );
        assert_eq!(selected.len(), 2);

        // Should include dual-stack and IPv6-only, NOT IPv4-only
        let ids: Vec<u8> = selected.iter().map(|p| p.peer_id.0[0]).collect();
        assert!(ids.contains(&1)); // dual-stack
        assert!(!ids.contains(&2)); // IPv4-only excluded
        assert!(ids.contains(&3)); // IPv6-only
    }

    #[test]
    fn test_select_relays_prefer_dual_stack() {
        let peers = vec![
            // Dual-stack relay (lower quality)
            create_relay_peer_with_addresses(
                1,
                0.5,
                vec!["1.2.3.4:9000"],
                vec!["[2001:db8::10]:9000"],
            ),
            // IPv4-only relay (higher quality)
            create_relay_peer_with_addresses(2, 0.9, vec!["5.6.7.8:9001"], vec![]),
        ];

        // Without preference, higher quality first
        let selected = select_relays_for_target(&peers, 10, "8.8.8.8:443".parse().unwrap(), false);
        assert_eq!(selected[0].peer_id.0[0], 2); // IPv4-only first (higher quality)

        // With dual-stack preference, dual-stack first despite lower quality
        let selected = select_relays_for_target(&peers, 10, "8.8.8.8:443".parse().unwrap(), true);
        assert_eq!(selected[0].peer_id.0[0], 1); // Dual-stack first
    }

    #[test]
    fn test_select_dual_stack_relays() {
        let peers = vec![
            // Dual-stack relay
            create_relay_peer_with_addresses(
                1,
                0.9,
                vec!["1.2.3.4:9000"],
                vec!["[2001:db8::10]:9000"],
            ),
            // IPv4-only relay
            create_relay_peer_with_addresses(2, 0.8, vec!["5.6.7.8:9001"], vec![]),
            // IPv6-only relay
            create_relay_peer_with_addresses(3, 0.7, vec![], vec!["[2001:db8::1]:9002"]),
            // Another dual-stack relay
            create_relay_peer_with_addresses(
                4,
                0.6,
                vec!["9.9.9.9:9003"],
                vec!["[2001:db8::2]:9003"],
            ),
        ];

        let selected = select_dual_stack_relays(&peers, 10);
        assert_eq!(selected.len(), 2);

        // All selected should be dual-stack
        for peer in &selected {
            assert!(peer.capabilities.supports_dual_stack());
        }

        // Should be sorted by quality
        assert!(selected[0].quality_score >= selected[1].quality_score);
    }

    #[test]
    fn test_select_relays_excludes_non_relays() {
        let mut peers = vec![create_relay_peer_with_addresses(
            1,
            0.9,
            vec!["1.2.3.4:9000"],
            vec![],
        )];

        // Add a non-relay peer with high quality
        let mut non_relay = CachedPeer::new(PeerId([2; 32]), vec![], PeerSource::Seed);
        non_relay.quality_score = 0.99;
        non_relay.capabilities.supports_relay = false;
        non_relay
            .capabilities
            .external_addresses
            .push("5.6.7.8:9001".parse().unwrap());
        non_relay.capabilities.direct_reachability_scope = Some(ReachabilityScope::LocalNetwork);
        peers.push(non_relay);

        let selected = select_relays_for_target(&peers, 10, "8.8.8.8:443".parse().unwrap(), false);
        assert_eq!(selected.len(), 2);
        // Globally verified relay evidence should beat local-only fallback evidence.
        assert_eq!(selected[0].peer_id.0[0], 1);
    }

    #[test]
    fn test_select_relays_empty_when_no_match() {
        let peers = vec![
            // IPv6-only relay
            create_relay_peer_with_addresses(1, 0.9, vec![], vec!["[2001:db8::1]:9000"]),
        ];

        // Looking for IPv4 target - should return empty
        let selected = select_relays_for_target(&peers, 10, "8.8.8.8:443".parse().unwrap(), false);
        assert!(selected.is_empty());
    }
}
