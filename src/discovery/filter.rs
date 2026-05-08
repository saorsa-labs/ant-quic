// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! `AddrFilter` trait + a few default impls (X0X-0038).
//!
//! Filters reorder / drop addresses produced by [`super::lookup::LookupRegistry`]
//! before they reach the connection pipeline. Mirrors iroh's `AddrFilter`
//! split: one trait, many small composable filters, no global registry.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Reorder/filter the addresses produced by a [`super::lookup::LookupRegistry`].
///
/// Filters are stateless from the caller's perspective: each call gets the
/// full address slice and returns the post-filter slice. Filters are NOT
/// allowed to mutate the input list — they consume `Vec<SocketAddr>` so the
/// type signature makes the ownership explicit.
pub trait AddrFilter: Send + Sync + 'static {
    /// Apply the filter.
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr>;
}

/// A no-op filter. Useful as a default and in tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassThroughFilter;

impl AddrFilter for PassThroughFilter {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        addrs
    }
}

/// Drops loopback addresses. Useful when we want to avoid attempting localhost
/// dials over an external resolver path.
#[derive(Debug, Default, Clone, Copy)]
pub struct DropLoopbackFilter;

impl AddrFilter for DropLoopbackFilter {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        addrs
            .into_iter()
            .filter(|sa| !sa.ip().is_loopback())
            .collect()
    }
}

/// Drops unspecified addresses (`0.0.0.0` / `::`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DropUnspecifiedFilter;

impl AddrFilter for DropUnspecifiedFilter {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        addrs
            .into_iter()
            .filter(|sa| !sa.ip().is_unspecified())
            .collect()
    }
}

/// Deduplicate addresses while preserving the first-seen order. Matches the
/// "stable order, no duplicates" expectation of iroh PR #4126.
#[derive(Debug, Default, Clone, Copy)]
pub struct DedupFilter;

impl AddrFilter for DedupFilter {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut seen = std::collections::HashSet::with_capacity(addrs.len());
        let mut out = Vec::with_capacity(addrs.len());
        for sa in addrs {
            if seen.insert(sa) {
                out.push(sa);
            }
        }
        out
    }
}

/// Prefer IPv6 over IPv4 (stable sort: IPv6 first, IPv4 after, original order
/// preserved within each family).
#[derive(Debug, Default, Clone, Copy)]
pub struct PreferIpv6Filter;

impl AddrFilter for PreferIpv6Filter {
    fn filter(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        addrs.sort_by_key(|sa| match sa.ip() {
            IpAddr::V6(_) => 0u8,
            IpAddr::V4(_) => 1u8,
        });
        addrs
    }
}

/// Compose multiple filters in sequence. Each filter sees the output of the
/// previous one.
#[derive(Default, Clone)]
pub struct CompositeFilter {
    filters: Vec<Arc<dyn AddrFilter>>,
}

impl std::fmt::Debug for CompositeFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeFilter")
            .field("filter_count", &self.filters.len())
            .finish()
    }
}

impl CompositeFilter {
    /// Empty composite. Equivalent to `PassThroughFilter`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a filter onto the end of the chain.
    pub fn push<F: AddrFilter>(mut self, f: F) -> Self {
        self.filters.push(Arc::new(f));
        self
    }

    /// Push an already-Arc'd filter onto the end.
    pub fn push_arc(mut self, f: Arc<dyn AddrFilter>) -> Self {
        self.filters.push(f);
        self
    }

    /// Number of filters in the chain.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

impl AddrFilter for CompositeFilter {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut current = addrs;
        for f in &self.filters {
            current = f.filter(current);
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        format!("192.0.2.1:{port}").parse().unwrap()
    }

    fn v6(port: u16) -> SocketAddr {
        format!("[2001:db8::1]:{port}").parse().unwrap()
    }

    fn lo(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn unspec(port: u16) -> SocketAddr {
        format!("0.0.0.0:{port}").parse().unwrap()
    }

    #[test]
    fn passthrough_returns_input_untouched() {
        let f = PassThroughFilter;
        let addrs = vec![v4(1), v6(2), lo(3)];
        assert_eq!(f.filter(addrs.clone()), addrs);
    }

    #[test]
    fn drop_loopback_removes_loopback_only() {
        let f = DropLoopbackFilter;
        let out = f.filter(vec![v4(1), lo(2), v6(3)]);
        assert_eq!(out, vec![v4(1), v6(3)]);
    }

    #[test]
    fn drop_unspecified_removes_zero_addrs() {
        let f = DropUnspecifiedFilter;
        let out = f.filter(vec![v4(1), unspec(2), v6(3)]);
        assert_eq!(out, vec![v4(1), v6(3)]);
    }

    #[test]
    fn dedup_preserves_first_seen_order() {
        let f = DedupFilter;
        let out = f.filter(vec![v4(1), v4(2), v4(1), v6(3), v4(2)]);
        assert_eq!(out, vec![v4(1), v4(2), v6(3)]);
    }

    #[test]
    fn prefer_ipv6_brings_v6_to_front_stable() {
        let f = PreferIpv6Filter;
        let out = f.filter(vec![v4(1), v6(2), v4(3), v6(4)]);
        assert_eq!(out, vec![v6(2), v6(4), v4(1), v4(3)]);
    }

    #[test]
    fn composite_chains_in_order() {
        let f = CompositeFilter::new()
            .push(DropLoopbackFilter)
            .push(DropUnspecifiedFilter)
            .push(DedupFilter)
            .push(PreferIpv6Filter);
        assert_eq!(f.len(), 4);
        let out = f.filter(vec![v4(1), lo(2), unspec(3), v4(1), v6(4)]);
        assert_eq!(out, vec![v6(4), v4(1)]);
    }

    #[test]
    fn empty_composite_is_passthrough() {
        let f = CompositeFilter::new();
        assert!(f.is_empty());
        let addrs = vec![v4(1), v6(2)];
        assert_eq!(f.filter(addrs.clone()), addrs);
    }
}
