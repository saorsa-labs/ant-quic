// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Path-adaptive QUIC keep-alive policy (#374 Wave 3).
//!
//! A flat keep-alive interval has to be short enough for the worst NAT on the
//! path (IPv4 NAT/CGNAT UDP bindings are often dropped after ~30 s of
//! silence). Paths that cross no address translation — native IPv6, a public
//! IPv4 address on the local interface, or a LAN/loopback path — do not need
//! that cadence. [`KeepAlivePolicy::PathAdaptive`] picks the interval per
//! connection from what the connection itself has observed, and sends no
//! extra bytes on the wire.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::Duration;

/// Default keep-alive interval for paths that cross (or may cross) IPv4 NAT/CGNAT.
pub const DEFAULT_TRANSLATED_KEEP_ALIVE: Duration = Duration::from_secs(22);

/// Default keep-alive interval for native IPv6 and public/direct paths.
pub const DEFAULT_DIRECT_KEEP_ALIVE: Duration = Duration::from_secs(55);

/// How a connection chooses its keep-alive interval.
///
/// The interval is always bounded by the connection's negotiated idle timeout
/// (see [`effective_keep_alive_interval`]), so an adaptive interval can never
/// let an otherwise healthy connection idle out. Keep-alives stay disabled
/// when [`crate::TransportConfig::keep_alive_interval`] is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KeepAlivePolicy {
    /// Use [`crate::TransportConfig::keep_alive_interval`] for every path (the default).
    #[default]
    Fixed,
    /// Pick the interval from the path class (see [`KeepAlivePathClass`]).
    PathAdaptive(AdaptiveKeepAlive),
}

impl KeepAlivePolicy {
    /// Path-adaptive keep-alives with the default intervals (22 s / 55 s).
    pub fn path_adaptive() -> Self {
        Self::PathAdaptive(AdaptiveKeepAlive::default())
    }
}

/// Intervals used by [`KeepAlivePolicy::PathAdaptive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveKeepAlive {
    /// Interval for paths that cross, or may cross, address translation
    /// (IPv4 NAT/CGNAT, NAT66) and for paths not yet classified. Default 22 s.
    pub translated: Duration,
    /// Interval for native IPv6, public IPv4 and LAN/loopback paths. Default 55 s.
    pub direct: Duration,
}

impl Default for AdaptiveKeepAlive {
    fn default() -> Self {
        Self {
            translated: DEFAULT_TRANSLATED_KEEP_ALIVE,
            direct: DEFAULT_DIRECT_KEEP_ALIVE,
        }
    }
}

/// What a connection knows about address translation on its local side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAlivePathClass {
    /// The path crosses no address translation on the local side: the peer saw
    /// our local address, the path is native IPv6, or the peer is on the
    /// loopback/LAN scope.
    Direct,
    /// The peer saw a different address than our local one (NAT/CGNAT/NAT66).
    Translated,
    /// No evidence yet, or none that can rule out translation. Treated like
    /// [`Self::Translated`].
    Unknown,
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

fn is_global_ipv6(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
        IpAddr::V4(_) => false,
    }
}

fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Classify a path for keep-alive purposes.
///
/// * `remote` — the peer's address on this path.
/// * `observed` — our own address as the peer reported it (QUIC
///   `OBSERVED_ADDRESS`, i.e. our server-reflexive address), if any.
/// * `local_ip` — the local IP the path uses, when the endpoint knows it (the
///   destination address of inbound packets; `None` on most client paths).
///
/// The rules, in order:
/// 1. A loopback or LAN-scoped peer is [`KeepAlivePathClass::Direct`].
/// 2. With both `observed` and `local_ip`: equal is `Direct`, different is
///    `Translated` (this also catches NAT66).
/// 3. An observed global IPv6 address is `Direct` (native IPv6).
/// 4. An observed IPv4 address without a local IP to compare with cannot rule
///    out NAT: `Unknown`.
/// 5. With no observation, a global IPv6 peer is `Direct`; anything else is
///    `Unknown`.
pub fn classify_keep_alive_path(
    remote: SocketAddr,
    observed: Option<SocketAddr>,
    local_ip: Option<IpAddr>,
) -> KeepAlivePathClass {
    let remote_ip = normalize_ip(remote.ip());
    if is_local_scope(remote_ip) {
        return KeepAlivePathClass::Direct;
    }
    let observed_ip = observed.map(|addr| normalize_ip(addr.ip()));
    let local_ip = local_ip.map(normalize_ip).filter(|ip| !ip.is_unspecified());
    match (observed_ip, local_ip) {
        (Some(seen), Some(local)) if seen == local => KeepAlivePathClass::Direct,
        (Some(_), Some(_)) => KeepAlivePathClass::Translated,
        (Some(seen), None) if is_global_ipv6(seen) => KeepAlivePathClass::Direct,
        (Some(_), None) => KeepAlivePathClass::Unknown,
        (None, _) if is_global_ipv6(remote_ip) => KeepAlivePathClass::Direct,
        (None, _) => KeepAlivePathClass::Unknown,
    }
}

/// Fraction of the negotiated idle timeout an adaptive interval may use.
///
/// The remaining quarter leaves room for a lost keep-alive PING to be
/// retransmitted (PTO) and acknowledged before either side's idle timer fires.
const IDLE_TIMEOUT_NUMERATOR: u32 = 3;
const IDLE_TIMEOUT_DENOMINATOR: u32 = 4;

/// The keep-alive interval a connection should use.
///
/// * `configured` — [`crate::TransportConfig::keep_alive_interval`]; `None`
///   disables keep-alives under every policy.
/// * `idle_timeout` — the negotiated idle timeout, if any. An adaptive
///   interval is capped at 3/4 of it. A [`KeepAlivePolicy::Fixed`] interval is
///   returned unchanged (the application chose it).
pub fn effective_keep_alive_interval(
    configured: Option<Duration>,
    policy: KeepAlivePolicy,
    class: KeepAlivePathClass,
    idle_timeout: Option<Duration>,
) -> Option<Duration> {
    let configured = configured?;
    let adaptive = match policy {
        KeepAlivePolicy::Fixed => return Some(configured),
        KeepAlivePolicy::PathAdaptive(adaptive) => adaptive,
    };
    let target = match class {
        KeepAlivePathClass::Direct => adaptive.direct,
        KeepAlivePathClass::Translated | KeepAlivePathClass::Unknown => adaptive.translated,
    };
    let capped = match idle_timeout {
        Some(idle) => target.min(idle * IDLE_TIMEOUT_NUMERATOR / IDLE_TIMEOUT_DENOMINATOR),
        None => target,
    };
    // A zero interval would re-arm the timer in a busy loop.
    Some(capped.max(Duration::from_millis(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("valid socket address")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip")
    }

    const IDLE_30S: Option<Duration> = Some(Duration::from_secs(30));
    const IDLE_120S: Option<Duration> = Some(Duration::from_secs(120));
    const FLAT: Option<Duration> = Some(Duration::from_secs(15));

    #[test]
    fn natted_ipv4_client_is_translated() {
        let class = classify_keep_alive_path(
            addr("203.0.113.7:443"),
            Some(addr("198.51.100.20:61000")),
            Some(ip("192.168.1.10")),
        );
        assert_eq!(class, KeepAlivePathClass::Translated);
    }

    #[test]
    fn cgnat_shared_address_is_translated() {
        // RFC 6598 100.64/10 local address, observed from outside as public.
        let class = classify_keep_alive_path(
            addr("203.0.113.7:443"),
            Some(addr("198.51.100.20:40000")),
            Some(ip("100.64.3.9")),
        );
        assert_eq!(class, KeepAlivePathClass::Translated);
    }

    #[test]
    fn public_ipv4_server_is_direct() {
        let class = classify_keep_alive_path(
            addr("198.51.100.20:61000"),
            Some(addr("203.0.113.7:443")),
            Some(ip("203.0.113.7")),
        );
        assert_eq!(class, KeepAlivePathClass::Direct);
    }

    #[test]
    fn dual_stack_mapped_addresses_compare_as_ipv4() {
        let class = classify_keep_alive_path(
            addr("[::ffff:198.51.100.20]:61000"),
            Some(addr("[::ffff:203.0.113.7]:443")),
            Some(ip("203.0.113.7")),
        );
        assert_eq!(class, KeepAlivePathClass::Direct);
    }

    #[test]
    fn native_ipv6_is_direct() {
        let remote = addr("[2001:db8:1::1]:443");
        assert_eq!(
            classify_keep_alive_path(remote, Some(addr("[2001:db8:2::5]:9000")), None),
            KeepAlivePathClass::Direct
        );
        assert_eq!(
            classify_keep_alive_path(remote, None, None),
            KeepAlivePathClass::Direct
        );
    }

    #[test]
    fn nat66_is_translated() {
        let class = classify_keep_alive_path(
            addr("[2001:db8:1::1]:443"),
            Some(addr("[2001:db8:ffff::1]:9000")),
            Some(ip("fd00::5")),
        );
        assert_eq!(class, KeepAlivePathClass::Translated);
    }

    #[test]
    fn ipv4_without_local_ip_is_unknown() {
        let remote = addr("203.0.113.7:443");
        assert_eq!(
            classify_keep_alive_path(remote, Some(addr("198.51.100.20:61000")), None),
            KeepAlivePathClass::Unknown
        );
        assert_eq!(
            classify_keep_alive_path(remote, None, None),
            KeepAlivePathClass::Unknown
        );
        // An unspecified local IP (wildcard bind) is no evidence either.
        assert_eq!(
            classify_keep_alive_path(remote, Some(addr("198.51.100.20:1")), Some(ip("0.0.0.0"))),
            KeepAlivePathClass::Unknown
        );
    }

    #[test]
    fn lan_and_loopback_peers_are_direct() {
        for remote in ["127.0.0.1:9000", "192.168.1.4:9000", "[fe80::1]:9000"] {
            assert_eq!(
                classify_keep_alive_path(addr(remote), None, None),
                KeepAlivePathClass::Direct,
                "{remote}"
            );
        }
    }

    #[test]
    fn fixed_policy_keeps_configured_interval() {
        for class in [
            KeepAlivePathClass::Direct,
            KeepAlivePathClass::Translated,
            KeepAlivePathClass::Unknown,
        ] {
            assert_eq!(
                effective_keep_alive_interval(FLAT, KeepAlivePolicy::Fixed, class, IDLE_30S),
                FLAT
            );
        }
    }

    #[test]
    fn disabled_keep_alive_stays_disabled() {
        assert_eq!(
            effective_keep_alive_interval(
                None,
                KeepAlivePolicy::path_adaptive(),
                KeepAlivePathClass::Translated,
                IDLE_120S,
            ),
            None
        );
    }

    #[test]
    fn adaptive_selects_by_class_when_idle_allows() {
        let policy = KeepAlivePolicy::path_adaptive();
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Translated, IDLE_120S),
            Some(Duration::from_secs(22))
        );
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Unknown, IDLE_120S),
            Some(Duration::from_secs(22))
        );
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Direct, IDLE_120S),
            Some(Duration::from_secs(55))
        );
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Direct, None),
            Some(Duration::from_secs(55))
        );
    }

    #[test]
    fn adaptive_is_capped_below_idle_timeout() {
        let policy = KeepAlivePolicy::path_adaptive();
        // 30 s idle (x0x default): cap is 22.5 s, so direct paths get 22.5 s
        // and translated paths keep their 22 s.
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Direct, IDLE_30S),
            Some(Duration::from_millis(22_500))
        );
        assert_eq!(
            effective_keep_alive_interval(FLAT, policy, KeepAlivePathClass::Translated, IDLE_30S),
            Some(Duration::from_secs(22))
        );
        assert_eq!(
            effective_keep_alive_interval(
                FLAT,
                policy,
                KeepAlivePathClass::Translated,
                Some(Duration::ZERO)
            ),
            Some(Duration::from_millis(1))
        );
    }
}
