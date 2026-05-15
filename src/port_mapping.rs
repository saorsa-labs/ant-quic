use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use igd_next::aio::Gateway as IgdGatewayHandle;
use igd_next::aio::tokio::{Tokio as IgdTokio, search_gateway};
use igd_next::{PortMappingProtocol, SearchOptions};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::unified_config::PortMappingConfig;

const DISCOVERY_RETRY_DELAY_INITIAL: Duration = Duration::from_secs(2);
/// Reviewer P2 #1: cap the exponential backoff at 5 minutes so we still
/// retry occasionally on a long-running daemon (e.g. user moves to a
/// network that does have IGD) without continuously hammering the network
/// when no gateway is present.
const DISCOVERY_RETRY_DELAY_MAX: Duration = Duration::from_secs(300);
/// After this many consecutive no-gateway failures, cap the retry interval
/// at `DISCOVERY_RETRY_DELAY_MAX` rather than continuing to double.
const DISCOVERY_RETRY_BACKOFF_DOUBLINGS: u32 = 7; // 2 → 4 → 8 → 16 → 32 → 64 → 128 → 256 → cap
const ZERO_LEASE_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const PORT_MAPPING_DESCRIPTION: &str = "ant-quic";

/// Reviewer P1 #2: filter UPnP-reported external addresses to those that
/// can plausibly serve as a globally-routable relay/candidate address.
/// Rejects:
/// - IPv4 private ranges (RFC 1918): 10/8, 172.16/12, 192.168/16
/// - IPv4 CGNAT (RFC 6598): 100.64.0.0/10 — common on cellular and
///   double-NAT residential setups; not globally routable
/// - IPv4 loopback (127/8), link-local (169.254/16), broadcast,
///   multicast (224/4), and reserved (240/4)
/// - IPv4 documentation/test ranges
/// - IPv6 anything non-global (loopback, link-local, ULA, multicast,
///   unspecified, IPv4-mapped)
///
/// On a CGNAT/double-NAT network the gateway's `get_external_ip()` returns
/// the inner-NAT's WAN address (e.g. 100.64.x.x or 192.168.x.x), not the
/// real internet address. Publishing such an address weakens MASQUE
/// fallback because peers will try to dial an address that doesn't route
/// from the public internet.
pub(crate) fn is_globally_routable_advertise_address(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => {
            // RFC 1918 private ranges
            if v4.is_private() {
                return false;
            }
            // RFC 6598 CGNAT — 100.64.0.0/10. `Ipv4Addr::is_shared` is
            // unstable on stable Rust as of 1.95, so test the range manually.
            let octets = v4.octets();
            if octets[0] == 100 && (octets[1] & 0xC0) == 0x40 {
                return false;
            }
            // Loopback / link-local / broadcast / multicast / unspecified /
            // documentation. `is_documentation` is unstable; covers 192.0.2/24,
            // 198.51.100/24, 203.0.113/24 — test manually.
            if v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
            {
                return false;
            }
            let is_documentation = matches!(
                (octets[0], octets[1], octets[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            );
            if is_documentation {
                return false;
            }
            // 240.0.0.0/4 reserved for future use
            if octets[0] >= 240 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            // UPnP IGD is IPv4-only, but the trait surface allows v6.
            // Be conservative: only accept truly-global v6.
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            // ULA fc00::/7
            let seg0 = v6.segments()[0];
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local fe80::/10
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            // IPv4-mapped ::ffff:0:0/96 — reject; would be smuggling a v4
            // address through a v6 surface, route via v4 checks instead.
            if matches!(v6.segments(), [0, 0, 0, 0, 0, 0xffff, _, _]) {
                return false;
            }
            true
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PortMappingSnapshot {
    pub active: bool,
    pub external_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortMappingEvent {
    Established { snapshot: PortMappingSnapshot },
    Renewed { snapshot: PortMappingSnapshot },
    Failed { error: String },
    Removed { external_addr: Option<SocketAddr> },
}

#[derive(Debug, thiserror::Error)]
enum PortMappingError {
    #[error("gateway discovery failed: {0}")]
    Discovery(String),
    #[error("gateway external IP lookup failed: {0}")]
    ExternalIp(String),
    #[error("router port-mapping request failed: {0}")]
    AddPort(String),
    #[error("router random-port-mapping request failed: {0}")]
    AddAnyPort(String),
    #[error("router mapping cleanup failed: {0}")]
    RemovePort(String),
    #[error("gateway address {0} is not IPv4")]
    UnsupportedGatewayAddress(SocketAddr),
    #[error("failed to determine LAN IPv4 via gateway {gateway}: {reason}")]
    DetermineLanIpv4 { gateway: SocketAddr, reason: String },
}

struct ActivePortMapping {
    gateway: Box<dyn GatewayControl>,
    local_addr: SocketAddr,
    external_addr: SocketAddr,
}

#[async_trait]
trait GatewayControl: Send + Sync {
    fn gateway_addr(&self) -> SocketAddr;

    async fn get_external_ip(&self) -> Result<IpAddr, PortMappingError>;

    async fn add_port(
        &self,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration_secs: u32,
        description: &str,
    ) -> Result<(), PortMappingError>;

    async fn add_any_port(
        &self,
        local_addr: SocketAddr,
        lease_duration_secs: u32,
        description: &str,
    ) -> Result<u16, PortMappingError>;

    async fn remove_port(&self, external_port: u16) -> Result<(), PortMappingError>;
}

#[async_trait]
trait GatewayDiscoverer: Send + Sync {
    async fn discover(&self) -> Result<Box<dyn GatewayControl>, PortMappingError>;
}

#[derive(Debug, Default)]
struct IgdGatewayDiscoverer;

#[derive(Clone)]
struct IgdGatewayClient {
    gateway: IgdGatewayHandle<IgdTokio>,
}

#[async_trait]
impl GatewayDiscoverer for IgdGatewayDiscoverer {
    async fn discover(&self) -> Result<Box<dyn GatewayControl>, PortMappingError> {
        let gateway = search_gateway(SearchOptions {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            timeout: Some(Duration::from_secs(3)),
            single_search_timeout: Some(Duration::from_secs(1)),
            ..SearchOptions::default()
        })
        .await
        .map_err(|error| PortMappingError::Discovery(error.to_string()))?;

        Ok(Box::new(IgdGatewayClient { gateway }))
    }
}

#[async_trait]
impl GatewayControl for IgdGatewayClient {
    fn gateway_addr(&self) -> SocketAddr {
        self.gateway.addr
    }

    async fn get_external_ip(&self) -> Result<IpAddr, PortMappingError> {
        self.gateway
            .get_external_ip()
            .await
            .map_err(|error| PortMappingError::ExternalIp(error.to_string()))
    }

    async fn add_port(
        &self,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration_secs: u32,
        description: &str,
    ) -> Result<(), PortMappingError> {
        self.gateway
            .add_port(
                PortMappingProtocol::UDP,
                external_port,
                local_addr,
                lease_duration_secs,
                description,
            )
            .await
            .map_err(|error| PortMappingError::AddPort(error.to_string()))
    }

    async fn add_any_port(
        &self,
        local_addr: SocketAddr,
        lease_duration_secs: u32,
        description: &str,
    ) -> Result<u16, PortMappingError> {
        self.gateway
            .add_any_port(
                PortMappingProtocol::UDP,
                local_addr,
                lease_duration_secs,
                description,
            )
            .await
            .map_err(|error| PortMappingError::AddAnyPort(error.to_string()))
    }

    async fn remove_port(&self, external_port: u16) -> Result<(), PortMappingError> {
        self.gateway
            .remove_port(PortMappingProtocol::UDP, external_port)
            .await
            .map_err(|error| PortMappingError::RemovePort(error.to_string()))
    }
}

pub(crate) fn spawn_best_effort_port_mapping<F>(
    config: PortMappingConfig,
    internal_port: u16,
    shutdown: CancellationToken,
    on_update: F,
) where
    F: FnMut(PortMappingEvent) + Send + 'static,
{
    tokio::spawn(async move {
        run_port_mapping_lifecycle(
            IgdGatewayDiscoverer,
            config,
            internal_port,
            shutdown,
            on_update,
        )
        .await;
    });
}

/// Reviewer P2 #1: exponential backoff with jitter for UPnP discovery
/// retries. Returns the delay before the next discovery attempt given a
/// count of consecutive failures so far. Doubles from
/// `DISCOVERY_RETRY_DELAY_INITIAL` (2 s) up to `DISCOVERY_RETRY_DELAY_MAX`
/// (5 min), with ±25% jitter to avoid synchronised retries across many
/// daemons on the same LAN.
fn discovery_retry_delay(consecutive_failures: u32) -> Duration {
    let base = DISCOVERY_RETRY_DELAY_INITIAL.as_secs();
    let exponent = consecutive_failures.min(DISCOVERY_RETRY_BACKOFF_DOUBLINGS);
    let doubled = base.saturating_mul(1u64 << exponent);
    let capped = doubled.min(DISCOVERY_RETRY_DELAY_MAX.as_secs());
    // ±25% jitter. We use a coarse pseudo-random source seeded from the
    // failure count + system time low bits — adequate for desync, no need
    // for crypto quality.
    let jitter_range = capped.max(1) / 4;
    let seed_bits = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        .wrapping_add(consecutive_failures);
    let jitter = (seed_bits as u64 % (2 * jitter_range + 1)) as i64 - jitter_range as i64;
    let delay_secs = (capped as i64 + jitter).max(1) as u64;
    Duration::from_secs(delay_secs)
}

async fn run_port_mapping_lifecycle<D, F>(
    discoverer: D,
    config: PortMappingConfig,
    internal_port: u16,
    shutdown: CancellationToken,
    mut on_update: F,
) where
    D: GatewayDiscoverer,
    F: FnMut(PortMappingEvent) + Send,
{
    let mut published_snapshot = PortMappingSnapshot::default();
    let mut active_mapping: Option<ActivePortMapping> = None;
    let mut last_failure: Option<String> = None;
    // Reviewer P2 #1: exponential backoff for discovery retries. Networks
    // without IGD support previously got a fixed 2s retry forever, which is
    // not quiet enough for "doesn't interrupt normal users". Each
    // consecutive failure doubles the delay up to a 5 min cap; success
    // resets to the initial 2s delay so a transient discovery failure
    // recovers quickly.
    let mut consecutive_failures: u32 = 0;

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        if active_mapping.is_none() {
            match establish_mapping(&discoverer, config, internal_port).await {
                Ok(mapping) => {
                    last_failure = None;
                    consecutive_failures = 0;
                    let snapshot = PortMappingSnapshot {
                        active: true,
                        external_addr: Some(mapping.external_addr),
                    };
                    publish_snapshot(&mut published_snapshot, snapshot, &mut on_update);
                    on_update(PortMappingEvent::Established { snapshot });
                    info!(
                        internal_addr = %mapping.local_addr,
                        external_addr = %mapping.external_addr,
                        "Best-effort router port mapping is active"
                    );
                    active_mapping = Some(mapping);
                }
                Err(error) => {
                    let error_message = error.to_string();
                    if last_failure.as_deref() != Some(error_message.as_str()) {
                        on_update(PortMappingEvent::Failed {
                            error: error_message.clone(),
                        });
                        last_failure = Some(error_message);
                    }
                    debug!(error = %error, "Best-effort router port mapping unavailable");
                    publish_snapshot(
                        &mut published_snapshot,
                        PortMappingSnapshot::default(),
                        &mut on_update,
                    );
                    let retry_delay = discovery_retry_delay(consecutive_failures);
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(retry_delay) => {}
                    }
                }
            }
            continue;
        }

        let renewal_delay = renewal_interval(config.lease_duration_secs);

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(renewal_delay) => {}
        }

        let Some(mapping) = active_mapping.as_mut() else {
            continue;
        };

        match renew_mapping(mapping, config).await {
            Ok(changed) => {
                last_failure = None;
                let snapshot = PortMappingSnapshot {
                    active: true,
                    external_addr: Some(mapping.external_addr),
                };
                if changed {
                    publish_snapshot(&mut published_snapshot, snapshot, &mut on_update);
                    info!(
                        internal_addr = %mapping.local_addr,
                        external_addr = %mapping.external_addr,
                        "Best-effort router port mapping external address refreshed"
                    );
                }
                on_update(PortMappingEvent::Renewed { snapshot });
            }
            Err(error) => {
                on_update(PortMappingEvent::Failed {
                    error: error.to_string(),
                });
                warn!(
                    error = %error,
                    external_addr = %mapping.external_addr,
                    "Router port-mapping renewal failed; dropping mapping state and retrying"
                );
                let failed_mapping = active_mapping.take();
                publish_snapshot(
                    &mut published_snapshot,
                    PortMappingSnapshot::default(),
                    &mut on_update,
                );
                if let Some(mapping) = failed_mapping.as_ref() {
                    let _ = cleanup_mapping(mapping).await;
                    on_update(PortMappingEvent::Removed {
                        external_addr: Some(mapping.external_addr),
                    });
                }
            }
        }
    }

    if let Some(mapping) = active_mapping.as_ref() {
        if let Err(error) = cleanup_mapping(mapping).await {
            debug!(
                error = %error,
                external_addr = %mapping.external_addr,
                "Best-effort router port-mapping cleanup failed during shutdown"
            );
        }
        on_update(PortMappingEvent::Removed {
            external_addr: Some(mapping.external_addr),
        });
    }

    publish_snapshot(
        &mut published_snapshot,
        PortMappingSnapshot::default(),
        &mut on_update,
    );
}

async fn establish_mapping<D>(
    discoverer: &D,
    config: PortMappingConfig,
    internal_port: u16,
) -> Result<ActivePortMapping, PortMappingError>
where
    D: GatewayDiscoverer,
{
    let gateway = discoverer.discover().await?;
    let local_addr = determine_lan_ipv4(gateway.gateway_addr(), internal_port).await?;
    let external_ip = gateway.get_external_ip().await?;

    let external_port = match gateway
        .add_port(
            internal_port,
            local_addr,
            config.lease_duration_secs,
            PORT_MAPPING_DESCRIPTION,
        )
        .await
    {
        Ok(()) => internal_port,
        Err(error) if config.allow_random_external_port => {
            warn!(
                error = %error,
                internal_addr = %local_addr,
                "Same-port mapping failed; falling back to a random external port"
            );
            gateway
                .add_any_port(
                    local_addr,
                    config.lease_duration_secs,
                    PORT_MAPPING_DESCRIPTION,
                )
                .await?
        }
        Err(error) => return Err(error),
    };

    Ok(ActivePortMapping {
        gateway,
        local_addr,
        external_addr: SocketAddr::new(external_ip, external_port),
    })
}

async fn renew_mapping(
    mapping: &mut ActivePortMapping,
    config: PortMappingConfig,
) -> Result<bool, PortMappingError> {
    mapping
        .gateway
        .add_port(
            mapping.external_addr.port(),
            mapping.local_addr,
            config.lease_duration_secs,
            PORT_MAPPING_DESCRIPTION,
        )
        .await?;

    let refreshed_addr = SocketAddr::new(
        mapping.gateway.get_external_ip().await?,
        mapping.external_addr.port(),
    );
    let changed = mapping.external_addr != refreshed_addr;
    mapping.external_addr = refreshed_addr;

    Ok(changed)
}

async fn cleanup_mapping(mapping: &ActivePortMapping) -> Result<(), PortMappingError> {
    mapping
        .gateway
        .remove_port(mapping.external_addr.port())
        .await
}

async fn determine_lan_ipv4(
    gateway_addr: SocketAddr,
    internal_port: u16,
) -> Result<SocketAddr, PortMappingError> {
    let gateway_ip = match gateway_addr.ip() {
        IpAddr::V4(ipv4) => ipv4,
        _ => return Err(PortMappingError::UnsupportedGatewayAddress(gateway_addr)),
    };

    let probe_socket =
        tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .await
            .map_err(|error| PortMappingError::DetermineLanIpv4 {
                gateway: gateway_addr,
                reason: error.to_string(),
            })?;

    probe_socket
        .connect(SocketAddr::new(IpAddr::V4(gateway_ip), gateway_addr.port()))
        .await
        .map_err(|error| PortMappingError::DetermineLanIpv4 {
            gateway: gateway_addr,
            reason: error.to_string(),
        })?;

    let local_addr =
        probe_socket
            .local_addr()
            .map_err(|error| PortMappingError::DetermineLanIpv4 {
                gateway: gateway_addr,
                reason: error.to_string(),
            })?;

    match local_addr.ip() {
        IpAddr::V4(ipv4) => Ok(SocketAddr::new(IpAddr::V4(ipv4), internal_port)),
        _ => Err(PortMappingError::DetermineLanIpv4 {
            gateway: gateway_addr,
            reason: format!("temporary local address {} was not IPv4", local_addr),
        }),
    }
}

fn renewal_interval(lease_duration_secs: u32) -> Duration {
    if lease_duration_secs == 0 {
        ZERO_LEASE_REFRESH_INTERVAL
    } else {
        Duration::from_secs(u64::from((lease_duration_secs / 2).max(1)))
    }
}

fn publish_snapshot<F>(
    published_snapshot: &mut PortMappingSnapshot,
    next_snapshot: PortMappingSnapshot,
    _on_update: &mut F,
) where
    F: FnMut(PortMappingEvent),
{
    if *published_snapshot != next_snapshot {
        *published_snapshot = next_snapshot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, VecDeque};
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use mock_igd::{Action, MockIgdServer, Protocol, Responder};

    fn s4(octets: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 5483)
    }

    fn s6(seg: [u16; 8]) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            )),
            5483,
        )
    }

    /// Reviewer P1 #2: UPnP-reported external addresses that look private
    /// or non-routable must NOT be advertised as relay/NAT candidates. The
    /// soak failure modes the reviewer cited (CGNAT publishing 100.64/10,
    /// double-NAT publishing 192.168/x) would weaken MASQUE fallback because
    /// peers dial addresses that don't route from the public internet.
    #[test]
    fn is_globally_routable_advertise_address_rejects_non_global_v4() {
        // RFC 1918 private
        assert!(!is_globally_routable_advertise_address(s4([10, 0, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([172, 16, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([
            172, 31, 255, 254
        ])));
        assert!(!is_globally_routable_advertise_address(s4([
            192, 168, 1, 1
        ])));

        // RFC 6598 CGNAT 100.64.0.0/10
        assert!(!is_globally_routable_advertise_address(s4([100, 64, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([
            100, 127, 255, 254
        ])));
        // 100.63.x and 100.128.x are NOT in the CGNAT range — should be accepted
        assert!(is_globally_routable_advertise_address(s4([100, 63, 0, 1])));
        assert!(is_globally_routable_advertise_address(s4([100, 128, 0, 1])));

        // Loopback / link-local / broadcast / multicast / reserved
        assert!(!is_globally_routable_advertise_address(s4([127, 0, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([
            169, 254, 1, 1
        ])));
        assert!(!is_globally_routable_advertise_address(s4([
            255, 255, 255, 255
        ])));
        assert!(!is_globally_routable_advertise_address(s4([224, 0, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([240, 0, 0, 1])));
        assert!(!is_globally_routable_advertise_address(s4([0, 0, 0, 0])));

        // Documentation ranges
        assert!(!is_globally_routable_advertise_address(s4([192, 0, 2, 1])));
        assert!(!is_globally_routable_advertise_address(s4([
            198, 51, 100, 1
        ])));
        assert!(!is_globally_routable_advertise_address(s4([
            203, 0, 113, 1
        ])));
    }

    #[test]
    fn is_globally_routable_advertise_address_accepts_global_v4() {
        // Examples of globally-routable IPv4 addresses
        assert!(is_globally_routable_advertise_address(s4([8, 8, 8, 8]))); // Google DNS
        assert!(is_globally_routable_advertise_address(s4([1, 1, 1, 1]))); // Cloudflare
        assert!(is_globally_routable_advertise_address(s4([
            142, 93, 199, 50
        ]))); // nyc VPS
        assert!(is_globally_routable_advertise_address(s4([
            170, 64, 176, 102
        ]))); // sydney VPS
    }

    #[test]
    fn is_globally_routable_advertise_address_rejects_non_global_v6() {
        assert!(!is_globally_routable_advertise_address(s6([0; 8]))); // unspecified
        assert!(!is_globally_routable_advertise_address(s6([
            0, 0, 0, 0, 0, 0, 0, 1
        ]))); // loopback
        assert!(!is_globally_routable_advertise_address(s6([
            0xff00, 0, 0, 0, 0, 0, 0, 1
        ]))); // multicast
        assert!(!is_globally_routable_advertise_address(s6([
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ]))); // link-local
        assert!(!is_globally_routable_advertise_address(s6([
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ]))); // ULA
        assert!(!is_globally_routable_advertise_address(s6([
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ]))); // ULA
        // IPv4-mapped — should be rejected; route via v4 check
        assert!(!is_globally_routable_advertise_address(s6([
            0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808
        ])));
    }

    /// Reviewer P2 #1: UPnP discovery retry must back off exponentially
    /// rather than hammering every 2 s forever. Networks without IGD
    /// support should reach the 5 min cap within ~8 failures.
    #[test]
    fn discovery_retry_delay_exponential_backoff() {
        // First failure → ~2s (with ±25% jitter, so 1s-3s)
        let d0 = discovery_retry_delay(0).as_secs();
        assert!(
            (1..=3).contains(&d0),
            "first retry should be ~2s, got {}s",
            d0
        );

        // After 7 doublings: 2 → 4 → 8 → 16 → 32 → 64 → 128 → 256 → capped
        // at 300s. With jitter, 225s-375s but capped at the 25% jitter
        // *of the cap*, so 225-375. Just verify it's substantially larger
        // than the initial delay.
        let d_many = discovery_retry_delay(20).as_secs();
        assert!(
            d_many >= 100,
            "after many failures, retry delay should be substantially larger than initial; got {}s",
            d_many
        );
        // And capped — never above max + max/4 jitter (375s)
        assert!(
            d_many <= 400,
            "retry delay must be capped near DISCOVERY_RETRY_DELAY_MAX; got {}s",
            d_many
        );
    }

    struct TestGateway {
        gateway_addr: SocketAddr,
        external_ip: Mutex<IpAddr>,
        add_port_results: Mutex<VecDeque<Result<(), String>>>,
        add_any_port_results: Mutex<VecDeque<Result<u16, String>>>,
        add_port_calls: Mutex<Vec<u16>>,
        add_any_port_calls: Mutex<usize>,
        remove_port_calls: Mutex<Vec<u16>>,
    }

    impl TestGateway {
        fn new(gateway_addr: SocketAddr, external_ip: IpAddr) -> Self {
            Self {
                gateway_addr,
                external_ip: Mutex::new(external_ip),
                add_port_results: Mutex::new(VecDeque::new()),
                add_any_port_results: Mutex::new(VecDeque::new()),
                add_port_calls: Mutex::new(Vec::new()),
                add_any_port_calls: Mutex::new(0),
                remove_port_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[derive(Clone)]
    struct TestGatewayHandle {
        inner: Arc<TestGateway>,
    }

    #[async_trait]
    impl GatewayControl for TestGatewayHandle {
        fn gateway_addr(&self) -> SocketAddr {
            self.inner.gateway_addr
        }

        async fn get_external_ip(&self) -> Result<IpAddr, PortMappingError> {
            Ok(*self.inner.external_ip.lock().expect("lock external_ip"))
        }

        async fn add_port(
            &self,
            external_port: u16,
            _local_addr: SocketAddr,
            _lease_duration_secs: u32,
            _description: &str,
        ) -> Result<(), PortMappingError> {
            self.inner
                .add_port_calls
                .lock()
                .expect("lock add_port_calls")
                .push(external_port);
            self.inner
                .add_port_results
                .lock()
                .expect("lock add_port_results")
                .pop_front()
                .unwrap_or(Ok(()))
                .map_err(PortMappingError::AddPort)
        }

        async fn add_any_port(
            &self,
            _local_addr: SocketAddr,
            _lease_duration_secs: u32,
            _description: &str,
        ) -> Result<u16, PortMappingError> {
            *self
                .inner
                .add_any_port_calls
                .lock()
                .expect("lock add_any_port_calls") += 1;
            self.inner
                .add_any_port_results
                .lock()
                .expect("lock add_any_port_results")
                .pop_front()
                .unwrap_or(Err("missing add_any_port result".to_string()))
                .map_err(PortMappingError::AddAnyPort)
        }

        async fn remove_port(&self, external_port: u16) -> Result<(), PortMappingError> {
            self.inner
                .remove_port_calls
                .lock()
                .expect("lock remove_port_calls")
                .push(external_port);
            Ok(())
        }
    }

    struct TestDiscoverer {
        gateway: Arc<TestGateway>,
        failures_before_success: AtomicUsize,
    }

    #[async_trait]
    impl GatewayDiscoverer for TestDiscoverer {
        async fn discover(&self) -> Result<Box<dyn GatewayControl>, PortMappingError> {
            let remaining = self.failures_before_success.load(Ordering::SeqCst);
            if remaining > 0 {
                self.failures_before_success.fetch_sub(1, Ordering::SeqCst);
                return Err(PortMappingError::Discovery(
                    "scripted discovery failure".to_string(),
                ));
            }

            Ok(Box::new(TestGatewayHandle {
                inner: Arc::clone(&self.gateway),
            }))
        }
    }

    fn collect_events() -> (
        Arc<Mutex<Vec<PortMappingEvent>>>,
        impl FnMut(PortMappingEvent) + Send + 'static,
    ) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);
        let on_update = move |event: PortMappingEvent| {
            events_clone
                .lock()
                .expect("lock port-mapping events")
                .push(event);
        };
        (events, on_update)
    }

    async fn wait_for_events(
        events: &Arc<Mutex<Vec<PortMappingEvent>>>,
        min_len: usize,
    ) -> Vec<PortMappingEvent> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let current = events.lock().expect("lock events").clone();
            if current.len() >= min_len {
                return current;
            }

            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {} port-mapping events; got {:?}",
                min_len,
                current
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn mock_gateway(server: &MockIgdServer) -> IgdGatewayClient {
        let mut control_schema = HashMap::new();
        control_schema.insert("GetExternalIPAddress".to_string(), Vec::new());
        control_schema.insert(
            "AddPortMapping".to_string(),
            vec![
                "NewRemoteHost".to_string(),
                "NewExternalPort".to_string(),
                "NewProtocol".to_string(),
                "NewInternalPort".to_string(),
                "NewInternalClient".to_string(),
                "NewEnabled".to_string(),
                "NewPortMappingDescription".to_string(),
                "NewLeaseDuration".to_string(),
            ],
        );
        control_schema.insert(
            "DeletePortMapping".to_string(),
            vec![
                "NewRemoteHost".to_string(),
                "NewExternalPort".to_string(),
                "NewProtocol".to_string(),
            ],
        );

        IgdGatewayClient {
            gateway: IgdGatewayHandle {
                addr: server.http_addr(),
                root_url: "/rootDesc.xml".to_string(),
                control_url: "/ctl/IPConn".to_string(),
                control_schema_url: "/WANIPCn.xml".to_string(),
                control_schema,
                provider: IgdTokio,
            },
        }
    }

    #[tokio::test]
    async fn test_mapping_success_updates_snapshot_and_cleans_up() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.10".parse().expect("valid external IP"),
        ));
        let discoverer = TestDiscoverer {
            gateway: Arc::clone(&gateway),
            failures_before_success: AtomicUsize::new(0),
        };
        let shutdown = CancellationToken::new();
        let (events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig::default(),
            31000,
            shutdown.clone(),
            on_update,
        ));

        let events = wait_for_events(&events, 1).await;
        assert_eq!(
            events[0],
            PortMappingEvent::Established {
                snapshot: PortMappingSnapshot {
                    active: true,
                    external_addr: Some("203.0.113.10:31000".parse().expect("valid mapped addr")),
                },
            }
        );

        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");

        let removed_ports = gateway
            .remove_port_calls
            .lock()
            .expect("lock remove_port_calls")
            .clone();
        assert_eq!(removed_ports, vec![31000]);
    }

    #[tokio::test]
    async fn test_same_port_conflict_falls_back_to_random_port() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.20".parse().expect("valid external IP"),
        ));
        gateway
            .add_port_results
            .lock()
            .expect("lock add_port_results")
            .push_back(Err("conflict".to_string()));
        gateway
            .add_any_port_results
            .lock()
            .expect("lock add_any_port_results")
            .push_back(Ok(41000));

        let discoverer = TestDiscoverer {
            gateway: Arc::clone(&gateway),
            failures_before_success: AtomicUsize::new(0),
        };
        let shutdown = CancellationToken::new();
        let (events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig::default(),
            31001,
            shutdown.clone(),
            on_update,
        ));

        let events = wait_for_events(&events, 1).await;
        assert!(events.iter().any(|event| matches!(
            event,
            PortMappingEvent::Established { snapshot }
                if snapshot.external_addr == Some("203.0.113.20:41000".parse().expect("valid mapped addr"))
        )));
        assert_eq!(
            *gateway
                .add_any_port_calls
                .lock()
                .expect("lock add_any_port_calls"),
            1
        );

        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");
    }

    #[tokio::test]
    async fn test_same_port_conflict_without_random_fallback_reports_failure() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.21".parse().expect("valid external IP"),
        ));
        gateway
            .add_port_results
            .lock()
            .expect("lock add_port_results")
            .push_back(Err("conflict".to_string()));

        let discoverer = TestDiscoverer {
            gateway: Arc::clone(&gateway),
            failures_before_success: AtomicUsize::new(0),
        };
        let shutdown = CancellationToken::new();
        let (events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig {
                allow_random_external_port: false,
                ..PortMappingConfig::default()
            },
            31011,
            shutdown.clone(),
            on_update,
        ));

        let events = wait_for_events(&events, 1).await;
        assert!(
            matches!(events.as_slice(), [PortMappingEvent::Failed { error }] if error.contains("conflict"))
        );
        assert_eq!(
            *gateway
                .add_any_port_calls
                .lock()
                .expect("lock add_any_port_calls"),
            0,
            "random external port fallback must not run when disabled"
        );

        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");
    }

    #[tokio::test]
    async fn test_renewal_reuses_existing_external_port() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.30".parse().expect("valid external IP"),
        ));
        gateway
            .add_port_results
            .lock()
            .expect("lock add_port_results")
            .extend([Ok(()), Ok(())]);

        let discoverer = TestDiscoverer {
            gateway: Arc::clone(&gateway),
            failures_before_success: AtomicUsize::new(0),
        };
        let shutdown = CancellationToken::new();
        let (_events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig {
                lease_duration_secs: 2,
                ..PortMappingConfig::default()
            },
            31002,
            shutdown.clone(),
            on_update,
        ));

        tokio::time::sleep(Duration::from_millis(1200)).await;
        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");

        let add_port_calls = gateway
            .add_port_calls
            .lock()
            .expect("lock add_port_calls")
            .clone();
        assert!(
            add_port_calls.len() >= 2,
            "expected at least initial map and one renewal, got {:?}",
            add_port_calls
        );
        assert_eq!(add_port_calls[0], 31002);
        assert_eq!(add_port_calls[1], 31002);
    }

    #[tokio::test]
    async fn test_renewal_refreshes_external_ip() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.31".parse().expect("valid external IP"),
        ));
        gateway
            .add_port_results
            .lock()
            .expect("lock add_port_results")
            .extend([Ok(()), Ok(())]);

        let discoverer = TestDiscoverer {
            gateway: Arc::clone(&gateway),
            failures_before_success: AtomicUsize::new(0),
        };
        let shutdown = CancellationToken::new();
        let (events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig {
                lease_duration_secs: 2,
                ..PortMappingConfig::default()
            },
            31012,
            shutdown.clone(),
            on_update,
        ));

        let initial = wait_for_events(&events, 1).await;
        assert!(initial.iter().any(|event| matches!(
            event,
            PortMappingEvent::Established { snapshot }
                if snapshot.external_addr == Some("203.0.113.31:31012".parse().expect("valid mapped addr"))
        )));

        *gateway.external_ip.lock().expect("lock external_ip") =
            "203.0.113.99".parse().expect("valid external IP");

        let refreshed = wait_for_events(&events, 2).await;
        assert!(refreshed.iter().any(|event| matches!(
            event,
            PortMappingEvent::Renewed { snapshot }
                if snapshot.external_addr == Some("203.0.113.99:31012".parse().expect("valid refreshed addr"))
        )));

        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");
    }

    #[tokio::test]
    async fn test_discovery_failures_are_non_fatal_until_shutdown() {
        let gateway = Arc::new(TestGateway::new(
            "127.0.0.1:1900".parse().expect("valid gateway"),
            "203.0.113.40".parse().expect("valid external IP"),
        ));
        let discoverer = TestDiscoverer {
            gateway,
            failures_before_success: AtomicUsize::new(10),
        };
        let shutdown = CancellationToken::new();
        let (events, on_update) = collect_events();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig::default(),
            31003,
            shutdown.clone(),
            on_update,
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();
        task.await.expect("port-mapping task should exit cleanly");

        let snapshots = events.lock().expect("lock events").clone();
        assert!(
            snapshots
                .iter()
                .all(|event| matches!(event, PortMappingEvent::Failed { .. })),
            "discovery failure should remain non-fatal and only publish failure events"
        );
    }

    #[test]
    fn test_zero_lease_still_refreshes_periodically() {
        assert_eq!(renewal_interval(0), ZERO_LEASE_REFRESH_INTERVAL);
    }

    #[tokio::test]
    async fn test_igd_gateway_client_uses_mock_igd_server() {
        let server = MockIgdServer::start().await.expect("mock IGD server");
        server
            .mock(
                Action::GetExternalIPAddress,
                Responder::success()
                    .with_external_ip("198.51.100.5".parse::<IpAddr>().expect("valid external IP")),
            )
            .await;
        server
            .mock(
                Action::add_port_mapping()
                    .with_external_port(31004)
                    .with_protocol(Protocol::UDP),
                Responder::success(),
            )
            .await;
        server
            .mock(
                Action::delete_port_mapping()
                    .with_external_port(31004)
                    .with_protocol(Protocol::UDP),
                Responder::success(),
            )
            .await;

        let gateway = mock_gateway(&server);
        let external_ip = gateway
            .get_external_ip()
            .await
            .expect("external IP request should succeed");
        assert_eq!(
            external_ip,
            "198.51.100.5".parse::<IpAddr>().expect("valid external IP")
        );

        let local_addr: SocketAddr = "127.0.0.1:31004".parse().expect("valid local addr");
        gateway
            .add_port(31004, local_addr, 60, "ant-quic test")
            .await
            .expect("add_port should succeed");
        gateway
            .remove_port(31004)
            .await
            .expect("remove_port should succeed");

        let requests = server.received_requests().await;
        assert_eq!(requests.len(), 3);
    }
}
