use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use igd_next::aio::Gateway as IgdGatewayHandle;
use igd_next::aio::tokio::{Tokio as IgdTokio, search_gateway};
use igd_next::{PortMappingProtocol, SearchOptions};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::unified_config::PortMappingConfig;

const DISCOVERY_RETRY_DELAY: Duration = Duration::from_secs(2);
const ZERO_LEASE_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const PORT_MAPPING_DESCRIPTION: &str = "ant-quic";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PortMappingSnapshot {
    pub active: bool,
    pub external_addr: Option<SocketAddr>,
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
    F: FnMut(PortMappingSnapshot) + Send + 'static,
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

async fn run_port_mapping_lifecycle<D, F>(
    discoverer: D,
    config: PortMappingConfig,
    internal_port: u16,
    shutdown: CancellationToken,
    mut on_update: F,
) where
    D: GatewayDiscoverer,
    F: FnMut(PortMappingSnapshot) + Send,
{
    let mut published_snapshot = PortMappingSnapshot::default();
    let mut active_mapping: Option<ActivePortMapping> = None;

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        if active_mapping.is_none() {
            match establish_mapping(&discoverer, config, internal_port).await {
                Ok(mapping) => {
                    let snapshot = PortMappingSnapshot {
                        active: true,
                        external_addr: Some(mapping.external_addr),
                    };
                    publish_snapshot(&mut published_snapshot, snapshot, &mut on_update);
                    info!(
                        internal_addr = %mapping.local_addr,
                        external_addr = %mapping.external_addr,
                        "Best-effort router port mapping is active"
                    );
                    active_mapping = Some(mapping);
                }
                Err(error) => {
                    debug!(error = %error, "Best-effort router port mapping unavailable");
                    publish_snapshot(
                        &mut published_snapshot,
                        PortMappingSnapshot::default(),
                        &mut on_update,
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(DISCOVERY_RETRY_DELAY) => {}
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
                if changed {
                    publish_snapshot(
                        &mut published_snapshot,
                        PortMappingSnapshot {
                            active: true,
                            external_addr: Some(mapping.external_addr),
                        },
                        &mut on_update,
                    );
                    info!(
                        internal_addr = %mapping.local_addr,
                        external_addr = %mapping.external_addr,
                        "Best-effort router port mapping external address refreshed"
                    );
                }
            }
            Err(error) => {
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
    on_update: &mut F,
) where
    F: FnMut(PortMappingSnapshot),
{
    if *published_snapshot != next_snapshot {
        *published_snapshot = next_snapshot;
        on_update(next_snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use mock_igd::{Action, MockIgdServer, Protocol, Responder};

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

    fn collect_updates() -> (
        Arc<Mutex<Vec<PortMappingSnapshot>>>,
        impl FnMut(PortMappingSnapshot) + Send + 'static,
    ) {
        let updates = Arc::new(Mutex::new(Vec::new()));
        let updates_clone = Arc::clone(&updates);
        let on_update = move |snapshot: PortMappingSnapshot| {
            updates_clone
                .lock()
                .expect("lock port-mapping updates")
                .push(snapshot);
        };
        (updates, on_update)
    }

    async fn wait_for_updates(
        updates: &Arc<Mutex<Vec<PortMappingSnapshot>>>,
        min_len: usize,
    ) -> Vec<PortMappingSnapshot> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = updates.lock().expect("lock updates").clone();
            if snapshot.len() >= min_len {
                return snapshot;
            }

            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {} port-mapping updates; got {:?}",
                min_len,
                snapshot
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
        let (updates, on_update) = collect_updates();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig::default(),
            31000,
            shutdown.clone(),
            on_update,
        ));

        let snapshots = wait_for_updates(&updates, 1).await;
        assert_eq!(
            snapshots[0],
            PortMappingSnapshot {
                active: true,
                external_addr: Some("203.0.113.10:31000".parse().expect("valid mapped addr")),
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
        let (updates, on_update) = collect_updates();

        let task = tokio::spawn(run_port_mapping_lifecycle(
            discoverer,
            PortMappingConfig::default(),
            31001,
            shutdown.clone(),
            on_update,
        ));

        let snapshots = wait_for_updates(&updates, 1).await;
        assert_eq!(
            snapshots[0].external_addr,
            Some("203.0.113.20:41000".parse().expect("valid mapped addr"))
        );
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
        let (_updates, on_update) = collect_updates();

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
        let (updates, on_update) = collect_updates();

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

        let initial = wait_for_updates(&updates, 1).await;
        assert_eq!(
            initial[0].external_addr,
            Some("203.0.113.31:31012".parse().expect("valid mapped addr"))
        );

        *gateway.external_ip.lock().expect("lock external_ip") =
            "203.0.113.99".parse().expect("valid external IP");

        let refreshed = wait_for_updates(&updates, 2).await;
        assert_eq!(
            refreshed[1].external_addr,
            Some("203.0.113.99:31012".parse().expect("valid refreshed addr"))
        );

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
        let (updates, on_update) = collect_updates();

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

        let snapshots = updates.lock().expect("lock updates").clone();
        assert!(
            snapshots.is_empty(),
            "discovery failure should remain non-fatal and not publish active snapshots"
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
