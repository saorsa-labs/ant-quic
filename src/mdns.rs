use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::nat_traversal_api::PeerId;
use crate::unified_config::MdnsConfig;

const RESERVED_METADATA_KEYS: [&str; 7] = [
    "peer_id",
    "namespace",
    "service",
    "assist_connectivity",
    "relay_service",
    "coordinator_service",
    "bootstrap_service",
];

/// Public snapshot of the endpoint's mDNS runtime state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsSnapshot {
    /// Whether the endpoint is currently browsing the configured service.
    pub browsing: bool,
    /// Whether the endpoint is currently advertising the local service.
    pub advertising: bool,
    /// Configured service/application scope.
    pub service: Option<String>,
    /// Configured namespace/workspace scope.
    pub namespace: Option<String>,
    /// Full advertised instance name, when advertising is active.
    pub advertised_instance_fullname: Option<String>,
    /// Eligible peers currently surfaced by the mDNS directory.
    pub discovered_peers: Vec<MdnsPeerRecord>,
}

/// Queryable record for a discovered mDNS peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsPeerRecord {
    /// Service type this record belongs to.
    pub service: String,
    /// Fully qualified DNS-SD service instance name.
    pub fullname: String,
    /// Hostname carried by the SRV record.
    pub hostname: String,
    /// Optional namespace/workspace scope from TXT metadata.
    pub namespace: Option<String>,
    /// Optional pre-auth claimed peer ID from TXT metadata.
    pub claimed_peer_id: Option<PeerId>,
    /// Candidate socket addresses after address-hygiene filtering.
    pub addresses: Vec<SocketAddr>,
    /// TXT metadata surfaced as UTF-8 key/value pairs.
    pub metadata: BTreeMap<String, String>,
    /// Whether the record passed local eligibility checks.
    pub eligible: bool,
    /// Reason the record was deemed ineligible, when applicable.
    pub ineligible_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MdnsRuntimeEvent {
    ServiceAdvertised {
        service: String,
        namespace: Option<String>,
        instance_fullname: String,
    },
    PeerDiscovered(MdnsPeerRecord),
    PeerUpdated(MdnsPeerRecord),
    PeerRemoved(MdnsPeerRecord),
    PeerEligible(MdnsPeerRecord),
    PeerIneligible {
        peer: MdnsPeerRecord,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedMdnsService {
    fullname: String,
    hostname: String,
    port: u16,
    addresses: Vec<IpAddr>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
pub(crate) struct MdnsDirectory {
    local_peer_id: Option<PeerId>,
    namespace: Option<String>,
    service: Option<String>,
    advertised_instance_fullname: Option<String>,
    eligible_records: HashMap<String, MdnsPeerRecord>,
    observed_records: HashMap<String, MdnsPeerRecord>,
}

impl MdnsDirectory {
    pub(crate) fn new(
        local_peer_id: PeerId,
        service: Option<String>,
        namespace: Option<String>,
    ) -> Self {
        Self {
            local_peer_id: Some(local_peer_id),
            namespace,
            service,
            advertised_instance_fullname: None,
            eligible_records: HashMap::new(),
            observed_records: HashMap::new(),
        }
    }

    pub(crate) fn set_advertised_instance_fullname(&mut self, fullname: Option<String>) {
        self.advertised_instance_fullname = fullname;
    }

    pub(crate) fn apply_resolved(
        &mut self,
        resolved: ResolvedMdnsService,
    ) -> Vec<MdnsRuntimeEvent> {
        let record = self.build_record(resolved);
        let key = record.fullname.clone();

        if self.observed_records.get(&key) == Some(&record) {
            return Vec::new();
        }

        self.observed_records.insert(key.clone(), record.clone());

        let mut events = Vec::new();
        if record.eligible {
            if self.eligible_records.contains_key(&key) {
                self.eligible_records.insert(key.clone(), record.clone());
                events.push(MdnsRuntimeEvent::PeerUpdated(record.clone()));
            } else {
                self.eligible_records.insert(key.clone(), record.clone());
                events.push(MdnsRuntimeEvent::PeerDiscovered(record.clone()));
            }
            events.push(MdnsRuntimeEvent::PeerEligible(record));
        } else {
            if let Some(previous) = self.eligible_records.remove(&key) {
                events.push(MdnsRuntimeEvent::PeerRemoved(previous));
            }
            if let Some(reason) = record.ineligible_reason.clone() {
                events.push(MdnsRuntimeEvent::PeerIneligible {
                    peer: record,
                    reason,
                });
            }
        }

        events
    }

    pub(crate) fn remove(&mut self, fullname: &str) -> Vec<MdnsRuntimeEvent> {
        self.observed_records.remove(fullname);
        self.eligible_records
            .remove(fullname)
            .map(MdnsRuntimeEvent::PeerRemoved)
            .into_iter()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self, browsing: bool, advertising: bool) -> MdnsSnapshot {
        let mut discovered_peers: Vec<_> = self.eligible_records.values().cloned().collect();
        discovered_peers.sort_by(|left, right| left.fullname.cmp(&right.fullname));

        MdnsSnapshot {
            browsing,
            advertising,
            service: self.service.clone(),
            namespace: self.namespace.clone(),
            advertised_instance_fullname: self.advertised_instance_fullname.clone(),
            discovered_peers,
        }
    }

    fn build_record(&self, resolved: ResolvedMdnsService) -> MdnsPeerRecord {
        let mut addresses: Vec<_> = resolved
            .addresses
            .into_iter()
            .filter(is_eligible_mdns_ip)
            .map(|ip| SocketAddr::new(ip, resolved.port))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();

        let claimed_peer_id = resolved
            .metadata
            .get("peer_id")
            .and_then(|value| parse_peer_id_hex(value));
        let namespace = resolved.metadata.get("namespace").cloned();

        let ineligible_reason = self.ineligible_reason(
            &resolved.fullname,
            claimed_peer_id,
            namespace.as_deref(),
            &addresses,
        );
        let eligible = ineligible_reason.is_none();

        MdnsPeerRecord {
            service: self.service.clone().unwrap_or_default(),
            fullname: resolved.fullname,
            hostname: resolved.hostname,
            namespace,
            claimed_peer_id,
            addresses,
            metadata: resolved.metadata,
            eligible,
            ineligible_reason,
        }
    }

    fn ineligible_reason(
        &self,
        fullname: &str,
        claimed_peer_id: Option<PeerId>,
        namespace: Option<&str>,
        addresses: &[SocketAddr],
    ) -> Option<String> {
        if self
            .local_peer_id
            .is_some_and(|local_peer_id| claimed_peer_id == Some(local_peer_id))
            || self
                .advertised_instance_fullname
                .as_deref()
                .is_some_and(|local_fullname| local_fullname == fullname)
        {
            return Some("self registration".to_string());
        }

        if self.namespace.as_deref() != namespace && self.namespace.is_some() {
            return Some("namespace mismatch".to_string());
        }

        if addresses.is_empty() {
            return Some("no routable addresses".to_string());
        }

        None
    }
}

pub(crate) fn advertised_metadata(
    config: &MdnsConfig,
    local_peer_id: PeerId,
) -> BTreeMap<String, String> {
    let mut metadata = config.metadata.clone();
    for reserved in RESERVED_METADATA_KEYS {
        metadata.remove(reserved);
    }

    metadata.insert("peer_id".to_string(), hex::encode(local_peer_id.0));
    metadata.insert(
        "service".to_string(),
        config.service.clone().unwrap_or_default(),
    );
    metadata.insert("assist_connectivity".to_string(), "true".to_string());
    metadata.insert("relay_service".to_string(), "true".to_string());
    metadata.insert("coordinator_service".to_string(), "true".to_string());
    metadata.insert("bootstrap_service".to_string(), "true".to_string());
    if let Some(namespace) = config.namespace.clone() {
        metadata.insert("namespace".to_string(), namespace);
    }

    metadata
}

pub(crate) fn service_type_for(service: &str) -> String {
    format!("_{service}._udp.local.")
}

pub(crate) fn instance_name_for(local_peer_id: PeerId, port: u16) -> String {
    format!("ant-quic-{}-{port}", hex::encode(&local_peer_id.0[..6]))
}

pub(crate) fn host_name_for(local_peer_id: PeerId, port: u16) -> String {
    format!(
        "ant-quic-{}-{port}.local.",
        hex::encode(&local_peer_id.0[..6])
    )
}

pub(crate) fn is_eligible_mdns_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !ipv4.is_unspecified()
                && !ipv4.is_loopback()
                && !ipv4.is_link_local()
                && *ipv4 != Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ipv6) => {
            !ipv6.is_unspecified() && !ipv6.is_loopback() && !ipv6.is_unicast_link_local()
        }
    }
}

pub(crate) fn parse_peer_id_hex(value: &str) -> Option<PeerId> {
    if value.len() != 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(PeerId(bytes))
}

pub(crate) fn spawn_mdns_runtime<F>(
    config: MdnsConfig,
    local_peer_id: PeerId,
    local_port: u16,
    shutdown: CancellationToken,
    on_event: F,
) where
    F: FnMut(MdnsRuntimeEvent) + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) =
            run_mdns_runtime(config, local_peer_id, local_port, shutdown, on_event).await
        {
            warn!(error = %error, "mDNS runtime exited with an error");
        }
    });
}

async fn run_mdns_runtime<F>(
    config: MdnsConfig,
    local_peer_id: PeerId,
    local_port: u16,
    shutdown: CancellationToken,
    mut on_event: F,
) -> Result<(), String>
where
    F: FnMut(MdnsRuntimeEvent) + Send + 'static,
{
    use mdns_sd::{ServiceDaemon, ServiceInfo};

    let service = config.service.clone().unwrap_or_default();
    let service_type = service_type_for(&service);
    let mut directory = MdnsDirectory::new(
        local_peer_id,
        Some(service.clone()),
        config.namespace.clone(),
    );

    let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
    let _ = daemon.include_apple_p2p(false);

    let browse_rx = if config.mode.browse_enabled() {
        Some(
            daemon
                .browse(&service_type)
                .map_err(|error| format!("failed to start mDNS browse: {error}"))?,
        )
    } else {
        None
    };

    let advertised_instance_fullname = if config.mode.advertise_enabled() {
        let instance_name = instance_name_for(local_peer_id, local_port);
        let host_name = host_name_for(local_peer_id, local_port);
        let empty_addrs: &[IpAddr] = &[];
        let service_info = ServiceInfo::new(
            &service_type,
            &instance_name,
            &host_name,
            empty_addrs,
            local_port,
            advertised_metadata(&config, local_peer_id)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .map_err(|error| format!("failed to build mDNS service info: {error}"))?
        .enable_addr_auto();
        let instance_fullname = service_info.get_fullname().to_string();
        daemon
            .register(service_info)
            .map_err(|error| format!("failed to register mDNS service: {error}"))?;
        directory.set_advertised_instance_fullname(Some(instance_fullname.clone()));
        on_event(MdnsRuntimeEvent::ServiceAdvertised {
            service: service.clone(),
            namespace: config.namespace.clone(),
            instance_fullname: instance_fullname.clone(),
        });
        Some(instance_fullname)
    } else {
        None
    };

    if browse_rx.is_none() {
        shutdown.cancelled().await;
    } else if let Some(receiver) = browse_rx {
        drive_browse_loop(receiver, shutdown.clone(), &mut directory, &mut on_event).await;
    }

    if let Some(instance_fullname) = advertised_instance_fullname {
        graceful_unregister(&daemon, &instance_fullname).await;
    }

    graceful_shutdown(&daemon).await;

    Ok(())
}

async fn drive_browse_loop<F>(
    receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>,
    shutdown: CancellationToken,
    directory: &mut MdnsDirectory,
    on_event: &mut F,
) where
    F: FnMut(MdnsRuntimeEvent),
{
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            event = receiver.recv_async() => {
                match event {
                    Ok(mdns_sd::ServiceEvent::ServiceResolved(service)) => {
                        let metadata = service.get_properties().clone().into_property_map_str().into_iter().collect::<BTreeMap<_, _>>();
                        let resolved = ResolvedMdnsService {
                            fullname: service.get_fullname().to_string(),
                            hostname: service.get_hostname().to_string(),
                            port: service.get_port(),
                            addresses: service.get_addresses().iter().map(mdns_sd::ScopedIp::to_ip_addr).collect(),
                            metadata,
                        };
                        for event in directory.apply_resolved(resolved) {
                            on_event(event);
                        }
                    }
                    Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, fullname)) => {
                        for event in directory.remove(&fullname) {
                            on_event(event);
                        }
                    }
                    Ok(mdns_sd::ServiceEvent::SearchStarted(service_type)) => {
                        debug!(service_type = %service_type, "mDNS browse started");
                    }
                    Ok(mdns_sd::ServiceEvent::SearchStopped(service_type)) => {
                        debug!(service_type = %service_type, "mDNS browse stopped");
                    }
                    Ok(mdns_sd::ServiceEvent::ServiceFound(service_type, fullname)) => {
                        debug!(service_type = %service_type, fullname = %fullname, "mDNS service found");
                    }
                    Err(error) => {
                        warn!(error = %error, "mDNS browse receiver closed");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn graceful_unregister(daemon: &mdns_sd::ServiceDaemon, fullname: &str) {
    match daemon.unregister(fullname) {
        Ok(receiver) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), receiver.recv_async()).await;
        }
        Err(error) => {
            debug!(error = %error, fullname = %fullname, "mDNS unregister returned an error");
        }
    }
}

async fn graceful_shutdown(daemon: &mdns_sd::ServiceDaemon) {
    match daemon.shutdown() {
        Ok(receiver) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), receiver.recv_async()).await;
        }
        Err(error) => {
            debug!(error = %error, "mDNS daemon shutdown returned an error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified_config::{AutoConnectPolicy, MdnsMode};

    fn base_directory(local_peer_id: PeerId) -> MdnsDirectory {
        MdnsDirectory::new(
            local_peer_id,
            Some("ant-quic".to_string()),
            Some("workspace-a".to_string()),
        )
    }

    fn resolved_service(
        fullname: &str,
        port: u16,
        addresses: Vec<IpAddr>,
        metadata: &[(&str, &str)],
    ) -> ResolvedMdnsService {
        let mut map = BTreeMap::new();
        for (key, value) in metadata {
            map.insert((*key).to_string(), (*value).to_string());
        }

        ResolvedMdnsService {
            fullname: fullname.to_string(),
            hostname: "peer.local.".to_string(),
            port,
            addresses,
            metadata: map,
        }
    }

    #[test]
    fn test_service_namespace_filtering() {
        let local_peer_id = PeerId([0x11; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_id = PeerId([0x22; 32]);
        let events = directory.apply_resolved(resolved_service(
            "peer-a._ant-quic._udp.local.",
            9000,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-b"),
            ],
        ));

        assert!(matches!(
            events.as_slice(),
            [MdnsRuntimeEvent::PeerIneligible { reason, .. }] if reason == "namespace mismatch"
        ));
        assert!(directory.snapshot(true, false).discovered_peers.is_empty());
    }

    #[test]
    fn test_self_filtering_uses_claimed_peer_id() {
        let local_peer_id = PeerId([0x33; 32]);
        let mut directory = base_directory(local_peer_id);
        let events = directory.apply_resolved(resolved_service(
            "self._ant-quic._udp.local.",
            9000,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
            &[
                ("peer_id", &hex::encode(local_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        assert!(matches!(
            events.as_slice(),
            [MdnsRuntimeEvent::PeerIneligible { reason, .. }] if reason == "self registration"
        ));
    }

    #[test]
    fn test_address_hygiene_filtering() {
        let local_peer_id = PeerId([0x44; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_id = PeerId([0x55; 32]);

        let events = directory.apply_resolved(resolved_service(
            "peer-b._ant-quic._udp.local.",
            9000,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 20)),
            ],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        assert!(matches!(
            events.as_slice(),
            [MdnsRuntimeEvent::PeerIneligible { reason, .. }] if reason == "no routable addresses"
        ));
    }

    #[test]
    fn test_deduplicates_repeat_resolutions() {
        let local_peer_id = PeerId([0x66; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_id = PeerId([0x77; 32]);
        let resolved = resolved_service(
            "peer-c._ant-quic._udp.local.",
            9000,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30))],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        );

        let first = directory.apply_resolved(resolved.clone());
        let second = directory.apply_resolved(resolved);

        assert_eq!(first.len(), 2);
        assert!(second.is_empty());
    }

    #[test]
    fn test_multiple_local_instances_on_same_host_can_coexist() {
        let local_peer_id = PeerId([0x78; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_a = PeerId([0x79; 32]);
        let remote_peer_b = PeerId([0x7a; 32]);
        let shared_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 35));

        let first = directory.apply_resolved(resolved_service(
            "peer-c._ant-quic._udp.local.",
            9000,
            vec![shared_ip],
            &[
                ("peer_id", &hex::encode(remote_peer_a.0)),
                ("namespace", "workspace-a"),
            ],
        ));
        let second = directory.apply_resolved(resolved_service(
            "peer-d._ant-quic._udp.local.",
            9001,
            vec![shared_ip],
            &[
                ("peer_id", &hex::encode(remote_peer_b.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        assert!(matches!(
            first.as_slice(),
            [
                MdnsRuntimeEvent::PeerDiscovered(_),
                MdnsRuntimeEvent::PeerEligible(_)
            ]
        ));
        assert!(matches!(
            second.as_slice(),
            [
                MdnsRuntimeEvent::PeerDiscovered(_),
                MdnsRuntimeEvent::PeerEligible(_)
            ]
        ));

        let snapshot = directory.snapshot(true, false);
        assert_eq!(snapshot.discovered_peers.len(), 2);
        assert!(snapshot.discovered_peers.iter().any(|peer| {
            peer.fullname == "peer-c._ant-quic._udp.local."
                && peer.addresses == vec![SocketAddr::new(shared_ip, 9000)]
        }));
        assert!(snapshot.discovered_peers.iter().any(|peer| {
            peer.fullname == "peer-d._ant-quic._udp.local."
                && peer.addresses == vec![SocketAddr::new(shared_ip, 9001)]
        }));
    }

    #[test]
    fn test_updates_existing_peer_when_addresses_change() {
        let local_peer_id = PeerId([0x88; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_id = PeerId([0x99; 32]);

        let _ = directory.apply_resolved(resolved_service(
            "peer-d._ant-quic._udp.local.",
            9000,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        let events = directory.apply_resolved(resolved_service(
            "peer-d._ant-quic._udp.local.",
            9000,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 41)),
            ],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        assert!(matches!(
            events.as_slice(),
            [
                MdnsRuntimeEvent::PeerUpdated(_),
                MdnsRuntimeEvent::PeerEligible(_)
            ]
        ));
    }

    #[test]
    fn test_remove_drops_peer_record() {
        let local_peer_id = PeerId([0xaa; 32]);
        let mut directory = base_directory(local_peer_id);
        let remote_peer_id = PeerId([0xbb; 32]);

        let _ = directory.apply_resolved(resolved_service(
            "peer-e._ant-quic._udp.local.",
            9000,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))],
            &[
                ("peer_id", &hex::encode(remote_peer_id.0)),
                ("namespace", "workspace-a"),
            ],
        ));

        let events = directory.remove("peer-e._ant-quic._udp.local.");
        assert!(matches!(
            events.as_slice(),
            [MdnsRuntimeEvent::PeerRemoved(_)]
        ));
    }

    #[test]
    fn test_advertised_metadata_preserves_user_entries_and_overrides_reserved_keys() {
        let local_peer_id = PeerId([0xcc; 32]);
        let mut config = MdnsConfig {
            enabled: true,
            service: Some("ant-quic".to_string()),
            namespace: Some("workspace-a".to_string()),
            mode: MdnsMode::Both,
            auto_connect: AutoConnectPolicy::Enabled,
            metadata: BTreeMap::new(),
        };
        config
            .metadata
            .insert("role".to_string(), "builder".to_string());
        config
            .metadata
            .insert("peer_id".to_string(), "incorrect".to_string());

        let metadata = advertised_metadata(&config, local_peer_id);
        let expected_peer_id = hex::encode(local_peer_id.0);
        assert_eq!(metadata.get("role").map(String::as_str), Some("builder"));
        assert_eq!(
            metadata.get("peer_id").map(String::as_str),
            Some(expected_peer_id.as_str())
        );
        assert_eq!(
            metadata.get("namespace").map(String::as_str),
            Some("workspace-a")
        );
        assert_eq!(
            metadata.get("assist_connectivity").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            metadata.get("relay_service").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            metadata.get("coordinator_service").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            metadata.get("bootstrap_service").map(String::as_str),
            Some("true")
        );
    }
}
