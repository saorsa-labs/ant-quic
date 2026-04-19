#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PeerId, PqcConfig};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Registry};

pub const LIFECYCLE_TARGET: &str = "ant_quic::p2p_endpoint::lifecycle";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_WAIT: Duration = Duration::from_millis(150);

#[derive(Debug, Clone)]
pub struct LifecycleEventRecord {
    pub target: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct FieldVisitor {
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

struct LifecycleCaptureLayer {
    events: Arc<Mutex<Vec<LifecycleEventRecord>>>,
}

impl<S> Layer<S> for LifecycleCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != LIFECYCLE_TARGET {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(LifecycleEventRecord {
            target: event.metadata().target().to_string(),
            fields: visitor.fields,
        });
    }
}

fn captured_events_store() -> Arc<Mutex<Vec<LifecycleEventRecord>>> {
    static INIT: Once = Once::new();
    static EVENTS: OnceLock<Arc<Mutex<Vec<LifecycleEventRecord>>>> = OnceLock::new();

    INIT.call_once(|| {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber =
            Registry::default()
                .with(EnvFilter::new("info"))
                .with(LifecycleCaptureLayer {
                    events: Arc::clone(&events),
                });
        let _ = tracing::subscriber::set_global_default(subscriber);
        let _ = EVENTS.set(events);
    });

    EVENTS.get().expect("capture store initialized").clone()
}

pub fn reset_lifecycle_events() {
    captured_events_store().lock().unwrap().clear();
}

pub fn lifecycle_events() -> Vec<LifecycleEventRecord> {
    captured_events_store().lock().unwrap().clone()
}

pub async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

pub fn normalize_local_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

pub fn test_node_config(known_peers: Vec<SocketAddr>) -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .nat(NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("test config")
}

pub async fn make_node(known_peers: Vec<SocketAddr>) -> Arc<P2pEndpoint> {
    Arc::new(
        P2pEndpoint::new(test_node_config(known_peers))
            .await
            .expect("node creation"),
    )
}

pub fn spawn_accept_loop(node: Arc<P2pEndpoint>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while node.accept().await.is_some() {} })
}

pub async fn connect_pair(
    a: &Arc<P2pEndpoint>,
    b: &Arc<P2pEndpoint>,
) -> (PeerId, PeerId, SocketAddr) {
    let b_addr = normalize_local_addr(b.local_addr().expect("bound addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let _ = tokio::time::timeout(CONNECT_TIMEOUT, a.connect_addr(b_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");
    sleep(DEFAULT_WAIT).await;
    (a_id, b_id, b_addr)
}

pub async fn wait_until<F>(timeout: Duration, mut check: F)
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within {timeout:?}");
}

pub fn lifecycle_generations_for_peer(peer_id: PeerId) -> Vec<u64> {
    let prefix = hex::encode(&peer_id.0[..4]);
    lifecycle_events()
        .into_iter()
        .filter(|event| event.fields.get("peer_id") == Some(&prefix))
        .filter(|event| event.fields.get("to_state") == Some(&"Live".to_string()))
        .filter_map(|event| {
            event
                .fields
                .get("generation")
                .and_then(|value| value.parse().ok())
        })
        .collect()
}

pub fn latest_live_connection_id_for_peer(peer_id: PeerId) -> Option<String> {
    let prefix = hex::encode(&peer_id.0[..4]);
    lifecycle_events()
        .into_iter()
        .filter(|event| event.fields.get("peer_id") == Some(&prefix))
        .filter(|event| event.fields.get("to_state") == Some(&"Live".to_string()))
        .filter_map(|event| event.fields.get("connection_id").cloned())
        .last()
}

fn lifecycle_connection_id_for_initiator(
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    initiator: PeerId,
) -> [u8; 32] {
    let (left, right) = if local_peer_id.0 <= remote_peer_id.0 {
        (local_peer_id, remote_peer_id)
    } else {
        (remote_peer_id, local_peer_id)
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ant-quic.lifecycle.family.v1");
    hasher.update(&left.0);
    hasher.update(&right.0);
    hasher.update(&initiator.0);

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

pub fn preferred_lifecycle_initiator(a: PeerId, b: PeerId) -> PeerId {
    let a_id = lifecycle_connection_id_for_initiator(a, b, a);
    let b_id = lifecycle_connection_id_for_initiator(a, b, b);
    if a_id > b_id { a } else { b }
}
