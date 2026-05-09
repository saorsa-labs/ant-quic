//! Integration coverage for read-only path handles.
//!
//! This crate exercises the high-level endpoint API and verifies that the
//! single-path skeleton exposes one path with retained stats after close.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, sync::Arc};

use ant_quic::{
    PathId,
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Duration, timeout};

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn client_config(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in chain.iter().cloned() {
        roots.add(cert).expect("add root");
    }
    ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config")
}

#[tokio::test]
async fn single_path_stats_remain_readable_after_close() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (chain, key) = gen_self_signed_cert();
    let server_config = ServerConfig::with_single_cert(chain.clone(), key).expect("server config");
    let server =
        Endpoint::server(server_config, ([127, 0, 0, 1], 0).into()).expect("server endpoint");
    let server_addr: SocketAddr = server.local_addr().expect("server local addr");

    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("server accept wait")
            .expect("incoming connection");
        let conn = timeout(Duration::from_secs(10), incoming)
            .await
            .expect("server handshake wait")
            .expect("server handshake");
        let _ = timeout(Duration::from_secs(10), conn.closed()).await;
    });

    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client endpoint");
    client.set_default_client_config(client_config(&chain));
    let connecting = client
        .connect(server_addr, "localhost")
        .expect("connect start");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client handshake wait")
        .expect("client handshake");

    let weak_conn = conn.weak_handle();
    let paths = conn.paths();
    assert_eq!(paths.len(), 1);

    let path = paths.into_iter().next().expect("primary path");
    assert_eq!(path.id(), PathId::PRIMARY);
    assert_eq!(path.remote_address(), server_addr);
    assert_eq!(
        conn.path_stats(PathId::PRIMARY)
            .expect("primary stats")
            .current_mtu,
        path.stats().current_mtu
    );
    assert!(conn.path_stats(PathId::from(99)).is_none());

    let live_stats = path.stats();
    assert!(live_stats.current_mtu >= 1200);

    let weak_path = path.weak_handle();
    assert!(weak_path.is_alive());
    assert!(weak_path.upgrade().is_some());

    conn.close(0u32.into(), b"x0x-0046");
    let _ = timeout(Duration::from_secs(10), conn.closed())
        .await
        .expect("client closed");

    let closed_stats = weak_path.stats();
    assert!(closed_stats.current_mtu >= 1200);
    assert_eq!(weak_path.remote_address(), server_addr);

    drop(path);
    drop(conn);
    drop(client);

    timeout(Duration::from_secs(10), async {
        while weak_conn.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client connection state released");

    assert!(!weak_path.is_alive());
    assert!(weak_path.upgrade().is_none());

    let retained_stats = weak_path.stats();
    assert_eq!(retained_stats.current_mtu, closed_stats.current_mtu);
    assert_eq!(weak_path.id(), PathId::PRIMARY);
    assert_eq!(weak_path.remote_address(), server_addr);
    assert_eq!(weak_path.observed_external_addr(), None);

    server_task.await.expect("server task");
}
