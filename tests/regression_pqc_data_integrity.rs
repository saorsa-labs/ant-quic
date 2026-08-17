//! PQC-enabled content verification test.
//!
//! Exercises the REAL ML-KEM-768 key exchange → TLS 1.3 key schedule →
//! AES-128-GCM AEAD path that x0x uses. Previous tests used classical TLS.
//! If the PQC key derivation produces wrong AEAD keys, the connection
//! would fail (handshake error) or produce garbled plaintext (AEAD tag
//! mismatch → drop). This test verifies correct application data delivery.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ant_quic::{
    TransportConfig,
    config::{ClientConfig, ServerConfig},
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    high_level::Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

const MESSAGE_LEN: usize = 5_300;
const NUM_MESSAGES: usize = 10;

fn payload_for(message: usize) -> Vec<u8> {
    (0..MESSAGE_LEN)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(message * 7)) % 250 + 1) as u8)
        .collect()
}

fn gen_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    (
        vec![CertificateDer::from(c.cert)],
        PrivateKeyDer::Pkcs8(c.signing_key.serialize_der().into()),
    )
}

/// Provider with ML-KEM-768 key exchange + classical signature verification
/// (for rcgen certs). This exercises the PQC key exchange → AEAD key path.
fn ml_kem_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768];
    Arc::new(provider)
}

fn pqc_transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.enable_pqc(true);
    Arc::new(t)
}

fn pqc_server(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (Endpoint, std::net::SocketAddr) {
    let rustls_cfg = rustls::ServerConfig::builder_with_provider(ml_kem_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("cert");

    let mut cfg = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls_cfg).expect("qsc"),
    ));
    cfg.transport_config(pqc_transport());

    let server = Endpoint::server(cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr = server.local_addr().expect("addr");
    (server, addr)
}

fn pqc_client(chain: &[CertificateDer<'static>]) -> (Endpoint, ClientConfig) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in chain.iter().cloned() {
        roots.add(cert).expect("root");
    }

    let rustls_cfg = rustls::ClientConfig::builder_with_provider(ml_kem_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut cfg = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(rustls_cfg).expect("qcc"),
    ));
    cfg.transport_config(pqc_transport());

    let client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    (client, cfg)
}

#[tokio::test(flavor = "multi_thread")]
async fn pqc_ml_kem_768_handshake_preserves_data_integrity() {
    let (chain, key) = gen_cert();
    let (server, server_addr) = pqc_server(chain.clone(), key);
    let (mut client, client_cfg) = pqc_client(&chain);
    client.set_default_client_config(client_cfg);

    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(15), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        let conn = timeout(Duration::from_secs(15), incoming)
            .await
            .expect("hs timeout")
            .expect("hs");

        let mut failures = Vec::new();
        for _ in 0..NUM_MESSAGES {
            let mut recv = match timeout(Duration::from_secs(30), conn.accept_uni()).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    failures.push(format!("accept_uni: {e}"));
                    break;
                }
                Err(_) => {
                    failures.push("accept_uni timeout".into());
                    break;
                }
            };
            match timeout(Duration::from_secs(30), recv.read_to_end(MESSAGE_LEN * 2)).await {
                Ok(Ok(buf)) if buf.len() >= 8 => {
                    let mut idx = [0u8; 8];
                    idx.copy_from_slice(&buf[..8]);
                    let msg = u64::from_be_bytes(idx) as usize;
                    let expected = payload_for(msg);
                    if buf[8..] != expected[..] {
                        let diff = expected.iter().zip(&buf[8..]).position(|(a, b)| a != b);
                        failures.push(format!("msg {msg}: first diff at {diff:?}"));
                    }
                }
                Ok(Ok(buf)) => failures.push(format!("short: {}B", buf.len())),
                Ok(Err(e)) => failures.push(format!("read_to_end: {e}")),
                Err(_) => failures.push("read_to_end timeout".into()),
            }
        }
        failures
    });

    let conn = timeout(
        Duration::from_secs(15),
        client.connect(server_addr, "localhost").expect("connect"),
    )
    .await
    .expect("connect timeout")
    .expect("connect error");

    for msg_idx in 0..NUM_MESSAGES as u64 {
        let mut send = timeout(Duration::from_secs(10), conn.open_uni())
            .await
            .expect("open_uni timeout")
            .expect("open_uni");
        send.write_all(&msg_idx.to_be_bytes())
            .await
            .expect("write idx");
        send.write_all(&payload_for(msg_idx as usize))
            .await
            .expect("write payload");
        send.finish().expect("finish");
        let _ = timeout(Duration::from_secs(30), send.stopped()).await;
    }

    let failures = server_task.await.expect("server task");
    assert!(
        failures.is_empty(),
        "PQC ML-KEM-768 data corruption:\n{}",
        failures.join("\n")
    );
}
