//! Integration coverage for the `AsyncUdpSocket` / `UdpSender` split.

#![allow(clippy::expect_used)]

use std::{
    collections::{HashMap, VecDeque},
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use ant_quic::{
    EndpointConfig,
    config::{ClientConfig, ServerConfig},
    high_level::{AsyncUdpSocket, Endpoint, TokioRuntime, UdpSender},
};
use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Duration, timeout};

#[derive(Debug, Default)]
struct MockNetwork {
    queues: Mutex<HashMap<SocketAddr, Arc<MockQueue>>>,
}

#[derive(Debug, Default)]
struct MockQueue {
    packets: Mutex<VecDeque<(Bytes, SocketAddr)>>,
    waker: Mutex<Option<Waker>>,
}

#[derive(Debug, Default)]
struct MockSendGate {
    state: Mutex<MockSendGateState>,
    pending_seen: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct MockSendGateState {
    blocked: bool,
    pending_count: usize,
    waker: Option<Waker>,
}

impl MockSendGate {
    fn block(self: &Arc<Self>) -> Arc<Self> {
        self.state.lock().expect("send gate").blocked = true;
        Arc::clone(self)
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().expect("send gate");
        if !state.blocked {
            return Poll::Ready(());
        }

        state.pending_count += 1;
        state.waker = Some(cx.waker().clone());
        drop(state);
        self.pending_seen.notify_one();
        Poll::Pending
    }

    async fn wait_for_pending(&self) {
        loop {
            let pending_count = self.state.lock().expect("send gate").pending_count;
            if pending_count > 0 {
                return;
            }
            self.pending_seen.notified().await;
        }
    }

    fn make_writable(&self) {
        let waker = {
            let mut state = self.state.lock().expect("send gate");
            state.blocked = false;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct MockUdpSocket {
    addr: SocketAddr,
    network: Arc<MockNetwork>,
    queue: Arc<MockQueue>,
    send_gate: Arc<MockSendGate>,
}

impl MockUdpSocket {
    fn bind(network: Arc<MockNetwork>, port: u16) -> Arc<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let queue = Arc::new(MockQueue::default());
        network
            .queues
            .lock()
            .expect("network queues")
            .insert(addr, Arc::clone(&queue));
        Arc::new(Self {
            addr,
            network,
            queue,
            send_gate: Arc::new(MockSendGate::default()),
        })
    }

    fn block_sender(&self) -> Arc<MockSendGate> {
        self.send_gate.block()
    }
}

impl Drop for MockUdpSocket {
    fn drop(&mut self) {
        let _ = self
            .network
            .queues
            .lock()
            .map(|mut queues| queues.remove(&self.addr));
    }
}

impl AsyncUdpSocket for MockUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MockUdpSender {
            source: self.addr,
            network: Arc::clone(&self.network),
            send_gate: Arc::clone(&self.send_gate),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let Some((payload, source)) = self
            .queue
            .packets
            .lock()
            .expect("queue packets")
            .pop_front()
        else {
            *self.queue.waker.lock().expect("queue waker") = Some(cx.waker().clone());
            return Poll::Pending;
        };

        let len = payload.len().min(bufs[0].len());
        bufs[0][..len].copy_from_slice(&payload[..len]);
        meta[0] = RecvMeta {
            len,
            stride: len,
            addr: source,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct MockUdpSender {
    source: SocketAddr,
    network: Arc<MockNetwork>,
    send_gate: Arc<MockSendGate>,
}

impl UdpSender for MockUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.send_gate.poll_ready(cx).is_pending() {
            return Poll::Pending;
        }

        let queue = self
            .network
            .queues
            .lock()
            .expect("network queues")
            .get(&transmit.destination)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "unknown mock peer"));
        let queue = match queue {
            Ok(queue) => queue,
            Err(e) => return Poll::Ready(Err(e)),
        };

        queue
            .packets
            .lock()
            .expect("queue packets")
            .push_back((Bytes::copy_from_slice(transmit.contents), self.source));
        if let Some(waker) = queue.waker.lock().expect("queue waker").take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

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
async fn mock_udp_sender_endpoint_round_trips_stream_data() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let runtime = Arc::new(TokioRuntime);
    let network = Arc::new(MockNetwork::default());
    let server_socket = MockUdpSocket::bind(Arc::clone(&network), 41000);
    let client_socket = MockUdpSocket::bind(network, 41001);

    let (chain, key) = gen_self_signed_cert();
    let server_config = ServerConfig::with_single_cert(chain.clone(), key).expect("server config");
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .expect("server endpoint");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("server accept wait")
            .expect("incoming connection");
        let conn = timeout(Duration::from_secs(10), incoming)
            .await
            .expect("server handshake wait")
            .expect("server handshake");
        let mut recv = timeout(Duration::from_secs(10), conn.accept_uni())
            .await
            .expect("server accept_uni wait")
            .expect("server accept_uni");
        recv.read_to_end(1024).await.expect("server read")
    });

    let mut client =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, client_socket, runtime)
            .expect("client endpoint");
    client.set_default_client_config(client_config(&chain));

    let conn = timeout(
        Duration::from_secs(10),
        client
            .connect(server_addr, "localhost")
            .expect("connect start"),
    )
    .await
    .expect("client handshake wait")
    .expect("client handshake");

    let mut send = timeout(Duration::from_secs(10), conn.open_uni())
        .await
        .expect("client open_uni wait")
        .expect("client open_uni");
    send.write_all(b"x0x-0047")
        .await
        .expect("client stream write");
    send.finish().expect("client stream finish");

    let received = server_task.await.expect("server task");
    assert_eq!(received, b"x0x-0047");
}

#[tokio::test]
async fn mock_udp_sender_retries_initial_transmit_after_wakeup() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let runtime = Arc::new(TokioRuntime);
    let network = Arc::new(MockNetwork::default());
    let server_socket = MockUdpSocket::bind(Arc::clone(&network), 41002);
    let client_socket = MockUdpSocket::bind(network, 41003);

    let (chain, key) = gen_self_signed_cert();
    let server_config = ServerConfig::with_single_cert(chain.clone(), key).expect("server config");
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .expect("server endpoint");
    let server_addr = server.local_addr().expect("server addr");

    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("server accept wait")
            .expect("incoming connection");
        let conn = timeout(Duration::from_secs(10), incoming)
            .await
            .expect("server handshake wait")
            .expect("server handshake");
        let mut recv = timeout(Duration::from_secs(10), conn.accept_uni())
            .await
            .expect("server accept_uni wait")
            .expect("server accept_uni");
        recv.read_to_end(1024).await.expect("server read")
    });

    let client_endpoint_socket: Arc<dyn AsyncUdpSocket> = client_socket.clone();
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_endpoint_socket,
        runtime,
    )
    .expect("client endpoint");
    client.set_default_client_config(client_config(&chain));

    let send_block = client_socket.block_sender();
    let mut connecting = client
        .connect(server_addr, "localhost")
        .expect("connect start");

    timeout(Duration::from_secs(10), send_block.wait_for_pending())
        .await
        .expect("client sender pending");
    assert!(
        timeout(Duration::from_millis(50), &mut connecting)
            .await
            .is_err(),
        "client handshake completed before sender wake"
    );

    send_block.make_writable();

    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client handshake wait")
        .expect("client handshake");

    let mut send = timeout(Duration::from_secs(10), conn.open_uni())
        .await
        .expect("client open_uni wait")
        .expect("client open_uni");
    send.write_all(b"x0x-0048")
        .await
        .expect("client stream write");
    send.finish().expect("client stream finish");

    let received = server_task.await.expect("server task");
    assert_eq!(received, b"x0x-0048");
}
