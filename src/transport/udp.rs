// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! UDP transport provider implementation
//!
//! This module implements the [`TransportProvider`] trait for UDP/IP sockets,
//! providing high-bandwidth, low-latency transport for standard Internet connectivity.
//!
//! The UDP transport is the default and most capable transport, supporting:
//! - Full QUIC protocol
//! - IPv4 and IPv6 dual-stack
//! - Broadcast on local networks
//! - No link-layer acknowledgements (QUIC handles reliability)

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::addr::{TransportAddr, TransportType};
use super::capabilities::TransportCapabilities;
use super::provider::{
    InboundDatagram, LinkQuality, TransportError, TransportProvider, TransportStats,
};

/// UDP transport provider for standard Internet connectivity
///
/// This is the primary transport for ant-quic, providing high-bandwidth,
/// low-latency connectivity over UDP/IP.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    capabilities: TransportCapabilities,
    local_addr: SocketAddr,
    online: AtomicBool,
    /// Whether the socket has been delegated to Quinn (recv handled externally)
    delegated_to_quinn: AtomicBool,
    stats: UdpTransportStats,
    inbound_tx: mpsc::Sender<InboundDatagram>,
    shutdown_tx: mpsc::Sender<()>,
}

struct UdpTransportStats {
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_errors: AtomicU64,
    receive_errors: AtomicU64,
}

impl Default for UdpTransportStats {
    fn default() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
        }
    }
}

impl UdpTransport {
    /// Bind a new UDP transport to the specified address
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to. Use `0.0.0.0:0` for automatic port selection.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let transport = Self {
            socket: socket.clone(),
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            delegated_to_quinn: AtomicBool::new(false),
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        // Spawn receive loop
        transport.spawn_recv_loop(socket, shutdown_rx);

        Ok(transport)
    }

    /// Bind a new UDP transport for use with Quinn (no recv loop)
    ///
    /// This creates a transport where the socket will be shared with Quinn's
    /// QUIC endpoint. The transport can still send, but receiving is handled
    /// by Quinn's internal polling.
    ///
    /// When `addr` is an IPv6 address (e.g. `[::]:0`), this creates a dual-stack socket
    /// with `IPV6_V6ONLY=0`, allowing both IPv4 and IPv6 peers on a single socket.
    /// IPv4 connections appear as IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`).
    ///
    /// If dual-stack socket creation fails, falls back to a standard bind.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to. Use `[::]:0` for dual-stack with automatic
    ///   port selection, or `0.0.0.0:0` for IPv4-only.
    ///
    /// # Returns
    ///
    /// Returns a tuple of:
    /// - The `UdpTransport` for use in the transport registry
    /// - The `std::net::UdpSocket` for Quinn's endpoint
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind_for_quinn(addr: SocketAddr) -> io::Result<(Self, std::net::UdpSocket)> {
        let std_socket = Self::create_socket_for_quinn(addr)?;
        let local_addr = std_socket.local_addr()?;

        // Clone for transport's tokio socket
        let std_socket_for_transport = std_socket.try_clone()?;
        let tokio_socket = UdpSocket::from_std(std_socket_for_transport)?;
        let socket_arc = Arc::new(tokio_socket);

        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);

        let transport = Self {
            socket: socket_arc,
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            delegated_to_quinn: AtomicBool::new(true), // Quinn handles recv
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        // Do NOT spawn recv loop - Quinn will handle packet reception

        Ok((transport, std_socket))
    }

    /// Bind separate IPv4 and IPv6 sockets for true dual-stack operation.
    ///
    /// Returns the `UdpTransport` (for the transport registry) and an
    /// `Arc<DualStackSocket>` that wraps both sockets behind a single
    /// `AsyncUdpSocket` interface for the QUIC endpoint.
    ///
    /// The transport registry gets a clone of the IPv4 socket (or IPv6 if
    /// IPv4 is unavailable). The QUIC endpoint receives the `DualStackSocket`.
    pub async fn bind_dual_stack_for_endpoint(
        port: u16,
    ) -> io::Result<(
        Self,
        std::sync::Arc<crate::high_level::runtime::dual_stack::DualStackSocket>,
    )> {
        use crate::high_level::runtime::dual_stack;

        let (v4_std, v6_std) = dual_stack::create_dual_stack_sockets(port)?;

        // Pick a socket for the transport registry (prefer v4)
        let registry_socket = v4_std
            .as_ref()
            .or(v6_std.as_ref())
            .ok_or_else(|| io::Error::other("no sockets created"))?;

        // Clone for the transport's tokio socket
        let transport_clone = registry_socket.try_clone()?;
        let tokio_socket = UdpSocket::from_std(transport_clone)?;
        let local_addr = tokio_socket.local_addr()?;

        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, _) = mpsc::channel(1);

        let transport = Self {
            socket: Arc::new(tokio_socket),
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            delegated_to_quinn: AtomicBool::new(true),
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        // Create the DualStackSocket wrapper
        let dual = dual_stack::wrap_dual_stack(v4_std, v6_std)?;
        Ok((transport, std::sync::Arc::new(dual)))
    }

    /// Create a std UDP socket with proper dual-stack configuration.
    ///
    /// Uses `socket2` (when available via the `network-discovery` feature) to set
    /// `IPV6_V6ONLY=0` on IPv6 sockets, enabling true dual-stack operation.
    /// Falls back to standard `std::net::UdpSocket::bind` otherwise.
    #[cfg(feature = "network-discovery")]
    fn create_socket_for_quinn(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        if addr.is_ipv6() {
            // Enable dual-stack: accept both IPv4 and IPv6 on a single socket
            if let Err(e) = socket.set_only_v6(false) {
                tracing::debug!(%e, "unable to make socket dual-stack, IPv6-only mode");
            }
        }

        socket.set_nonblocking(true)?;

        // Apply platform-appropriate buffer sizes
        let buffer_size = crate::config::buffer_defaults::PLATFORM_DEFAULT;
        if let Err(e) = socket.set_send_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set send buffer size to {}", buffer_size);
        }
        if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set recv buffer size to {}", buffer_size);
        }

        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    /// Fallback socket creation without `socket2` (no dual-stack configuration).
    #[cfg(not(feature = "network-discovery"))]
    fn create_socket_for_quinn(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    /// Create a UDP transport from an existing socket
    ///
    /// This is useful when you want to share a socket with other components.
    /// Note: This spawns a recv loop, so don't use this if Quinn will handle recv.
    /// Use `bind_for_quinn()` instead for Quinn integration.
    pub fn from_socket(socket: Arc<UdpSocket>, local_addr: SocketAddr) -> Self {
        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let transport = Self {
            socket: socket.clone(),
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            delegated_to_quinn: AtomicBool::new(false),
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        transport.spawn_recv_loop(socket, shutdown_rx);
        transport
    }

    /// Check if this transport's recv is delegated to Quinn
    ///
    /// When true, the socket is shared with Quinn's QUIC endpoint and
    /// packet reception is handled by Quinn, not this transport.
    pub fn is_delegated_to_quinn(&self) -> bool {
        self.delegated_to_quinn.load(Ordering::SeqCst)
    }

    fn spawn_recv_loop(&self, socket: Arc<UdpSocket>, mut shutdown_rx: mpsc::Receiver<()>) {
        let inbound_tx = self.inbound_tx.clone();
        let online = self.online.load(Ordering::SeqCst);

        if !online {
            return;
        }

        // Note: This is a simplified receive loop for the transport abstraction.
        // In practice, the actual packet reception is handled by the QUIC endpoint's
        // polling mechanism, not this transport directly.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, source)) => {
                                let datagram = InboundDatagram {
                                    data: buf[..len].to_vec(),
                                    source: TransportAddr::Udp(source),
                                    received_at: Instant::now(),
                                    link_quality: None,
                                };

                                // Best-effort send; drop if channel is full
                                let _ = inbound_tx.try_send(datagram);
                            }
                            Err(_) => {
                                // Receive error, but continue trying
                                continue;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });
    }

    /// Get the underlying UDP socket
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Get the local address this transport is bound to
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl TransportProvider for UdpTransport {
    fn name(&self) -> &str {
        "UDP"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        Some(TransportAddr::Udp(self.local_addr))
    }

    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        let socket_addr = match dest {
            TransportAddr::Udp(addr) => *addr,
            _ => {
                return Err(TransportError::AddressMismatch {
                    expected: TransportType::Udp,
                    actual: dest.transport_type(),
                });
            }
        };

        if data.len() > self.capabilities.mtu {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: self.capabilities.mtu,
            });
        }

        match self.socket.send_to(data, socket_addr).await {
            Ok(sent) => {
                self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(sent as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(TransportError::SendFailed {
                    reason: e.to_string(),
                })
            }
        }
    }

    fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
        // Create a new receiver from the same channel
        // Note: In a real implementation, you might want to use a broadcast channel
        // or have the endpoint subscribe to the transport's inbound stream.
        let (_, rx) = mpsc::channel(1024);
        rx
    }

    fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    async fn shutdown(&self) -> Result<(), TransportError> {
        self.online.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(()).await;
        Ok(())
    }

    async fn broadcast(&self, data: &[u8]) -> Result<(), TransportError> {
        // UDP supports broadcast
        if !self.capabilities.broadcast {
            return Err(TransportError::BroadcastNotSupported);
        }

        // Broadcast to 255.255.255.255 on the same port
        let broadcast_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            self.local_addr.port(),
        );

        self.send(data, &TransportAddr::Udp(broadcast_addr)).await
    }

    async fn link_quality(&self, _peer: &TransportAddr) -> Option<LinkQuality> {
        // UDP doesn't provide link quality metrics directly
        None
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            datagrams_sent: self.stats.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            receive_errors: self.stats.receive_errors.load(Ordering::Relaxed),
            current_rtt: None,
        }
    }

    fn socket(&self) -> Option<&Arc<UdpSocket>> {
        Some(&self.socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_bind() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.is_online());
        assert_eq!(transport.transport_type(), TransportType::Udp);
        assert!(transport.capabilities().supports_full_quic());

        let local_addr = transport.local_addr();
        assert!(local_addr.is_some());
        if let Some(TransportAddr::Udp(addr)) = local_addr {
            assert_eq!(
                addr.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            );
            assert_ne!(addr.port(), 0);
        }
    }

    #[tokio::test]
    async fn test_udp_transport_send() {
        let transport1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let transport2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let dest = transport2.local_addr().unwrap();
        let result = transport1.send(b"hello", &dest).await;
        assert!(result.is_ok());

        let stats = transport1.stats();
        assert_eq!(stats.datagrams_sent, 1);
        assert_eq!(stats.bytes_sent, 5);
    }

    #[tokio::test]
    async fn test_udp_transport_address_mismatch() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let ble_addr = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        let result = transport.send(b"hello", &ble_addr).await;

        match result {
            Err(TransportError::AddressMismatch { expected, actual }) => {
                assert_eq!(expected, TransportType::Udp);
                assert_eq!(actual, TransportType::Ble);
            }
            _ => panic!("expected AddressMismatch error"),
        }
    }

    #[tokio::test]
    async fn test_udp_transport_shutdown() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.is_online());
        transport.shutdown().await.unwrap();
        assert!(!transport.is_online());

        // Sending after shutdown should fail
        let dest = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
        let result = transport.send(b"hello", &dest).await;
        assert!(matches!(result, Err(TransportError::Offline)));
    }

    #[test]
    fn test_udp_capabilities() {
        let caps = TransportCapabilities::broadband();

        assert!(caps.supports_full_quic());
        assert!(!caps.half_duplex);
        assert!(caps.broadcast);
        assert!(!caps.metered);
        assert!(!caps.power_constrained);
    }

    #[tokio::test]
    async fn test_udp_transport_socket_accessor() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Test the inherent socket() method
        let socket_ref = transport.socket();
        assert!(socket_ref.local_addr().is_ok());

        // Test the trait method via TransportProvider
        let provider: &dyn TransportProvider = &transport;
        let socket_opt = provider.socket();
        assert!(socket_opt.is_some());
        assert!(socket_opt.unwrap().local_addr().is_ok());
    }

    // ─── Dual-stack IPv4/IPv6 tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_bind_for_quinn_ipv6_dual_stack() {
        // Bind to [::]:0 — should create a dual-stack socket
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let (transport, quinn_socket) = UdpTransport::bind_for_quinn(addr).await.unwrap();

        let local = quinn_socket.local_addr().unwrap();
        assert!(local.is_ipv6(), "expected IPv6 address, got {local}");
        assert_ne!(local.port(), 0, "port should be assigned by OS");

        // Transport should report same address
        let transport_addr = transport.local_address();
        assert!(transport_addr.is_ipv6());
        assert_eq!(transport_addr.port(), local.port());
    }

    #[tokio::test]
    async fn test_bind_for_quinn_ipv4_explicit() {
        // Explicit IPv4 bind should still work
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let (transport, quinn_socket) = UdpTransport::bind_for_quinn(addr).await.unwrap();

        let local = quinn_socket.local_addr().unwrap();
        assert!(local.is_ipv4(), "expected IPv4 address, got {local}");
        assert_ne!(local.port(), 0);
        assert_eq!(transport.local_address().port(), local.port());
    }

    // Windows default dual-stack behaviour differs for IPv4-mapped addresses;
    // the functional dual-stack tests (receive_from_ipv4_sender, communicate_ipv6)
    // cover Windows adequately.
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_dual_stack_socket_can_send_to_ipv4_mapped() {
        // Bind a dual-stack receiver on [::]:0
        let receiver = std::net::UdpSocket::bind("[::]:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let recv_port = receiver.local_addr().unwrap().port();

        // Bind a dual-stack sender via bind_for_quinn
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let (transport, _quinn_socket) = UdpTransport::bind_for_quinn(addr).await.unwrap();

        // Send to the receiver using an IPv4-mapped IPv6 address (::ffff:127.0.0.1)
        let ipv4_mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{recv_port}").parse().unwrap();
        let dest = TransportAddr::Udp(ipv4_mapped);
        transport.send(b"dual-stack-test", &dest).await.unwrap();

        // Verify the datagram arrived
        let mut buf = [0u8; 64];
        // Give it a moment — non-blocking so we retry briefly
        let mut received = false;
        for _ in 0..50 {
            match receiver.recv_from(&mut buf) {
                Ok((len, _src)) => {
                    assert_eq!(&buf[..len], b"dual-stack-test");
                    received = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("unexpected recv error: {e}"),
            }
        }
        assert!(received, "receiver did not get the dual-stack datagram");
    }

    #[tokio::test]
    async fn test_dual_stack_socket_can_receive_from_ipv4_sender() {
        // Bind a dual-stack socket via bind_for_quinn
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let (_transport, quinn_socket) = UdpTransport::bind_for_quinn(addr).await.unwrap();
        let recv_port = quinn_socket.local_addr().unwrap().port();
        quinn_socket.set_nonblocking(true).unwrap();

        // Send from a plain IPv4 socket
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest: SocketAddr = format!("127.0.0.1:{recv_port}").parse().unwrap();
        sender.send_to(b"from-ipv4", dest).unwrap();

        // The dual-stack socket should receive it
        let mut buf = [0u8; 64];
        let mut received = false;
        for _ in 0..50 {
            match quinn_socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    assert_eq!(&buf[..len], b"from-ipv4");
                    // Source should be IPv4-mapped IPv6 or plain IPv4 depending on OS
                    let src_ip = src.ip();
                    let is_loopback = match src_ip {
                        std::net::IpAddr::V4(v4) => v4.is_loopback(),
                        std::net::IpAddr::V6(v6) => {
                            // IPv4-mapped: ::ffff:127.0.0.1
                            v6.to_ipv4_mapped()
                                .map(|v4| v4.is_loopback())
                                .unwrap_or(false)
                        }
                    };
                    assert!(is_loopback, "source should be loopback, got {src_ip}");
                    received = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("unexpected recv error: {e}"),
            }
        }
        assert!(received, "dual-stack socket did not receive IPv4 datagram");
    }

    #[tokio::test]
    async fn test_dual_stack_socket_can_communicate_ipv6() {
        // Bind a dual-stack socket via bind_for_quinn
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let (_transport, quinn_socket) = UdpTransport::bind_for_quinn(addr).await.unwrap();
        let recv_port = quinn_socket.local_addr().unwrap().port();
        quinn_socket.set_nonblocking(true).unwrap();

        // Send from a pure IPv6 socket to ::1 (loopback)
        let sender = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let dest: SocketAddr = format!("[::1]:{recv_port}").parse().unwrap();
        sender.send_to(b"from-ipv6", dest).unwrap();

        // The dual-stack socket should receive it
        let mut buf = [0u8; 64];
        let mut received = false;
        for _ in 0..50 {
            match quinn_socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    assert_eq!(&buf[..len], b"from-ipv6");
                    // Source should be ::1 (IPv6 loopback)
                    let is_v6_loopback = match src.ip() {
                        std::net::IpAddr::V6(v6) => v6 == std::net::Ipv6Addr::LOCALHOST,
                        _ => false,
                    };
                    assert!(is_v6_loopback, "source should be ::1, got {}", src.ip());
                    received = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("unexpected recv error: {e}"),
            }
        }
        assert!(received, "dual-stack socket did not receive IPv6 datagram");
    }

    #[tokio::test]
    async fn test_bind_for_quinn_with_specific_port() {
        // Bind to a specific port on IPv6 dual-stack
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let (_, socket1) = UdpTransport::bind_for_quinn(addr).await.unwrap();
        let port = socket1.local_addr().unwrap().port();

        // Port should be non-zero and allocated
        assert!(port > 0);

        // Binding to the same port again should fail (port in use)
        let specific: SocketAddr = format!("[::]:{port}").parse().unwrap();
        let result = UdpTransport::bind_for_quinn(specific).await;
        assert!(result.is_err(), "binding to same port should fail");
    }

    #[cfg(all(feature = "network-discovery", not(target_os = "windows")))]
    #[test]
    fn test_create_socket_for_quinn_dual_stack_flag() {
        use socket2::Socket;

        // Create socket via our helper
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let std_socket = UdpTransport::create_socket_for_quinn(addr).unwrap();

        // Verify it's actually dual-stack by checking the socket option
        // Note: Socket::from() panics on Windows due to handle type validation,
        // so this test is Unix-only. Windows dual-stack is verified by the
        // functional send/receive tests instead.
        let socket2_sock = Socket::from(std_socket);
        let only_v6 = socket2_sock.only_v6().unwrap();
        assert!(!only_v6, "IPV6_V6ONLY should be false (dual-stack enabled)");
    }
}
