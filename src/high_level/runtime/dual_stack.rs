// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Dual-stack UDP socket that manages separate IPv4 and IPv6 sockets.
//!
//! Implements [`AsyncUdpSocket`] to present a single socket interface to the QUIC endpoint
//! while internally routing traffic to the appropriate address-family socket.
//!
//! This avoids relying on `IPV6_V6ONLY=0` dual-stack sockets, which behave inconsistently
//! across platforms (Windows defaults to `IPV6_V6ONLY=1`, some Linux kernels, embedded systems).

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use quinn_udp::{RecvMeta, Transmit};
use tokio::io::ReadBuf;
use tracing::{debug, info};

use super::{AsyncUdpSocket, UdpPollHelper, UdpPoller};

/// A dual-stack UDP socket that manages separate IPv4 and IPv6 sockets.
///
/// Routes outgoing traffic to the appropriate socket based on the destination address family.
/// Multiplexes incoming traffic from both sockets with fair polling.
///
/// When both sockets are present, `local_addr()` returns the IPv6 address so that the
/// QUIC endpoint sets `ipv6 = true`. The endpoint then converts all outgoing IPv4
/// destinations to IPv4-mapped IPv6 addresses (e.g. `::ffff:1.2.3.4`), which this
/// wrapper detects and routes to the IPv4 socket.
pub struct DualStackSocket {
    v4: Option<Arc<tokio::net::UdpSocket>>,
    v6: Option<Arc<tokio::net::UdpSocket>>,
    /// Alternates which socket is polled first for fairness
    poll_v4_first: AtomicBool,
}

impl fmt::Debug for DualStackSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualStackSocket")
            .field("v4", &self.v4.as_ref().and_then(|s| s.local_addr().ok()))
            .field("v6", &self.v6.as_ref().and_then(|s| s.local_addr().ok()))
            .finish()
    }
}

impl DualStackSocket {
    /// Create a dual-stack socket with explicit IPv4 and IPv6 sockets.
    ///
    /// At least one socket must be provided.
    pub fn new(
        v4: Option<tokio::net::UdpSocket>,
        v6: Option<tokio::net::UdpSocket>,
    ) -> io::Result<Self> {
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one socket (IPv4 or IPv6) must be provided",
            ));
        }
        Ok(Self {
            v4: v4.map(Arc::new),
            v6: v6.map(Arc::new),
            poll_v4_first: AtomicBool::new(false),
        })
    }

    /// Get the IPv4 local address, if available.
    pub fn local_addr_v4(&self) -> Option<SocketAddr> {
        self.v4.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Get the IPv6 local address, if available.
    pub fn local_addr_v6(&self) -> Option<SocketAddr> {
        self.v6.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Get both local addresses: (IPv4, IPv6).
    pub fn local_addrs(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
        (self.local_addr_v4(), self.local_addr_v6())
    }

    /// Whether this socket has both address families.
    pub fn is_dual(&self) -> bool {
        self.v4.is_some() && self.v6.is_some()
    }

    /// Select the appropriate socket for a destination address.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are routed to the IPv4 socket.
    fn select_socket(&self, dest: &SocketAddr) -> Option<&Arc<tokio::net::UdpSocket>> {
        match dest {
            SocketAddr::V4(_) => self.v4.as_ref().or(self.v6.as_ref()),
            SocketAddr::V6(v6) => {
                if let Some(_v4) = v6.ip().to_ipv4_mapped() {
                    // IPv4-mapped address: prefer the IPv4 socket
                    self.v4.as_ref().or(self.v6.as_ref())
                } else {
                    // Native IPv6 address
                    self.v6.as_ref().or(self.v4.as_ref())
                }
            }
        }
    }

    /// Convert a destination address for the selected socket.
    ///
    /// If sending an IPv4-mapped IPv6 address through the IPv4 socket, unwrap to native IPv4.
    /// If sending an IPv4 address through the IPv6 socket, wrap as IPv4-mapped IPv6.
    fn convert_dest(dest: SocketAddr, socket: &tokio::net::UdpSocket) -> io::Result<SocketAddr> {
        let socket_is_v6 = socket.local_addr()?.is_ipv6();

        match dest {
            SocketAddr::V4(v4) if socket_is_v6 => {
                // Sending IPv4 through IPv6 socket: map to IPv4-mapped
                Ok(SocketAddr::V6(to_mapped_v6(v4)))
            }
            SocketAddr::V6(v6) if !socket_is_v6 => {
                // Sending IPv6 through IPv4 socket: must be IPv4-mapped
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    Ok(SocketAddr::new(v4.into(), v6.port()))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "cannot send native IPv6 address through IPv4 socket",
                    ))
                }
            }
            other => Ok(other),
        }
    }

    /// Poll a single socket for incoming datagrams.
    fn poll_recv_one(
        socket: &tokio::net::UdpSocket,
        socket_is_v4: bool,
        cx: &mut Context<'_>,
        buf: &mut IoSliceMut<'_>,
        meta: &mut RecvMeta,
    ) -> Poll<io::Result<()>> {
        let mut read_buf = ReadBuf::new(buf);
        let addr = match socket.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(addr)) => addr,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let len = read_buf.filled().len();

        // If received on the v4 socket, convert source address to IPv4-mapped IPv6
        // so the Endpoint (which thinks it has an IPv6 socket) can handle it.
        let mapped_addr = if socket_is_v4 {
            match addr {
                SocketAddr::V4(v4) => SocketAddr::V6(to_mapped_v6(v4)),
                other => other,
            }
        } else {
            addr
        };

        *meta = RecvMeta {
            len,
            stride: len,
            addr: mapped_addr,
            ecn: None,
            dst_ip: None,
        };

        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for DualStackSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move {
                // Wait until either socket is writable
                let v4_fut = async {
                    if let Some(ref s) = socket.v4 {
                        s.writable().await
                    } else {
                        // Never resolves if no v4 socket
                        std::future::pending().await
                    }
                };
                let v6_fut = async {
                    if let Some(ref s) = socket.v6 {
                        s.writable().await
                    } else {
                        std::future::pending().await
                    }
                };

                tokio::select! {
                    result = v4_fut => result,
                    result = v6_fut => result,
                }
            }
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let socket = self.select_socket(&transmit.destination).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no socket available for destination address family",
            )
        })?;

        let dest = Self::convert_dest(transmit.destination, socket)?;
        socket.try_send_to(transmit.contents, dest)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Alternate poll order for fairness
        let v4_first = self.poll_v4_first.fetch_xor(true, Ordering::Relaxed);

        let (first_socket, first_is_v4, second_socket, second_is_v4) = if v4_first {
            (&self.v4, true, &self.v6, false)
        } else {
            (&self.v6, false, &self.v4, true)
        };

        // Poll first socket
        if let Some(socket) = first_socket {
            match Self::poll_recv_one(socket, first_is_v4, cx, &mut bufs[0], &mut meta[0]) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(1)),
                Poll::Ready(Err(e)) => {
                    // Log but continue to try second socket
                    debug!(
                        "recv error on {} socket: {}",
                        if first_is_v4 { "IPv4" } else { "IPv6" },
                        e
                    );
                }
                Poll::Pending => {} // Try second socket
            }
        }

        // Poll second socket
        if let Some(socket) = second_socket {
            match Self::poll_recv_one(socket, second_is_v4, cx, &mut bufs[0], &mut meta[0]) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(1)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {} // Both pending
            }
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Prefer IPv6 so that endpoint.ipv6 = true, which triggers ensure_ipv6()
        // for all outgoing connections, sending IPv4-mapped addresses to try_send().
        if let Some(ref s) = self.v6 {
            return s.local_addr();
        }
        if let Some(ref s) = self.v4 {
            return s.local_addr();
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no socket bound",
        ))
    }

    fn may_fragment(&self) -> bool {
        // Conservative: if either socket may fragment, report true
        let v4_frag = self
            .v4
            .as_ref()
            .map(|_| true) // default for tokio sockets
            .unwrap_or(true);
        let v6_frag = self.v6.as_ref().map(|_| true).unwrap_or(true);
        v4_frag || v6_frag
    }
}

// ─── Address conversion helpers ──────────────────────────────────────────────

/// Convert an IPv4 socket address to an IPv4-mapped IPv6 socket address.
fn to_mapped_v6(v4: SocketAddrV4) -> SocketAddrV6 {
    SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)
}

// ─── Factory functions ───────────────────────────────────────────────────────

/// Create a dual-stack socket binding separate IPv4 and IPv6 sockets.
///
/// The IPv6 socket is bound with `IPV6_V6ONLY=1` (pure IPv6, no dual-stack kernel
/// behavior) because we manage the address-family separation ourselves.
///
/// If `port` is 0, the OS assigns ports (they may differ between v4 and v6).
/// If `port` is non-zero, both sockets attempt to bind to the same port.
///
/// Gracefully degrades to single-stack if one address family is unavailable.
#[cfg(feature = "network-discovery")]
pub fn create_dual_stack_sockets(
    port: u16,
) -> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)> {
    let mut v6_result = None;
    let mut v4_result = None;
    let mut actual_port = port;

    // Try IPv6 first
    match create_v6_socket(port) {
        Ok(socket) => {
            if port == 0 {
                // Learn the OS-assigned port so v4 can try the same port
                actual_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
            }
            v6_result = Some(socket);
        }
        Err(e) => {
            debug!("IPv6 socket creation failed: {e}");
        }
    }

    // Try IPv4, preferring same port if v6 succeeded
    match create_v4_socket(actual_port) {
        Ok(socket) => {
            v4_result = Some(socket);
        }
        Err(e) if actual_port != 0 && port == 0 => {
            // Port conflict on OS-assigned port, try with port 0
            debug!("IPv4 bind to port {actual_port} failed ({e}), trying OS-assigned");
            match create_v4_socket(0) {
                Ok(socket) => {
                    v4_result = Some(socket);
                }
                Err(e2) => {
                    debug!("IPv4 socket creation failed: {e2}");
                }
            }
        }
        Err(e) => {
            debug!("IPv4 socket creation failed: {e}");
        }
    }

    if v4_result.is_none() && v6_result.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "failed to bind both IPv4 and IPv6 sockets",
        ));
    }

    let v4_desc = v4_result
        .as_ref()
        .and_then(|s| s.local_addr().ok())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    let v6_desc = v6_result
        .as_ref()
        .and_then(|s| s.local_addr().ok())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    info!("Dual-stack sockets: IPv4={v4_desc}, IPv6={v6_desc}");

    Ok((v4_result, v6_result))
}

#[cfg(feature = "network-discovery")]
fn create_v6_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // Pure IPv6 — we manage v4/v6 separation ourselves
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;

    let buffer_size = crate::config::buffer_defaults::PLATFORM_DEFAULT;
    let _ = socket.set_send_buffer_size(buffer_size);
    let _ = socket.set_recv_buffer_size(buffer_size);

    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket.into())
}

#[cfg(feature = "network-discovery")]
fn create_v4_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;

    let buffer_size = crate::config::buffer_defaults::PLATFORM_DEFAULT;
    let _ = socket.set_send_buffer_size(buffer_size);
    let _ = socket.set_recv_buffer_size(buffer_size);

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket.into())
}

/// Fallback when `network-discovery` feature is not enabled.
#[cfg(not(feature = "network-discovery"))]
pub fn create_dual_stack_sockets(
    port: u16,
) -> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)> {
    let v6_addr: SocketAddr = format!("[::]:{port}")
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad address: {e}")))?;
    let v4_addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad address: {e}")))?;

    let v6 = std::net::UdpSocket::bind(v6_addr).ok();
    let v4 = std::net::UdpSocket::bind(v4_addr).ok();

    if v4.is_none() && v6.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "failed to bind both IPv4 and IPv6 sockets",
        ));
    }

    Ok((v4, v6))
}

/// Create a `DualStackSocket` from std sockets, converting to tokio.
pub fn wrap_dual_stack(
    v4: Option<std::net::UdpSocket>,
    v6: Option<std::net::UdpSocket>,
) -> io::Result<DualStackSocket> {
    let v4_tokio = match v4 {
        Some(s) => {
            s.set_nonblocking(true)?;
            Some(tokio::net::UdpSocket::from_std(s)?)
        }
        None => None,
    };
    let v6_tokio = match v6 {
        Some(s) => {
            s.set_nonblocking(true)?;
            Some(tokio::net::UdpSocket::from_std(s)?)
        }
        None => None,
    };
    DualStackSocket::new(v4_tokio, v6_tokio)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_mapped_v6() {
        let v4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 9000);
        let mapped = to_mapped_v6(v4);
        assert_eq!(mapped.port(), 9000);
        assert!(mapped.ip().to_ipv4_mapped().is_some());
        assert_eq!(
            mapped.ip().to_ipv4_mapped().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }

    #[tokio::test]
    async fn test_dual_stack_socket_creation() {
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();

        let ds = DualStackSocket::new(Some(v4), Some(v6)).unwrap();
        assert!(ds.is_dual());
        assert!(ds.local_addr_v4().is_some());
        assert!(ds.local_addr_v6().is_some());

        // local_addr() should prefer IPv6
        let addr = ds.local_addr().unwrap();
        assert!(addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_v4_only_fallback() {
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let ds = DualStackSocket::new(Some(v4), None).unwrap();
        assert!(!ds.is_dual());
        assert!(ds.local_addr_v4().is_some());
        assert!(ds.local_addr_v6().is_none());

        let addr = ds.local_addr().unwrap();
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_v6_only_fallback() {
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();

        let ds = DualStackSocket::new(None, Some(v6)).unwrap();
        assert!(!ds.is_dual());
        assert!(ds.local_addr_v4().is_none());
        assert!(ds.local_addr_v6().is_some());

        let addr = ds.local_addr().unwrap();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_no_socket_fails() {
        let result = DualStackSocket::new(None, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_routing_ipv4_mapped() {
        // Create a v4 receiver
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let recv_port = receiver.local_addr().unwrap().port();

        // Create dual-stack socket — await writability before try_send
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        v4.writable().await.unwrap();
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        v6.writable().await.unwrap();
        let ds = DualStackSocket::new(Some(v4), Some(v6)).unwrap();

        // Send to an IPv4-mapped IPv6 address — should route to v4 socket
        let mapped_dest: SocketAddr = format!("[::ffff:127.0.0.1]:{recv_port}").parse().unwrap();
        let transmit = Transmit {
            destination: mapped_dest,
            ecn: None,
            contents: b"hello-v4-mapped",
            segment_size: None,
            src_ip: None,
        };
        ds.try_send(&transmit).unwrap();

        // Verify receipt on the v4 receiver
        let mut buf = [0u8; 64];
        let mut received = false;
        for _ in 0..50 {
            match receiver.recv_from(&mut buf) {
                Ok((len, _)) => {
                    assert_eq!(&buf[..len], b"hello-v4-mapped");
                    received = true;
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("recv error: {e}"),
            }
        }
        assert!(received, "v4 receiver should get the IPv4-mapped datagram");
    }

    #[tokio::test]
    async fn test_send_routing_native_v6() {
        // Create a v6 receiver
        let receiver = std::net::UdpSocket::bind("[::1]:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let recv_port = receiver.local_addr().unwrap().port();

        // Create dual-stack socket — await writability before try_send
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        v4.writable().await.unwrap();
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        v6.writable().await.unwrap();
        let ds = DualStackSocket::new(Some(v4), Some(v6)).unwrap();

        // Send to native IPv6 — should route to v6 socket
        let dest: SocketAddr = format!("[::1]:{recv_port}").parse().unwrap();
        let transmit = Transmit {
            destination: dest,
            ecn: None,
            contents: b"hello-v6",
            segment_size: None,
            src_ip: None,
        };
        ds.try_send(&transmit).unwrap();

        // Verify receipt
        let mut buf = [0u8; 64];
        let mut received = false;
        for _ in 0..50 {
            match receiver.recv_from(&mut buf) {
                Ok((len, _)) => {
                    assert_eq!(&buf[..len], b"hello-v6");
                    received = true;
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("recv error: {e}"),
            }
        }
        assert!(received, "v6 receiver should get the native v6 datagram");
    }

    #[cfg(feature = "network-discovery")]
    #[test]
    fn test_create_dual_stack_sockets_port_zero() {
        let (v4, v6) = create_dual_stack_sockets(0).unwrap();
        assert!(v4.is_some() || v6.is_some());

        if let Some(ref s) = v4 {
            assert!(s.local_addr().unwrap().is_ipv4());
            assert_ne!(s.local_addr().unwrap().port(), 0);
        }
        if let Some(ref s) = v6 {
            assert!(s.local_addr().unwrap().is_ipv6());
            assert_ne!(s.local_addr().unwrap().port(), 0);
        }
    }

    #[tokio::test]
    async fn test_recv_v4_address_mapping() {
        // Create dual-stack socket
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v4_port = v4.local_addr().unwrap().port();
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let ds = DualStackSocket::new(Some(v4), Some(v6)).unwrap();

        // Send a datagram from an external IPv4 socket to the dual-stack v4 port
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"from-v4", format!("127.0.0.1:{v4_port}"))
            .unwrap();

        // Receive via DualStackSocket — address should be IPv4-mapped IPv6
        let mut buf_data = [0u8; 256];
        let mut bufs = [IoSliceMut::new(&mut buf_data)];
        let mut meta = [RecvMeta::default()];

        // Poll with a runtime
        let ds_arc = Arc::new(ds);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            wait_for_recv(ds_arc.clone(), &mut bufs, &mut meta),
        )
        .await;

        assert!(result.is_ok(), "should receive within timeout");
        let n = result.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf_data[..meta[0].len], b"from-v4");

        // Source address should be IPv4-mapped IPv6 (::ffff:127.0.0.1)
        let source = meta[0].addr;
        assert!(
            source.is_ipv6(),
            "source should be IPv6 (mapped), got {source}"
        );
        if let SocketAddr::V6(v6_addr) = source {
            assert!(
                v6_addr.ip().to_ipv4_mapped().is_some(),
                "should be IPv4-mapped, got {v6_addr}"
            );
        }
    }

    /// Helper: poll recv until a datagram arrives.
    async fn wait_for_recv(
        socket: Arc<DualStackSocket>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> usize {
        std::future::poll_fn(|cx| socket.poll_recv(cx, bufs, meta))
            .await
            .unwrap()
    }
}
