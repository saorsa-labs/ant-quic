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
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;
use tracing::debug;

use super::{AsyncUdpSocket, UdpPollHelper, UdpPoller, UdpSender};

/// A dual-stack UDP socket that manages separate IPv4 and IPv6 sockets.
///
/// Routes outgoing traffic to the appropriate socket based on the destination address family.
/// Multiplexes incoming traffic from both sockets with fair polling.
///
/// Each underlying socket is paired with a [`quinn_udp::UdpSocketState`] to enable
/// kernel UDP batching (`recvmmsg` / GRO), segmentation offload (GSO), ECN
/// codepoints, and don't-fragment (`may_fragment`) reporting across both families.
///
/// When both sockets are present, `local_addr()` returns the IPv6 address so that the
/// QUIC endpoint sets `ipv6 = true`. The endpoint then converts all outgoing IPv4
/// destinations to IPv4-mapped IPv6 addresses (e.g. `::ffff:1.2.3.4`), which this
/// wrapper detects and routes to the IPv4 socket.
pub struct DualStackSocket {
    v4: Option<Arc<tokio::net::UdpSocket>>,
    v6: Option<Arc<tokio::net::UdpSocket>>,
    v4_state: Option<Arc<UdpSocketState>>,
    v6_state: Option<Arc<UdpSocketState>>,
    /// Cached IPv4 `local_addr()` captured at construction so hot paths
    /// (quinn's `ConnectionDriver::poll` calls `AsyncUdpSocket::local_addr`
    /// on every iteration) avoid a `getsockname(2)` syscall per poll.
    /// Sockets do not rebind after construction, so this stays valid for
    /// the lifetime of the wrapper.
    v4_addr: Option<SocketAddr>,
    v6_addr: Option<SocketAddr>,
    /// Alternates which socket is polled first for fairness
    poll_v4_first: AtomicBool,
}

impl fmt::Debug for DualStackSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualStackSocket")
            .field("v4", &self.v4_addr)
            .field("v6", &self.v6_addr)
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
        let v4_addr = v4.as_ref().map(|socket| socket.local_addr()).transpose()?;
        let v6_addr = v6.as_ref().map(|socket| socket.local_addr()).transpose()?;
        let v4_state = v4
            .as_ref()
            .map(|socket| UdpSocketState::new(UdpSockRef::from(socket)).map(Arc::new))
            .transpose()?;
        let v6_state = v6
            .as_ref()
            .map(|socket| UdpSocketState::new(UdpSockRef::from(socket)).map(Arc::new))
            .transpose()?;
        Ok(Self {
            v4: v4.map(Arc::new),
            v6: v6.map(Arc::new),
            v4_state,
            v6_state,
            v4_addr,
            v6_addr,
            poll_v4_first: AtomicBool::new(false),
        })
    }

    /// Get the IPv4 local address, if available.
    pub fn local_addr_v4(&self) -> Option<SocketAddr> {
        self.v4_addr
    }

    /// Get the IPv6 local address, if available.
    pub fn local_addr_v6(&self) -> Option<SocketAddr> {
        self.v6_addr
    }

    /// Get both local addresses: (IPv4, IPv6).
    pub fn local_addrs(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
        (self.v4_addr, self.v6_addr)
    }

    /// Whether this socket has both address families.
    pub fn is_dual(&self) -> bool {
        self.v4.is_some() && self.v6.is_some()
    }

    /// Convert a destination address for the selected socket.
    ///
    /// If sending an IPv4-mapped IPv6 address through the IPv4 socket, unwrap to native IPv4.
    /// If sending an IPv4 address through the IPv6 socket, wrap as IPv4-mapped IPv6.
    ///
    /// `socket_is_v6` must match the selected socket's bound family — it is
    /// derived from [`select_socket`] rather than re-discovered via
    /// `local_addr()` so that this function is free of syscalls.
    fn convert_dest(dest: SocketAddr, socket_is_v6: bool) -> io::Result<SocketAddr> {
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

    /// Convert an optional source IP hint to match the selected socket family.
    fn convert_src_ip(src_ip: Option<IpAddr>, socket_is_v6: bool) -> Option<IpAddr> {
        match (src_ip?, socket_is_v6) {
            (IpAddr::V4(v4), true) => Some(IpAddr::V6(v4.to_ipv6_mapped())),
            (IpAddr::V6(v6), false) => v6.to_ipv4_mapped().map(IpAddr::V4),
            (other, _) => Some(other),
        }
    }

    /// Poll a single socket for a batch of incoming datagrams via `quinn_udp`.
    fn poll_recv_batch(
        socket: &tokio::net::UdpSocket,
        state: &UdpSocketState,
        socket_is_v4: bool,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let res = socket.try_io(Interest::READABLE, || {
                state.recv(UdpSockRef::from(socket), bufs, meta)
            });

            match res {
                Ok(count) => {
                    if socket_is_v4 {
                        for m in &mut meta[..count] {
                            if let SocketAddr::V4(v4) = m.addr {
                                m.addr = SocketAddr::V6(to_mapped_v6(v4));
                            }
                            if let Some(IpAddr::V4(v4)) = m.dst_ip {
                                m.dst_ip = Some(IpAddr::V6(v4.to_ipv6_mapped()));
                            }
                        }
                    }
                    return Poll::Ready(Ok(count));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncUdpSocket for DualStackSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(DualStackUdpSender {
            v4: self.v4.clone(),
            v6: self.v6.clone(),
            v4_state: self.v4_state.clone(),
            v6_state: self.v6_state.clone(),
            v4_writable: self.v4.as_ref().map(make_socket_poller),
            v6_writable: self.v6.as_ref().map(make_socket_poller),
        })
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

        let (first_socket, first_state, first_is_v4, second_socket, second_state, second_is_v4) =
            if v4_first {
                (
                    &self.v4,
                    &self.v4_state,
                    true,
                    &self.v6,
                    &self.v6_state,
                    false,
                )
            } else {
                (
                    &self.v6,
                    &self.v6_state,
                    false,
                    &self.v4,
                    &self.v4_state,
                    true,
                )
            };

        // Poll first socket
        if let (Some(socket), Some(state)) = (first_socket, first_state) {
            match Self::poll_recv_batch(socket, state, first_is_v4, cx, bufs, meta) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
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
        if let (Some(socket), Some(state)) = (second_socket, second_state) {
            match Self::poll_recv_batch(socket, state, second_is_v4, cx, bufs, meta) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {} // Both pending
            }
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Prefer IPv6 so that endpoint.ipv6 = true, which triggers ensure_ipv6()
        // for all outgoing connections, sending IPv4-mapped addresses to try_send().
        //
        // Uses the cached value captured in [`DualStackSocket::new`] — quinn's
        // `ConnectionDriver::poll` invokes this on every poll iteration, so a
        // `getsockname(2)` per-poll pegs a CPU under high packet rates.
        if let Some(addr) = self.v6_addr {
            return Ok(addr);
        }
        if let Some(addr) = self.v4_addr {
            return Ok(addr);
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no socket bound",
        ))
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let addresses: Vec<_> = [self.v4_addr, self.v6_addr].into_iter().flatten().collect();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "dual-stack socket has no bound addresses",
            ));
        }
        Ok(addresses)
    }

    fn max_receive_segments(&self) -> usize {
        let v4_gro = self.v4_state.as_ref().map_or(1, |s| s.gro_segments());
        let v6_gro = self.v6_state.as_ref().map_or(1, |s| s.gro_segments());
        v4_gro.max(v6_gro).max(1)
    }

    fn may_fragment(&self) -> bool {
        let v4_frag = self.v4_state.as_ref().is_some_and(|s| s.may_fragment());
        let v6_frag = self.v6_state.as_ref().is_some_and(|s| s.may_fragment());
        v4_frag || v6_frag
    }
}

fn make_socket_poller(socket: &Arc<tokio::net::UdpSocket>) -> Pin<Box<dyn UdpPoller>> {
    let socket = Arc::clone(socket);
    Box::pin(UdpPollHelper::new(move || {
        let socket = Arc::clone(&socket);
        async move { socket.writable().await }
    }))
}

#[derive(Debug)]
struct DualStackUdpSender {
    v4: Option<Arc<tokio::net::UdpSocket>>,
    v6: Option<Arc<tokio::net::UdpSocket>>,
    v4_state: Option<Arc<UdpSocketState>>,
    v6_state: Option<Arc<UdpSocketState>>,
    v4_writable: Option<Pin<Box<dyn UdpPoller>>>,
    v6_writable: Option<Pin<Box<dyn UdpPoller>>>,
}

impl DualStackUdpSender {
    fn select_family(&self, dest: &SocketAddr) -> Option<bool> {
        let has_v4 = self.v4.is_some();
        let has_v6 = self.v6.is_some();
        match dest {
            SocketAddr::V4(_) => {
                if has_v4 {
                    Some(false)
                } else {
                    has_v6.then_some(true)
                }
            }
            SocketAddr::V6(addr) if addr.ip().to_ipv4_mapped().is_some() => {
                if has_v4 {
                    Some(false)
                } else {
                    has_v6.then_some(true)
                }
            }
            SocketAddr::V6(_) => {
                if has_v6 {
                    Some(true)
                } else {
                    has_v4.then_some(false)
                }
            }
        }
    }
}

impl UdpSender for DualStackUdpSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let socket_is_v6 = self.select_family(&transmit.destination).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no socket available for destination address family",
            )
        })?;

        loop {
            let (socket, state, poller) = if socket_is_v6 {
                (
                    self.v6.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 socket unavailable")
                    })?,
                    self.v6_state.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 state unavailable")
                    })?,
                    self.v6_writable.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 poller unavailable")
                    })?,
                )
            } else {
                (
                    self.v4.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 socket unavailable")
                    })?,
                    self.v4_state.as_ref().cloned().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 state unavailable")
                    })?,
                    self.v4_writable.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 poller unavailable")
                    })?,
                )
            };

            match poller.as_mut().poll_writable(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let dest = DualStackSocket::convert_dest(transmit.destination, socket_is_v6)?;
            let converted = Transmit {
                destination: dest,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: DualStackSocket::convert_src_ip(transmit.src_ip, socket_is_v6),
            };
            let res = socket.try_io(Interest::WRITABLE, || {
                state.send(UdpSockRef::from(&*socket), &converted)
            });
            match res {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn max_transmit_segments(&self) -> usize {
        match (&self.v4_state, &self.v6_state) {
            (Some(v4), Some(v6)) => v4.max_gso_segments().min(v6.max_gso_segments()).max(1),
            (Some(v4), None) => v4.max_gso_segments().max(1),
            (None, Some(v6)) => v6.max_gso_segments().max(1),
            (None, None) => 1,
        }
    }
}

// ─── Address conversion helpers ──────────────────────────────────────────────

/// Convert an IPv4 socket address to an IPv4-mapped IPv6 socket address.
fn to_mapped_v6(v4: SocketAddrV4) -> SocketAddrV6 {
    SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)
}

// ─── Factory functions ───────────────────────────────────────────────────────

/// Bound attempts to find a shared OS-assigned port when `port == 0`.
///
/// With `IPV6_V6ONLY=1`, the IPv4 and IPv6 port namespaces are independent, so an
/// ephemeral v6 port may already be taken on v4. Rather than returning a silent
/// v6-only socket or a split-port dual bind (both break advertised `local_addr()`
/// reachability — #246), we drop the pair and retry with a fresh OS port.
const SHARED_PORT_BIND_ATTEMPTS: u32 = 16;

fn is_port_conflict(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::AddrInUse => true,
        // Windows can surface excluded/reserved UDP port conflicts as WSAEACCES
        // (PermissionDenied) rather than WSAEADDRINUSE. Treat that as a conflict
        // for the ephemeral shared-port retry path only.
        #[cfg(windows)]
        io::ErrorKind::PermissionDenied => true,
        _ => false,
    }
}

/// Create a dual-stack socket binding separate IPv4 and IPv6 sockets.
///
/// The IPv6 socket is bound with `IPV6_V6ONLY=1` (pure IPv6, no dual-stack kernel
/// behavior) because we manage the address-family separation ourselves.
///
/// If `port` is 0, the OS assigns a port on IPv6 first and IPv4 reuses it. On an
/// IPv4 port conflict the bind is retried (up to [`SHARED_PORT_BIND_ATTEMPTS`]
/// times) with a fresh OS-assigned port; exhausting retries returns
/// [`io::ErrorKind::AddrInUse`] rather than a silent v6-only socket.
/// If `port` is non-zero, both sockets attempt to bind to that port.
///
/// Gracefully degrades to single-stack if one address family is unavailable
/// (as opposed to a same-port conflict while both families work).
pub fn create_dual_stack_sockets(
    port: u16,
) -> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)> {
    if port == 0 {
        create_dual_stack_sockets_ephemeral()
    } else {
        create_dual_stack_sockets_fixed(port)
    }
}

fn create_dual_stack_sockets_ephemeral()
-> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)> {
    create_dual_stack_sockets_ephemeral_with(create_v6_socket, create_v4_socket)
}

/// Ephemeral shared-port allocator with injectable binders (test seam).
///
/// Production callers use [`create_dual_stack_sockets_ephemeral`]; tests inject an
/// IPv4 binder that fails with [`io::ErrorKind::AddrInUse`] for the first N
/// attempts so conflict → retry → success and retry exhaustion are deterministic.
fn create_dual_stack_sockets_ephemeral_with<V6, V4>(
    mut bind_v6: V6,
    mut bind_v4: V4,
) -> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)>
where
    V6: FnMut(u16) -> io::Result<std::net::UdpSocket>,
    V4: FnMut(u16) -> io::Result<std::net::UdpSocket>,
{
    let mut last_conflict: Option<io::Error> = None;

    for attempt in 0..SHARED_PORT_BIND_ATTEMPTS {
        let v6 = match bind_v6(0) {
            Ok(socket) => socket,
            Err(e) => {
                debug!("IPv6 socket creation failed: {e}");
                // IPv6 unavailable — fall back to IPv4-only.
                return match bind_v4(0) {
                    Ok(v4) => {
                        log_dual_stack_result(Some(&v4), None);
                        Ok((Some(v4), None))
                    }
                    Err(e4) => {
                        debug!("IPv4 socket creation failed: {e4}");
                        Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "failed to bind both IPv4 and IPv6 sockets",
                        ))
                    }
                };
            }
        };

        let assigned = v6.local_addr()?.port();

        match bind_v4(assigned) {
            Ok(v4) => {
                log_dual_stack_result(Some(&v4), Some(&v6));
                return Ok((Some(v4), Some(v6)));
            }
            Err(e) if is_port_conflict(&e) => {
                debug!(
                    "IPv4 bind to shared OS port {assigned} failed ({e}), \
                     retrying fresh dual-stack allocation \
                     (attempt {}/{SHARED_PORT_BIND_ATTEMPTS})",
                    attempt + 1
                );
                last_conflict = Some(e);
                drop(v6);
            }
            Err(e) => {
                // Address family unavailable (not a same-port conflict) — documented
                // single-stack fallback.
                debug!("IPv4 socket creation failed ({e}); returning v6-only");
                log_dual_stack_result(None, Some(&v6));
                return Ok((None, Some(v6)));
            }
        }
    }

    let detail = last_conflict
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown conflict".to_string());
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "failed to bind dual-stack sockets on a shared OS-assigned port \
             after {SHARED_PORT_BIND_ATTEMPTS} attempts: {detail}"
        ),
    ))
}

fn create_dual_stack_sockets_fixed(
    port: u16,
) -> io::Result<(Option<std::net::UdpSocket>, Option<std::net::UdpSocket>)> {
    let v6 = match create_v6_socket(port) {
        Ok(socket) => Some(socket),
        Err(e) => {
            debug!("IPv6 socket creation failed: {e}");
            None
        }
    };

    let v4 = match create_v4_socket(port) {
        Ok(socket) => Some(socket),
        Err(e) => {
            debug!("IPv4 socket creation failed: {e}");
            None
        }
    };

    if v4.is_none() && v6.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "failed to bind both IPv4 and IPv6 sockets",
        ));
    }

    log_dual_stack_result(v4.as_ref(), v6.as_ref());
    Ok((v4, v6))
}

fn log_dual_stack_result(v4: Option<&std::net::UdpSocket>, v6: Option<&std::net::UdpSocket>) {
    let v4_desc = v4
        .and_then(|s| s.local_addr().ok())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    let v6_desc = v6
        .and_then(|s| s.local_addr().ok())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    tracing::info!("Dual-stack sockets: IPv4={v4_desc}, IPv6={v6_desc}");
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

    let addr = SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0);
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

    let addr = SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket.into())
}

/// Fallback socket constructors when `network-discovery` (and thus `socket2`) is off.
///
/// On Unix, `IPV6_V6ONLY` must be set *before* bind: the platform default is often 0,
/// which would make the v6 wildcard also claim the IPv4 port and force every shared
/// bind into a conflict. Windows defaults to `IPV6_V6ONLY=1`, so a plain bind is fine.
#[cfg(all(not(feature = "network-discovery"), unix))]
fn create_v6_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // Prefer atomic close-on-exec at creation time (matches std/socket2). Apple
    // platforms (and other Unixes without `SOCK_CLOEXEC` in libc) fall back to
    // `fcntl(FD_CLOEXEC)` immediately below.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "solaris",
    ))]
    let type_flags = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "solaris",
    )))]
    let type_flags = libc::SOCK_DGRAM;

    // SAFETY: `socket` is a standard POSIX syscall; AF_INET6 / SOCK_DGRAM /
    // IPPROTO_UDP (and SOCK_CLOEXEC where set) are valid type flags. A negative
    // return is converted to `io::Error` before the fd is wrapped.
    let fd = unsafe { libc::socket(libc::AF_INET6, type_flags, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created socket descriptor we exclusively own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Portable close-on-exec: always set via fcntl so platforms that lack atomic
    // SOCK_CLOEXEC (or whose socket() ignores the flag) still get FD_CLOEXEC.
    // SAFETY: `owned` is a live socket fd we exclusively own; F_SETFD with
    // FD_CLOEXEC is a documented fcntl operation on that descriptor.
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: same exclusive fd; only toggling the close-on-exec bit.
        let set =
            unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if set < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let enabled: libc::c_int = 1;
    // SAFETY: `owned` is a live AF_INET6 socket; IPV6_V6ONLY takes a c_int and
    // the pointer/len describe that value for the life of the call.
    let ret = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&raw const enabled).cast::<libc::c_void>(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Zero then assign known fields so targets with extra sockaddr_in6 members
    // (e.g. illumos/Solaris `__sin6_src_id`) still compile and bind correctly.
    // SAFETY: `sockaddr_in6` is a C POD; zeroed bytes are a valid all-zero
    // representation before we overwrite the fields bind requires.
    let mut storage: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        storage.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    }
    storage.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    storage.sin6_port = port.to_be();
    storage.sin6_flowinfo = 0;
    // SAFETY: `in6addr_any` is the immutable IPv6 wildcard constant.
    storage.sin6_addr = unsafe { libc::in6addr_any };
    storage.sin6_scope_id = 0;

    // SAFETY: `owned` is a live AF_INET6 datagram socket; `storage` is a fully
    // initialized sockaddr_in6 whose size matches the socklen passed to bind.
    let bind_ret = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            (&raw const storage).cast::<libc::sockaddr>(),
            std::mem::size_of_val(&storage) as libc::socklen_t,
        )
    };
    if bind_ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(std::net::UdpSocket::from(owned))
}

#[cfg(all(not(feature = "network-discovery"), not(unix)))]
fn create_v6_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    let addr = SocketAddr::from(SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port,
        0,
        0,
    ));
    std::net::UdpSocket::bind(addr)
}

#[cfg(not(feature = "network-discovery"))]
fn create_v4_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    let addr = SocketAddr::from(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port));
    std::net::UdpSocket::bind(addr)
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
    use std::net::Ipv4Addr;

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

    /// Pins that `select_family` routes IPv4-mapped destinations (`::ffff:x.x.x.x`) through the
    /// v4 socket, not the v6 socket. The discriminating assertion is the egress source port: since
    /// the two sender sockets are bound independently (OS assigns ephemeral ports from separate
    /// pools for AF_INET vs AF_INET6), their ports will differ. If `select_family`'s IPv4-mapped
    /// arm is broken — e.g. inverted to route to v6 — the receiver sees the v6 sender port and
    /// the assertion fails with a clear message.
    #[tokio::test]
    async fn test_send_routing_ipv4_mapped() {
        // Create a v4 receiver
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let recv_port = receiver.local_addr().unwrap().port();

        // Create dual-stack socket — await writability before try_send.
        // Bind v4 and v6 independently so they get distinct OS-assigned ports.
        // v6 is bound to [::] (not [::1]) so that under mutation the send to an
        // IPv4-mapped destination succeeds from the v6 socket; the packet arrives at
        // the receiver from a different source port, triggering the discriminating assertion.
        let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        v4.writable().await.unwrap();
        let v6 = tokio::net::UdpSocket::bind("[::]:0").await.unwrap();
        v6.writable().await.unwrap();
        let ds = DualStackSocket::new(Some(v4), Some(v6)).unwrap();

        // Capture sender ports before the sockets are moved into the sender.
        let v4_port = ds.local_addr_v4().unwrap().port();
        let v6_port = ds.local_addr_v6().unwrap().port();
        assert_ne!(
            v4_port, v6_port,
            "test requires distinct v4/v6 sender ports to discriminate egress socket"
        );

        // Send to an IPv4-mapped IPv6 address — select_family must route to the v4 socket.
        let mapped_dest: SocketAddr = format!("[::ffff:127.0.0.1]:{recv_port}").parse().unwrap();
        let transmit = Transmit {
            destination: mapped_dest,
            ecn: None,
            contents: b"hello-v4-mapped",
            segment_size: None,
            src_ip: None,
        };
        let mut sender = ds.create_sender();
        std::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
            .await
            .unwrap();

        // Verify receipt on the v4 receiver and check the egress socket by source port.
        let mut buf = [0u8; 64];
        let mut received = false;
        for _ in 0..50 {
            match receiver.recv_from(&mut buf) {
                Ok((len, sender_addr)) => {
                    assert_eq!(&buf[..len], b"hello-v4-mapped");
                    // The packet must have egressed the v4 socket, not the v6 socket.
                    // Under mutation (IPv4-mapped arm inverted to route to v6), the
                    // source port would be v6_port and this assertion catches it.
                    assert_eq!(
                        sender_addr.port(),
                        v4_port,
                        "reply must egress the v4 socket (port {v4_port}), saw port {} (v6 socket is {v6_port})",
                        sender_addr.port()
                    );
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

    /// Pins that `select_family` routes native IPv6 destinations (`::1`) through the v6 socket.
    /// This test does not carry the egress-port discriminator (that is in
    /// `test_send_routing_ipv4_mapped`); it verifies that a native-v6 send reaches a v6 receiver
    /// at all — covering the `SocketAddr::V6(_)` arm of `select_family`.
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
        let mut sender = ds.create_sender();
        std::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
            .await
            .unwrap();

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

    /// Regression for #246: with `port == 0`, the v6 OS-assigned port must be
    /// reused for the v4 bind so `local_addr()` (which prefers v6) names a port
    /// that the v4 listener actually owns. Without that propagation, dialing
    /// the advertised address over IPv4 never reaches the acceptor.
    #[test]
    fn create_dual_stack_sockets_port_zero_shares_port_across_families() {
        let (v4, v6) = create_dual_stack_sockets(0).unwrap();
        let (Some(v4), Some(v6)) = (v4, v6) else {
            // Single-stack environments (one family unavailable) are fine —
            // there is only one advertised port in that case.
            return;
        };
        let v4_port = v4.local_addr().unwrap().port();
        let v6_port = v6.local_addr().unwrap().port();
        assert_ne!(v4_port, 0);
        assert_ne!(v6_port, 0);
        assert_eq!(
            v4_port, v6_port,
            "v4 and v6 must share the OS-assigned port so advertised local_addr() is reachable on both families"
        );
    }

    /// Occupy an IPv4 port, then prove the shared-port allocator either retries
    /// onto a free shared port with working v4+v6, or returns a clear
    /// [`io::ErrorKind::AddrInUse`] — never a silent v6-only / split-port result.
    ///
    /// Both address families are proven available before the allocator call, so
    /// a single-stack `Ok` is rejected (that would be the #246 silent fallback).
    #[test]
    fn create_dual_stack_sockets_retries_past_occupied_v4_port() {
        let blocker =
            std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let busy_port = blocker.local_addr().unwrap().port();

        // Confirm this platform can express the conflict: v6 binds on `busy_port`
        // while v4 is held (requires IPV6_V6ONLY=1). If not, skip.
        match create_v6_socket(busy_port) {
            Ok(probe) => drop(probe),
            Err(_) => return,
        }

        // Both families work: v4 conflicts on the occupied port, v6 bound above.
        let conflict = create_v4_socket(busy_port);
        assert!(
            conflict.as_ref().err().is_some_and(is_port_conflict),
            "blocker must make IPv4 port {busy_port} conflict, got {conflict:?}"
        );

        match create_dual_stack_sockets(0) {
            Ok((Some(v4), Some(v6))) => {
                let v4_port = v4.local_addr().unwrap().port();
                let v6_port = v6.local_addr().unwrap().port();
                assert_eq!(
                    v4_port, v6_port,
                    "retry must keep a shared port, not degrade to split ports"
                );
                assert_ne!(v4_port, 0);
                assert_ne!(
                    v4_port, busy_port,
                    "shared allocation must not reuse the occupied IPv4 port"
                );

                // Working v4 path: datagram to the shared port must be receivable.
                v4.set_nonblocking(true).unwrap();
                let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                probe
                    .send_to(b"conflict-retry", format!("127.0.0.1:{v4_port}"))
                    .unwrap();
                let mut buf = [0u8; 32];
                let mut got = false;
                for _ in 0..50 {
                    match v4.recv_from(&mut buf) {
                        Ok((n, _)) if &buf[..n] == b"conflict-retry" => {
                            got = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(e) => panic!("v4 recv failed: {e}"),
                    }
                }
                assert!(got, "v4 socket on shared port must receive traffic");

                // Working v6 path on the same port.
                v6.set_nonblocking(true).unwrap();
                let probe_v6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
                probe_v6
                    .send_to(b"conflict-retry-v6", format!("[::1]:{v6_port}"))
                    .unwrap();
                got = false;
                for _ in 0..50 {
                    match v6.recv_from(&mut buf) {
                        Ok((n, _)) if &buf[..n] == b"conflict-retry-v6" => {
                            got = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(e) => panic!("v6 recv failed: {e}"),
                    }
                }
                assert!(got, "v6 socket on shared port must receive traffic");
            }
            Ok((None, Some(_))) | Ok((Some(_), None)) => {
                panic!(
                    "both address families were proven available; \
                     silent single-stack success is the #246 failure mode"
                );
            }
            Ok((None, None)) => panic!("empty Ok from create_dual_stack_sockets"),
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    io::ErrorKind::AddrInUse,
                    "exhausted shared-port retries must surface AddrInUse, got: {e}"
                );
            }
        }
    }

    /// Deterministic conflict → retry → success via an injected IPv4 binder that
    /// fails with AddrInUse on the first attempt, then delegates to the real binder.
    #[test]
    fn create_dual_stack_sockets_conflict_then_retry_succeeds() {
        let mut v4_calls = 0u32;
        let (v4, v6) = create_dual_stack_sockets_ephemeral_with(create_v6_socket, |port| {
            v4_calls += 1;
            if v4_calls == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "injected first-attempt conflict",
                ));
            }
            create_v4_socket(port)
        })
        .expect("allocator must recover after one injected conflict");

        let (Some(v4), Some(v6)) = (v4, v6) else {
            panic!("both families available: must not degrade to single-stack after a conflict");
        };
        assert!(
            v4_calls >= 2,
            "injected conflict must force at least one retry, got {v4_calls} v4 calls"
        );
        let v4_port = v4.local_addr().unwrap().port();
        let v6_port = v6.local_addr().unwrap().port();
        assert_eq!(v4_port, v6_port, "retry must keep a shared port");
        assert_ne!(v4_port, 0);
    }

    /// Deterministic retry exhaustion: IPv4 binder always reports AddrInUse.
    #[test]
    fn create_dual_stack_sockets_retry_exhaustion_returns_addr_in_use() {
        let mut v4_calls = 0u32;
        let err = create_dual_stack_sockets_ephemeral_with(create_v6_socket, |_port| {
            v4_calls += 1;
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "injected persistent conflict",
            ))
        })
        .expect_err("persistent conflict must exhaust retries");

        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        assert!(
            err.to_string()
                .contains(&SHARED_PORT_BIND_ATTEMPTS.to_string()),
            "error should mention attempt budget, got: {err}"
        );
        assert_eq!(
            v4_calls, SHARED_PORT_BIND_ATTEMPTS,
            "every attempt must try the IPv4 binder"
        );
    }

    /// Live occupied-port smoke: fixed-port bind against a busy v4 port, then a
    /// fresh ephemeral allocation must still produce a shared-port dual bind.
    #[test]
    fn create_dual_stack_sockets_shared_port_conflict_then_ephemeral_ok() {
        let blocker =
            std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let busy_port = blocker.local_addr().unwrap().port();

        // Direct fixed-port attempt: v6 may bind, v4 conflicts → single-stack or
        // dual failure is fine for a *requested* busy port; the ephemeral path
        // below is what must recover. (Whether fixed-port should error instead
        // of silent v6-only is deferred — see QUESTIONS.md.)
        let _ = create_dual_stack_sockets(busy_port);

        let (v4, v6) = match create_dual_stack_sockets(0) {
            Ok(pair) => pair,
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "{e}");
                return;
            }
        };
        let (Some(v4), Some(v6)) = (v4, v6) else {
            // Only acceptable if this host cannot bind both families at all.
            // The injected-binder tests above cover the dual-stack contract.
            return;
        };
        let v4_port = v4.local_addr().unwrap().port();
        let v6_port = v6.local_addr().unwrap().port();
        assert_eq!(v4_port, v6_port, "ephemeral allocation must share a port");
        assert_ne!(v4_port, busy_port);
    }

    /// Dual-stack UDP sockets must be close-on-exec so exec'd children cannot
    /// inherit the listener and hold the port after endpoint shutdown.
    #[cfg(unix)]
    #[test]
    fn create_dual_stack_sockets_set_close_on_exec() {
        use std::os::fd::AsRawFd;

        let (v4, v6) = create_dual_stack_sockets(0).expect("bind dual-stack");
        assert!(v4.is_some() || v6.is_some());

        for (label, sock) in [("v4", v4.as_ref()), ("v6", v6.as_ref())] {
            let Some(sock) = sock else {
                continue;
            };
            // SAFETY: sock is a live UdpSocket; F_GETFD is valid on its fd.
            let flags = unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_GETFD) };
            assert!(
                flags >= 0,
                "{label}: F_GETFD failed: {}",
                io::Error::last_os_error()
            );
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "{label}: FD_CLOEXEC must be set (flags={flags:#x})"
            );
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

    // ─── Inbound reply path (ant-quic #234/#235) ─────────────────────────────
    //
    // Field failure: host B dials host A over IPv4 on a shared LAN. A binds true
    // dual-stack, so A's endpoint reports `local_addr() == [::]:port` and runs
    // with `ipv6 = true`; every peer address A handles is therefore the
    // IPv4-mapped form `[::ffff:192.168.1.108]:port`. B's packets kept arriving
    // at A for minutes, but no application data A sent ever reached B.
    //
    // The two tests below pin the invariants that inbound replies depend on.

    /// A datagram received on the IPv4 socket must be answered *from* the IPv4
    /// socket.
    ///
    /// This mirrors what the QUIC endpoint does: it takes the peer address
    /// `poll_recv` reports (handed back IPv4-mapped) and feeds that same address
    /// straight back as a `Transmit` destination. If the wrapper routed that
    /// mapped address to the IPv6 socket, a native-IPv4 peer would never see the
    /// reply — the field symptom.
    /// Pins that `select_family` routes IPv4-mapped destinations back through the v4 socket.
    ///
    /// The sockets are bound independently (not via `create_dual_stack_sockets(0)`, which
    /// co-allocates both to the same port) so that the OS assigns each a distinct ephemeral
    /// port. The final assertion checks the source port: under the mutation that inverts the
    /// v4-mapped arm of `select_family` to route to the v6 socket, the receiver sees the v6
    /// port and the assertion fails with a clear message. Without distinct ports the assertion
    /// is non-discriminating (both sockets share the same port).
    #[tokio::test]
    async fn reply_to_v4_mapped_peer_egresses_from_the_v4_socket() {
        // Independent binds → OS assigns separate ephemeral ports to AF_INET and AF_INET6.
        let v4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_v4_port = v4.local_addr().unwrap().port();
        // v6 is bound to [::] (not [::1]) so that under mutation the send to an
        // IPv4-mapped destination succeeds from the v6 socket; the packet then arrives
        // from the v6 source port, triggering the discriminating port assertion.
        let v6 = std::net::UdpSocket::bind("[::]:0").unwrap();
        let listener_v6_port = v6.local_addr().unwrap().port();
        assert_ne!(
            listener_v4_port, listener_v6_port,
            "test requires distinct v4/v6 listener ports to discriminate egress socket"
        );

        let dual = wrap_dual_stack(Some(v4), Some(v6)).expect("wrap dual-stack");

        // Stand in for the remote LAN host: a plain IPv4 socket that knows
        // nothing about IPv6, dialling the listener's IPv4 port as host B did.
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        peer.send_to(b"dial", (Ipv4Addr::LOCALHOST, listener_v4_port))
            .unwrap();

        let mut buf = [0u8; 512];
        let mut bufs = [IoSliceMut::new(&mut buf)];
        let mut meta = [RecvMeta::default()];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| dual.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("listener should receive the dial")
        .expect("poll_recv should succeed");
        assert_eq!(n, 1);

        // The wrapper reports the peer IPv4-mapped because the endpoint believes
        // it owns an IPv6 socket. This is the address the connection records as
        // its remote, and the address every reply is sent to.
        let learned_peer = meta[0].addr;
        assert!(
            matches!(learned_peer, SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_some()),
            "peer learned on the v4 socket should be reported IPv4-mapped, got {learned_peer}"
        );
        assert_eq!(learned_peer.port(), peer_port);

        let transmit = Transmit {
            destination: learned_peer,
            ecn: None,
            contents: b"reply",
            segment_size: None,
            src_ip: None,
        };
        let mut sender = dual.create_sender();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx)),
        )
        .await
        .expect("send should not stall")
        .expect("send should succeed");

        // The native-IPv4 peer must see it, and must see it from the listener's
        // IPv4 address — not from an IPv6 source it never talked to.
        let mut reply = [0u8; 512];
        let (len, src) = peer
            .recv_from(&mut reply)
            .expect("native-IPv4 peer must receive the reply; a v6 egress black-holes it");
        assert_eq!(&reply[..len], b"reply");
        assert_eq!(
            src,
            SocketAddr::from((Ipv4Addr::LOCALHOST, listener_v4_port)),
            "reply must egress the v4 socket (port {listener_v4_port}), saw port {} \
             (v6 socket is {listener_v6_port}); check select_family's IPv4-mapped arm",
            src.port()
        );
    }

    /// An inbound IPv4 connection into a true-dual-stack listener must carry
    /// application data back to the dialer.
    ///
    /// The field failure completed its handshake and reached Live on both hosts,
    /// then black-holed every server->client byte, so this asserts on delivered
    /// stream payload in the server->client direction. A connect-only assertion
    /// would have stayed green throughout the outage.
    /// Pins that an inbound IPv4 QUIC connection delivers server→client stream data.
    ///
    /// Uses distinct v4/v6 listener ports (independent binds, not `create_dual_stack_sockets(0)`)
    /// so that if `select_family`'s IPv4-mapped arm routes replies to the v6 socket, the QUIC
    /// client sees packets from an unexpected source and the connection/read fails.
    #[tokio::test]
    async fn inbound_ipv4_connection_delivers_server_to_client_data() {
        use crate::config::{ClientConfig, EndpointConfig, ServerConfig};
        use crate::high_level::{Endpoint, TokioRuntime};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Independent binds ensure v4 and v6 get distinct OS-assigned ports.
        // v6 is bound to [::] so that under mutation the v6 socket can reach IPv4-mapped
        // destinations; distinct ports cause QUIC to reject the mis-routed packets.
        let v4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_v4_port = v4.local_addr().unwrap().port();
        let v6 = std::net::UdpSocket::bind("[::]:0").unwrap();
        let listener_v6_port = v6.local_addr().unwrap().port();
        assert_ne!(
            listener_v4_port, listener_v6_port,
            "test requires distinct v4/v6 listener ports to discriminate egress socket"
        );
        let _ = listener_v6_port; // captured for the assert_ne; QUIC discriminates through peer mismatch

        let dual: Arc<dyn AsyncUdpSocket> =
            Arc::new(wrap_dual_stack(Some(v4), Some(v6)).expect("wrap dual-stack"));

        // Precondition that makes this test meaningful: the endpoint must
        // believe it is IPv6, which is what forces every peer address through
        // the IPv4-mapped representation.
        assert!(
            dual.local_addr().unwrap().is_ipv6(),
            "true dual-stack listener must report an IPv6 local_addr"
        );

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let chain = vec![cert_der];
        let server_cfg =
            ServerConfig::with_single_cert(chain.clone(), key_der).expect("server config");

        let server_ep = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_cfg),
            dual,
            Arc::new(TokioRuntime),
        )
        .expect("dual-stack server endpoint");

        // The server echoes on a bidirectional stream; everything it writes
        // travels in the direction that died in the field.
        let server = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("server handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("server accept_bi");
            let got = recv.read_to_end(64).await.expect("server read");
            assert_eq!(got, b"ping");
            send.write_all(b"pong").await.expect("server write");
            send.finish().expect("server finish");
            // Hold the connection open until the client has drained the reply:
            // dropping here could close before delivery and mask a real failure
            // as a clean shutdown.
            conn.closed().await;
        });

        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).expect("add server cert to roots");
        }
        let client_cfg =
            ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");

        // The dialer is plain IPv4, exactly like the LAN host in the field report.
        let mut client_ep =
            Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
        client_ep.set_default_client_config(client_cfg);

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_ep
                .connect((Ipv4Addr::LOCALHOST, listener_v4_port).into(), "localhost")
                .expect("start connect"),
        )
        .await
        .expect("handshake must not stall")
        .expect("client connected");

        let (mut send, mut recv) = conn.open_bi().await.expect("client open_bi");
        send.write_all(b"ping").await.expect("client write");
        send.finish().expect("client finish");

        // The assertion the field bug fails: handshake succeeded, but no server
        // payload ever arrived.
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_to_end(64))
            .await
            .expect("server->client data must arrive on an inbound dual-stack connection")
            .expect("client read");
        assert_eq!(
            echoed, b"pong",
            "server reply must reach the IPv4 dialer intact"
        );

        conn.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    /// The exact field topology: *both* peers bind true dual-stack, and the
    /// dialer reaches the listener over IPv4.
    ///
    /// This differs from the test above in that the dialer's endpoint also
    /// reports an IPv6 `local_addr`, so both sides record the peer in
    /// IPv4-mapped form and both must route their sends back down to the IPv4
    /// socket. Host A and host B were both dual-stack in the field, so this is
    /// the configuration that actually failed.
    /// Pins the field topology: both peers true dual-stack, dial over IPv4.
    ///
    /// Uses distinct v4/v6 ports per peer (independent binds, not `create_dual_stack_sockets(0)`)
    /// so that the mutation — routing IPv4-mapped sends to the v6 socket — produces packets from
    /// an unexpected source port, causing QUIC to reject them and the test to fail.
    #[tokio::test]
    async fn dual_stack_peers_exchange_data_over_an_ipv4_dial() {
        use crate::config::{ClientConfig, EndpointConfig, ServerConfig};
        use crate::high_level::{Endpoint, TokioRuntime};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Independent binds ensure v4 and v6 get distinct OS-assigned ports per endpoint.
        let make_dual = || {
            let v4 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4");
            let v4_port = v4.local_addr().unwrap().port();
            let v6 = std::net::UdpSocket::bind("[::]:0").expect("bind v6");
            let v6_port = v6.local_addr().unwrap().port();
            assert_ne!(
                v4_port, v6_port,
                "test requires distinct v4/v6 ports to discriminate egress socket"
            );
            let socket: Arc<dyn AsyncUdpSocket> =
                Arc::new(wrap_dual_stack(Some(v4), Some(v6)).expect("wrap dual-stack"));
            (socket, v4_port)
        };

        let (server_socket, server_v4_port) = make_dual();
        let (client_socket, _client_v4_port) = make_dual();
        assert!(server_socket.local_addr().unwrap().is_ipv6());
        assert!(client_socket.local_addr().unwrap().is_ipv6());

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let chain = vec![cert_der];
        let server_cfg =
            ServerConfig::with_single_cert(chain.clone(), key_der).expect("server config");

        let server_ep = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_cfg),
            server_socket,
            Arc::new(TokioRuntime),
        )
        .expect("dual-stack server endpoint");

        let server = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("server handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("server accept_bi");
            let got = recv.read_to_end(64).await.expect("server read");
            assert_eq!(got, b"ping");
            send.write_all(b"pong").await.expect("server write");
            send.finish().expect("server finish");
            conn.closed().await;
        });

        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).expect("add server cert to roots");
        }
        let client_cfg =
            ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");

        let mut client_ep = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            client_socket,
            Arc::new(TokioRuntime),
        )
        .expect("dual-stack client endpoint");
        client_ep.set_default_client_config(client_cfg);

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_ep
                .connect((Ipv4Addr::LOCALHOST, server_v4_port).into(), "localhost")
                .expect("start connect"),
        )
        .await
        .expect("handshake must not stall")
        .expect("client connected");

        let (mut send, mut recv) = conn.open_bi().await.expect("client open_bi");
        send.write_all(b"ping").await.expect("client write");
        send.finish().expect("client finish");

        let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_to_end(64))
            .await
            .expect("server->client data must arrive between two dual-stack peers")
            .expect("client read");
        assert_eq!(echoed, b"pong");

        conn.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }
}
