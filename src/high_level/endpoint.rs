// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    io::IoSliceMut,
    mem,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

#[cfg(not(wasm_browser))]
use super::runtime::default_runtime;
use super::{
    runtime::{AsyncUdpSocket, Runtime},
    udp_transmit,
};
use crate::{
    ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent, EndpointEvent,
    ServerConfig,
};
use crate::{Duration, Instant};
use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use quinn_udp::{BATCH_SIZE, RecvMeta};
use rustc_hash::FxHashMap;
#[cfg(all(not(wasm_browser), feature = "network-discovery"))]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, futures::Notified, mpsc};
use tracing::{Instrument, Span, debug, error};

use super::{
    ConnectionEvent, IO_LOOP_BOUND, RECV_TIME_BOUND, connection::Connecting,
    work_limiter::WorkLimiter,
};
use crate::{EndpointConfig, VarInt};

/// Transient per-datagram socket errors that must NOT terminate the endpoint
/// driver (x0x issue #262).
///
/// On Linux, an unconnected UDP socket surfaces asynchronous ICMP errors
/// (host/net unreachable, port unreachable) as a pending socket error on the
/// next `recvmsg` — i.e. one unreachable *peer* manifests as a recv error on
/// the *shared* socket. Terminating the driver on such an error kills all
/// QUIC I/O for the process: `driver_lost` makes every future `connect()`
/// fail synchronously and nothing polls the socket again, while the host
/// process stays alive. A production bootstrap node sat in exactly that
/// wedged state for 14+ hours. These errors are scoped to a single datagram
/// exchange: drop it and keep polling.
///
/// Raw errnos cover platform gaps in `io::ErrorKind` mapping: 49
/// (EADDRNOTAVAIL, macOS), 51/65 (ENETUNREACH/EHOSTUNREACH, macOS),
/// 101/113 (ENETUNREACH/EHOSTUNREACH, Linux).
fn is_transient_socket_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    ) || matches!(error.raw_os_error(), Some(49 | 51 | 65 | 101 | 113))
}

/// `EndpointRef`s held by driver infrastructure rather than user-visible
/// handles (issue #220).
///
/// `ref_count` tracks `EndpointRef::clone()` calls, so it is always one less
/// than the number of live refs (the root ref from `EndpointRef::new` is
/// never counted). The supervisor task holds one counted clone for the
/// endpoint's whole lifetime, so when the user drops their last handle
/// `ref_count` falls to `DRIVER_INFRA_REFS` — the supervisor's ref plus the
/// driver's own. That is the driver's cue to shut down (see
/// `EndpointDriver::poll` and `EndpointRef::drop`).
const DRIVER_INFRA_REFS: usize = 1;

/// Initial delay before respawning a fatally terminated endpoint driver
/// (issue #220). Doubles on each consecutive quick failure, capped at
/// [`DRIVER_RESPAWN_MAX_BACKOFF`]; a driver that stayed up for at least
/// [`DRIVER_RESPAWN_HEALTHY_RUN`] resets the backoff to this value.
const DRIVER_RESPAWN_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
/// Upper bound on the driver respawn backoff (issue #220), so a permanently
/// broken socket is retried slowly instead of hot-looping.
const DRIVER_RESPAWN_MAX_BACKOFF: Duration = Duration::from_secs(5);
/// How long a driver must stay up for its death to count as a fresh failure
/// rather than a crash loop (issue #220).
const DRIVER_RESPAWN_HEALTHY_RUN: Duration = Duration::from_secs(30);

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: Option<ClientConfig>,
    runtime: Arc<dyn Runtime>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 addresses. As such, calling `Endpoint::client` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to connect to other
    /// address. For example:
    ///
    /// ```
    /// # use std::net::{Ipv6Addr, SocketAddr};
    /// # fn example() -> std::io::Result<()> {
    /// use ant_quic::high_level::Endpoint;
    ///
    /// let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
    /// let endpoint = Endpoint::client(addr)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// client will only be able to connect to IPv6 servers. An IPv4 client is never dual-stack.
    #[cfg(all(not(wasm_browser), feature = "network-discovery"))]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                tracing::debug!(%e, "unable to make socket dual-stack");
            }
        }

        // Apply platform-appropriate buffer sizes to avoid WSAEMSGSIZE errors on Windows
        // and ensure reliable QUIC connections, especially with PQC
        use crate::config::buffer_defaults;
        let buffer_size = buffer_defaults::PLATFORM_DEFAULT;
        if let Err(e) = socket.set_send_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set send buffer size to {}", buffer_size);
        }
        if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set recv buffer size to {}", buffer_size);
        }

        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Helper to construct an endpoint for use with outgoing connections only
    /// (fallback without network-discovery feature)
    #[cfg(all(not(wasm_browser), not(feature = "network-discovery")))]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Returns relevant stats from this Endpoint
    pub fn stats(&self) -> EndpointStats {
        self.inner
            .state
            .lock()
            .map(|state| state.stats)
            .unwrap_or_else(|_| {
                error!("Endpoint state mutex poisoned");
                EndpointStats::default()
            })
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// When binding to an IPv6 address, this creates a dual-stack socket (IPV6_V6ONLY=0)
    /// that can accept both IPv4 and IPv6 connections. IPv4 connections will appear as
    /// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. This method explicitly enables dual-stack for IPv6 sockets.
    #[cfg(all(not(wasm_browser), feature = "network-discovery"))]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

        // Enable dual-stack for IPv6 sockets (consistent with client() behavior)
        if addr.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                tracing::debug!(%e, "unable to make server socket dual-stack");
            }
        }

        socket.set_nonblocking(true)?;

        // Apply platform-appropriate buffer sizes to avoid WSAEMSGSIZE errors on Windows
        // and ensure reliable QUIC connections, especially with PQC
        use crate::config::buffer_defaults;
        let buffer_size = buffer_defaults::PLATFORM_DEFAULT;
        if let Err(e) = socket.set_send_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set send buffer size to {}", buffer_size);
        }
        if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
            tracing::debug!(%e, "unable to set recv buffer size to {}", buffer_size);
        }

        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    /// (fallback without network-discovery feature)
    #[cfg(all(not(wasm_browser), not(feature = "network-discovery")))]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    #[cfg(not(wasm_browser))]
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket(config, server_config, socket, runtime)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        let allow_mtud = !socket.may_fragment();
        let rc = EndpointRef::new(
            socket,
            crate::endpoint::Endpoint::new(
                Arc::new(config),
                server_config.map(Arc::new),
                allow_mtud,
                None,
            ),
            addr.is_ipv6(),
            runtime.clone(),
        );
        spawn_supervised_driver(rc.clone(), runtime.clone());
        Ok(Self {
            inner: rc,
            default_client_config: None,
            runtime,
        })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields `Incoming`s, or `None` if the endpoint is [`close`](Self::close)d. `Incoming`
    /// can be `await`ed to obtain the final [`Connection`](crate::Connection), or used to e.g.
    /// filter connection attempts or force address validation, or converted into an intermediate
    /// `Connecting` future which can be used to e.g. send 0.5-RTT data.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&mut self, config: ClientConfig) {
        self.default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let config = match &self.default_client_config {
            Some(config) => config.clone(),
            None => return Err(ConnectError::NoDefaultClientConfig),
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self
            .inner
            .state
            .lock()
            .map_err(|_| ConnectError::EndpointStopping)?;
        if endpoint.driver_lost || endpoint.recv_state.connections.close.is_some() {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = endpoint
            .inner
            .connect(self.runtime.now(), config, addr, server_name)?;

        let socket = endpoint.socket.clone();
        endpoint.stats.outgoing_handshakes += 1;
        Ok(endpoint
            .recv_state
            .connections
            .insert(ch, conn, socket, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// See [`Endpoint::rebind_abstract()`] for details.
    #[cfg(not(wasm_browser))]
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(self.runtime.wrap_udp_socket(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind_abstract(&self, socket: Arc<dyn AsyncUdpSocket>) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let mut inner = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Endpoint state mutex poisoned"))?;
        inner.prev_socket = Some(mem::replace(&mut inner.socket, socket));
        inner.ipv6 = addr.is_ipv6();

        // Update connection socket references
        let socket = inner.socket.clone();
        inner
            .recv_state
            .connections
            .broadcast_control(move || ConnectionEvent::Rebind(socket.clone()));

        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.inner.set_server_config(server_config.map(Arc::new));
        } else {
            error!("Failed to set server config: endpoint state mutex poisoned");
        }
    }

    /// Register a peer ID for an existing connection, enabling PUNCH_ME_NOW relay
    /// routing by peer identity instead of socket address.
    pub fn register_connection_peer_id(
        &self,
        addr: SocketAddr,
        peer_id: crate::nat_traversal_api::PeerId,
    ) {
        if let Ok(mut state) = self.inner.state.lock() {
            let handle = state.inner.connection_handle_for_addr(&addr);
            if let Some(ch) = handle {
                state.inner.set_connection_peer_id(ch, peer_id);
                tracing::info!(
                    "Registered peer ID {} for connection {} at low-level endpoint",
                    hex::encode(&peer_id.0[..8]),
                    addr
                );
            } else {
                tracing::debug!(
                    "No connection handle found for {} — peer ID not registered",
                    addr
                );
            }
        }
    }

    /// Set the channel for forwarding peer address updates to the upper layer.
    pub fn set_peer_address_update_tx(&self, tx: mpsc::UnboundedSender<(SocketAddr, SocketAddr)>) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.peer_address_update_tx = Some(tx);
        }
    }

    /// Get the remote address of a peer's connection by peer ID.
    pub fn peer_connection_addr_by_id(&self, peer_id: &[u8; 32]) -> Option<SocketAddr> {
        let state = self.inner.state.lock().ok()?;
        let pid = crate::nat_traversal_api::PeerId(*peer_id);
        state.inner.peer_connection_addr(&pid)
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Endpoint state mutex poisoned"))?
            .socket
            .local_addr()
    }

    /// Replace the endpoint's UDP socket with an ephemeral loopback socket.
    ///
    /// This is used during explicit shutdown to synchronously release the
    /// externally visible bind port while the `Endpoint` handle itself may stay
    /// alive in an embedding process. Unlike `rebind_abstract`, this deliberately
    /// clears `prev_socket` so the old socket is dropped immediately rather than
    /// retained until migration traffic arrives on the replacement socket.
    ///
    /// The replaced socket(s) are returned so the caller can wait out any
    /// remaining `Arc` clones (held by live connection driver tasks and the
    /// senders built from the socket) before reporting shutdown complete —
    /// the OS file descriptor stays open until the last clone drops (issue
    /// #199). Returns an empty `Vec` when the socket was already released.
    #[cfg(not(wasm_browser))]
    pub(crate) fn release_socket_for_shutdown(&self) -> io::Result<Vec<Arc<dyn AsyncUdpSocket>>> {
        let (old_addr, runtime) = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| io::Error::other("Endpoint state mutex poisoned"))?;
            if state.socket_released_for_shutdown {
                return Ok(Vec::new());
            }
            (state.socket.local_addr()?, state.runtime.clone())
        };

        let replacement_addr = if old_addr.is_ipv6() {
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0))
        } else {
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))
        };

        let replacement = std::net::UdpSocket::bind(replacement_addr).or_else(|first_error| {
            if old_addr.is_ipv6() {
                let fallback_addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
                std::net::UdpSocket::bind(fallback_addr)
            } else {
                Err(first_error)
            }
        })?;
        replacement.set_nonblocking(true)?;
        let replacement = runtime.wrap_udp_socket(replacement)?;
        let replacement_addr = replacement.local_addr()?;

        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Endpoint state mutex poisoned"))?;
        if state.socket_released_for_shutdown {
            return Ok(Vec::new());
        }
        let mut released = Vec::with_capacity(2);
        released.push(mem::replace(&mut state.socket, replacement));
        if let Some(prev_socket) = state.prev_socket.take() {
            released.push(prev_socket);
        }
        state.ipv6 = replacement_addr.is_ipv6();
        state.socket_released_for_shutdown = true;

        Ok(released)
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner
            .state
            .lock()
            .map(|state| state.inner.open_connections())
            .unwrap_or(0)
    }

    /// Set the maximum number of simultaneously live connections the endpoint
    /// will accept. New incoming connections are refused past this cap (x0x#278).
    pub fn set_max_connections(&self, max: usize) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.recv_state.connections.max_connections = max.max(1);
        }
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = match self.inner.state.lock() {
            Ok(endpoint) => endpoint,
            Err(_) => {
                error!("Failed to close endpoint: state mutex poisoned");
                return;
            }
        };
        // Record the close so new connection attempts are rejected, `accept`
        // drains, and the driver supervisor treats a driver exit as
        // intentional rather than respawning it (issue #220).
        endpoint.recv_state.connections.close = Some((error_code, reason.clone()));
        endpoint
            .recv_state
            .connections
            .broadcast_control(move || ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        self.inner.shared.incoming.notify_waiters();
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = match self.inner.state.lock() {
                    Ok(endpoint) => endpoint,
                    Err(_) => {
                        error!("Failed to wait for idle: state mutex poisoned");
                        break;
                    }
                };
                if endpoint.recv_state.connections.is_empty() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
    }
}

/// Statistics on [Endpoint] activity
#[non_exhaustive]
#[derive(Debug, Default, Copy, Clone)]
pub struct EndpointStats {
    /// Cummulative number of Quic handshakes accepted by this [Endpoint]
    pub accepted_handshakes: u64,
    /// Cummulative number of Quic handshakees sent from this [Endpoint]
    pub outgoing_handshakes: u64,
    /// Cummulative number of Quic handshakes refused on this [Endpoint]
    pub refused_handshakes: u64,
    /// Cummulative number of Quic handshakes ignored on this [Endpoint]
    pub ignored_handshakes: u64,
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs. A fatal exit is not terminal for the endpoint: the
/// supervisor that spawned the driver (see [`spawn_supervised_driver`])
/// observes the exit, rebinds the socket, and respawns the driver (issue
/// #220), so a fatal-class socket error no longer permanently ends QUIC I/O
/// for a live process.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut endpoint = match self.0.state.lock() {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other("Endpoint state mutex poisoned")));
            }
        };
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let now = endpoint.runtime.now();
        let mut keep_going = false;
        keep_going |= endpoint.drive_recv(cx, now)?;
        keep_going |= endpoint.handle_events(cx, &self.0.shared);

        if !endpoint.recv_state.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        if endpoint.ref_count == DRIVER_INFRA_REFS && endpoint.recv_state.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        if let Ok(mut endpoint) = self.0.state.lock() {
            // The stored waker belongs to this dead driver; a respawned
            // driver must register a fresh one (issue #220).
            endpoint.driver = None;
            if endpoint.recv_state.connections.close.is_some() {
                // Intentional close: terminal teardown, and quiet by design
                // (x0x issue #262) — nothing will respawn this driver.
                endpoint.driver_lost = true;
                // Drop all outgoing channels, signaling the termination of the endpoint to the associated
                // connections.
                endpoint.recv_state.connections.senders.clear();
            } else {
                // Supervised (issue #220): the supervisor observes this exit
                // and respawns the driver. Connections and `driver_lost`
                // stay untouched so live connections ride out the respawn
                // instead of being torn down. The supervisor logs the fatal
                // error itself; keep this at debug to avoid double-logging
                // on every respawn cycle.
                debug!("endpoint driver exited without close; supervisor will respawn it");
            }
            self.0.shared.incoming.notify_waiters();
        } else {
            error!("Failed to lock endpoint state in drop - mutex poisoned");
        }
    }
}

/// Spawn the endpoint driver under a supervisor that respawns it after a
/// fatal exit (issue #220).
///
/// A fatal driver exit used to be terminal for the process's QUIC I/O:
/// `driver_lost` failed every future `connect()` and the socket was never
/// polled again, with recovery only via process restart (x0x issue #262 hid
/// that wedge for 14h at debug level). The supervisor instead logs the fatal
/// error, waits out an exponential backoff, rebinds the socket on a
/// best-effort basis, and spawns a fresh driver. Live connections survive:
/// the dead driver's `Drop` leaves their channels in place and the rebind
/// migrates them onto the new socket, exactly like [`Endpoint::rebind`].
///
/// The loop ends when the driver exits cleanly (every `Endpoint` handle and
/// connection is gone) or when the endpoint was closed intentionally — a
/// close must never resurrect I/O.
///
/// `rc` is the one infrastructure-held [`EndpointRef`] accounted for by
/// [`DRIVER_INFRA_REFS`]; the supervisor holds it for the endpoint's whole
/// lifetime so `ref_count` only ever reflects user-visible handles.
fn spawn_supervised_driver(rc: EndpointRef, runtime: Arc<dyn Runtime>) {
    let task_runtime = runtime.clone();
    runtime.spawn(Box::pin(
        async move {
            let mut backoff = DRIVER_RESPAWN_INITIAL_BACKOFF;
            loop {
                let started = task_runtime.now();
                let result = EndpointDriver(rc.clone()).await;
                let Err(error) = result else {
                    // Clean exit: no live handles or connections remain, so
                    // there is nothing left to drive.
                    return;
                };
                let closed = match rc.state.lock() {
                    // An explicit shutdown releases the socket without
                    // recording a close reason; both are deliberate, so
                    // neither may be resurrected by a respawn.
                    Ok(state) => {
                        state.recv_state.connections.close.is_some()
                            || state.socket_released_for_shutdown
                    }
                    Err(_) => {
                        error!(
                            "endpoint driver terminated ({error}) and the state mutex is poisoned; \
                             not respawning"
                        );
                        return;
                    }
                };
                if closed {
                    debug!("endpoint driver terminated after intentional close: {error}");
                    return;
                }
                // Anything reaching here is fatal and must stay loud (x0x
                // issue #262): unlike the pre-supervisor behavior the
                // transport recovers, but operators still need the failures
                // in their logs.
                error!("endpoint driver terminated: {error} — respawning in {backoff:?}");
                if task_runtime.now() >= started + DRIVER_RESPAWN_HEALTHY_RUN {
                    // The driver had a healthy run; treat this as a fresh
                    // failure rather than a crash loop.
                    backoff = DRIVER_RESPAWN_INITIAL_BACKOFF;
                }
                sleep_for(&*task_runtime, backoff).await;
                backoff = (backoff * 2).min(DRIVER_RESPAWN_MAX_BACKOFF);
                // An intentional close or shutdown can land during the
                // backoff sleep; respawning past it would resurrect a
                // deliberately released socket.
                let closed_during_backoff = match rc.state.lock() {
                    Ok(state) => {
                        state.recv_state.connections.close.is_some()
                            || state.socket_released_for_shutdown
                    }
                    Err(_) => true,
                };
                if closed_during_backoff {
                    debug!("endpoint driver not respawned: endpoint closed during backoff");
                    return;
                }
                #[cfg(not(wasm_browser))]
                rebind_for_respawn(&rc, &*task_runtime);
            }
        }
        .instrument(Span::current()),
    ));
}

/// Runtime-agnostic sleep used for the driver respawn backoff.
async fn sleep_for(runtime: &dyn Runtime, duration: Duration) {
    let mut timer = runtime.new_timer(runtime.now() + duration);
    std::future::poll_fn(|cx| timer.as_mut().poll(cx)).await;
}

/// Best-effort socket replacement before a driver respawn (issue #220).
///
/// A fatal driver exit usually means the socket itself is broken (e.g. its
/// fd was closed from under us), so bind a fresh socket on the same local
/// address and swap it in, migrating live connections via the same
/// `ConnectionEvent::Rebind` broadcast as [`Endpoint::rebind_abstract`]. If
/// the old socket still owns the address the bind fails and we keep it — the
/// respawned driver either recovers on it or fails again under backoff.
#[cfg(not(wasm_browser))]
fn rebind_for_respawn(rc: &EndpointRef, runtime: &dyn Runtime) {
    let old_addr = match rc.state.lock() {
        Ok(state) => match state.socket.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                debug!("driver respawn: old socket address unreadable ({e}); keeping old socket");
                return;
            }
        },
        Err(_) => {
            error!("endpoint state mutex poisoned; cannot rebind for driver respawn");
            return;
        }
    };
    let socket = match bind_replacement_socket(old_addr)
        .and_then(|socket| runtime.wrap_udp_socket(socket))
    {
        Ok(socket) => socket,
        Err(e) => {
            debug!("driver respawn: rebind to {old_addr} failed ({e}); keeping old socket");
            return;
        }
    };
    let mut state = match rc.state.lock() {
        Ok(state) => state,
        Err(_) => {
            error!("endpoint state mutex poisoned; cannot rebind for driver respawn");
            return;
        }
    };
    state.prev_socket = Some(mem::replace(&mut state.socket, socket));
    state.ipv6 = old_addr.is_ipv6();
    let socket = state.socket.clone();
    state
        .recv_state
        .connections
        .broadcast_control(move || ConnectionEvent::Rebind(socket.clone()));
    tracing::info!("endpoint driver respawn rebound socket on {old_addr}");
}

/// Bind a fresh UDP socket on `addr` to replace a broken one, mirroring
/// [`Endpoint::server`]: dual-stack where possible, platform buffer sizes.
#[cfg(all(not(wasm_browser), feature = "network-discovery"))]
fn bind_replacement_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        if let Err(e) = socket.set_only_v6(false) {
            debug!(%e, "unable to make replacement socket dual-stack");
        }
    }
    socket.set_nonblocking(true)?;

    use crate::config::buffer_defaults;
    let buffer_size = buffer_defaults::PLATFORM_DEFAULT;
    if let Err(e) = socket.set_send_buffer_size(buffer_size) {
        debug!(%e, "unable to set send buffer size on replacement socket");
    }
    if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
        debug!(%e, "unable to set recv buffer size on replacement socket");
    }

    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Bind a fresh UDP socket on `addr` to replace a broken one (fallback
/// without the `network-discovery` feature).
#[cfg(all(not(wasm_browser), not(feature = "network-discovery")))]
fn bind_replacement_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl EndpointInner {
    pub(crate) fn accept(
        &self,
        incoming: crate::Incoming,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let mut state = self.state.lock().map_err(|_| {
            ConnectionError::TransportError(crate::transport_error::Error::INTERNAL_ERROR(
                "Endpoint state mutex poisoned".to_string(),
            ))
        })?;
        let mut response_buffer = Vec::new();
        let now = state.runtime.now();
        match state
            .inner
            .accept(incoming, now, &mut response_buffer, server_config)
        {
            Ok((handle, conn)) => {
                state.stats.accepted_handshakes += 1;
                let socket = state.socket.clone();
                let runtime = state.runtime.clone();
                Ok(state
                    .recv_state
                    .connections
                    .insert(handle, conn, socket, runtime))
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    respond(transmit, &response_buffer, &*state.socket);
                }
                Err(error.cause)
            }
        }
    }

    pub(crate) fn refuse(&self, incoming: crate::Incoming) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                error!("Failed to refuse connection: endpoint state mutex poisoned");
                return;
            }
        };
        state.stats.refused_handshakes += 1;
        let mut response_buffer = Vec::new();
        let transmit = state.inner.refuse(incoming, &mut response_buffer);
        respond(transmit, &response_buffer, &*state.socket);
    }

    pub(crate) fn retry(
        &self,
        incoming: crate::Incoming,
    ) -> Result<(), crate::endpoint::RetryError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                error!("Failed to retry connection: endpoint state mutex poisoned");
                return Err(crate::endpoint::RetryError::incoming(incoming));
            }
        };
        let mut response_buffer = Vec::new();
        let transmit = state.inner.retry(incoming, &mut response_buffer)?;
        respond(transmit, &response_buffer, &*state.socket);
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: crate::Incoming) {
        if let Ok(mut state) = self.state.lock() {
            state.stats.ignored_handshakes += 1;
            state.inner.ignore(incoming);
        } else {
            error!("Failed to ignore incoming connection: endpoint state mutex poisoned");
        }
    }
}

#[derive(Debug)]
pub(crate) struct State {
    socket: Arc<dyn AsyncUdpSocket>,
    /// During an active migration, abandoned_socket receives traffic
    /// until the first packet arrives on the new socket.
    prev_socket: Option<Arc<dyn AsyncUdpSocket>>,
    inner: crate::endpoint::Endpoint,
    recv_state: RecvState,
    driver: Option<Waker>,
    ipv6: bool,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    /// and the supervisor's infrastructure ref (see `DRIVER_INFRA_REFS`)
    ref_count: usize,
    driver_lost: bool,
    runtime: Arc<dyn Runtime>,
    stats: EndpointStats,
    /// Channel for forwarding peer address updates to the upper layer.
    peer_address_update_tx: Option<mpsc::UnboundedSender<(SocketAddr, SocketAddr)>>,
    socket_released_for_shutdown: bool,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
}

impl State {
    fn drive_recv(&mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        let get_time = || self.runtime.now();
        self.recv_state.recv_limiter.start_cycle(get_time);
        if let Some(socket) = &self.prev_socket {
            // We don't care about the `PollProgress` from old sockets.
            let poll_res =
                self.recv_state
                    .poll_socket(cx, &mut self.inner, &**socket, &*self.runtime, now);
            if poll_res.is_err() {
                self.prev_socket = None;
            }
        };
        let poll_res =
            self.recv_state
                .poll_socket(cx, &mut self.inner, &*self.socket, &*self.runtime, now);
        self.recv_state.recv_limiter.finish_cycle(get_time);
        let poll_res = poll_res?;
        if poll_res.received_connection_packet {
            // Traffic has arrived on self.socket, therefore there is no need for the abandoned
            // one anymore. TODO: Account for multiple outgoing connections.
            self.prev_socket = None;
        }
        Ok(poll_res.keep_going)
    }

    fn handle_events(&mut self, cx: &mut Context, shared: &Shared) -> bool {
        let mut did_work = false;

        for _ in 0..IO_LOOP_BOUND {
            let (ch, event) = match self.events.poll_recv(cx) {
                Poll::Ready(Some(x)) => x,
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    break;
                }
            };

            did_work = true;

            if event.is_drained() {
                self.recv_state.connections.senders.remove(&ch);
                if self.recv_state.connections.is_empty() {
                    shared.idle.notify_waiters();
                }
            }
            let Some(event) = self.inner.handle_event(ch, event) else {
                continue;
            };
            // Backpressure the event on the bounded per-connection channel;
            // a permanently full channel force-closes the connection (x0x#278).
            self.recv_state.connections.send_proto(ch, event);
        }

        // Process relay events generated by the endpoint
        // These are PUNCH_ME_NOW frames that need to be forwarded to target connections
        for (ch, event) in self.inner.drain_relay_events() {
            did_work = true;
            if self.recv_state.connections.senders.contains_key(&ch) {
                tracing::debug!("Sending relay event to connection {:?}", ch);
                self.recv_state.connections.send_proto(ch, event);
            } else {
                tracing::warn!(
                    "Cannot send relay event: connection {:?} not found in senders",
                    ch
                );
            }
        }

        // Forward peer address updates from ADD_ADDRESS frames to the
        // NatTraversalEndpoint so it can update the DHT routing table.
        let address_updates: Vec<(SocketAddr, SocketAddr)> =
            self.inner.drain_peer_address_updates().collect();
        for (peer_addr, advertised_addr) in address_updates {
            did_work = true;
            if let Some(ref tx) = self.peer_address_update_tx {
                let _ = tx.send((peer_addr, advertised_addr));
            }
        }

        did_work
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for incoming in self.recv_state.incoming.drain(..) {
            self.inner.ignore(incoming);
        }
    }
}

fn respond(transmit: crate::Transmit, response_buffer: &[u8], socket: &dyn AsyncUdpSocket) {
    // Send if there's kernel buffer space; otherwise, drop it
    //
    // As an endpoint-generated packet, we know this is an
    // immediate, stateless response to an unconnected peer,
    // one of:
    //
    // - A version negotiation response due to an unknown version
    // - A `CLOSE` due to a malformed or unwanted connection attempt
    // - A stateless reset due to an unrecognized connection
    // - A `Retry` packet due to a connection attempt when
    //   `use_retry` is set
    //
    // In each case, a well-behaved peer can be trusted to retry a
    // few times, which is guaranteed to produce the same response
    // from us. Repeated failures might at worst cause a peer's new
    // connection attempt to time out, which is acceptable if we're
    // under such heavy load that there's never room for this code
    // to transmit. This is morally equivalent to the packet getting
    // lost due to congestion further along the link, which
    // similarly relies on peer retries for recovery.
    let mut sender = socket.create_sender();
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let _ = sender.as_mut().poll_send(
        &udp_transmit(&transmit, &response_buffer[..transmit.size]),
        &mut cx,
    );
}

#[inline]
fn proto_ecn(ecn: quinn_udp::EcnCodepoint) -> crate::EcnCodepoint {
    match ecn {
        quinn_udp::EcnCodepoint::Ect0 => crate::EcnCodepoint::Ect0,
        quinn_udp::EcnCodepoint::Ect1 => crate::EcnCodepoint::Ect1,
        quinn_udp::EcnCodepoint::Ce => crate::EcnCodepoint::Ce,
    }
}

/// Per-connection bound on the recv-event channel. A connection whose
/// application never drains its events is backpressured at this depth instead
/// of buffering indefinitely (x0x#278).
const RECV_EVENT_BOUND: usize = 256;
/// Consecutive recv-event overflows after which a stuck connection is
/// force-closed (→ terminate → Drained → reaped) rather than allowed to pin
/// memory indefinitely (x0x#278).
const RECV_OVERFLOW_KILL_THRESHOLD: u64 = 1024;
/// Hard cap on the number of live connections an endpoint will accept. Beyond
/// the cap new incoming connections are refused (existing refuse path) to bound
/// memory on fleet/bootstrap nodes (x0x#278).
const DEFAULT_MAX_CONNECTIONS: usize = 4096;

#[derive(Debug)]
struct ConnectionChannels {
    sender: mpsc::Sender<ConnectionEvent>,
    /// Consecutive recv-event overflows on this connection's bounded channel.
    /// Reset to 0 on a successful send; past `RECV_OVERFLOW_KILL_THRESHOLD` the
    /// connection is force-closed (x0x#278).
    recv_overflows: AtomicU64,
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, ConnectionChannels>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
    /// Maximum number of simultaneously live connections; new incoming
    /// connections are refused past this cap (x0x#278).
    max_connections: usize,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: crate::Connection,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::channel(RECV_EVENT_BOUND);
        if let Some((error_code, ref reason)) = self.close {
            // Fresh (empty) channel — cannot be full; a failure here only means
            // the connection task was already dropped.
            let _ = send.try_send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.senders.insert(
            handle,
            ConnectionChannels {
                sender: send,
                recv_overflows: AtomicU64::new(0),
            },
        );
        Connecting::new(handle, conn, self.sender.clone(), recv, socket, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    /// Enqueue a Proto (datagram/relay) event under backpressure. On a full
    /// channel the event is dropped (never retained) and the per-connection
    /// overflow counter ticks up; once it crosses `RECV_OVERFLOW_KILL_THRESHOLD`
    /// the connection is force-closed by dropping our sender (the connection
    /// task then observes a closed channel → terminate → Drained → reaped) so a
    /// permanently stuck consumer cannot pin memory (x0x#278).
    fn send_proto(&mut self, ch: ConnectionHandle, event: crate::shared::ConnectionEvent) {
        let kill = match self.senders.get(&ch) {
            None => return,
            Some(channels) => match channels.sender.try_send(ConnectionEvent::Proto(event)) {
                Ok(()) => {
                    channels.recv_overflows.store(0, Ordering::Relaxed);
                    false
                }
                Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(_)) => {
                    channels.recv_overflows.fetch_add(1, Ordering::Relaxed) + 1
                        >= RECV_OVERFLOW_KILL_THRESHOLD
                }
            },
        };
        if kill {
            self.senders.remove(&ch);
        }
    }

    /// Broadcast a control event (Close/Rebind) to every connection. Control
    /// events must never be silently dropped: connections whose bounded channel
    /// is already full are force-closed by dropping our sender (→ terminate →
    /// Drained → reaped) rather than losing the event; handles are collected
    /// first to avoid aliasing the map during iteration (x0x#278).
    fn broadcast_control<F>(&mut self, mut make_event: F)
    where
        F: FnMut() -> ConnectionEvent,
    {
        let mut kill = Vec::new();
        for (ch, channels) in self.senders.iter() {
            match channels.sender.try_send(make_event()) {
                Ok(()) => {}
                Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(_)) => kill.push(*ch),
            }
        }
        for ch in kill {
            self.senders.remove(&ch);
        }
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for Accept<'_> {
    type Output = Option<super::incoming::Incoming>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut endpoint = match this.endpoint.inner.state.lock() {
            Ok(endpoint) => endpoint,
            Err(_) => return Poll::Ready(None),
        };
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(incoming) = endpoint.recv_state.incoming.pop_front() {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(endpoint);
            let incoming = super::incoming::Incoming::new(incoming, this.endpoint.inner.clone());
            return Poll::Ready(Some(incoming));
        }
        if endpoint.recv_state.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(
        socket: Arc<dyn AsyncUdpSocket>,
        inner: crate::endpoint::Endpoint,
        ipv6: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let recv_state = RecvState::new(sender, socket.max_receive_segments(), &inner);
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
            },
            state: Mutex::new(State {
                socket,
                prev_socket: None,
                inner,
                ipv6,
                events,
                driver: None,
                ref_count: 0,
                driver_lost: false,
                recv_state,
                runtime,
                stats: EndpointStats::default(),
                peer_address_update_tx: None,
                socket_released_for_shutdown: false,
            }),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        if let Ok(mut state) = self.0.state.lock() {
            state.ref_count += 1;
        }
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        if let Ok(mut endpoint) = self.0.state.lock() {
            if let Some(x) = endpoint.ref_count.checked_sub(1) {
                endpoint.ref_count = x;
                if x == DRIVER_INFRA_REFS {
                    // Only infrastructure refs remain (the supervisor's and
                    // the driver's own, see DRIVER_INFRA_REFS): wake the
                    // driver so it can shut down once the last connection is
                    // gone.
                    if let Some(task) = endpoint.driver.take() {
                        task.wake();
                    }
                }
            }
        } else {
            error!("Failed to drop EndpointRef: state mutex poisoned");
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// State directly involved in handling incoming packets
struct RecvState {
    incoming: VecDeque<crate::Incoming>,
    connections: ConnectionSet,
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
}

impl RecvState {
    fn new(
        sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        max_receive_segments: usize,
        endpoint: &crate::endpoint::Endpoint,
    ) -> Self {
        // Use a receive buffer size large enough to handle any incoming packet.
        // This is especially important for PQC handshakes which can send 4096+ byte datagrams
        // before transport parameters are exchanged. We use the maximum of:
        // - The configured max_udp_payload_size (what we expect to receive)
        // - PQC minimum MTU (4096 bytes) to handle PQC handshakes regardless of config
        // - Capped at 64KB for practical memory usage
        const PQC_MIN_RECV_SIZE: u64 = 4096;
        let configured_size = endpoint.config().get_max_udp_payload_size();
        let effective_size = configured_size.max(PQC_MIN_RECV_SIZE).min(64 * 1024) as usize;

        let recv_buf = vec![0; effective_size * max_receive_segments * BATCH_SIZE];
        Self {
            connections: ConnectionSet {
                senders: FxHashMap::default(),
                sender,
                close: None,
                max_connections: DEFAULT_MAX_CONNECTIONS,
            },
            incoming: VecDeque::new(),
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
        }
    }

    fn poll_socket(
        &mut self,
        cx: &mut Context,
        endpoint: &mut crate::endpoint::Endpoint,
        socket: &dyn AsyncUdpSocket,
        runtime: &dyn Runtime,
        now: Instant,
    ) -> Result<PollProgress, io::Error> {
        let mut received_connection_packet = false;
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs: [IoSliceMut; BATCH_SIZE] = {
            let mut bufs = self
                .recv_buf
                .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
                .map(IoSliceMut::new);

            // expect() safe as self.recv_buf is chunked into BATCH_SIZE items
            // and iovs will be of size BATCH_SIZE, thus from_fn is called
            // exactly BATCH_SIZE times.
            std::array::from_fn(|_| {
                bufs.next().unwrap_or_else(|| {
                    error!("Insufficient buffers for BATCH_SIZE");
                    IoSliceMut::new(&mut [])
                })
            })
        };
        loop {
            match socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {
                            let buf = data.split_to(meta.stride.min(data.len()));
                            let mut response_buffer = Vec::new();
                            match endpoint.handle(
                                now,
                                meta.addr,
                                meta.dst_ip,
                                meta.ecn.map(proto_ecn),
                                buf,
                                &mut response_buffer,
                            ) {
                                Some(DatagramEvent::NewConnection(incoming)) => {
                                    if self.connections.close.is_none()
                                        && self.connections.senders.len()
                                            < self.connections.max_connections
                                    {
                                        self.incoming.push_back(incoming);
                                    } else {
                                        let transmit =
                                            endpoint.refuse(incoming, &mut response_buffer);
                                        respond(transmit, &response_buffer, socket);
                                    }
                                }
                                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                                    // Ignoring errors from dropped connections that haven't yet been cleaned up
                                    received_connection_packet = true;
                                    self.connections.send_proto(handle, event);
                                }
                                Some(DatagramEvent::Response(transmit)) => {
                                    respond(transmit, &response_buffer, socket);
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => {
                    return Ok(PollProgress {
                        received_connection_packet,
                        keep_going: false,
                    });
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker; likewise every ICMP-derived transient error a
                // single unreachable peer can pin on the shared socket —
                // terminating the driver here silently kills ALL transport
                // for the process (x0x issue #262). Drop the datagram and
                // keep polling.
                Poll::Ready(Err(ref e)) if is_transient_socket_error(e) => {
                    debug!("ignoring transient socket recv error: {}", e);
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
            if !self.recv_limiter.allow_work(|| runtime.now()) {
                return Ok(PollProgress {
                    received_connection_packet,
                    keep_going: true,
                });
            }
        }
    }
}

impl fmt::Debug for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RecvState")
            .field("incoming", &self.incoming)
            .field("connections", &self.connections)
            // recv_buf too large
            .field("recv_limiter", &self.recv_limiter)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct PollProgress {
    /// Whether a datagram was routed to an existing connection
    received_connection_packet: bool,
    /// Whether datagram handling was interrupted early by the work limiter for fairness
    keep_going: bool,
}

#[cfg(test)]
mod driver_error_tests {
    use super::is_transient_socket_error;
    use std::io;

    /// WHY (x0x issue #262): on Linux, one unreachable peer surfaces as an
    /// ICMP-derived recv error on the SHARED endpoint socket. If any of
    /// these terminate the driver, the whole process loses QUIC I/O
    /// silently — a prod bootstrap sat wedged like that for 14+ hours.
    #[test]
    fn icmp_derived_errors_are_transient() {
        for kind in [
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::NotConnected,
            io::ErrorKind::TimedOut,
        ] {
            assert!(
                is_transient_socket_error(&io::Error::new(kind, "test")),
                "{kind:?} must not kill the endpoint driver"
            );
        }
        // Raw errnos with platform-dependent ErrorKind mapping.
        for errno in [49, 51, 65, 101, 113] {
            assert!(
                is_transient_socket_error(&io::Error::from_raw_os_error(errno)),
                "errno {errno} must not kill the endpoint driver"
            );
        }
    }

    /// Genuinely fatal socket states must still terminate the driver: a
    /// dead file descriptor or permission loss is not per-datagram.
    #[test]
    fn fatal_errors_still_terminate() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidInput,
        ] {
            assert!(
                !is_transient_socket_error(&io::Error::new(kind, "test")),
                "{kind:?} must remain driver-fatal"
            );
        }
    }
}

#[cfg(test)]
mod recv_event_backpressure_tests {
    use super::*;
    use crate::shared::ConnectionEventInner;

    /// Build a throwaway low-level `ConnectionEvent` to feed `send_proto`.
    fn proto_event() -> crate::shared::ConnectionEvent {
        crate::shared::ConnectionEvent(ConnectionEventInner::NewIdentifiers(
            Vec::new(),
            Instant::now(),
        ))
    }

    /// Build an empty `ConnectionSet` (its endpoint-event sender is discarded).
    fn empty_set() -> ConnectionSet {
        let (sender, _events) = mpsc::unbounded_channel();
        ConnectionSet {
            senders: FxHashMap::default(),
            sender,
            close: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Insert a connection whose receiver is held and never drained, returning
    /// the handle and the receiver (which the caller must keep alive so the
    /// channel stays open and merely fills, rather than closing).
    fn insert_stuck_connection(
        cs: &mut ConnectionSet,
    ) -> (ConnectionHandle, mpsc::Receiver<ConnectionEvent>) {
        let (tx, rx) = mpsc::channel(RECV_EVENT_BOUND);
        let handle = ConnectionHandle(0);
        cs.senders.insert(
            handle,
            ConnectionChannels {
                sender: tx,
                recv_overflows: AtomicU64::new(0),
            },
        );
        (handle, rx)
    }

    /// A consumer that never drains its recv-event channel is backpressured:
    /// events past the bound are dropped (not retained) and the overflow
    /// counter ticks up, but the connection is not yet killed (x0x#278).
    #[test]
    fn full_channel_drops_events_and_counts_overflows() {
        let mut cs = empty_set();
        let (handle, _rx) = insert_stuck_connection(&mut cs);

        // Fill the bounded channel exactly.
        for _ in 0..RECV_EVENT_BOUND {
            cs.send_proto(handle, proto_event());
        }
        assert_eq!(
            cs.senders
                .get(&handle)
                .unwrap()
                .recv_overflows
                .load(Ordering::Relaxed),
            0,
            "successful sends must reset the overflow counter"
        );

        // Further sends must overflow without growing the channel.
        for _ in 0..10 {
            cs.send_proto(handle, proto_event());
        }
        assert_eq!(
            cs.senders
                .get(&handle)
                .unwrap()
                .recv_overflows
                .load(Ordering::Relaxed),
            10,
            "each dropped event must increment the overflow counter"
        );
        assert!(
            cs.senders.contains_key(&handle),
            "below the kill threshold the connection must stay alive"
        );
    }

    /// Past the overflow kill threshold a stuck connection is force-closed:
    /// its sender is removed from the set (→ terminate → Drained → reaped)
    /// (x0x#278).
    #[test]
    fn overflow_past_threshold_force_closes_connection() {
        let mut cs = empty_set();
        let (tx, _rx) = mpsc::channel(RECV_EVENT_BOUND);
        let handle = ConnectionHandle(7);
        cs.senders.insert(
            handle,
            ConnectionChannels {
                sender: tx,
                recv_overflows: AtomicU64::new(0),
            },
        );

        // Fill, then overflow well past the kill threshold.
        for _ in 0..RECV_EVENT_BOUND {
            cs.send_proto(handle, proto_event());
        }
        for _ in 0..RECV_OVERFLOW_KILL_THRESHOLD {
            cs.send_proto(handle, proto_event());
        }

        assert!(
            !cs.senders.contains_key(&handle),
            "past the kill threshold the sender must be dropped (force-close)"
        );
        assert!(cs.senders.is_empty());
    }

    /// A draining consumer resets its overflow counter on success and is never
    /// force-closed however many events flow through (x0x#278).
    #[test]
    fn draining_consumer_never_killed() {
        let mut cs = empty_set();
        let (tx, mut rx) = mpsc::channel(RECV_EVENT_BOUND);
        let handle = ConnectionHandle(1);
        cs.senders.insert(
            handle,
            ConnectionChannels {
                sender: tx,
                recv_overflows: AtomicU64::new(0),
            },
        );

        // Overrun the bound a few times (below the kill threshold) while the
        // consumer is momentarily idle.
        for _ in 0..(RECV_EVENT_BOUND + 50) {
            cs.send_proto(handle, proto_event());
        }
        assert!(cs.senders.contains_key(&handle));

        // Drain everything; subsequent sends succeed and reset the counter.
        while rx.try_recv().is_ok() {}
        for _ in 0..5 {
            cs.send_proto(handle, proto_event());
        }
        assert_eq!(
            cs.senders
                .get(&handle)
                .unwrap()
                .recv_overflows
                .load(Ordering::Relaxed),
            0,
            "a successful send after draining must reset the overflow counter"
        );
        assert!(cs.senders.contains_key(&handle));
    }
}

#[cfg(test)]
mod driver_supervisor_tests {
    use super::*;
    use crate::high_level::runtime::UdpSender;
    use std::sync::atomic::AtomicUsize;

    /// A socket whose recv path can be failed on demand, to force the
    /// endpoint driver into a fatal exit without OS trickery (issue #220).
    #[derive(Debug)]
    struct ControllableSocket {
        addr: SocketAddr,
        fail_with: Mutex<Option<io::ErrorKind>>,
        recv_calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct NoopSender;

    impl UdpSender for NoopSender {
        fn poll_send(
            self: Pin<&mut Self>,
            _transmit: &quinn_udp::Transmit,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for ControllableSocket {
        fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
            Box::pin(NoopSender)
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.recv_calls.fetch_add(1, Ordering::Relaxed);
            match *self.fail_with.lock().unwrap() {
                Some(kind) => Poll::Ready(Err(io::Error::new(kind, "injected fatal recv error"))),
                None => Poll::Pending,
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.addr)
        }
    }

    /// Build the endpoint internals the way `new_with_abstract_socket` does,
    /// returning the root ref plus a clone of the inner Arc so tests can
    /// inspect state without disturbing `ref_count` accounting.
    fn test_endpoint_ref(
        socket: Arc<ControllableSocket>,
    ) -> (EndpointRef, Arc<EndpointInner>, Arc<dyn Runtime>) {
        let runtime = default_runtime().expect("tests run inside a tokio runtime");
        let rc = EndpointRef::new(
            socket,
            crate::endpoint::Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None),
            false,
            runtime.clone(),
        );
        let inner = rc.0.clone();
        (rc, inner, runtime)
    }

    /// Unbindable TEST-NET address: the supervisor's rebind attempt fails on
    /// it, so the respawned driver retries on the same controllable socket.
    fn unbindable_addr() -> SocketAddr {
        SocketAddr::from((std::net::Ipv4Addr::new(192, 0, 2, 1), 12345))
    }

    async fn wait_until(mut condition: impl FnMut() -> bool, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while !condition() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    fn recv_calls(socket: &ControllableSocket) -> usize {
        socket.recv_calls.load(Ordering::Relaxed)
    }

    /// Insert a stand-in connection channel, returning the receiver the test
    /// must keep alive for the channel to stay open.
    fn insert_fake_connection(
        inner: &EndpointInner,
    ) -> (ConnectionHandle, mpsc::Receiver<ConnectionEvent>) {
        let (tx, rx) = mpsc::channel(RECV_EVENT_BOUND);
        let handle = ConnectionHandle(0);
        inner
            .state
            .lock()
            .unwrap()
            .recv_state
            .connections
            .senders
            .insert(
                handle,
                ConnectionChannels {
                    sender: tx,
                    recv_overflows: AtomicU64::new(0),
                },
            );
        (handle, rx)
    }

    /// WHY (issue #220): a fatal driver exit used to be terminal — driver_lost
    /// failed every future connect and the socket was never polled again. The
    /// supervisor must respawn the driver instead, and clean shutdown (all
    /// handles dropped) must still end the loop.
    #[tokio::test]
    async fn fatal_driver_exit_is_respawned_and_shutdown_stays_clean() {
        let socket = Arc::new(ControllableSocket {
            addr: unbindable_addr(),
            fail_with: Mutex::new(Some(io::ErrorKind::PermissionDenied)),
            recv_calls: AtomicUsize::new(0),
        });
        let (rc, inner, runtime) = test_endpoint_ref(socket.clone());
        let user_handle = rc.clone();
        spawn_supervised_driver(rc, runtime);

        // The first driver dies on the injected fatal error...
        assert!(
            wait_until(|| recv_calls(&socket) >= 1, Duration::from_secs(5)).await,
            "driver must poll the socket"
        );
        // ...and the supervisor respawns it despite the socket still failing.
        assert!(
            wait_until(|| recv_calls(&socket) >= 2, Duration::from_secs(5)).await,
            "supervisor must respawn the driver after a fatal exit"
        );
        assert!(
            !inner.state.lock().unwrap().driver_lost,
            "supervised driver death must not set driver_lost"
        );

        // Recover the socket; the next respawn stays up (poll_recv pends).
        *socket.fail_with.lock().unwrap() = None;
        let calls = recv_calls(&socket);
        assert!(
            wait_until(|| recv_calls(&socket) > calls, Duration::from_secs(5)).await,
            "respawned driver must poll the recovered socket"
        );

        // Clean shutdown: dropping the last user handle lets the driver exit
        // and the supervisor task end, releasing all refs.
        drop(user_handle);
        assert!(
            wait_until(|| Arc::strong_count(&inner) == 1, Duration::from_secs(5)).await,
            "driver and supervisor must release the endpoint after the last handle drops"
        );
    }

    /// A supervised driver death must not tear down live connections: their
    /// channels stay in place so the respawned driver (and a rebind) can
    /// resume I/O for them (issue #220).
    #[tokio::test]
    async fn respawn_preserves_connection_channels() {
        let socket = Arc::new(ControllableSocket {
            addr: unbindable_addr(),
            fail_with: Mutex::new(Some(io::ErrorKind::PermissionDenied)),
            recv_calls: AtomicUsize::new(0),
        });
        let (rc, inner, runtime) = test_endpoint_ref(socket.clone());
        let _user_handle = rc.clone();
        let (handle, _rx) = insert_fake_connection(&inner);
        spawn_supervised_driver(rc, runtime);

        assert!(
            wait_until(|| recv_calls(&socket) >= 2, Duration::from_secs(5)).await,
            "supervisor must respawn the driver after a fatal exit"
        );
        let state = inner.state.lock().unwrap();
        assert!(
            state.recv_state.connections.senders.contains_key(&handle),
            "respawn must preserve live connection channels"
        );
        assert!(!state.driver_lost);

        // Stop the failure spam before the test runtime tears the task down.
        *socket.fail_with.lock().unwrap() = None;
    }

    /// An intentional close must never resurrect I/O: the supervisor observes
    /// the close reason and lets the driver stay dead, with terminal teardown
    /// (driver_lost, connection channels dropped) as before (issue #220).
    #[tokio::test]
    async fn closed_endpoint_driver_is_not_respawned() {
        let socket = Arc::new(ControllableSocket {
            addr: unbindable_addr(),
            fail_with: Mutex::new(Some(io::ErrorKind::PermissionDenied)),
            recv_calls: AtomicUsize::new(0),
        });
        let (rc, inner, runtime) = test_endpoint_ref(socket.clone());
        let _user_handle = rc.clone();
        let (_handle, _rx) = insert_fake_connection(&inner);
        inner.state.lock().unwrap().recv_state.connections.close =
            Some((VarInt::from_u32(0), Bytes::new()));
        spawn_supervised_driver(rc, runtime);

        assert!(
            wait_until(|| recv_calls(&socket) >= 1, Duration::from_secs(5)).await,
            "driver must poll the socket once"
        );
        // Well past the initial backoff, there must be no second poll: the
        // supervisor respected the close instead of respawning.
        tokio::time::sleep(DRIVER_RESPAWN_INITIAL_BACKOFF * 5).await;
        assert_eq!(
            recv_calls(&socket),
            1,
            "driver on a closed endpoint must not be respawned"
        );
        let state = inner.state.lock().unwrap();
        assert!(
            state.driver_lost,
            "terminal teardown on a closed endpoint must set driver_lost"
        );
        assert!(
            state.recv_state.connections.senders.is_empty(),
            "terminal teardown must drop connection channels"
        );
    }

    /// WHY (issue #220 vs #199): `shutdown()` can fire while the supervisor is
    /// sleeping out its respawn backoff. Without a post-sleep re-check the
    /// supervisor would rebind and spawn a fresh driver on a socket that
    /// shutdown had just released, leaving a zombie driver behind.
    #[tokio::test]
    async fn shutdown_during_backoff_prevents_respawn() {
        let socket = Arc::new(ControllableSocket {
            addr: unbindable_addr(),
            fail_with: Mutex::new(Some(io::ErrorKind::PermissionDenied)),
            recv_calls: AtomicUsize::new(0),
        });
        let (rc, inner, runtime) = test_endpoint_ref(socket.clone());
        let _user_handle = rc.clone();
        spawn_supervised_driver(rc, runtime);

        // The first driver dies fatally and the supervisor enters its
        // backoff sleep...
        assert!(
            wait_until(|| recv_calls(&socket) >= 1, Duration::from_secs(5)).await,
            "driver must poll the socket once"
        );
        // ...then shutdown lands mid-backoff (the release path sets this
        // flag before swapping the socket out).
        inner.state.lock().unwrap().socket_released_for_shutdown = true;

        tokio::time::sleep(DRIVER_RESPAWN_INITIAL_BACKOFF * 5).await;
        assert_eq!(
            recv_calls(&socket),
            1,
            "supervisor must not respawn a driver after shutdown released the socket"
        );
    }

    /// `Endpoint::close` must record the close reason: new incoming connection
    /// attempts are rejected, `accept` drains, and the supervisor can tell an
    /// intentional close apart from a fatal driver exit (issue #220).
    #[tokio::test]
    async fn close_marks_endpoint_closed() {
        let socket = Arc::new(ControllableSocket {
            addr: unbindable_addr(),
            fail_with: Mutex::new(None),
            recv_calls: AtomicUsize::new(0),
        });
        let runtime = default_runtime().expect("tests run inside a tokio runtime");
        let endpoint =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
                .expect("endpoint construction");

        endpoint.close(VarInt::from_u32(0), b"done");
        assert!(
            endpoint
                .inner
                .state
                .lock()
                .unwrap()
                .recv_state
                .connections
                .close
                .is_some(),
            "close must record the close reason"
        );
        assert!(
            endpoint.accept().await.is_none(),
            "accept must drain once the endpoint is closed"
        );
    }

    /// The supervisor's rebind helper must be able to take over the address
    /// once the old socket is gone, and must fail (so the old socket is kept)
    /// while the old socket still owns it (issue #220).
    #[cfg(not(wasm_browser))]
    #[test]
    fn replacement_socket_rebinds_after_old_socket_gone() {
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        let first = bind_replacement_socket(addr).expect("initial bind");
        let bound = first.local_addr().expect("local addr");
        assert!(
            bind_replacement_socket(bound).is_err(),
            "rebind must fail while the old socket owns the address"
        );
        drop(first);
        let second = bind_replacement_socket(bound).expect("rebind after old socket is gone");
        assert_eq!(
            second.local_addr().expect("local addr"),
            bound,
            "replacement socket must take over the old address"
        );
    }
}
