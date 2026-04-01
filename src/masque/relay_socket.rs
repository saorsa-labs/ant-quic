// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Socket
//!
//! A virtual UDP socket that routes QUIC packets through a MASQUE relay
//! via a persistent QUIC stream (length-prefixed framing).
//!
//! Implements [`AsyncUdpSocket`] so it can be plugged into a Quinn endpoint
//! as a transparent replacement for a real UDP socket.

use bytes::Bytes;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use quinn_udp::{RecvMeta, Transmit};

use crate::VarInt;
use crate::high_level::{AsyncUdpSocket, UdpPoller};
use crate::masque::UncompressedDatagram;

/// A virtual UDP socket that tunnels packets through a MASQUE relay
/// via a persistent QUIC stream with length-prefixed framing.
pub struct MasqueRelaySocket {
    /// The relay's public address (returned as our local address)
    relay_public_addr: SocketAddr,
    /// Queue of received packets (payload, source_addr)
    recv_queue: std::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Waker to notify when new packets arrive
    recv_waker: std::sync::Mutex<Option<Waker>>,
    /// Channel for outbound packets (written to the relay stream by background task)
    send_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
}

impl fmt::Debug for MasqueRelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueRelaySocket")
            .field("relay_public_addr", &self.relay_public_addr)
            .field(
                "recv_queue_len",
                &self.recv_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl MasqueRelaySocket {
    /// Create a new stream-based relay socket.
    ///
    /// Spawns two background tasks:
    /// - Read from `recv_stream`, decode frames, queue for `poll_recv`
    /// - Read from `send_tx` channel, write length-prefixed frames to `send_stream`
    pub fn new(
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
        relay_public_addr: SocketAddr,
    ) -> Arc<Self> {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let socket = Arc::new(Self {
            relay_public_addr,
            recv_queue: std::sync::Mutex::new(VecDeque::new()),
            recv_waker: std::sync::Mutex::new(None),
            send_tx,
        });

        // Background task: read length-prefixed frames from relay stream → queue
        let socket_ref = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (length)");
                    break;
                }
                let frame_len = u32::from_be_bytes(len_buf) as usize;
                if frame_len > 65536 {
                    tracing::warn!(frame_len, "MasqueRelaySocket: oversized frame");
                    break;
                }

                // Read frame data
                let mut frame_buf = vec![0u8; frame_len];
                if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream read error (data)");
                    break;
                }

                // Decode as UncompressedDatagram
                let mut cursor = Bytes::from(frame_buf);
                match UncompressedDatagram::decode(&mut cursor) {
                    Ok(datagram) => {
                        let payload = datagram.payload.to_vec();
                        let source = datagram.target; // "target" in datagram = source from relay's perspective

                        if let Ok(mut queue) = socket_ref.recv_queue.lock() {
                            queue.push_back((payload, source));
                        }
                        if let Ok(mut waker) = socket_ref.recv_waker.lock() {
                            if let Some(w) = waker.take() {
                                w.wake();
                            }
                        }
                    }
                    Err(_) => {
                        tracing::trace!("MasqueRelaySocket: failed to decode frame");
                    }
                }
            }

            // Wake pending recv on stream close
            if let Ok(mut waker) = socket_ref.recv_waker.lock() {
                if let Some(w) = waker.take() {
                    w.wake();
                }
            }
        });

        // Background task: write queued outbound packets to relay stream
        tokio::spawn(async move {
            while let Some(encoded) = send_rx.recv().await {
                let frame_len = encoded.len() as u32;
                if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (length)");
                    break;
                }
                if let Err(e) = send_stream.write_all(&encoded).await {
                    tracing::debug!(error = %e, "MasqueRelaySocket: stream write error (data)");
                    break;
                }
            }
        });

        socket
    }
}

impl AsyncUdpSocket for MasqueRelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let datagram = UncompressedDatagram::new(
            VarInt::from_u32(0),
            transmit.destination,
            Bytes::copy_from_slice(transmit.contents),
        );
        let encoded = datagram.encode();

        self.send_tx
            .send(encoded)
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted, "relay stream closed"))
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

        if let Ok(mut queue) = self.recv_queue.lock() {
            if let Some((payload, source)) = queue.pop_front() {
                let len = payload.len().min(bufs[0].len());
                bufs[0][..len].copy_from_slice(&payload[..len]);

                let mut recv_meta = RecvMeta::default();
                recv_meta.len = len;
                recv_meta.stride = len;
                recv_meta.addr = source;
                recv_meta.ecn = None;
                recv_meta.dst_ip = None;
                meta[0] = recv_meta;

                return Poll::Ready(Ok(1));
            }
        }

        // Register waker for when data arrives
        if let Ok(mut waker) = self.recv_waker.lock() {
            *waker = Some(cx.waker().clone());
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.relay_public_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
