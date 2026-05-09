// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::ReadBuf,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper, UdpPoller, UdpSender};
use crate::Instant;

/// Tokio runtime implementation
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(TokioTimer(Box::pin(sleep_until(i.into()))))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        t.set_nonblocking(true)?;
        Ok(Arc::new(UdpSocket {
            inner: Arc::new(tokio::net::UdpSocket::from_std(t)?),
            may_fragment: true, // Default to true for now
        }))
    }

    fn now(&self) -> Instant {
        Instant::from(tokio::time::Instant::now())
    }
}

/// Tokio timer implementation
#[derive(Debug)]
struct TokioTimer(Pin<Box<Sleep>>);

impl AsyncTimer for TokioTimer {
    fn reset(mut self: Pin<&mut Self>, i: Instant) {
        self.0.as_mut().reset(i.into())
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        self.0.as_mut().poll(cx).map(|_| ())
    }
}

/// Tokio UDP socket implementation
#[derive(Debug)]
struct UdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
    may_fragment: bool,
}

impl AsyncUdpSocket for UdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        let inner = Arc::clone(&self.inner);
        let writable = Box::pin(UdpPollHelper::new({
            let inner = Arc::clone(&inner);
            move || {
                let socket = Arc::clone(&inner);
                async move { socket.writable().await }
            }
        }));
        Box::pin(TokioUdpSender { inner, writable })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // For now, use a simple single-packet receive
        // In production, should use quinn_udp::recv for GSO/GRO support

        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut buf = ReadBuf::new(&mut bufs[0]);
        let addr = match self.inner.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(addr)) => addr,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let len = buf.filled().len();
        meta[0] = quinn_udp::RecvMeta {
            len,
            stride: len,
            addr,
            ecn: None,
            dst_ip: None,
        };

        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.may_fragment
    }
}

#[derive(Debug)]
struct TokioUdpSender {
    inner: Arc<tokio::net::UdpSocket>,
    writable: Pin<Box<dyn UdpPoller>>,
}

impl UdpSender for TokioUdpSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &quinn_udp::Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.writable.as_mut().poll_writable(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            match self
                .inner
                .try_send_to(transmit.contents, transmit.destination)
            {
                Ok(_) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

/// Extension trait to convert tokio::Handle to Runtime
#[allow(dead_code)]
pub(super) trait HandleRuntime {
    /// Create a Runtime implementation from this handle
    fn as_runtime(&self) -> TokioRuntime;
}

impl HandleRuntime for tokio::runtime::Handle {
    fn as_runtime(&self) -> TokioRuntime {
        TokioRuntime
    }
}
