// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use crate::{Chunk, Chunks, ClosedStream, ConnectionError, ReadableError, StreamId};
use bytes::Bytes;
use thiserror::Error;
use tokio::io::ReadBuf;

use super::connection::ConnectionRef;
use crate::VarInt;

/// A stream that can only be used to receive data
///
/// `stop(0)` is implicitly called on drop unless:
/// - A variant of [`ReadError`] has been yielded by a read call
/// - [`stop()`] was called explicitly
///
/// # Cancellation
///
/// A `read` method is said to be *cancel-safe* when dropping its future before the future becomes
/// ready cannot lead to loss of stream data. This is true of methods which succeed immediately when
/// any progress is made, and is not true of methods which might need to perform multiple reads
/// internally before succeeding. Each `read` method documents whether it is cancel-safe.
///
/// # Common issues
///
/// ## Data never received on a locally-opened stream
///
/// Peers are not notified of streams until they or a later-numbered stream are used to send
/// data. If a bidirectional stream is locally opened but never used to send, then the peer may
/// never see it. Application protocols should always arrange for the endpoint which will first
/// transmit on a stream to be the endpoint responsible for opening it.
///
/// ## Data never received on a remotely-opened stream
///
/// Verify that the stream you are receiving is the same one that the server is sending on, e.g. by
/// logging the [`id`] of each. Streams are always accepted in the same order as they are created,
/// i.e. ascending order by [`StreamId`]. For example, even if a sender first transmits on
/// bidirectional stream 1, the first stream yielded by Connection's accept_bi method on the receiver
/// will be bidirectional stream 0.
///
/// [`ReadError`]: crate::ReadError
/// [`stop()`]: RecvStream::stop
/// [`SendStream::finish`]: crate::SendStream::finish
/// [`WriteError::Stopped`]: crate::WriteError::Stopped
/// [`id`]: RecvStream::id
/// `Connection::accept_bi`: See the Connection's accept_bi method
#[derive(Debug)]
pub struct RecvStream {
    conn: ConnectionRef,
    stream: StreamId,
    is_0rtt: bool,
    all_data_read: bool,
    reset: Option<VarInt>,
}

impl RecvStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            all_data_read: false,
            reset: None,
        }
    }

    /// Read data contiguously from the stream.
    ///
    /// Yields the number of bytes read into `buf` on success, or `None` if the stream was finished.
    ///
    /// This operation is cancel-safe.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        Read {
            stream: self,
            buf: ReadBuf::new(buf),
        }
        .await
    }

    /// Read an exact number of bytes contiguously from the stream.
    ///
    /// See [`read()`] for details. This operation is *not* cancel-safe.
    ///
    /// [`read()`]: RecvStream::read
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        ReadExact {
            stream: self,
            buf: ReadBuf::new(buf),
        }
        .await
    }

    /// Attempts to read from the stream into the provided buffer
    ///
    /// On success, returns `Poll::Ready(Ok(num_bytes_read))` and places data into `buf`. If this
    /// returns zero bytes read (and `buf` has a non-zero length), that indicates that the remote
    /// side has [`finish`]ed the stream and the local side has already read all bytes.
    ///
    /// If no data is available for reading, this returns `Poll::Pending` and arranges for the
    /// current task (via `cx.waker()`) to be notified when the stream becomes readable or is
    /// closed.
    ///
    /// [`finish`]: crate::SendStream::finish
    pub fn poll_read(
        &mut self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ReadError>> {
        let mut buf = ReadBuf::new(buf);
        ready!(self.poll_read_buf(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }

    /// Attempts to read from the stream into the provided buffer, which may be uninitialized
    ///
    /// On success, returns `Poll::Ready(Ok(()))` and places data into the unfilled portion of
    /// `buf`. If this does not write any bytes to `buf` (and `buf.remaining()` is non-zero), that
    /// indicates that the remote side has [`finish`]ed the stream and the local side has already
    /// read all bytes.
    ///
    /// If no data is available for reading, this returns `Poll::Pending` and arranges for the
    /// current task (via `cx.waker()`) to be notified when the stream becomes readable or is
    /// closed.
    ///
    /// [`finish`]: crate::SendStream::finish
    pub fn poll_read_buf(
        &mut self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), ReadError>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        self.poll_read_generic(cx, true, |chunks| {
            let mut read = false;
            loop {
                if buf.remaining() == 0 {
                    // We know `read` is `true` because `buf.remaining()` was not 0 before
                    return ReadStatus::Readable(());
                }

                match chunks.next(buf.remaining()) {
                    Ok(Some(chunk)) => {
                        buf.put_slice(&chunk.bytes);
                        read = true;
                    }
                    res => return (if read { Some(()) } else { None }, res.err()).into(),
                }
            }
        })
        .map(|res| res.map(|_| ()))
    }

    /// Read the next segment of data
    ///
    /// Yields `None` if the stream was finished. Otherwise, yields a segment of data and its
    /// offset in the stream. If `ordered` is `true`, the chunk's offset will be immediately after
    /// the last data yielded by `read()` or `read_chunk()`. If `ordered` is `false`, segments may
    /// be received in any order, and the `Chunk`'s `offset` field can be used to determine
    /// ordering in the caller. Unordered reads are less prone to head-of-line blocking within a
    /// stream, but require the application to manage reassembling the original data.
    ///
    /// Slightly more efficient than `read` due to not copying. Chunk boundaries do not correspond
    /// to peer writes, and hence cannot be used as framing.
    ///
    /// This operation is cancel-safe.
    pub async fn read_chunk(
        &mut self,
        max_length: usize,
        ordered: bool,
    ) -> Result<Option<Chunk>, ReadError> {
        ReadChunk {
            stream: self,
            max_length,
            ordered,
        }
        .await
    }

    /// Attempts to read a chunk from the stream.
    ///
    /// On success, returns `Poll::Ready(Ok(Some(chunk)))`. If `Poll::Ready(Ok(None))`
    /// is returned, it implies that EOF has been reached.
    ///
    /// If no data is available for reading, the method returns `Poll::Pending`
    /// and arranges for the current task (via cx.waker()) to receive a notification
    /// when the stream becomes readable or is closed.
    fn poll_read_chunk(
        &mut self,
        cx: &mut Context,
        max_length: usize,
        ordered: bool,
    ) -> Poll<Result<Option<Chunk>, ReadError>> {
        self.poll_read_generic(cx, ordered, |chunks| match chunks.next(max_length) {
            Ok(Some(chunk)) => ReadStatus::Readable(chunk),
            res => (None, res.err()).into(),
        })
    }

    /// Read the next segments of data
    ///
    /// Fills `bufs` with the segments of data beginning immediately after the
    /// last data yielded by `read` or `read_chunk`, or `None` if the stream was
    /// finished.
    ///
    /// Slightly more efficient than `read` due to not copying. Chunk boundaries
    /// do not correspond to peer writes, and hence cannot be used as framing.
    ///
    /// This operation is cancel-safe.
    pub async fn read_chunks(&mut self, bufs: &mut [Bytes]) -> Result<Option<usize>, ReadError> {
        ReadChunks { stream: self, bufs }.await
    }

    /// Foundation of [`Self::read_chunks`]
    fn poll_read_chunks(
        &mut self,
        cx: &mut Context,
        bufs: &mut [Bytes],
    ) -> Poll<Result<Option<usize>, ReadError>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(Some(0)));
        }

        self.poll_read_generic(cx, true, |chunks| {
            let mut read = 0;
            loop {
                if read >= bufs.len() {
                    // We know `read > 0` because `bufs` cannot be empty here
                    return ReadStatus::Readable(read);
                }

                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => {
                        bufs[read] = chunk.bytes;
                        read += 1;
                    }
                    res => return (if read == 0 { None } else { Some(read) }, res.err()).into(),
                }
            }
        })
    }

    /// Convenience method to read all remaining data into a buffer
    ///
    /// Fails with [`ReadToEndError::TooLong`] on reading more than `size_limit` bytes, discarding
    /// all data read. Uses unordered reads to be more efficient than using `AsyncRead` would
    /// allow. `size_limit` should be set to limit worst-case memory use.
    ///
    /// The returned buffer is guaranteed to be contiguous stream data: if any range between the
    /// first and last byte this call observed was consumed elsewhere and never delivered (for
    /// example by an earlier `read_to_end` future that was dropped mid-read, or by prior
    /// unordered reads), this fails with [`ReadToEndError::MissingData`] instead of silently
    /// filling the holes.
    ///
    /// This operation is *not* cancel-safe: dropping the returned future after it has consumed
    /// stream data discards that data irrecoverably. A subsequent `read_to_end` returns the
    /// remaining contiguous data, or fails with [`ReadToEndError::MissingData`] if the discard
    /// left a hole in what it observes.
    ///
    /// `ReadToEndError::TooLong`: Error returned when size limit is exceeded
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        ReadToEnd {
            stream: self,
            size_limit,
            read: Vec::new(),
            start: u64::MAX,
            end: 0,
        }
        .await
    }

    /// Stop accepting data
    ///
    /// Discards unread data and notifies the peer to stop transmitting. Once stopped, further
    /// attempts to operate on a stream will yield `ClosedStream` errors.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        let mut conn = self.conn.state.lock("RecvStream::stop");
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return Ok(());
        }
        conn.inner.recv_stream(self.stream).stop(error_code)?;
        conn.wake();
        self.all_data_read = true;
        Ok(())
    }

    /// Check if this stream has been opened during 0-RTT.
    ///
    /// In which case any non-idempotent request should be considered dangerous at the application
    /// level. Because read data is subject to replay attacks.
    pub fn is_0rtt(&self) -> bool {
        self.is_0rtt
    }

    /// Get the identity of this stream
    pub fn id(&self) -> StreamId {
        self.stream
    }

    /// Completes when the stream has been reset by the peer or otherwise closed
    ///
    /// Yields `Some` with the reset error code when the stream is reset by the peer. Yields `None`
    /// when the stream was previously [`stop()`](Self::stop)ed, or when the stream was
    /// [`finish()`](crate::SendStream::finish)ed by the peer and all data has been received, after
    /// which it is no longer meaningful for the stream to be reset.
    ///
    /// This operation is cancel-safe.
    pub async fn received_reset(&mut self) -> Result<Option<VarInt>, ResetError> {
        poll_fn(|cx| {
            let mut conn = self.conn.state.lock("RecvStream::reset");
            if self.is_0rtt && conn.check_0rtt().is_err() {
                return Poll::Ready(Err(ResetError::ZeroRttRejected));
            }

            if let Some(code) = self.reset {
                return Poll::Ready(Ok(Some(code)));
            }

            match conn.inner.recv_stream(self.stream).received_reset() {
                Err(_) => Poll::Ready(Ok(None)),
                Ok(Some(error_code)) => {
                    // Stream state has just now been freed, so the connection may need to issue new
                    // stream ID flow control credit
                    conn.wake();
                    Poll::Ready(Ok(Some(error_code)))
                }
                Ok(None) => {
                    if let Some(e) = &conn.error {
                        return Poll::Ready(Err(e.clone().into()));
                    }
                    // Resets always notify readers, since a reset is an immediate read error. We
                    // could introduce a dedicated channel to reduce the risk of spurious wakeups,
                    // but that increased complexity is probably not justified, as an application
                    // that is expecting a reset is not likely to receive large amounts of data.
                    conn.blocked_readers.insert(self.stream, cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Handle common logic related to reading out of a receive stream
    ///
    /// This takes an `FnMut` closure that takes care of the actual reading process, matching
    /// the detailed read semantics for the calling function with a particular return type.
    /// The closure can read from the passed `&mut Chunks` and has to return the status after
    /// reading: the amount of data read, and the status after the final read call.
    fn poll_read_generic<T, U>(
        &mut self,
        cx: &mut Context,
        ordered: bool,
        mut read_fn: T,
    ) -> Poll<Result<Option<U>, ReadError>>
    where
        T: FnMut(&mut Chunks) -> ReadStatus<U>,
    {
        use crate::ReadError::*;
        if self.all_data_read {
            return Poll::Ready(Ok(None));
        }

        let mut conn = self.conn.state.lock("RecvStream::poll_read");
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }

        // If we stored an error during a previous call, return it now. This can happen if a
        // `read_fn` both wants to return data and also returns an error in its final stream status.
        let status = match self.reset {
            Some(code) => ReadStatus::Failed(None, Reset(code)),
            None => {
                let mut recv = conn.inner.recv_stream(self.stream);
                let mut chunks = recv.read(ordered)?;
                let status = read_fn(&mut chunks);
                if chunks.finalize().should_transmit() {
                    conn.wake();
                }
                status
            }
        };

        match status {
            ReadStatus::Readable(read) => Poll::Ready(Ok(Some(read))),
            ReadStatus::Finished(read) => {
                self.all_data_read = true;
                Poll::Ready(Ok(read))
            }
            ReadStatus::Failed(read, Blocked) => match read {
                Some(val) => Poll::Ready(Ok(Some(val))),
                None => {
                    if let Some(ref x) = conn.error {
                        return Poll::Ready(Err(ReadError::ConnectionLost(x.clone())));
                    }
                    conn.blocked_readers.insert(self.stream, cx.waker().clone());
                    Poll::Pending
                }
            },
            ReadStatus::Failed(read, Reset(error_code)) => match read {
                None => {
                    self.all_data_read = true;
                    self.reset = Some(error_code);
                    Poll::Ready(Err(ReadError::Reset(error_code)))
                }
                done => {
                    self.reset = Some(error_code);
                    Poll::Ready(Ok(done))
                }
            },
            ReadStatus::Failed(_read, ConnectionClosed) => {
                self.all_data_read = true;
                Poll::Ready(Err(ReadError::ConnectionLost(
                    ConnectionError::LocallyClosed,
                )))
            }
        }
    }
}

enum ReadStatus<T> {
    Readable(T),
    Finished(Option<T>),
    Failed(Option<T>, crate::ReadError),
}

impl<T> From<(Option<T>, Option<crate::ReadError>)> for ReadStatus<T> {
    fn from(status: (Option<T>, Option<crate::ReadError>)) -> Self {
        match status {
            (read, None) => Self::Finished(read),
            (read, Some(e)) => Self::Failed(read, e),
        }
    }
}

/// Future produced by `RecvStream::read_to_end()`.
struct ReadToEnd<'a> {
    stream: &'a mut RecvStream,
    read: Vec<(Bytes, u64)>,
    start: u64,
    end: u64,
    size_limit: usize,
}

impl Future for ReadToEnd<'_> {
    type Output = Result<Vec<u8>, ReadToEndError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match ready!(self.stream.poll_read_chunk(cx, usize::MAX, false))? {
                Some(chunk) => {
                    self.start = self.start.min(chunk.offset);
                    let end = chunk.bytes.len() as u64 + chunk.offset;
                    if (end - self.start) > self.size_limit as u64 {
                        return Poll::Ready(Err(ReadToEndError::TooLong));
                    }
                    self.end = self.end.max(end);
                    self.read.push((chunk.bytes, chunk.offset));
                }
                None => {
                    if self.end == 0 {
                        // Never received anything
                        return Poll::Ready(Ok(Vec::new()));
                    }
                    let (start, end) = (self.start, self.end);
                    return match assemble_unordered_chunks(&mut self.read, start, end) {
                        Some(buffer) => Poll::Ready(Ok(buffer)),
                        // End-of-stream was signaled but ranges in [start, end)
                        // were consumed elsewhere (e.g. by a dropped earlier
                        // read) and can never be re-read. Fail loud rather
                        // than fabricate zero-filled bytes.
                        None => Poll::Ready(Err(ReadToEndError::MissingData)),
                    };
                }
            }
        }
    }
}

/// Assemble unordered chunks into a contiguous buffer
///
/// Returns `None` unless the chunks tile `[start, end)` exactly — each byte
/// present once, with no gaps and no overlaps. A `None` means part of the
/// stream was consumed but never delivered to this reader; zero-filling the
/// holes (the previous behavior) would silently corrupt the result.
///
/// Overlapping chunks (from retransmissions or the ordered→unordered
/// transition) are expected to carry identical data at the same offsets.
/// If overlapping bytes DIFFER, the transport has delivered corrupt content
/// — a data-integrity violation. This function fails loud (returns `None`)
/// rather than silently assembling mismatched bytes, and logs a diagnostic
/// so the root cause can be identified.
fn assemble_unordered_chunks(chunks: &mut [(Bytes, u64)], start: u64, end: u64) -> Option<Vec<u8>> {
    chunks.sort_unstable_by_key(|&(_, offset)| offset);
    let mut buffer = Vec::with_capacity((end - start) as usize);
    for (data, offset) in chunks.iter() {
        let expected = start + buffer.len() as u64;
        if *offset > expected {
            // Gap: a range in [start, end) was consumed but never delivered
            // to this reader. Zero-filling it (the previous behavior) would
            // silently corrupt the result.
            return None;
        }
        // Benign overlap (duplicate delivery, e.g. across the
        // ordered->unordered transition): skip the already-assembled prefix.
        let skip = (expected - *offset) as usize;
        if skip > 0 && skip <= data.len() {
            // Data-integrity check: when chunks overlap, the overlapping
            // bytes MUST be identical (QUIC RFC 9000 §13.1 requires
            // retransmissions to carry the same data). If they differ, the
            // transport has delivered corrupt content. Fail loud rather
            // than silently assembling mismatched bytes.
            let prev = &buffer[buffer.len() - skip..];
            let curr = &data[..skip];
            if prev != curr {
                let first_diff = prev.iter().zip(curr).position(|(a, b)| a != b);
                tracing::error!(
                    target: "ant_quic::data_integrity",
                    stream_offset = offset,
                    overlap_len = skip,
                    first_diff_within_overlap = first_diff,
                    "DATA INTEGRITY VIOLATION: overlapping stream chunks have \
                     different byte content at the same offset — the transport \
                     delivered corrupt data. Dropping message to prevent silent \
                     corruption of signed payloads."
                );
                return None;
            }
        }
        if skip < data.len() {
            buffer.extend_from_slice(&data[skip..]);
        }
    }
    // `end` is the maximum chunk end, so full coverage always lands on it
    if start + buffer.len() as u64 == end {
        Some(buffer)
    } else {
        None
    }
}

/// Errors from [`RecvStream::read_to_end`]
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadToEndError {
    /// An error occurred during reading
    #[error("read error: {0}")]
    Read(#[from] ReadError),
    /// The stream is larger than the user-supplied limit
    #[error("stream too long")]
    TooLong,
    /// The stream ended, but ranges of it were consumed and never delivered to this call
    ///
    /// Returning a buffer would require fabricating the missing bytes (previously they were
    /// silently zero-filled — a data-integrity hazard for consumers without payload checksums).
    /// This happens after an earlier `read_to_end` future on this stream was dropped mid-read
    /// (`read_to_end` is not cancel-safe), or when prior unordered reads left a hole between
    /// the chunks this call observed.
    #[error("stream ended with undelivered data ranges")]
    MissingData,
}

impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(Self::poll_read_buf(self.get_mut(), cx, buf))?;
        Poll::Ready(Ok(()))
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let mut conn = self.conn.state.lock("RecvStream::drop");

        // clean up any previously registered wakers
        conn.blocked_readers.remove(&self.stream);

        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if !self.all_data_read {
            // Ignore ClosedStream errors
            let _ = conn.inner.recv_stream(self.stream).stop(0u32.into());
            conn.wake();
        }
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream
    ///
    /// Carries an application-defined error code.
    #[error("stream reset by peer: error {0}")]
    Reset(VarInt),
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been stopped, finished, or reset
    #[error("closed stream")]
    ClosedStream,
    /// Attempted an ordered read following an unordered read
    ///
    /// Performing an unordered read allows discontinuities to arise in the receive buffer of a
    /// stream which cannot be recovered, making further ordered reads impossible.
    #[error("ordered read after unordered read")]
    IllegalOrderedRead,
    /// This was a 0-RTT stream and the server rejected it
    ///
    /// Can only occur on clients for 0-RTT streams, which can be opened using
    /// [`Connecting::into_0rtt()`].
    ///
    /// [`Connecting::into_0rtt()`]: crate::Connecting::into_0rtt()
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

impl From<ReadableError> for ReadError {
    fn from(e: ReadableError) -> Self {
        match e {
            ReadableError::ClosedStream => Self::ClosedStream,
            ReadableError::IllegalOrderedRead => Self::IllegalOrderedRead,
            ReadableError::ConnectionClosed => Self::ConnectionLost(ConnectionError::LocallyClosed),
        }
    }
}

impl From<ResetError> for ReadError {
    fn from(e: ResetError) -> Self {
        match e {
            ResetError::ConnectionLost(e) => Self::ConnectionLost(e),
            ResetError::ZeroRttRejected => Self::ZeroRttRejected,
        }
    }
}

impl From<ReadError> for io::Error {
    fn from(x: ReadError) -> Self {
        use ReadError::*;
        let kind = match x {
            Reset { .. } | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            ConnectionLost(_) | ClosedStream => io::ErrorKind::NotConnected,
            IllegalOrderedRead => io::ErrorKind::InvalidInput,
        };
        Self::new(kind, x)
    }
}

/// Errors that arise while waiting for a stream to be reset
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResetError {
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// This was a 0-RTT stream and the server rejected it
    ///
    /// Can only occur on clients for 0-RTT streams, which can be opened using
    /// [`Connecting::into_0rtt()`].
    ///
    /// [`Connecting::into_0rtt()`]: crate::Connecting::into_0rtt()
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

impl From<ResetError> for io::Error {
    fn from(x: ResetError) -> Self {
        use ResetError::*;
        let kind = match x {
            ZeroRttRejected => io::ErrorKind::ConnectionReset,
            ConnectionLost(_) => io::ErrorKind::NotConnected,
        };
        Self::new(kind, x)
    }
}

/// Future produced by [`RecvStream::read()`].
///
/// [`RecvStream::read()`]: crate::RecvStream::read
struct Read<'a> {
    stream: &'a mut RecvStream,
    buf: ReadBuf<'a>,
}

impl Future for Read<'_> {
    type Output = Result<Option<usize>, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        ready!(this.stream.poll_read_buf(cx, &mut this.buf))?;
        match this.buf.filled().len() {
            0 if this.buf.capacity() != 0 => Poll::Ready(Ok(None)),
            n => Poll::Ready(Ok(Some(n))),
        }
    }
}

/// Future produced by `RecvStream::read_exact()`.
struct ReadExact<'a> {
    stream: &'a mut RecvStream,
    buf: ReadBuf<'a>,
}

impl Future for ReadExact<'_> {
    type Output = Result<(), ReadExactError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut remaining = this.buf.remaining();
        while remaining > 0 {
            ready!(this.stream.poll_read_buf(cx, &mut this.buf))?;
            let new = this.buf.remaining();
            if new == remaining {
                return Poll::Ready(Err(ReadExactError::FinishedEarly(this.buf.filled().len())));
            }
            remaining = new;
        }
        Poll::Ready(Ok(()))
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadExactError {
    /// The stream finished before all bytes were read
    #[error("stream finished early ({0} bytes read)")]
    FinishedEarly(usize),
    /// A read error occurred
    #[error(transparent)]
    ReadError(#[from] ReadError),
}

/// Future produced by `RecvStream::read_chunk()`.
struct ReadChunk<'a> {
    stream: &'a mut RecvStream,
    max_length: usize,
    ordered: bool,
}

impl Future for ReadChunk<'_> {
    type Output = Result<Option<Chunk>, ReadError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (max_length, ordered) = (self.max_length, self.ordered);
        self.stream.poll_read_chunk(cx, max_length, ordered)
    }
}

/// Future produced by `RecvStream::read_chunks()`.
struct ReadChunks<'a> {
    stream: &'a mut RecvStream,
    bufs: &'a mut [Bytes],
}

impl Future for ReadChunks<'_> {
    type Output = Result<Option<usize>, ReadError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read_chunks(cx, this.bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks_of(payload: &[u8], ranges: &[(usize, usize)]) -> Vec<(Bytes, u64)> {
        ranges
            .iter()
            .map(|&(start, end)| (Bytes::copy_from_slice(&payload[start..end]), start as u64))
            .collect()
    }

    #[test]
    fn assemble_accepts_exact_tiling_in_any_order() {
        let payload: Vec<u8> = (0..10_706).map(|i| (i % 250 + 1) as u8).collect();
        let mut chunks = chunks_of(&payload, &[(4344, 10_706), (0, 1448), (1448, 4344)]);
        let buffer =
            assemble_unordered_chunks(&mut chunks, 0, 10_706).expect("exact tiling must assemble");
        assert_eq!(buffer, payload);
    }

    #[test]
    fn assemble_accepts_nonzero_start() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 250 + 1) as u8).collect();
        let mut chunks = chunks_of(&payload, &[(2048, 4096), (1024, 2048)]);
        let buffer = assemble_unordered_chunks(&mut chunks, 1024, 4096)
            .expect("suffix tiling must assemble");
        assert_eq!(buffer, &payload[1024..]);
    }

    /// The captured corruption geometry: a 10,706-byte message whose range
    /// [1085, 3981) (2×1448 bytes) was consumed by a dropped reader. The old
    /// code shipped this as `Ok` with the hole zero-filled; it must now be
    /// rejected.
    #[test]
    fn assemble_rejects_captured_zero_gap_geometry() {
        let payload: Vec<u8> = (0..10_706).map(|i| (i % 250 + 1) as u8).collect();
        let mut chunks = chunks_of(&payload, &[(0, 1085), (3981, 10_706)]);
        assert!(assemble_unordered_chunks(&mut chunks, 0, 10_706).is_none());
    }

    /// Overlaps are benign duplicate delivery (e.g. across the
    /// ordered->unordered transition) — the overlapping prefix is skipped
    /// and assembly succeeds with each byte appearing exactly once. Only
    /// gaps (missing data) are fatal.
    #[test]
    fn assemble_tolerates_overlapping_chunks() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 250 + 1) as u8).collect();
        let mut chunks = chunks_of(&payload, &[(0, 2048), (1024, 4096)]);
        let buffer = assemble_unordered_chunks(&mut chunks, 0, 4096).expect("overlap is benign");
        assert_eq!(buffer, payload);
    }

    #[test]
    fn assemble_tolerates_duplicate_chunk() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 250 + 1) as u8).collect();
        let mut chunks = chunks_of(&payload, &[(0, 2048), (0, 2048), (2048, 4096)]);
        let buffer = assemble_unordered_chunks(&mut chunks, 0, 4096).expect("duplicate is benign");
        assert_eq!(buffer, payload);
    }
}
