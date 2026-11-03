// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use stored_run::StoredRun;

use crate::{Chunk, Chunks, ClosedStream, ConnectionError, ReadableError, StreamId};
use bytes::Bytes;
use thiserror::Error;
use tokio::io::ReadBuf;

use super::connection::ConnectionRef;
use crate::VarInt;

/// Bound on the number of disjoint entries `read_to_end` accumulates
///
/// `read_to_end` keeps delivered chunks ordered by offset and merges a chunk
/// into every neighbour it touches, so a contiguous stream — however it is
/// framed or reordered — is a single entry whose bytes are bounded by the
/// caller's `size_limit`. A new entry is needed only across a gap that is
/// still open. This cap is the ceiling on the entry count after that merge;
/// it matches the stream assembler's bound on disjoint received ranges, so
/// ordinary reordered or lossy traffic stays well under it while the per-read
/// overhead stays bounded regardless of how the data is framed.
const MAX_READ_TO_END_ENTRIES: usize = 4096;

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
    /// Lifecycle generation of the connection this stream was accepted on,
    /// stamped by the P2P layer. `u64::MAX` until stamped.
    connection_generation: u64,
    all_data_read: bool,
    reset: Option<VarInt>,
}

impl RecvStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            connection_generation: u64::MAX,
            all_data_read: false,
            reset: None,
        }
    }

    pub(crate) fn set_connection_generation(&mut self, generation: u64) {
        self.connection_generation = generation;
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
            read: BTreeMap::new(),
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

    /// Lifecycle generation of the connection this stream was accepted or
    /// opened on.
    ///
    /// The value is stamped when the stream is handed to the application by
    /// [`P2pEndpoint::accept_bi`] or opened through [`P2pEndpoint::open_bi`],
    /// and never changes afterwards, so it is provenance: after a follow
    /// (ADR-017) a superseded connection stays open and keeps delivering
    /// streams, and the live winner may change again while this stream is
    /// being processed — this still reports the connection the stream
    /// actually arrived on or was opened over. Generations are allocated
    /// per endpoint; compare them only with values from the same endpoint
    /// (for example [`P2pEndpoint::current_connection_generation`] or
    /// [`P2pEndpoint::recv_with_generation`]).
    ///
    /// Returns `u64::MAX` when the stream was not accepted through a
    /// lifecycle-tracked path — the same sentinel [`Node::recv_with_generation`]
    /// uses for data that predates authentication.
    ///
    /// [`P2pEndpoint::accept_bi`]: crate::P2pEndpoint::accept_bi
    /// [`P2pEndpoint::current_connection_generation`]: crate::P2pEndpoint::current_connection_generation
    /// [`P2pEndpoint::recv_with_generation`]: crate::P2pEndpoint::recv_with_generation
    /// [`Node::recv_with_generation`]: crate::Node::recv_with_generation
    pub fn connection_generation(&self) -> u64 {
        self.connection_generation
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
///
/// CRITICAL: Chunks are copied into owned `Vec<u8>` immediately on arrival,
/// NOT stored as `Bytes` references. This is because `Bytes` slices alias
/// decrypted packet allocations that the QUIC stack recycles under concurrent
/// multi-stream load. Holding `Bytes` references across `.await` points
/// (between `poll_read_chunk` calls) creates a window where another reader
/// task can trigger packet processing that overwrites the aliased allocation,
/// producing a torn read. Copying to `Vec<u8>` on arrival closes this window.
/// See: FINDING-recv-boundary-aliasing.md
struct ReadToEnd<'a> {
    stream: &'a mut RecvStream,
    /// Contiguous runs keyed by start offset. [`StoredRun`] keeps both append
    /// and prepend of newly delivered bytes amortised O(new bytes), and its
    /// merge helpers always charge bulk copies of already-stored bytes so
    /// reverse gap-filling cannot force O(n²) work.
    read: BTreeMap<u64, StoredRun>,
    start: u64,
    end: u64,
    size_limit: usize,
}

/// Whether accepting a chunk at `chunk_offset` of length `chunk_len` would make
/// the observed `[start, end)` span exceed `size_limit`.
///
/// Uses the global end (`end.max(chunk_end)`), not only the arriving chunk's
/// end: a high offset accepted first must still bound a later low-offset chunk.
fn read_to_end_span_too_long(
    start: u64,
    end: u64,
    chunk_offset: u64,
    chunk_len: usize,
    size_limit: usize,
) -> bool {
    let span_start = start.min(chunk_offset);
    let Some(chunk_end) = chunk_offset.checked_add(chunk_len as u64) else {
        return true;
    };
    let span_end = end.max(chunk_end);
    span_end.saturating_sub(span_start) > size_limit as u64
}

impl Future for ReadToEnd<'_> {
    type Output = Result<Vec<u8>, ReadToEndError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match ready!(self.stream.poll_read_chunk(cx, usize::MAX, false))? {
                Some(chunk) => {
                    if read_to_end_span_too_long(
                        self.start,
                        self.end,
                        chunk.offset,
                        chunk.bytes.len(),
                        self.size_limit,
                    ) {
                        return Poll::Ready(Err(ReadToEndError::TooLong));
                    }
                    self.start = self.start.min(chunk.offset);
                    let end = chunk.bytes.len() as u64 + chunk.offset;
                    self.end = self.end.max(end);
                    // Copy bytes into owned storage IMMEDIATELY, dropping the
                    // Bytes reference before the next poll cycle. This prevents
                    // aliasing corruption from recycled packet allocations under
                    // concurrent multi-stream load.
                    if let Err(e) = push_read_chunk(&mut self.read, &chunk.bytes, chunk.offset) {
                        return Poll::Ready(Err(e));
                    }
                }
                None => {
                    if self.end == 0 {
                        // Never received anything
                        return Poll::Ready(Ok(Vec::new()));
                    }
                    let (start, end) = (self.start, self.end);
                    let mut ordered: Vec<(Vec<u8>, u64)> = std::mem::take(&mut self.read)
                        .into_iter()
                        .map(|(offset, data)| (data.into_vec(), offset))
                        .collect();
                    return match assemble_unordered_chunks(&mut ordered, start, end) {
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

/// Contiguous byte run with merge primitives that always charge stored copies.
///
/// The inner deque is private to this module so bulk movement of already-stored
/// bytes cannot bypass [`record_stored_byte_copy`]. Newly delivered bytes use
/// [`StoredRun::extend_new`] / [`StoredRun::prepend_new`] (no stored charge);
/// joining two runs uses [`StoredRun::append_run`] / [`StoredRun::prepend_run`]
/// (always charges the side being moved). Heap requests during tests are also
/// observed by [`crate::test_alloc`] so a silent `bytes ++ suffix` rebuild in
/// [`StoredRun::prepend_new`] cannot dodge the copy-cost regression.
mod stored_run {
    use std::collections::VecDeque;

    use super::record_stored_byte_copy;

    #[derive(Clone, Debug, Default)]
    pub(super) struct StoredRun {
        bytes: VecDeque<u8>,
    }

    impl StoredRun {
        pub(super) fn from_slice(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.iter().copied().collect(),
            }
        }

        pub(super) fn from_vec(bytes: Vec<u8>) -> Self {
            Self {
                bytes: VecDeque::from(bytes),
            }
        }

        pub(super) fn len(&self) -> usize {
            self.bytes.len()
        }

        pub(super) fn get(&self, index: usize) -> Option<u8> {
            self.bytes.get(index).copied()
        }

        pub(super) fn into_vec(self) -> Vec<u8> {
            self.bytes.into_iter().collect()
        }

        #[cfg(test)]
        pub(super) fn to_vec(&self) -> Vec<u8> {
            self.bytes.iter().copied().collect()
        }

        /// Append newly delivered bytes (not already stored). No copy charge.
        pub(super) fn extend_new(&mut self, bytes: &[u8]) {
            self.bytes.extend(bytes.iter().copied());
        }

        /// Prepend newly delivered bytes in place. Amortised O(`bytes.len()`);
        /// the already-stored suffix is not recopied and is not charged.
        pub(super) fn prepend_new(&mut self, bytes: &[u8]) {
            self.bytes.reserve(bytes.len());
            for &b in bytes.iter().rev() {
                self.bytes.push_front(b);
            }
        }

        /// Rebuild as `prefix ++ self`, charging and allocating `|self|`.
        ///
        /// Models the pre-fix `Vec` prepend for the descending allocation
        /// control. Production [`Self::prepend_new`] must not call this.
        #[cfg(test)]
        pub(super) fn rebuild_with_prefix(&mut self, prefix: &[u8]) {
            record_stored_byte_copy(self.bytes.len());
            let need = prefix.len().saturating_add(self.bytes.len());
            let mut rebuilt = VecDeque::with_capacity(need);
            rebuilt.extend(prefix.iter().copied());
            rebuilt.extend(self.bytes.iter().copied());
            self.bytes = rebuilt;
        }

        /// Append another stored run onto `self`. Charges `|other|`.
        pub(super) fn append_run(&mut self, other: &mut Self) {
            record_stored_byte_copy(other.bytes.len());
            self.bytes.append(&mut other.bytes);
        }

        /// Prepend another stored run onto `self`. Charges `|prefix|`.
        pub(super) fn prepend_run(&mut self, prefix: &Self) {
            record_stored_byte_copy(prefix.bytes.len());
            self.bytes.reserve(prefix.bytes.len());
            for &b in prefix.bytes.iter().rev() {
                self.bytes.push_front(b);
            }
        }

        /// Copy this run into a flat buffer. Charges `|self|`.
        pub(super) fn copy_into(&self, dst: &mut [u8], base: usize) -> Result<(), ()> {
            let end = base.saturating_add(self.bytes.len());
            if end > dst.len() || base > dst.len() {
                return Err(());
            }
            record_stored_byte_copy(self.bytes.len());
            let (left, right) = self.bytes.as_slices();
            dst[base..base + left.len()].copy_from_slice(left);
            if !right.is_empty() {
                dst[base + left.len()..end].copy_from_slice(right);
            }
            Ok(())
        }
    }
}

/// Test-only counter of already-stored entry bytes bulk-copied during merge.
///
/// Every bulk move of stored bytes goes through [`StoredRun`] merge helpers
/// (`append_run` / `prepend_run` / `copy_into` / `rebuild_with_prefix`), which
/// always call [`record_stored_byte_copy`]. In-place prepend/extend of *new*
/// bytes does not charge — that is the amortised-O(new) path.
#[cfg(test)]
mod merge_copy_stats {
    use std::cell::Cell;

    thread_local! {
        static STORED_BYTES_COPIED: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn reset() {
        STORED_BYTES_COPIED.with(|c| c.set(0));
    }

    pub(super) fn record(len: usize) {
        STORED_BYTES_COPIED.with(|c| c.set(c.get().saturating_add(len as u64)));
    }

    pub(super) fn total() -> u64 {
        STORED_BYTES_COPIED.with(|c| c.get())
    }
}

/// Test-only heap-request scope backed by [`crate::test_alloc`].
///
/// Catches a `prepend_new` rebuild that skips [`record_stored_byte_copy`]:
/// at N=8 000 the bad path requests ~32 MB vs ~17 KB for in-place prepend.
#[cfg(test)]
mod merge_alloc_stats {
    pub(super) fn scope<T>(f: impl FnOnce() -> T) -> (T, u64) {
        crate::test_alloc::begin();
        let out = f();
        (out, crate::test_alloc::end())
    }
}

#[cfg(test)]
#[inline]
fn record_stored_byte_copy(len: usize) {
    merge_copy_stats::record(len);
}

#[cfg(not(test))]
#[inline]
fn record_stored_byte_copy(_len: usize) {}

/// Insert a delivered chunk, merging it into every neighbour it touches.
///
/// Bytes are copied into owned storage immediately (see [`ReadToEnd`]), dropping
/// the `Bytes` reference before the next poll cycle. Entries stay ordered by
/// offset. A chunk that continues an entry, precedes one, or closes the gap
/// between two is absorbed, so a contiguous stream stays a single entry
/// whichever order the chunks arrive in. The entry count is capped by
/// [`MAX_READ_TO_END_ENTRIES`] after that merge. A chunk that still needs its
/// own entry past the cap fails the read with [`ReadToEndError::TooLong`], the
/// same way the offset-span limit does.
///
/// Overlapping bytes must match. A mismatch is the same integrity failure
/// [`assemble_unordered_chunks`] reports, and fails the read with
/// [`ReadToEndError::MissingData`].
fn push_read_chunk(
    read: &mut BTreeMap<u64, StoredRun>,
    bytes: &[u8],
    offset: u64,
) -> Result<(), ReadToEndError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let Some(new_end) = offset.checked_add(bytes.len() as u64) else {
        return Err(ReadToEndError::TooLong);
    };

    if extend_exact_predecessor(read, bytes, offset, new_end) {
        return Ok(());
    }
    if prepend_exact_successor(read, bytes, offset, new_end) {
        return Ok(());
    }
    merge_overlapping_or_insert(read, bytes, offset, new_end)
}

/// Append `bytes` when they start exactly where an existing entry ends.
///
/// Returns `false` when the chunk overlaps that entry or a later one, so the
/// caller can merge with an integrity check instead of overwriting bytes.
fn extend_exact_predecessor(
    read: &mut BTreeMap<u64, StoredRun>,
    bytes: &[u8],
    offset: u64,
    new_end: u64,
) -> bool {
    let Some((&prev_off, prev)) = read.range(..=offset).next_back() else {
        return false;
    };
    let Some(prev_end) = prev_off.checked_add(prev.len() as u64) else {
        return false;
    };
    if prev_end != offset {
        return false;
    }
    // A later entry that starts inside this chunk overlaps it.
    if read.range(offset..new_end).next().is_some() {
        return false;
    }
    let Some(prev) = read.get_mut(&prev_off) else {
        return false;
    };
    prev.extend_new(bytes);
    absorb_following(read, prev_off);
    true
}

/// Place `bytes` immediately before the entry that starts at `new_end`.
///
/// Returns `false` when any stored entry overlaps the new chunk.
///
/// Cost is O(`bytes.len()`): each new byte is `push_front`ed onto the existing
/// run. The already-stored suffix is not recopied.
fn prepend_exact_successor(
    read: &mut BTreeMap<u64, StoredRun>,
    bytes: &[u8],
    offset: u64,
    new_end: u64,
) -> bool {
    if let Some((&prev_off, prev)) = read.range(..=offset).next_back() {
        let Some(prev_end) = prev_off.checked_add(prev.len() as u64) else {
            return false;
        };
        if prev_end > offset {
            return false;
        }
    }
    if read.range(offset..new_end).next().is_some() {
        return false;
    }
    let Some(mut next) = read.remove(&new_end) else {
        return false;
    };
    // Amortised O(bytes.len()) via StoredRun::prepend_new. Rebuilding with
    // `bytes ++ suffix` would have to go through append_run / copy_into and
    // would charge `|suffix|` — the copy-cost tests fail on that volume.
    next.prepend_new(bytes);
    read.insert(offset, next);
    let start = absorb_preceding(read, offset);
    absorb_following(read, start);
    true
}

/// Fold the entry that ends at `start` into a neighbour. Returns the key of the
/// combined entry.
///
/// Merges the smaller run into the larger so each join costs O(min(|left|,
/// |right|)), not O(|right|) unconditionally.
fn absorb_preceding(read: &mut BTreeMap<u64, StoredRun>, start: u64) -> u64 {
    let Some((&prev_off, prev)) = read.range(..start).next_back() else {
        return start;
    };
    let Some(prev_end) = prev_off.checked_add(prev.len() as u64) else {
        return start;
    };
    if prev_end != start {
        return start;
    }
    let Some(mut current) = read.remove(&start) else {
        return start;
    };
    let prev_len = read.get(&prev_off).map_or(0, StoredRun::len);
    if prev_len >= current.len() {
        let Some(prev) = read.get_mut(&prev_off) else {
            read.insert(start, current);
            return start;
        };
        prev.append_run(&mut current);
        prev_off
    } else {
        let Some(prev) = read.remove(&prev_off) else {
            read.insert(start, current);
            return start;
        };
        current.prepend_run(&prev);
        read.insert(prev_off, current);
        prev_off
    }
}

/// Join every entry that now starts where `start` ends.
///
/// Always merges the smaller run into the larger (append when the left is at
/// least as big; otherwise prepend the left onto the right and keep key
/// `start`). Reverse pairwise gap-filling therefore copies O(N) bytes total
/// instead of N*(N-2)/4.
fn absorb_following(read: &mut BTreeMap<u64, StoredRun>, start: u64) {
    loop {
        let Some(buf) = read.get(&start) else {
            return;
        };
        let Some(end) = start.checked_add(buf.len() as u64) else {
            return;
        };
        let Some(mut next) = read.remove(&end) else {
            return;
        };
        let left_len = read.get(&start).map_or(0, StoredRun::len);
        if left_len >= next.len() {
            let Some(buf) = read.get_mut(&start) else {
                read.insert(end, next);
                return;
            };
            buf.append_run(&mut next);
        } else {
            let Some(left) = read.remove(&start) else {
                read.insert(end, next);
                return;
            };
            next.prepend_run(&left);
            read.insert(start, next);
        }
    }
}

/// Merge `bytes` into every entry they overlap, or insert them as a new entry.
///
/// The cap is applied after the merge: a chunk absorbed by a neighbour does
/// not consume a new slot.
fn merge_overlapping_or_insert(
    read: &mut BTreeMap<u64, StoredRun>,
    bytes: &[u8],
    offset: u64,
    new_end: u64,
) -> Result<(), ReadToEndError> {
    let mut merge_from = offset;
    if let Some((&prev_off, prev)) = read.range(..=offset).next_back() {
        if let Some(prev_end) = prev_off.checked_add(prev.len() as u64)
            && prev_end > offset
        {
            merge_from = prev_off;
        }
    }

    let keys: Vec<u64> = read
        .range(merge_from..=new_end)
        .map(|(&key, _)| key)
        .collect();
    if keys.is_empty() {
        if read.len() >= MAX_READ_TO_END_ENTRIES {
            return Err(ReadToEndError::TooLong);
        }
        read.insert(offset, StoredRun::from_slice(bytes));
        return Ok(());
    }

    let first = keys[0];
    let last = keys[keys.len() - 1];
    let last_len = read.get(&last).map_or(0, StoredRun::len);
    let Some(last_end) = last.checked_add(last_len as u64) else {
        return Err(ReadToEndError::TooLong);
    };
    let merged_start = first.min(offset);
    let merged_end = last_end.max(new_end);
    let Ok(merged_len) = usize::try_from(merged_end - merged_start) else {
        return Err(ReadToEndError::TooLong);
    };
    let mut merged = vec![0u8; merged_len];
    for key in &keys {
        let Some(buf) = read.get(key) else {
            continue;
        };
        let base = usize::try_from(*key - merged_start).unwrap_or(merged_len);
        if buf.copy_into(&mut merged, base).is_err() {
            return Err(ReadToEndError::TooLong);
        }
    }

    let base = usize::try_from(offset - merged_start).unwrap_or(merged_len);
    for (i, &byte) in bytes.iter().enumerate() {
        let idx = base.saturating_add(i);
        let abs = offset + i as u64;
        if let Some(existing) = stored_byte(read, &keys, abs) {
            if existing != byte {
                let first_diff = bytes.iter().enumerate().position(|(j, b)| {
                    stored_byte(read, &keys, offset + j as u64).is_some_and(|prev| prev != *b)
                });
                tracing::error!(
                    target: "ant_quic::data_integrity",
                    stream_offset = offset,
                    overlap_len = bytes.len(),
                    first_diff_within_overlap = first_diff,
                    "DATA INTEGRITY VIOLATION: overlapping stream chunks have \
                     different byte content at the same offset — the transport \
                     delivered corrupt data. Dropping message to prevent silent \
                     corruption of signed payloads."
                );
                return Err(ReadToEndError::MissingData);
            }
        } else if idx >= merged.len() {
            return Err(ReadToEndError::TooLong);
        } else {
            merged[idx] = byte;
        }
    }

    for key in &keys {
        read.remove(key);
    }
    read.insert(merged_start, StoredRun::from_vec(merged));
    if read.len() > MAX_READ_TO_END_ENTRIES {
        return Err(ReadToEndError::TooLong);
    }
    Ok(())
}

fn stored_byte(read: &BTreeMap<u64, StoredRun>, keys: &[u64], abs: u64) -> Option<u8> {
    for key in keys {
        let Some(buf) = read.get(key) else {
            continue;
        };
        let Some(end) = key.checked_add(buf.len() as u64) else {
            continue;
        };
        if abs >= *key && abs < end {
            return buf.get((abs - key) as usize);
        }
    }
    None
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
fn assemble_unordered_chunks(
    chunks: &mut [(Vec<u8>, u64)],
    start: u64,
    end: u64,
) -> Option<Vec<u8>> {
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

    fn chunks_of(payload: &[u8], ranges: &[(usize, usize)]) -> Vec<(Vec<u8>, u64)> {
        ranges
            .iter()
            .map(|&(start, end)| (payload[start..end].to_vec(), start as u64))
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

    /// RED: contiguous (in-order) one-byte chunks, one per frame, must not grow
    /// the entry list — each continues the previous entry. Fails today: every
    /// chunk is pushed as its own `(Vec<u8>, u64)`, so a peer sending one byte
    /// per frame holds one heap allocation per byte up to the size limit, with
    /// no coalescing and no cap, while `recvd` stays a single range.
    #[test]
    fn read_to_end_coalesces_adjacent_chunks() {
        let mut read = BTreeMap::new();
        for i in 0..1024u64 {
            push_read_chunk(&mut read, &[(i % 251) as u8], i).expect("contiguous push");
        }
        assert_eq!(
            read.len(),
            1,
            "contiguous chunks must coalesce into one entry, not grow per byte"
        );
        let (&start, buf) = read.iter().next().expect("one coalesced entry");
        assert_eq!(start, 0);
        assert_eq!(buf.len(), 1024);
    }

    /// Non-adjacent chunks cannot coalesce; the entry count is capped and the
    /// read is rejected with `TooLong` rather than growing without bound.
    #[test]
    fn read_to_end_caps_entry_count_across_gaps() {
        let mut read = BTreeMap::new();
        let mut rejected_at = None;
        for i in 0..(MAX_READ_TO_END_ENTRIES as u64 + 16) {
            // One byte at every even offset: a one-byte gap keeps each chunk
            // from continuing the previous entry.
            match push_read_chunk(&mut read, &[1u8], i * 2) {
                Ok(()) => {}
                Err(ReadToEndError::TooLong) => {
                    rejected_at = Some(i);
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        let rejected_at = rejected_at.expect("entry count must be capped");
        assert_eq!(rejected_at as usize, MAX_READ_TO_END_ENTRIES);
        assert!(read.len() <= MAX_READ_TO_END_ENTRIES);
    }

    /// Chunks delivered as offsets 1,0,3,2,... are one contiguous stream. Each
    /// gap-filling byte has to merge with the neighbours on either side, so
    /// the 4096-entry cap is not spent on a reordered run that still fits in
    /// `size_limit`. `read_to_end` then assembles the original payload.
    #[test]
    fn read_to_end_accepts_out_of_order_gap_fill_past_entry_cap() {
        let count = MAX_READ_TO_END_ENTRIES + 2;
        let size_limit = 16 * 1024 * 1024;
        assert!(count > MAX_READ_TO_END_ENTRIES);
        assert!(count <= size_limit);

        let mut read = BTreeMap::new();
        let mut payload = vec![0u8; count];
        let mut start = u64::MAX;
        let mut end = 0u64;
        for pair in 0..(count / 2) {
            for offset in [pair * 2 + 1, pair * 2] {
                let byte = ((offset * 17) % 251) as u8;
                payload[offset] = byte;
                let offset = offset as u64;
                start = start.min(offset);
                let chunk_end = offset + 1;
                assert!(
                    chunk_end - start <= size_limit as u64,
                    "span exceeded size_limit"
                );
                end = end.max(chunk_end);
                push_read_chunk(&mut read, &[byte], offset)
                    .expect("gap-filling chunk under the entry cap");
            }
        }
        assert_eq!(start, 0);
        assert_eq!(end, count as u64);
        assert_eq!(
            read.len(),
            1,
            "contiguous out-of-order chunks must merge into one entry"
        );
        let buffer =
            assemble_entries(&read, start, end).expect("read_to_end assembles a contiguous stream");
        assert_eq!(buffer, payload);
    }

    /// Coalescing must preserve the assembled bytes: a stream delivered as many
    /// one-byte chunks assembles to the same payload as the original.
    #[test]
    fn read_to_end_coalesced_entries_assemble_correctly() {
        let payload: Vec<u8> = (0..2048u32).map(|i| (i % 250 + 1) as u8).collect();
        let mut read = BTreeMap::new();
        for (i, b) in payload.iter().enumerate() {
            push_read_chunk(&mut read, &[*b], i as u64).expect("contiguous push");
        }
        assert_eq!(read.len(), 1);
        let buffer = assemble_entries(&read, 0, payload.len() as u64)
            .expect("coalesced single entry must assemble");
        assert_eq!(buffer, payload);
    }

    /// Cost model for the pre-fix prepend: `bytes.to_vec()` then
    /// `extend_from_slice(&suffix)` recopies the whole following entry.
    fn legacy_vec_prepend_suffix_copies(n: usize) -> u64 {
        let mut suffix = Vec::new();
        let mut copied = 0u64;
        for i in (0..n).rev() {
            let byte = ((i * 17) % 251) as u8;
            // Charge the `extend_from_slice(&next)` of the old prepend path.
            copied = copied.saturating_add(suffix.len() as u64);
            let mut merged = Vec::with_capacity(1 + suffix.len());
            merged.push(byte);
            merged.extend_from_slice(&suffix);
            suffix = merged;
        }
        copied
    }

    /// Cost model for always-append-right `absorb_following` under reverse
    /// pairwise arrival (`N-2,N-1,N-4,N-3,…,0,1`): exactly `N*(N-2)/4` for even N.
    fn legacy_always_append_right_pairwise_reverse_copies(n: usize) -> u64 {
        assert!(n % 2 == 0 && n >= 2);
        let mut suffix_len = 0u64;
        let mut copied = 0u64;
        for _ in (0..(n / 2)).rev() {
            if suffix_len == 0 {
                // First pair from the right only builds the suffix.
                suffix_len = 2;
                continue;
            }
            // Tiny left run (2 bytes) appends the whole growing suffix.
            copied = copied.saturating_add(suffix_len);
            suffix_len += 2;
        }
        copied
    }

    /// Descending one-byte chunks must prepend in O(new bytes), not O(suffix).
    ///
    /// On 569014fe the legacy `Vec` prepend copies N*(N-1)/2 suffix bytes for
    /// N one-byte chunks. [`StoredRun::prepend_new`] grows in place (0 stored
    /// copies; heap ≤ `128*N`). A silent `bytes ++ suffix` rebuild that skips
    /// [`record_stored_byte_copy`] still fails the allocation bound.
    #[test]
    fn read_to_end_prepend_copy_cost_is_linear_for_descending() {
        const N: usize = 8_000;
        let legacy_copies = legacy_vec_prepend_suffix_copies(N);
        let quadratic = (N as u64) * (N as u64 - 1) / 2;
        assert_eq!(
            legacy_copies, quadratic,
            "sanity: the 569014fe prepend cost model must be quadratic"
        );

        // Known-bad control: rebuild_with_prefix must blow both bounds.
        {
            merge_copy_stats::reset();
            let ((), bad_alloc) = merge_alloc_stats::scope(|| {
                let mut run = StoredRun::from_slice(&[]);
                for i in (0..N).rev() {
                    let byte = ((i * 17) % 251) as u8;
                    run.rebuild_with_prefix(&[byte]);
                }
            });
            let bad_copied = merge_copy_stats::total();
            assert!(
                bad_copied >= legacy_copies,
                "rebuild control must charge ≥ legacy {legacy_copies}, got {bad_copied}"
            );
            assert!(
                bad_alloc > 128 * N as u64,
                "rebuild control must exceed 128*N alloc bound, got {bad_alloc}"
            );
        }

        merge_copy_stats::reset();
        let ((read, payload), requested) = merge_alloc_stats::scope(|| {
            let mut read = BTreeMap::new();
            let mut payload = vec![0u8; N];
            for i in (0..N).rev() {
                let byte = ((i * 17) % 251) as u8;
                payload[i] = byte;
                push_read_chunk(&mut read, &[byte], i as u64).expect("descending push");
            }
            (read, payload)
        });
        assert_eq!(read.len(), 1);
        let copied = merge_copy_stats::total();
        let copy_bound = 8 * N as u64;
        let alloc_bound = 128 * N as u64;
        assert!(
            copied <= copy_bound,
            "descending prepend copied {copied} stored bytes; O(N) bound is {copy_bound} \
             (569014fe would copy {legacy_copies})"
        );
        assert_eq!(
            copied, 0,
            "pure descending prepend must not bulk-copy already-stored bytes"
        );
        assert!(
            requested <= alloc_bound,
            "descending prepend requested {requested} heap bytes; bound is {alloc_bound} \
             (rebuild control exceeds this)"
        );
        let buffer = assemble_entries(&read, 0, N as u64).expect("descending must assemble");
        assert_eq!(buffer, payload);
    }

    /// Reverse pairwise gap-fill (`N-2,N-1,…,0,1`) must stay O(N), not
    /// `N*(N-2)/4` from always-append-right `absorb_following`.
    #[test]
    fn read_to_end_merge_copy_cost_is_linear_for_reverse_pairwise_gaps() {
        const N: usize = 8_000;
        let legacy = legacy_always_append_right_pairwise_reverse_copies(N);
        let quadratic = (N as u64) * (N as u64 - 2) / 4;
        assert_eq!(
            legacy, quadratic,
            "sanity: always-append-right reverse pairwise is N*(N-2)/4"
        );

        merge_copy_stats::reset();
        let mut read = BTreeMap::new();
        let mut payload = vec![0u8; N];
        let mut max_entries = 0usize;
        for pair in (0..(N / 2)).rev() {
            for offset in [pair * 2, pair * 2 + 1] {
                let byte = ((offset * 17) % 251) as u8;
                payload[offset] = byte;
                push_read_chunk(&mut read, &[byte], offset as u64).expect("reverse pairwise push");
                max_entries = max_entries.max(read.len());
            }
        }
        assert_eq!(read.len(), 1);
        // Codex: this arrival order never needs more than two entries.
        assert!(
            max_entries <= 2,
            "reverse pairwise should stay within two entries, saw {max_entries}"
        );
        let copied = merge_copy_stats::total();
        let bound = 8 * N as u64;
        assert!(
            copied <= bound,
            "reverse pairwise copied {copied} stored bytes; O(N) bound is {bound} \
             (always-append-right would copy {legacy})"
        );
        assert!(
            copied < legacy,
            "smaller-into-larger copies {copied} must beat always-append-right {legacy}"
        );
        // The old 8*N descending bound fails on the pre-fix absorb path.
        assert!(
            legacy > bound,
            "regression guard: legacy {legacy} must exceed bound {bound}"
        );
        assert_eq!(
            assemble_entries(&read, 0, N as u64).expect("reverse pairwise assembles"),
            payload
        );
    }

    /// Gap-closing and shuffled arrival must keep bulk copies O(N log N).
    #[test]
    fn read_to_end_merge_copy_cost_is_linear_for_gap_fill_and_random() {
        const N: usize = 4_096;
        // Union-by-size merge: O(N log N). Loose constant that still fails the
        // always-append-right reverse-pairwise volume (N*(N-2)/4).
        let bound = (N as u64) * 16 * 12; // ~16 N log2(N) with log2(4096)=12
        let legacy_reverse = legacy_always_append_right_pairwise_reverse_copies(N);
        assert!(
            legacy_reverse > bound,
            "bound must fail always-append-right reverse pairwise \
             (legacy {legacy_reverse} vs bound {bound})"
        );

        // Pairwise gap-fill: 1,0,3,2,...
        merge_copy_stats::reset();
        let mut read = BTreeMap::new();
        let mut payload = vec![0u8; N];
        for pair in 0..(N / 2) {
            for offset in [pair * 2 + 1, pair * 2] {
                let byte = ((offset * 17) % 251) as u8;
                payload[offset] = byte;
                push_read_chunk(&mut read, &[byte], offset as u64).expect("gap-fill push");
            }
        }
        assert_eq!(read.len(), 1);
        let gap_copied = merge_copy_stats::total();
        assert!(
            gap_copied <= bound,
            "gap-fill merge copied {gap_copied} stored bytes; bound is {bound}"
        );
        assert_eq!(
            assemble_entries(&read, 0, N as u64).expect("gap-fill assembles"),
            payload
        );

        // Deterministic shuffle (LCG) over the same offsets.
        merge_copy_stats::reset();
        let mut read = BTreeMap::new();
        let mut order: Vec<usize> = (0..N).collect();
        let mut state = 0xC0FFEE_u64;
        for i in (1..N).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (state as usize) % (i + 1);
            order.swap(i, j);
        }
        for &offset in &order {
            let byte = payload[offset];
            push_read_chunk(&mut read, &[byte], offset as u64).expect("random-order push");
        }
        assert_eq!(read.len(), 1);
        let random_copied = merge_copy_stats::total();
        assert!(
            random_copied <= bound,
            "random-order merge copied {random_copied} stored bytes; bound is {bound}"
        );
        assert_eq!(
            assemble_entries(&read, 0, N as u64).expect("random-order assembles"),
            payload
        );
    }

    /// Span limit must use the global end, not only the arriving chunk's end.
    #[test]
    fn read_to_end_span_uses_global_end() {
        // First chunk [150, 160) alone is within a 100-byte limit.
        assert!(!read_to_end_span_too_long(u64::MAX, 0, 150, 10, 100));
        // After accepting it (start=150, end=160), a later [0, 10) makes the
        // observed span 160 > 100.
        assert!(read_to_end_span_too_long(150, 160, 0, 10, 100));
        // Contiguous growth that stays inside the limit is still accepted.
        assert!(!read_to_end_span_too_long(0, 50, 50, 50, 100));
        assert!(read_to_end_span_too_long(0, 50, 50, 51, 100));
    }

    fn assemble_entries(read: &BTreeMap<u64, StoredRun>, start: u64, end: u64) -> Option<Vec<u8>> {
        let mut chunks: Vec<(Vec<u8>, u64)> = read
            .iter()
            .map(|(&offset, data)| (data.to_vec(), offset))
            .collect();
        assemble_unordered_chunks(&mut chunks, start, end)
    }
}
