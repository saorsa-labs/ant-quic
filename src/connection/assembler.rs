// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, binary_heap::PeekMut},
    mem,
};

use bytes::{Buf, Bytes, BytesMut};

use crate::range_set::RangeSet;

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug, Default)]
pub(super) struct Assembler {
    state: State,
    data: BinaryHeap<Buffer>,
    /// Total number of buffered bytes, including duplicates in ordered mode.
    buffered: usize,
    /// Estimated number of allocated bytes, will never be less than `buffered`.
    allocated: usize,
    /// Number of bytes read by the application. When only ordered reads have been used, this is the
    /// length of the contiguous prefix of the stream which has been consumed by the application,
    /// aka the stream offset.
    bytes_read: u64,
    end: u64,
}

impl Assembler {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Reset to the initial state
    pub(super) fn reinit(&mut self) {
        let old_data = mem::take(&mut self.data);
        *self = Self::default();
        self.data = old_data;
        self.data.clear();
    }

    pub(super) fn ensure_ordering(&mut self, ordered: bool) -> Result<(), IllegalOrderedRead> {
        if ordered && !self.state.is_ordered() {
            return Err(IllegalOrderedRead);
        } else if !ordered && self.state.is_ordered() {
            // Enter unordered mode
            if !self.data.is_empty() {
                // Get rid of possible duplicates
                self.defragment();
            }
            let mut recvd = RangeSet::new();
            recvd.insert(0..self.bytes_read);
            for chunk in &self.data {
                recvd.insert(chunk.offset..chunk.offset + chunk.bytes.len() as u64);
            }
            self.state = State::Unordered { recvd };
        }
        Ok(())
    }

    /// Get the the next chunk
    pub(super) fn read(&mut self, max_length: usize, ordered: bool) -> Option<Chunk> {
        loop {
            let mut chunk = self.data.peek_mut()?;

            if ordered {
                if chunk.offset > self.bytes_read {
                    // Next chunk is after current read index
                    return None;
                } else if (chunk.offset + chunk.bytes.len() as u64) <= self.bytes_read {
                    // Next chunk is useless as the read index is beyond its end
                    self.buffered -= chunk.bytes.len();
                    self.allocated -= chunk.allocation_size;
                    PeekMut::pop(chunk);
                    continue;
                }

                // Determine `start` and `len` of the slice of useful data in chunk
                let start = (self.bytes_read - chunk.offset) as usize;
                if start > 0 {
                    chunk.bytes.advance(start);
                    chunk.offset += start as u64;
                    self.buffered -= start;
                }
            }

            return Some(if max_length < chunk.bytes.len() {
                self.bytes_read += max_length as u64;
                let offset = chunk.offset;
                chunk.offset += max_length as u64;
                self.buffered -= max_length;
                Chunk::new(offset, chunk.bytes.split_to(max_length))
            } else {
                self.bytes_read += chunk.bytes.len() as u64;
                self.buffered -= chunk.bytes.len();
                self.allocated -= chunk.allocation_size;
                let chunk = PeekMut::pop(chunk);
                Chunk::new(chunk.offset, chunk.bytes)
            });
        }
    }

    /// Copy fragmented chunk data to new chunks backed by a single buffer
    ///
    /// This makes sure we're not unnecessarily holding on to many larger allocations.
    /// We merge contiguous chunks in the process of doing so.
    fn defragment(&mut self) {
        let new = BinaryHeap::with_capacity(self.data.len());
        let old = mem::replace(&mut self.data, new);
        let mut buffers = old.into_sorted_vec();
        self.buffered = 0;
        let mut fragmented_buffered = 0;
        let mut offset = 0;
        for chunk in buffers.iter_mut().rev() {
            chunk.try_mark_defragment(offset);
            let size = chunk.bytes.len();
            offset = chunk.offset + size as u64;
            self.buffered += size;
            if !chunk.defragmented {
                fragmented_buffered += size;
            }
        }
        self.allocated = self.buffered;
        let mut buffer = BytesMut::with_capacity(fragmented_buffered);
        let mut offset = 0;
        for chunk in buffers.into_iter().rev() {
            if chunk.defragmented {
                // bytes might be empty after try_mark_defragment
                if !chunk.bytes.is_empty() {
                    self.data.push(chunk);
                }
                continue;
            }
            // Overlap is resolved by try_mark_defragment
            if chunk.offset != offset + (buffer.len() as u64) {
                if !buffer.is_empty() {
                    self.data
                        .push(Buffer::new_defragmented(offset, buffer.split().freeze()));
                }
                offset = chunk.offset;
            }
            buffer.extend_from_slice(&chunk.bytes);
        }
        if !buffer.is_empty() {
            self.data
                .push(Buffer::new_defragmented(offset, buffer.split().freeze()));
        }
    }

    // Note: If a packet contains many frames from the same stream, the estimated over-allocation
    // will be much higher because we are counting the same allocation multiple times.
    pub(super) fn insert(&mut self, mut offset: u64, bytes: Bytes, allocation_size: usize) {
        debug_assert!(
            bytes.len() <= allocation_size,
            "allocation_size less than bytes.len(): {:?} < {:?}",
            allocation_size,
            bytes.len()
        );
        // Copy to owned storage IMMEDIATELY. The input Bytes references a
        // decrypted packet allocation that the QUIC stack may recycle under
        // concurrent multi-stream load. Without this copy, out-of-order
        // reassembly can read stale/overwritten data from the recycled
        // allocation (torn read). See: FINDING-recv-boundary-aliasing.md
        let mut bytes: Bytes = Bytes::copy_from_slice(&bytes);
        self.end = self.end.max(offset + bytes.len() as u64);
        if let State::Unordered { ref mut recvd } = self.state {
            // Discard duplicate data
            for duplicate in recvd.replace(offset..offset + bytes.len() as u64) {
                if duplicate.start > offset {
                    let buffer = Buffer::new(
                        offset,
                        bytes.split_to((duplicate.start - offset) as usize),
                        allocation_size,
                    );
                    self.buffered += buffer.bytes.len();
                    self.allocated += buffer.allocation_size;
                    self.data.push(buffer);
                    offset = duplicate.start;
                }
                bytes.advance((duplicate.end - offset) as usize);
                offset = duplicate.end;
            }
        } else if offset < self.bytes_read {
            if (offset + bytes.len() as u64) <= self.bytes_read {
                return;
            } else {
                let diff = self.bytes_read - offset;
                offset += diff;
                bytes.advance(diff as usize);
            }
        }

        if bytes.is_empty() {
            return;
        }
        let buffer = Buffer::new(offset, bytes, allocation_size);
        self.buffered += buffer.bytes.len();
        self.allocated += buffer.allocation_size;
        self.data.push(buffer);
        // `self.buffered` also counts duplicate bytes, therefore we use
        // `self.end - self.bytes_read` as an upper bound of buffered unique
        // bytes. This will cause a defragmentation if the amount of duplicate
        // bytes exceedes a proportion of the receive window size.
        let buffered = self.buffered.min((self.end - self.bytes_read) as usize);
        let over_allocation = self.allocated - buffered;
        // Rationale: on the one hand, we want to defragment rarely, ideally never
        // in non-pathological scenarios. However, a pathological or malicious
        // peer could send us one-byte frames, and since we use reference-counted
        // buffers in order to prevent copying, this could result in keeping a lot
        // of memory allocated. This limits over-allocation in proportion to the
        // buffered data. The constants are chosen somewhat arbitrarily and try to
        // balance between defragmentation overhead and over-allocation.
        let threshold = 32768.max(buffered * 3 / 2);
        if over_allocation > threshold {
            self.defragment()
        }
    }

    /// Number of bytes consumed by the application
    pub(super) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Discard all buffered data
    pub(super) fn clear(&mut self) {
        self.data.clear();
        self.buffered = 0;
        self.allocated = 0;
    }
}

/// A chunk of data from the receive stream
#[derive(Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The offset in the stream
    pub offset: u64,
    /// The contents of the chunk
    pub bytes: Bytes,
}

impl Chunk {
    fn new(offset: u64, bytes: Bytes) -> Self {
        Self { offset, bytes }
    }
}

#[derive(Debug, Eq)]
struct Buffer {
    offset: u64,
    bytes: Bytes,
    /// Size of the allocation behind `bytes`, if `defragmented == false`.
    /// Otherwise this will be set to `bytes.len()` by `try_mark_defragment`.
    /// Will never be less than `bytes.len()`.
    allocation_size: usize,
    defragmented: bool,
}

impl Buffer {
    /// Constructs a new fragmented Buffer
    fn new(offset: u64, bytes: Bytes, allocation_size: usize) -> Self {
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: false,
        }
    }

    /// Constructs a new defragmented Buffer
    fn new_defragmented(offset: u64, bytes: Bytes) -> Self {
        let allocation_size = bytes.len();
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: true,
        }
    }

    /// Discards data before `offset` and flags `self` as defragmented if it has good utilization
    fn try_mark_defragment(&mut self, offset: u64) {
        let duplicate = offset.saturating_sub(self.offset) as usize;
        self.offset = self.offset.max(offset);
        if duplicate >= self.bytes.len() {
            // All bytes are duplicate
            self.bytes = Bytes::new();
            self.defragmented = true;
            self.allocation_size = 0;
            return;
        }
        self.bytes.advance(duplicate);
        // Make sure that fragmented buffers with high utilization become defragmented and
        // defragmented buffers remain defragmented
        self.defragmented = self.defragmented || self.bytes.len() * 6 / 5 >= self.allocation_size;
        if self.defragmented {
            // Make sure that defragmented buffers do not contribute to over-allocation
            self.allocation_size = self.bytes.len();
        }
    }
}

impl Ord for Buffer {
    // Invert ordering based on offset (max-heap, min offset first),
    // prioritize longer chunks at the same offset.
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset
            .cmp(&other.offset)
            .reverse()
            .then(self.bytes.len().cmp(&other.bytes.len()))
    }
}

impl PartialOrd for Buffer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Buffer {
    fn eq(&self, other: &Self) -> bool {
        (self.offset, self.bytes.len()) == (other.offset, other.bytes.len())
    }
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Ordered,
    Unordered {
        /// The set of offsets that have been received from the peer, including portions not yet
        /// read by the application.
        recvd: RangeSet,
    },
}

impl State {
    fn is_ordered(&self) -> bool {
        matches!(self, Self::Ordered)
    }
}

/// Error indicating that an ordered read was performed on a stream after an unordered read
#[derive(Debug)]
pub struct IllegalOrderedRead;

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3);
        assert_matches!(next(&mut x, 1), Some(ref y) if &y[..] == b"1");
        assert_matches!(next(&mut x, 3), Some(ref y) if &y[..] == b"23");
        x.insert(3, Bytes::from_static(b"456"), 3);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        x.insert(6, Bytes::from_static(b"789"), 3);
        x.insert(9, Bytes::from_static(b"10"), 2);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"789");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"10");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"456"), 3);
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3);
        x.insert(0, Bytes::from_static(b"123"), 3);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3);
        x.insert(0, Bytes::from_static(b"123"), 3);
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5);
        x.insert(1, Bytes::from_static(b"234"), 3);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5);
        x.insert(1, Bytes::from_static(b"234"), 3);
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3);
        x.insert(0, Bytes::from_static(b"12345"), 5);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains_compact() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3);
        x.insert(0, Bytes::from_static(b"12345"), 5);
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3);
        x.insert(1, Bytes::from_static(b"234"), 3);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"4");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 4);
        x.insert(1, Bytes::from_static(b"234"), 4);
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1);
        x.insert(2, Bytes::from_static(b"3"), 1);
        x.insert(4, Bytes::from_static(b"5"), 1);
        x.insert(0, Bytes::from_static(b"123456"), 6);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1);
        x.insert(2, Bytes::from_static(b"3"), 1);
        x.insert(4, Bytes::from_static(b"5"), 1);
        x.insert(0, Bytes::from_static(b"123456"), 6);
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"), 4);
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        x.insert(0, Bytes::from_static(b"1234"), 4);
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 4);
        x.insert(3, Bytes::from_static(b"def"), 4);
        x.insert(9, Bytes::from_static(b"jkl"), 4);
        x.insert(12, Bytes::from_static(b"mno"), 4);
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abcdef"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jklmno"))
        );
    }

    #[test]
    fn defrag_with_missing_prefix() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3);
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
    }

    #[test]
    fn defrag_read_chunk() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 4);
        x.insert(0, Bytes::from_static(b"abc"), 4);
        x.insert(7, Bytes::from_static(b"hij"), 4);
        x.insert(11, Bytes::from_static(b"lmn"), 4);
        x.defragment();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"abcdef");
        x.insert(5, Bytes::from_static(b"fghijklmn"), 9);
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"ghijklmn");
        x.insert(13, Bytes::from_static(b"nopq"), 4);
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"opq");
        x.insert(15, Bytes::from_static(b"pqrs"), 4);
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"rs");
        assert_matches!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn unordered_happy_path() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abc"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(3, Bytes::from_static(b"def"), 3);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn unordered_dedup() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"def"), 3);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(0, Bytes::from_static(b"a"), 1);
        x.insert(0, Bytes::from_static(b"abcdefghi"), 9);
        x.insert(0, Bytes::from_static(b"abcd"), 4);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"a"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(1, Bytes::from_static(b"bc"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(6, Bytes::from_static(b"ghi"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jkl"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(12, Bytes::from_static(b"mno"), 3);
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(12, Bytes::from_static(b"mno"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(2, Bytes::from_static(b"cde"), 3);
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn chunks_dedup() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3);
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(0, Bytes::from_static(b"a"), 1);
        x.insert(1, Bytes::from_static(b"bcdefghi"), 9);
        x.insert(0, Bytes::from_static(b"abcd"), 4);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abcd")))
        );
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(4, Bytes::from_static(b"efghi")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(9, Bytes::from_static(b"jkl")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(12, Bytes::from_static(b"mno"), 3);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(12, Bytes::from_static(b"mno")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(2, Bytes::from_static(b"cde"), 3);
        assert_eq!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn ordered_eager_discard() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3);
        assert_eq!(x.data.len(), 1);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        x.insert(0, Bytes::from_static(b"ab"), 2);
        assert_eq!(x.data.len(), 0);
        x.insert(2, Bytes::from_static(b"cd"), 2);
        assert_eq!(
            x.data.peek(),
            Some(&Buffer::new(3, Bytes::from_static(b"d"), 2))
        );
    }

    #[test]
    fn ordered_insert_unordered_read() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3);
        x.insert(0, Bytes::from_static(b"abc"), 3);
        x.ensure_ordering(false).unwrap();
        assert_eq!(
            x.read(3, false),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        assert_eq!(x.read(3, false), None);
    }

    /// Models the `read_to_end` contract end to end at the assembler layer.
    ///
    /// `ReadToEnd` performs unordered reads and, once the connection layer signals
    /// end-of-stream (`Chunks::next` gate: `bytes_read == final_size`), assembles the
    /// chunks by offset into a zero-initialized buffer. Any range the assembler counted
    /// as read but never yielded ships to the application as zeros inside `Ok` — a
    /// silent data-integrity failure (observed in the wild as 2×1448-byte zero gaps).
    ///
    /// This test replays randomized but deterministic frame schedules — duplicates,
    /// coalesced/resegmented retransmissions, arbitrary overlaps, reordering, and reads
    /// interleaved at random points (including the ordered→unordered transition at the
    /// first read) — and asserts the contract: every byte is yielded exactly once with
    /// correct content, and the end-of-stream gate never fires while data is missing.
    #[test]
    fn read_to_end_contract_random_schedules() {
        use rand::{Rng, SeedableRng};

        const PACKET: usize = 1448;
        for seed in 0..4096u64 {
            let mut rng = rand_pcg::Pcg64Mcg::seed_from_u64(seed);
            let n: usize = rng.gen_range(2 * PACKET..12 * PACKET);
            let payload: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();

            enum Ev {
                Insert { offset: usize, len: usize },
                Read,
                Defrag,
            }

            // Base segmentation at packet-sized boundaries, each frame delivered once
            let mut inserts: Vec<(usize, usize)> = Vec::new();
            let mut off = 0;
            while off < n {
                let end = (off + PACKET).min(n);
                inserts.push((off, end - off));
                off = end;
            }
            // Retransmission variants: duplicates, coalesced 2-packet frames,
            // subranges, and arbitrarily misaligned overlaps
            let base = inserts.clone();
            for &(s, l) in &base {
                if rng.gen_bool(0.6) {
                    match rng.gen_range(0..4u32) {
                        0 => inserts.push((s, l)),
                        1 => {
                            let end = (s + 2 * PACKET).min(n);
                            inserts.push((s, end - s));
                        }
                        2 => {
                            let ds = rng.gen_range(0..l);
                            let dl = rng.gen_range(1..=l - ds);
                            inserts.push((s + ds, dl));
                        }
                        _ => {
                            let rs = rng.gen_range(s.saturating_sub(PACKET)..(s + l).min(n - 1));
                            let rl = rng.gen_range(1..=(n - rs).min(2 * PACKET));
                            inserts.push((rs, rl));
                        }
                    }
                }
            }
            // Shuffle delivery order (Fisher-Yates)
            for i in (1..inserts.len()).rev() {
                let j = rng.gen_range(0..=i);
                inserts.swap(i, j);
            }
            let mut events: Vec<Ev> = Vec::new();
            for (offset, len) in inserts {
                events.push(Ev::Insert { offset, len });
                if rng.gen_bool(0.35) {
                    events.push(Ev::Read);
                }
                if rng.gen_bool(0.05) {
                    events.push(Ev::Defrag);
                }
            }
            events.push(Ev::Read);

            let mut x = Assembler::new();
            // (offset, len) of every chunk yielded to the "application"
            let mut yielded: Vec<(u64, u64)> = Vec::new();

            let verify = |yielded: &mut Vec<(u64, u64)>, gate_fired: bool, seed: u64| {
                yielded.sort_unstable();
                let mut pos = 0u64;
                let mut covered = 0u64;
                for &(s, l) in yielded.iter() {
                    assert!(
                        s >= pos,
                        "seed {seed}: range [{s}, {}) overlaps previously yielded data \
                         (double-yield inflates bytes_read)",
                        s + l
                    );
                    pos = s + l;
                    covered += l;
                }
                if gate_fired {
                    assert_eq!(
                        covered, n as u64,
                        "seed {seed}: end-of-stream gate fired with unyielded ranges — \
                         read_to_end would return zero-filled gaps"
                    );
                }
            };

            for ev in events {
                match ev {
                    Ev::Insert { offset, len } => {
                        let bytes = Bytes::copy_from_slice(&payload[offset..offset + len]);
                        let alloc = if rng.gen_bool(0.3) {
                            len + rng.gen_range(0..200)
                        } else {
                            len
                        };
                        x.insert(offset as u64, bytes, alloc);
                    }
                    Ev::Defrag => x.defragment(),
                    Ev::Read => {
                        x.ensure_ordering(false).unwrap();
                        while let Some(chunk) = x.read(usize::MAX, false) {
                            let s = chunk.offset as usize;
                            let e = s + chunk.bytes.len();
                            assert!(
                                e <= n,
                                "seed {seed}: chunk [{s}, {e}) exceeds stream size {n}"
                            );
                            assert_eq!(
                                &chunk.bytes[..],
                                &payload[s..e],
                                "seed {seed}: chunk content at [{s}, {e}) does not match payload"
                            );
                            yielded.push((chunk.offset, chunk.bytes.len() as u64));
                        }
                        // This is the end-of-stream gate from `Chunks::next`
                        let gate_fired = x.bytes_read() == n as u64;
                        verify(&mut yielded, gate_fired, seed);
                    }
                }
            }

            // All frames were delivered: the stream must complete with full coverage
            assert_eq!(
                x.bytes_read(),
                n as u64,
                "seed {seed}: stream stalled — all data inserted but end-of-stream gate never fired"
            );
            verify(&mut yielded, true, seed);
        }
    }

    /// Repro for the recv-boundary-aliasing corruption (FINDING-recv-boundary-aliasing.md).
    ///
    /// Without the fix (copy-to-owned at insert time), the assembler stores
    /// Bytes references into the packet allocation. If that allocation is
    /// recycled by the QUIC stack between insert and read, the read returns
    /// stale/overwritten data (torn read).
    ///
    /// This test simulates the recycling by modifying the allocation through
    /// a raw pointer after insert. With the fix, the assembler has its own
    /// copy and the modification is invisible.
    #[test]
    fn insert_copies_to_owned_storage_preventing_aliasing() {
        let mut x = Assembler::new();

        // Create data in a known allocation
        let data_vec = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ptr = data_vec.as_ptr() as *mut u8;
        let data = Bytes::from(data_vec);

        // Insert into assembler
        x.insert(0, data, 16);

        // Simulate packet allocation recycling: overwrite through raw pointer.
        // In production, this happens when the QUIC stack processes a new packet
        // and the allocator reuses the freed packet buffer.
        unsafe {
            for i in 0..16 {
                std::ptr::write_volatile(ptr.add(i), 200 + i as u8);
            }
        }

        // Read from assembler — must return ORIGINAL data, not modified.
        // Without the insert-time copy, this would return [200, 201, ...].
        let chunk = x.read(16, true).expect("data must be readable");
        assert_eq!(
            &chunk.bytes[..],
            &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            "Assembler must store owned copy, not reference to recyclable packet allocation"
        );
    }

    fn next_unordered(x: &mut Assembler) -> Chunk {
        x.read(usize::MAX, false).unwrap()
    }

    fn next(x: &mut Assembler, size: usize) -> Option<Bytes> {
        x.read(size, true).map(|chunk| chunk.bytes)
    }
}
