// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::ops::Range;

use tinyvec::TinyVec;

/// A set of u64 values optimized for long runs and random insert/delete/contains
///
/// `ArrayRangeSet` uses an array representation, where each array entry represents
/// a range.
///
/// The array-based RangeSet provides 2 benefits:
/// - There exists an inline representation, which avoids the need of heap
///   allocating ACK ranges for SentFrames for small ranges.
/// - Iterating over ranges should usually be faster since there is only
///   a single cache-friendly contiguous range.
///
/// `ArrayRangeSet` is especially useful for tracking ACK ranges where the amount
/// of ranges is usually very low (since ACK numbers are in consecutive fashion
/// unless reordering or packet loss occur).
#[derive(Debug, Default)]
pub struct ArrayRangeSet(TinyVec<[Range<u64>; ARRAY_RANGE_SET_INLINE_CAPACITY]>);

/// The capacity of elements directly stored in [`ArrayRangeSet`]
///
/// An inline capacity of 2 is chosen to keep `SentFrame` below 128 bytes.
const ARRAY_RANGE_SET_INLINE_CAPACITY: usize = 2;

impl Clone for ArrayRangeSet {
    fn clone(&self) -> Self {
        // tinyvec keeps the heap representation after clones.
        // We rather prefer the inline representation for clones if possible,
        // since clones (e.g. for storage in `SentFrames`) are rarely mutated
        if self.0.is_inline() || self.0.len() > ARRAY_RANGE_SET_INLINE_CAPACITY {
            return Self(self.0.clone());
        }

        let mut vec = TinyVec::new();
        vec.extend_from_slice(self.0.as_slice());
        Self(vec)
    }
}

impl ArrayRangeSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Range<u64>> + '_ {
        self.0.iter().cloned()
    }

    pub fn elts(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, x: u64) -> bool {
        // Use binary search since ranges are sorted by start
        // Find the rightmost range whose start <= x
        let idx = self.0.partition_point(|range| range.start <= x);
        if idx == 0 {
            return false;
        }
        // Check if x falls within the range that starts before or at x
        self.0[idx - 1].contains(&x)
    }

    pub fn subtract(&mut self, other: &Self) {
        // TODO: This can potentially be made more efficient, since the we know
        // individual ranges are not overlapping, and the next range must start
        // after the last one finished
        for range in &other.0 {
            self.remove(range.clone());
        }
    }

    pub fn insert_one(&mut self, x: u64) -> bool {
        self.insert(x..x + 1)
    }

    pub fn insert(&mut self, x: Range<u64>) -> bool {
        let mut result = false;

        if x.is_empty() {
            // Don't try to deal with ranges where x.end <= x.start
            return false;
        }

        let mut idx = 0;
        while idx != self.0.len() {
            let range = &mut self.0[idx];

            if range.start > x.end {
                // The range is fully before this range and therefore not extensible.
                // Add a new range to the left
                self.0.insert(idx, x);
                return true;
            } else if range.start > x.start {
                // The new range starts before this range but overlaps.
                // Extend the current range to the left
                // Note that we don't have to merge a potential left range, since
                // this case would have been captured by merging the right range
                // in the previous loop iteration
                result = true;
                range.start = x.start;
            }

            // At this point we have handled all parts of the new range which
            // are in front of the current range. Now we handle everything from
            // the start of the current range

            if x.end <= range.end {
                // Fully contained
                return result;
            } else if x.start <= range.end {
                // Extend the current range to the end of the new range.
                // Since it's not contained it must be bigger
                range.end = x.end;

                // Merge all follow-up ranges which overlap
                // Avoid cloning by using direct indexing
                while idx + 1 < self.0.len() {
                    let curr_end = self.0[idx].end;
                    let next_start = self.0[idx + 1].start;
                    if curr_end >= next_start {
                        let next_end = self.0[idx + 1].end;
                        self.0[idx].end = next_end.max(curr_end);
                        self.0.remove(idx + 1);
                    } else {
                        break;
                    }
                }

                return true;
            }

            idx += 1;
        }

        // Insert a range at the end
        self.0.push(x);
        true
    }

    pub fn remove(&mut self, x: Range<u64>) -> bool {
        let mut result = false;

        if x.is_empty() {
            // Don't try to deal with ranges where x.end <= x.start
            return false;
        }

        let mut idx = 0;
        while idx != self.0.len() && x.start != x.end {
            let range = self.0[idx].clone();

            if x.end <= range.start {
                // The range is fully before this range
                return result;
            } else if x.start >= range.end {
                // The range is fully after this range
                idx += 1;
                continue;
            }

            // The range overlaps with this range
            result = true;

            let left = range.start..x.start;
            let right = x.end..range.end;
            if left.is_empty() && right.is_empty() {
                self.0.remove(idx);
            } else if left.is_empty() {
                self.0[idx] = right;
                idx += 1;
            } else if right.is_empty() {
                self.0[idx] = left;
                idx += 1;
            } else {
                self.0[idx] = right;
                self.0.insert(idx, left);
                idx += 2;
            }
        }

        result
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn pop_min(&mut self) -> Option<Range<u64>> {
        if !self.0.is_empty() {
            Some(self.0.remove(0))
        } else {
            None
        }
    }

    pub fn min(&self) -> Option<u64> {
        self.iter().next().map(|x| x.start)
    }

    pub fn max(&self) -> Option<u64> {
        // SAFETY: Use checked_sub to prevent underflow if end is 0
        // (though this shouldn't happen with valid ranges, defensive programming is important)
        self.iter().next_back().and_then(|x| x.end.checked_sub(1))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> ArrayRangeSet {
        ArrayRangeSet::new()
    }

    fn single(start: u64, end: u64) -> ArrayRangeSet {
        let mut s = ArrayRangeSet::new();
        s.insert(start..end);
        s
    }

    // Basic construction tests

    #[test]
    fn new_is_empty() {
        let s = empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.iter().next().is_none());
    }

    #[test]
    fn default_is_empty() {
        let s = ArrayRangeSet::default();
        assert!(s.is_empty());
    }

    #[test]
    fn clone_empty() {
        let s = empty();
        let c = s.clone();
        assert!(c.is_empty());
    }

    // Insert single range tests

    #[test]
    fn insert_single_range() {
        let mut s = empty();
        assert!(s.insert(10..20));
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn insert_empty_range_is_noop() {
        let mut s = empty();
        assert!(!s.insert(10..10));
        assert!(s.is_empty());
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn insert_reverse_range_is_noop() {
        let mut s = empty();
        assert!(!s.insert(20..10));
        assert!(s.is_empty());
    }

    #[test]
    fn insert_one_then_get() {
        let mut s = empty();
        s.insert_one(42);
        assert!(s.contains(42));
        assert!(!s.contains(41));
        assert!(!s.contains(43));
    }

    // Contains tests

    #[test]
    fn contains_single_value() {
        let s = single(5, 10);
        assert!(s.contains(5));
        assert!(s.contains(7));
        assert!(s.contains(9));
        assert!(!s.contains(4));
        assert!(!s.contains(10));
    }

    #[test]
    fn contains_empty_set() {
        let s = empty();
        assert!(!s.contains(0));
        assert!(!s.contains(u64::MAX));
    }

    #[test]
    fn contains_multiple_ranges() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        assert!(s.contains(15));
        assert!(s.contains(35));
        assert!(!s.contains(25));
        assert!(!s.contains(20));
        assert!(s.contains(30));
    }

    // Insert adjacent ranges merge

    #[test]
    fn insert_adjacent_ranges_merge() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(20..30);
        assert_eq!(s.len(), 1);
        assert!(s.contains(19));
        assert!(s.contains(20));
    }

    #[test]
    fn insert_overlapping_ranges_merge() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(15..25);
        assert_eq!(s.len(), 1);
        assert!(s.contains(24));
        assert!(!s.contains(25));
    }

    #[test]
    fn insert_contained_range_no_change() {
        let mut s = single(10, 30);
        assert!(!s.insert(15..20));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn insert_extending_left_merges_with_adjacent() {
        let mut s = empty();
        s.insert(20..30);
        s.insert(15..25);
        assert_eq!(s.len(), 1);
        assert!(s.contains(15));
        assert!(s.contains(25));
        assert!(!s.contains(30));
    }

    #[test]
    fn insert_extending_right_merges_with_adjacent() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(15..30);
        assert_eq!(s.len(), 1);
        assert!(s.contains(10));
        assert!(s.contains(29));
    }

    #[test]
    fn insert_between_two_ranges_merges_all() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        s.insert(20..30);
        assert_eq!(s.len(), 1);
        assert!(s.contains(10));
        assert!(s.contains(39));
    }

    #[test]
    fn insert_separate_ranges_no_merge() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        assert_eq!(s.len(), 2);
        assert!(s.contains(15));
        assert!(s.contains(35));
    }

    // Remove tests

    #[test]
    fn remove_from_middle_splits_range() {
        let mut s = single(10, 30);
        assert!(s.remove(15..20));
        assert_eq!(s.len(), 2);
        assert!(s.contains(14));
        assert!(!s.contains(15));
        assert!(!s.contains(19));
        assert!(s.contains(20));
    }

    #[test]
    fn remove_from_start_truncates() {
        let mut s = single(10, 30);
        assert!(s.remove(10..15));
        assert_eq!(s.len(), 1);
        assert!(!s.contains(10));
        assert!(!s.contains(14));
        assert!(s.contains(15));
    }

    #[test]
    fn remove_from_end_truncates() {
        let mut s = single(10, 30);
        assert!(s.remove(25..30));
        assert_eq!(s.len(), 1);
        assert!(s.contains(24));
        assert!(!s.contains(25));
    }

    #[test]
    fn remove_entire_range_empties() {
        let mut s = single(10, 30);
        assert!(s.remove(10..30));
        assert!(s.is_empty());
    }

    #[test]
    fn remove_empty_range_is_noop() {
        let mut s = single(10, 30);
        assert!(!s.remove(15..15));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn remove_non_overlapping_is_noop() {
        let mut s = single(10, 20);
        assert!(!s.remove(30..40));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn remove_multiple_ranges() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        assert!(s.remove(10..40));
        assert!(s.is_empty());
    }

    // pop_min tests

    #[test]
    fn pop_min_empty() {
        let mut s = empty();
        assert!(s.pop_min().is_none());
    }

    #[test]
    fn pop_min_returns_first_range() {
        let mut s = empty();
        s.insert(10..20);
        let r = s.pop_min().unwrap();
        assert_eq!(r, 10..20);
        assert!(s.is_empty());
    }

    #[test]
    fn pop_min_multiple() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        assert_eq!(s.pop_min().unwrap(), 10..20);
        assert_eq!(s.pop_min().unwrap(), 30..40);
        assert!(s.pop_min().is_none());
    }

    // min/max tests

    #[test]
    fn min_max_empty() {
        let s = empty();
        assert!(s.min().is_none());
        assert!(s.max().is_none());
    }

    #[test]
    fn min_max_single_range() {
        let s = single(10, 20);
        assert_eq!(s.min(), Some(10));
        assert_eq!(s.max(), Some(19));
    }

    #[test]
    fn min_max_multiple_ranges() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        assert_eq!(s.min(), Some(10));
        assert_eq!(s.max(), Some(39));
    }

    // Subtract tests

    #[test]
    fn subtract_non_overlapping_no_change() {
        let mut s = single(10, 20);
        let other = single(30, 40);
        s.subtract(&other);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn subtract_overlapping_removes() {
        let mut s = single(10, 30);
        let other = single(15, 25);
        s.subtract(&other);
        assert_eq!(s.len(), 2);
        assert!(s.contains(14));
        assert!(!s.contains(15));
        assert!(!s.contains(24));
        assert!(s.contains(25));
    }

    #[test]
    fn subtract_identical_empties() {
        let mut s = single(10, 20);
        let other = single(10, 20);
        s.subtract(&other);
        assert!(s.is_empty());
    }

    // Iteration tests

    #[test]
    fn iter_over_multiple_ranges() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        let ranges: Vec<_> = s.iter().collect();
        assert_eq!(ranges, vec![10..20, 30..40]);
    }

    #[test]
    fn elts_over_multiple_ranges() {
        let mut s = empty();
        s.insert(10..12);
        s.insert(20..22);
        let values: Vec<_> = s.elts().collect();
        assert_eq!(values, vec![10, 11, 20, 21]);
    }

    #[test]
    fn elts_empty() {
        let s = empty();
        let values: Vec<_> = s.elts().collect();
        assert!(values.is_empty());
    }

    // Clone with inline representation

    #[test]
    fn clone_preserves_content() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(30..40);
        let c = s.clone();
        assert_eq!(c.len(), 2);
        assert!(c.contains(15));
        assert!(c.contains(35));
    }

    // Edge cases

    #[test]
    fn contains_at_boundaries() {
        let s = single(0, 100);
        assert!(s.contains(0));
        assert!(s.contains(99));
        assert!(!s.contains(100));
    }

    #[test]
    fn insert_at_zero() {
        let mut s = empty();
        s.insert(0..1);
        assert!(s.contains(0));
    }

    #[test]
    fn insert_large_values() {
        let mut s = empty();
        let near_max = u64::MAX - 10;
        s.insert(near_max..u64::MAX);
        assert!(s.contains(near_max));
        assert!(s.contains(u64::MAX - 1));
        assert!(!s.contains(u64::MAX));
    }

    #[test]
    fn remove_at_boundaries() {
        let mut s = single(0, 10);
        s.remove(0..1);
        assert!(!s.contains(0));
        assert!(s.contains(1));
    }

    #[test]
    fn insert_many_tiny_ranges() {
        let mut s = empty();
        for i in 0..10 {
            s.insert_one(i);
        }
        // Should merge into one range
        assert_eq!(s.len(), 1);
        assert!(s.contains(0));
        assert!(s.contains(9));
    }

    #[test]
    fn insert_sparse_ranges() {
        let mut s = empty();
        s.insert(10..20);
        s.insert(50..60);
        s.insert(100..110);
        assert_eq!(s.len(), 3);
        assert!(!s.contains(30));
        assert!(!s.contains(80));
    }
}
