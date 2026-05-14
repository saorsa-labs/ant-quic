// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

// This function is non-inline to prevent the optimizer from looking inside it.
#[inline(never)]
fn constant_time_ne(a: &[u8], b: &[u8]) -> u8 {
    assert!(a.len() == b.len());

    // These useless slices make the optimizer elide the bounds checks.
    // See the comment in clone_from_slice() added on Rust commit 6a7bc47.
    let len = a.len();
    let a = &a[..len];
    let b = &b[..len];

    let mut tmp = 0;
    for i in 0..len {
        tmp |= a[i] ^ b[i];
    }
    tmp // The compare with 0 must happen outside this function.
}

/// Compares byte strings in constant time.
pub(crate) fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && constant_time_ne(a, b) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_identical_bytes() {
        assert!(eq(b"hello", b"hello"));
    }

    #[test]
    fn eq_empty() {
        assert!(eq(b"", b""));
    }

    #[test]
    fn eq_different_bytes() {
        assert!(!eq(b"hello", b"world"));
    }

    #[test]
    fn eq_different_lengths() {
        assert!(!eq(b"hello", b"hi"));
    }

    #[test]
    fn eq_single_byte_difference() {
        assert!(!eq(b"abc", b"abd"));
    }

    #[test]
    fn eq_identical_one_byte() {
        assert!(eq(b"\x00", b"\x00"));
        assert!(eq(b"\xFF", b"\xFF"));
    }

    #[test]
    fn eq_zero_length_vs_nonzero() {
        assert!(!eq(b"", b"a"));
    }

    #[test]
    fn eq_long_identical() {
        let a: Vec<u8> = (0..255).collect();
        let b: Vec<u8> = (0..255).collect();
        assert!(eq(&a, &b));
    }

    #[test]
    fn eq_long_different() {
        let mut a: Vec<u8> = (0..255).collect();
        let b: Vec<u8> = (0..255).collect();
        a[127] = 0xFF;
        assert!(!eq(&a, &b));
    }

    #[test]
    fn eq_guards_against_mismatched_length() {
        let a = b"hello";
        let b = b"hell";
        // eq() guards against mismatched lengths and returns false
        assert!(!eq(a, b));
    }
}
