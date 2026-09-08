//! GREASE handling per RFC 8701.
//!
//! Browsers insert fake `0xXaXa` values (where `X` is `0..f` and both nibbles
//! match) into cipher suites, extensions, and other vectors to ensure servers
//! ignore unknown values. JA3/JA4 must strip these before hashing, and JA4
//! must also exclude them from counts/sorting.
//!
//! # Why filter before sort?
//! GREASE values are intentionally spaced (`0x0a0a, 0x1a1a, …, 0xfafa`) so that
//! sorting before filtering vs after can produce different hashes for the
//! same logical `ClientHello`. The spec mandates *filter → sort → hash*, so
//! that's what `filter_grease` + the fingerprint code does.
//!
//! # Security
//! GREASE detection is a pure function over `u16`; no I/O, no allocation.

/// All 16 GREASE values: `0x0a0a, 0x1a1a, …, 0xfafa`.
///
/// These are the only values where both bytes are identical and the low
/// nibble is `0xa` (see RFC 8701 §1).
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Returns `true` if `value` is a GREASE sentinel.
///
/// This is `const` so it can be used in const contexts and is trivially
/// inlinable in hot loops.
#[inline]
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    // Linear scan over 16 elements is faster than a HashSet and stays `const`.
    // The compiler will unroll it.
    let mut i = 0;
    while i < GREASE_VALUES.len() {
        if GREASE_VALUES[i] == value {
            return true;
        }
        i += 1;
    }
    false
}

/// Filter GREASE values from a slice, returning a new `Vec` without them.
///
/// The original order is preserved (important for JA3 which does **not** sort).
/// If you need sorted output, sort the returned `Vec` after calling this.
///
/// # Example
/// ```
/// # use grip::tls::grease::filter_grease;
/// let ciphers = [0x0a0a, 0x1301, 0x1a1a, 0x1302];
/// assert_eq!(filter_grease(&ciphers), vec![0x1301, 0x1302]);
/// ```
#[must_use]
pub fn filter_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

/// Filter GREASE from extension type ids (same table as ciphers).
///
/// TLS extensions use the same GREASE code points, so the same table applies.
#[inline]
#[must_use]
pub const fn is_grease_ext(ext_type: u16) -> bool {
    is_grease(ext_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_all_grease() {
        for v in GREASE_VALUES {
            assert!(is_grease(v), "{v:04x} should be GREASE");
        }
    }

    #[test]
    fn non_grease() {
        assert!(!is_grease(0x0303));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x00ff));
        assert!(!is_grease(0x0a0b));
    }

    #[test]
    fn filter_preserves_order() {
        let input = [0x0a0a, 0x1301, 0x1a1a, 0x1302, 0xc02b];
        assert_eq!(filter_grease(&input), vec![0x1301, 0x1302, 0xc02b]);
    }

    #[test]
    fn filter_before_sort_matters() {
        // GREASE values are interleaved; sorting first would place 0x0a0a at the front
        // then filtering would still yield sorted order, but if impl did sort->filter
        // vs filter->sort they'd match here. The real bug is forgetting to filter
        // before sorting in JA4 — this test documents the correct order.
        let input = [0x0a0a, 0x1302, 0x1301];
        let mut filtered = filter_grease(&input);
        filtered.sort_unstable();
        assert_eq!(filtered, vec![0x1301, 0x1302]);
    }
}
