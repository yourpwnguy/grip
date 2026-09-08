//! Hex encoding helpers.
//!
//! We wrap the `hex` crate with a couple of convenience functions so the
//! rest of the codebase doesn't need to remember `hex::encode` vs
//! `hex::encode_upper` etc. All output is lowercase without prefixes,
//! matching the style used in `--raw` dumps.

/// Encode bytes as lowercase hex without separators.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Encode bytes as colon-separated lowercase hex, e.g. `a8:3f:c1:44`.
///
/// Used for certificate SHA-256 fingerprints.
#[must_use]
pub fn encode_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Decode a lowercase or uppercase hex string (with optional `:` or ` ` separators)
/// into bytes. Returns `None` if the string contains non-hex characters or
/// odd length after stripping separators.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let filtered: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    hex::decode(filtered).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_colon_works() {
        assert_eq!(encode_colon(&[0xa8, 0x3f, 0xc1]), "a8:3f:c1");
    }

    #[test]
    fn decode_ignores_colons() {
        assert_eq!(decode("a8:3f:c1").unwrap(), vec![0xa8, 0x3f, 0xc1]);
    }
}
