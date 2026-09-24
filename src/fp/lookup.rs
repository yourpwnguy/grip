//! Known fingerprint lookup against an embedded DB.
//!
//! The DB is generated at build time from `assets/fingerprints.csv` into
//! `$OUT_DIR/known_db.rs` as two `phf::Map`s. Runtime lookup is O(1) with
//! no file I/O.

/// Lookup a JA3 hash against the known DB.
///
/// Returns the client name (e.g. `"Chrome 120"`) if found.
#[must_use]
pub fn lookup_ja3(ja3: &str) -> Option<&'static str> {
    crate::db::known::JA3_MAP.get(ja3).copied()
}

/// Lookup a JA4 hash against the known DB.
#[must_use]
pub fn lookup_ja4(ja4: &str) -> Option<&'static str> {
    crate::db::known::JA4_MAP.get(ja4).copied()
}

/// Lookup either JA3 or JA4, preferring JA4.
#[must_use]
pub fn lookup(ja4: Option<&str>, ja3: Option<&str>) -> Option<&'static str> {
    if let Some(j) = ja4
        && let Some(v) = lookup_ja4(j)
    {
        return Some(v);
    }
    if let Some(j) = ja3
        && let Some(v) = lookup_ja3(j)
    {
        return Some(v);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fp::{compute_ja3, compute_ja4};
    use crate::tls::{ClientHello, ClientHelloBuilder};

    #[test]
    fn known_chromium() {
        // From assets/fingerprints.csv (FoxIO ja4plus-mapping snapshot).
        let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
        assert_eq!(lookup_ja4(ja4), Some("Chromium Browser"));
    }

    /// grip's own probe hello must self-identify, so live `--lookup`
    /// reports `grip` instead of a miss.
    #[test]
    fn grip_self_identifies_with_and_without_sni() {
        for sni in [Some("example.com".to_string()), None] {
            let raw = ClientHelloBuilder::new().with_sni(sni).build();
            let ch = ClientHello::parse(&raw).unwrap();
            let ja4 = compute_ja4(&ch).to_string();
            let ja3 = compute_ja3(&ch);
            assert_eq!(lookup_ja4(&ja4), Some("grip"), "ja4 {ja4}");
            assert_eq!(
                lookup(Some(ja4.as_str()), Some(ja3.as_str())),
                Some("grip"),
                "ja4 {ja4}"
            );
        }
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(lookup_ja4("t00d0000_000000000000_000000000000"), None);
    }
}
