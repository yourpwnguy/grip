//! JA4 fingerprint.
//!
//! JA4 is the modern replacement for JA3. It has three underscore-separated
//! parts:
//! ```text
//! t13d1516h2_8daaf6152771_e5627ecdbbe6
//! |        |            |
//! |        |            +-- hash of sorted extensions + sig algs
//! |        +--------------- hash of sorted cipher suites
//! +------------------------ human-readable tag
//! ```
//! **Tag** `t13d1516h2`:
//! - `t` protocol (always `t` for TLS in v0.1.0)
//! - `13` real TLS version (from `supported_versions`, fallback legacy)
//! - `d`/`i` SNI: `d` domain, `i` IP or absent
//! - `15` cipher suite count (2 digits, GREASE filtered, zero-padded, excludes GREASE)
//! - `16` extension count (2 digits, excludes SNI `0x0000` + ALPN `0x0010`, GREASE filtered)
//! - `h2` first 2 chars of first ALPN, `00` if none
//!
//! **Part 2**: `SHA256( sorted_ciphers )[:12]` where ciphers are filtered
//! GREASE, sorted numeric, decimal strings joined with `,`, then hex hash truncated.
//!
//! **Part 3**: `SHA256( sorted_exts + "_" + sigalgs )[:12]` where extensions
//! are GREASE-filtered, SNI/ALPN excluded, sorted numeric, `,`-joined; sigalgs
//! are comma-joined decimal values from extension `0x000d` (or empty).
//!
//! The subtlety that hurts: **filter GREASE before sort**. Sorting first
//! then filtering yields wrong hashes for clients that inject GREASE.

use sha2::{Digest, Sha256};

use crate::tls::client_hello::ClientHello;
use crate::tls::extensions::Extension;
use crate::tls::grease::is_grease;

/// Newtype for JA4 hash string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4(pub String);

impl Ja4 {
    /// Inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Ja4 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Compute JA4 for a `ClientHello`.
#[must_use]
pub fn compute_ja4(ch: &ClientHello) -> Ja4 {
    let real_version = ch.real_version();
    let version_str = real_version.ja4_str();

    // SNI presence: 'd' for domain, 'i' otherwise. Detect IP by checking if SNI parses as IpAddr.
    let sni_char = match ch.sni() {
        Some(s) if !s.is_empty() => {
            if s.parse::<std::net::IpAddr>().is_ok() {
                'i'
            } else {
                'd'
            }
        }
        _ => 'i',
    };

    // Cipher suites: filter GREASE first, then count and sort for hashing.
    let ciphers_filtered = crate::tls::grease::filter_grease(&ch.cipher_suites);
    let cipher_count = ciphers_filtered.len().min(99);
    let cipher_count_str = format!("{cipher_count:02}");

    // Extensions: filter GREASE, exclude SNI (0x0000) and ALPN (0x0010) for count and hash.
    let exts_filtered: Vec<u16> = ch
        .extensions
        .iter()
        .map(super::super::tls::extensions::Extension::ext_type)
        .filter(|v| !is_grease(*v) && *v != 0x0000 && *v != 0x0010)
        .collect();
    let ext_count = exts_filtered.len().min(99);
    let ext_count_str = format!("{ext_count:02}");

    // ALPN first two chars, or "00"
    let alpn_chars = ch.alpn().and_then(|v| v.first()).map_or_else(
        || "00".to_string(),
        |s| {
            if s.len() >= 2 {
                s[..2].to_ascii_lowercase()
            } else if s.len() == 1 {
                format!("{}0", s.to_ascii_lowercase())
            } else {
                "00".to_string()
            }
        },
    );

    let tag = format!("t{version_str}{sni_char}{cipher_count_str}{ext_count_str}{alpn_chars}");

    // Part 2: hash of sorted ciphers (decimal, comma-joined)
    let part2 = {
        let mut sorted = ciphers_filtered;
        sorted.sort_unstable();
        let joined = sorted
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        sha256_truncate12(&joined)
    };

    // Part 3: hash of sorted extensions + "_" + sorted sig algs
    let part3 = {
        let mut sorted_exts = exts_filtered;
        sorted_exts.sort_unstable();
        let exts_str = sorted_exts
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        // Signature algorithms from 0x000d
        let sig_algs: Vec<u16> = ch
            .extensions
            .iter()
            .filter_map(|e| {
                if let Extension::SignatureAlgorithms(v) = e {
                    Some(v.as_slice())
                } else {
                    None
                }
            })
            .flatten()
            .copied()
            .filter(|v| !is_grease(*v))
            .collect();
        let mut sorted_sigs = sig_algs;
        sorted_sigs.sort_unstable();
        let sig_str = sorted_sigs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        let combined = if sig_str.is_empty() {
            exts_str
        } else if exts_str.is_empty() {
            sig_str
        } else {
            format!("{exts_str}_{sig_str}")
        };
        // If both empty, hash empty string (yields known prefix)
        sha256_truncate12(&combined)
    };

    Ja4(format!("{tag}_{part2}_{part3}"))
}

fn sha256_truncate12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let hex = hex::encode(result);
    hex[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ClientHelloBuilder;

    #[test]
    fn ja4_format() {
        let ch = ClientHello::parse(
            &ClientHelloBuilder::new()
                .with_sni(Some("example.com".to_string()))
                .build(),
        )
        .unwrap();
        let ja4 = compute_ja4(&ch);
        // Should be tag(10) + "_" + 12 + "_" + 12 = 36
        assert_eq!(ja4.as_str().len(), 36);
        assert_eq!(ja4.as_str().chars().filter(|&c| c == '_').count(), 2);
        assert!(ja4.as_str().starts_with('t'));
    }

    #[test]
    fn ja4_grease_filter_before_sort() {
        let b1 = ClientHelloBuilder::new().with_cipher_suites(vec![0x1301, 0x0a0a, 0x1302]);
        let ch1 = ClientHello::parse(&b1.build()).unwrap();

        let b2 = ClientHelloBuilder::new().with_cipher_suites(vec![0x1301, 0x1302]);
        let ch2 = ClientHello::parse(&b2.build()).unwrap();

        assert_eq!(compute_ja4(&ch1).as_str(), compute_ja4(&ch2).as_str());
    }

    #[test]
    fn ja4_no_sni_gives_i() {
        let ch = ClientHello::parse(&ClientHelloBuilder::new().with_sni(None).build()).unwrap();
        let ja4 = compute_ja4(&ch);
        // t13i...
        assert!(ja4.as_str().contains('i'));
    }

    #[test]
    fn ja4_alpn_chars() {
        let ch = ClientHello::parse(
            &ClientHelloBuilder::new()
                .with_sni(Some("a.com".to_string()))
                .with_alpn(vec!["h2".to_string()])
                .build(),
        )
        .unwrap();
        let ja4 = compute_ja4(&ch);
        assert!(ja4.as_str().starts_with("t13d"));
        assert_eq!(ja4.as_str()[8..10], *"h2");
    }
}
