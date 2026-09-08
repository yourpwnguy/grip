//! JA4S server fingerprint.
//!
//! The idea spec says JA4S is "what cipher suite did the server choose,
//! what extensions did it send back". Different server software (cloudflare,
//! nginx, Apache) picks different ciphers/extensions and thus has a distinct
//! JA4S.
//!
//! # Chosen algorithm for v0.1.0
//! There is no single canonical JA4S spec as stable as JA3; we implement a
//! simple, documented, deterministic one that satisfies the idea and is easy
//! to evolve:
//! ```text
//! JA4S = tag "_" cipher_hex "_" hash12
//! tag  = "t" + version(2) + "d" + ext_count(2) + "00" + "00"
//!        e.g. "t13d010000" for TLS 1.3 with 1 extension
//! cipher_hex = 4-char lowercase hex of selected cipher (e.g. "c02b")
//! hash12 = first 12 hex chars of SHA-256(sorted extension types, ","-joined)
//!          GREASE filtered, "00" if no extensions
//! Final example: "t13d010000_c02b_e5627ecdbbe6"
//! ```
//! The `idea.md` example `t13d000000_c02b_000f` would correspond to a server
//! with 0 extensions in its hash (we produce a hash, not raw list) — this is
//! intentional and documented here; the shape matches but the hash is real.
//!
//! Future: if the `FoxIO` JA4S spec solidifies, we can swap the impl behind
//! the same `compute_ja4s` function without API break.

use sha2::{Digest, Sha256};

use crate::tls::grease::is_grease;
use crate::tls::server_hello::ServerHello;

/// Newtype for JA4S.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4s(pub String);

impl Ja4s {
    /// Return inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Ja4s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Compute JA4S for a `ServerHello`.
#[must_use]
pub fn compute_ja4s(sh: &ServerHello) -> Ja4s {
    let version_str = sh.real_version().ja4_str();

    // Extensions: filter GREASE for count and hash.
    let ext_types: Vec<u16> = sh
        .extensions
        .iter()
        .map(super::super::tls::extensions::Extension::ext_type)
        .filter(|v| !is_grease(*v))
        .collect();
    let ext_count = ext_types.len().min(99);
    // Tag layout mirrors JA4 but server has no cipher count / ALPN, so pad with 00
    let tag = format!("t{version_str}d{ext_count:02}0000");

    let cipher_hex = format!("{:04x}", sh.cipher_suite);

    let hash12 = if ext_types.is_empty() {
        // Hash of empty string is known; but spec examples use "000000000000" for no ext.
        // We use hash of empty to stay consistent with JA4 hashing.
        sha256_truncate12("")
    } else {
        let mut sorted = ext_types;
        sorted.sort_unstable();
        let joined = sorted
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        sha256_truncate12(&joined)
    };

    Ja4s(format!("{tag}_{cipher_hex}_{hash12}"))
}

fn sha256_truncate12(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::server_hello::ServerHello;

    fn build_sh(cipher: u16, exts: Vec<u16>) -> ServerHello {
        // Build minimal ServerHello via raw bytes then parse?
        // Simpler: construct struct directly for test.
        let mut extensions = Vec::new();
        for t in exts {
            extensions.push(crate::tls::extensions::Extension::Unknown(t, vec![]));
        }
        ServerHello {
            legacy_version: 0x0303,
            random: [0x11; 32],
            session_id: vec![],
            cipher_suite: cipher,
            compression_method: 0,
            extensions,
            is_hello_retry_request: false,
            raw: vec![],
        }
    }

    #[test]
    fn ja4s_basic() {
        let sh = build_sh(0xc02b, vec![0x000f]);
        let ja4s = compute_ja4s(&sh);
        assert!(ja4s.as_str().contains("c02b"));
        assert!(ja4s.as_str().starts_with('t'));
        assert_eq!(ja4s.as_str().chars().filter(|&c| c == '_').count(), 2);
    }

    #[test]
    fn ja4s_empty_exts() {
        let sh = build_sh(0x1301, vec![]);
        let ja4s = compute_ja4s(&sh);
        assert!(ja4s.as_str().contains("1301"));
    }
}
