//! JA3 fingerprint.
//!
//! Spec: `MD5( TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats )`
//! where `TLSVersion` is the decimal of `legacy_version` (e.g. `771` for
//! `0x0303`), cipher suites / extensions are in **wire order** (not sorted),
//! GREASE filtered, and elliptic curves / point formats come from the
//! `supported_groups` / `ec_point_formats` extensions.
//!
//! This is pure and infallible.

use md5::{Digest, Md5};

use crate::tls::client_hello::ClientHello;
use crate::tls::extensions::Extension;
use crate::tls::grease::is_grease;

/// Compute JA3 hash for a `ClientHello`.
///
/// Returns lowercase hex MD5.
#[must_use]
pub fn compute_ja3(ch: &ClientHello) -> String {
    // TLSVersion — decimal of legacy_version (JA3 uses legacy, not real version)
    let version = ch.legacy_version.to_string();

    // CipherSuites — GREASE filtered, original order, decimal strings with "-"
    let ciphers: Vec<String> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .map(|v| v.to_string())
        .collect();
    let ciphers_str = ciphers.join("-");

    // Extensions — GREASE filtered, original order, decimal ext types
    let exts: Vec<String> = ch
        .extensions
        .iter()
        .map(super::super::tls::extensions::Extension::ext_type)
        .filter(|v| !is_grease(*v))
        .map(|v| v.to_string())
        .collect();
    let exts_str = exts.join("-");

    // EllipticCurves — from supported_groups, GREASE filtered, original order
    let curves_str = extract_curves(ch);

    // EC Point Formats — from ec_point_formats, original order (no GREASE concept for u8)
    let point_formats_str = extract_point_formats(ch);

    let ja3_str = format!("{version},{ciphers_str},{exts_str},{curves_str},{point_formats_str}");

    let mut hasher = Md5::new();
    hasher.update(ja3_str.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn extract_curves(ch: &ClientHello) -> String {
    for ext in &ch.extensions {
        if let Extension::SupportedGroups(groups) = ext {
            let filtered: Vec<String> = groups
                .iter()
                .copied()
                .filter(|v| !is_grease(*v))
                .map(|v| v.to_string())
                .collect();
            return filtered.join("-");
        }
    }
    String::new()
}

fn extract_point_formats(ch: &ClientHello) -> String {
    for ext in &ch.extensions {
        if let Extension::EcPointFormats(formats) = ext {
            return formats
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("-");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ClientHelloBuilder;

    #[test]
    fn ja3_deterministic() {
        let ch = ClientHello::parse(
            &ClientHelloBuilder::new()
                .with_sni(Some("example.com".to_string()))
                .build(),
        )
        .unwrap();
        let a = compute_ja3(&ch);
        let b = compute_ja3(&ch);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32); // MD5 hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ja3_grease_filtered() {
        let mut ciphers = vec![0x1301, 0x1302, 0xc02b];
        ciphers.insert(0, 0x0a0a);
        let builder = ClientHelloBuilder::new().with_cipher_suites(ciphers);
        let ch = ClientHello::parse(&builder.build()).unwrap();
        let hash_with_grease = compute_ja3(&ch);

        let builder2 = ClientHelloBuilder::new().with_cipher_suites(vec![0x1301, 0x1302, 0xc02b]);
        let ch2 = ClientHello::parse(&builder2.build()).unwrap();
        let hash_without = compute_ja3(&ch2);
        assert_eq!(hash_with_grease, hash_without);
    }
}
