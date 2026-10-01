//! Small, pure helpers shared by live and pcap pipelines.
//!
//! Keeping these out of `live.rs` and `pcap.rs` makes the two pipelines
//! trivially auditable: each file contains only the flow it owns, and this
//! module contains only stateless formatting.

use crate::output::model::CertSummary;
use crate::tls::{CertInfo, Extension};

/// Split a `host:port` target, falling back to `default_port`.
///
/// Only unbracketed IPv4/hostname forms are split: a bare IPv6 literal
/// contains colons and must not be misread as `host:port`.
pub fn parse_target_and_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some(idx) = target.rfind(':') {
        let host = &target[..idx];
        if let Ok(port) = target[idx + 1..].parse::<u16>()
            && !host.is_empty()
            && !host.contains(':')
        {
            return (host.to_string(), port);
        }
    }
    (target.to_string(), default_port)
}

/// Map a TLS named-group id to a display name.
pub fn group_name(g: u16) -> String {
    match g {
        0x001d => "X25519".to_string(),
        0x0017 => "P-256".to_string(),
        0x0018 => "P-384".to_string(),
        0x0019 => "P-521".to_string(),
        other => format!("0x{other:04x}"),
    }
}

/// First named group from a set of extensions, if any.
///
/// Prefers `supported_groups` over `key_share`, matching the order a reader
/// would expect when triaging a handshake.
pub fn first_group(exts: &[Extension]) -> Option<u16> {
    exts.iter().find_map(|e| match e {
        Extension::SupportedGroups(v) => v.first().copied(),
        Extension::KeyShare(k) => k.first().map(|e| e.group),
        _ => None,
    })
}

/// Flatten a parsed certificate into its display DTO.
pub fn summarise_cert(c: &CertInfo) -> CertSummary {
    CertSummary {
        subject: Some(c.subject.clone()),
        issuer: Some(c.issuer.clone()),
        sans: c.sans.clone(),
        expires: Some(crate::util::time::format_expiry(c.not_after)),
        sha256: Some(c.sha256_fingerprint.clone()),
        ct_logs: Some(if c.sct_count > 0 {
            format!(
                "{} sct{} embedded",
                c.sct_count,
                if c.sct_count == 1 { "" } else { "s" }
            )
        } else {
            "none".to_string()
        }),
    }
}

/// Field-by-field decode of a `ClientHello` for `--raw`.
///
/// This is not a second parser. It simply projects the already-parsed
/// `ClientHello` into a human-readable form without re-reading bytes.
pub fn describe_client_hello(ch: &crate::tls::ClientHello) -> String {
    let suites = ch
        .cipher_suites
        .iter()
        .map(|c| format!("0x{c:04x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let exts = ch
        .extensions
        .iter()
        .map(|e| format!("0x{:04x}", e.ext_type()))
        .collect::<Vec<_>>()
        .join(" ");
    let grease = ch
        .cipher_suites
        .iter()
        .filter(|c| crate::tls::is_grease(**c))
        .map(|c| format!("0x{c:04x}"))
        .collect::<Vec<_>>();

    [
        "content type: 0x16 handshake".to_string(),
        format!("legacy version: 0x{:04x}", ch.legacy_version),
        "handshake type: 0x01 client hello".to_string(),
        format!("real version: {}", ch.real_version()),
        format!("session id: {} bytes", ch.session_id.len()),
        format!("cipher suites: {suites}"),
        format!("extensions: {exts}"),
        format!(
            "grease: {}",
            if grease.is_empty() {
                "none".to_string()
            } else {
                grease.join(" ")
            }
        ),
    ]
    .join("\n")
}
