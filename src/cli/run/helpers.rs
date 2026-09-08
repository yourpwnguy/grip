//! Small, pure helpers shared by live and pcap pipelines.
//!
//! Keeping these out of `live.rs` and `pcap.rs` makes the two pipelines
//! trivially auditable: each file contains only the flow it owns, and this
//! module contains only stateless formatting.

use std::io::IsTerminal;

use crate::output::model::{CertSummary, LiveReport};
use crate::tls::{CertInfo, Extension};
use crate::ui::theme::Palette;

/// Live checklist steps, in execution order. Indices are used with the
/// [`Stage`] API and with the progress bridge in `live.rs`, so the two must
/// agree.
pub const LIVE_STEPS: [&str; 6] = [
    "resolve",
    "connect",
    "send",
    "receive",
    "fingerprint",
    "certificate",
];

/// Pcap checklist steps.
pub const PCAP_STEPS: [&str; 4] = ["read", "reassemble", "extract", "rank"];

/// Whether the animated stage may run.
///
/// Requires human output, no `--quiet`, no `--no-progress`, and an
/// interactive stderr — otherwise frames would corrupt logs or pipes.
pub fn should_animate(cli: &crate::cli::args::Cli) -> bool {
    use crate::cli::args::Format;
    use std::io::IsTerminal;
    !cli.quiet && !cli.no_progress && cli.format == Format::Human && std::io::stderr().is_terminal()
}

/// Palette for the report on stdout.
///
/// When `-o file` is given the report is a file, so color is suppressed to
/// keep the artifact clean.
pub fn report_palette(cli: &crate::cli::args::Cli) -> Palette {
    if cli.output.is_some() {
        return Palette::plain();
    }
    Palette::detect(std::io::stdout().is_terminal())
}

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
            format!("{} scts embedded", c.sct_count)
        } else {
            "none".to_string()
        }),
    }
}

/// Field-by-field decode of a `ClientHello` for `--raw`.
///
/// This is not a second parser — it simply projects the already-parsed
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

/// Build the `NegotiatedInfo` DTO from a completed probe.
pub fn build_negotiated(
    probe: &crate::net::connect::ProbeResult,
) -> crate::output::model::NegotiatedInfo {
    use crate::output::model::NegotiatedInfo;
    use std::net::IpAddr;

    let real_ver = probe.server_hello.real_version();
    let offered: Vec<String> = probe
        .client_hello
        .extensions
        .iter()
        .find_map(|e| match e {
            Extension::SupportedVersions(v) => Some(v),
            _ => None,
        })
        .map(|v| {
            v.iter()
                .map(|x| crate::tls::TlsVersion::from_u16(*x).to_string())
                .collect()
        })
        .unwrap_or_default();

    NegotiatedInfo {
        tls_version: real_ver.to_string(),
        offered_versions: offered,
        cipher_suite: crate::tls::cipher::name(probe.server_hello.cipher_suite)
            .map_or_else(|| "unknown".to_string(), str::to_string),
        cipher_hex: format!("0x{:04x}", probe.server_hello.cipher_suite),
        key_exchange: first_group(&probe.server_hello.extensions)
            .or_else(|| first_group(&probe.client_hello.extensions))
            .map(group_name),
        alpn: probe.negotiated_alpn.clone(),
        sni: probe.client_hello.sni().map(str::to_string),
        sni_is_ip: probe
            .client_hello
            .sni()
            .is_some_and(|s| s.parse::<IpAddr>().is_ok()),
    }
}

/// Build the full `LiveReport` after a successful probe.
///
/// This is the single place where DTOs are projected from domain types, so
/// `live.rs` can stay focused on orchestration.
pub fn build_live_report(
    cli: &crate::cli::args::Cli,
    endpoint: String,
    probe: &crate::net::connect::ProbeResult,
    handshake_ms: u128,
    verbose: bool,
) -> LiveReport {
    use crate::output::model::{RawHex, VerboseInfo};

    let negotiated = build_negotiated(probe);
    let certificate = probe
        .cert_chain
        .as_ref()
        .and_then(|c| c.leaf())
        .map(summarise_cert);

    let show_ja3 = cli.show_ja3(true);
    let show_ja4 = cli.show_ja4(true);
    let show_ja4s = cli.show_ja4s(true);
    let ja3 = show_ja3.then(|| crate::fp::compute_ja3(&probe.client_hello));
    let ja4 = show_ja4.then(|| crate::fp::compute_ja4(&probe.client_hello).to_string());
    let ja4s = show_ja4s.then(|| crate::fp::compute_ja4s(&probe.server_hello).to_string());
    let lookup = cli
        .lookup
        .then(|| crate::fp::lookup::lookup(ja4.as_deref(), ja3.as_deref()).map(str::to_string))
        .flatten();

    let (target, port) = parse_target_and_port(&endpoint, 443);
    let cert_chain = cli
        .cert_chain
        .then(|| {
            probe
                .cert_chain
                .as_ref()
                .map(|c| c.0.iter().map(summarise_cert).collect::<Vec<_>>())
        })
        .flatten();

    let verbose_info = verbose.then(|| VerboseInfo {
        handshake_ms,
        bytes_sent: probe.client_hello_raw.len(),
        bytes_received: probe.server_hello_raw.len(),
        resolved_ips: crate::net::connect::resolve_target(&target, port)
            .map(|a| a.iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
        grease_filtered: probe
            .client_hello
            .cipher_suites
            .iter()
            .filter(|c| crate::tls::is_grease(**c))
            .count(),
    });

    let raw = cli.raw.then(|| RawHex {
        client_hello_hex: hex::encode(&probe.client_hello_raw),
        server_hello_hex: hex::encode(&probe.server_hello_raw),
        client_hello_parsed: describe_client_hello(&probe.client_hello),
    });

    let mut report = LiveReport {
        target: endpoint,
        negotiated,
        certificate,
        cert_chain,
        fingerprints: crate::output::model::Fingerprints {
            ja3,
            ja4,
            ja4s,
            lookup,
        },
        raw,
        verbose_info,
    };

    // Augment leaf CT log with intermediates count for the human panel.
    if cli.cert_chain
        && let Some(chain) = &probe.cert_chain
        && chain.len() > 1
        && let Some(cert) = &mut report.certificate
    {
        cert.ct_logs = Some(format!(
            "{} + {} intermediates",
            cert.ct_logs.as_deref().unwrap_or("—"),
            chain.len() - 1
        ));
    }
    report
}
