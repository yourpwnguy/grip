//! Projecting a finished probe into the DTOs the renderers consume.
//!
//! This is the one place domain types become `output::model` structs, so the
//! renderers stay dumb and snapshot-testable without touching the network.

use crate::output::model::LiveReport;
use crate::tls::Extension;

use super::helpers::{
    describe_client_hello, first_group, group_name, parse_target_and_port, summarise_cert,
};

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
    let lookup = cli.lookup.then(|| {
        crate::fp::lookup::lookup(ja4.as_deref(), ja3.as_deref()).map_or_else(
            || crate::output::model::UNCLASSIFIED.to_string(),
            str::to_string,
        )
    });

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
