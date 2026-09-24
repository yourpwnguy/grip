//! Live probe — raw TLS handshake capture.
//!
//! This module owns the live network path: it crafts a `ClientHello` by hand,
//! speaks it over a raw `TcpStream`, and parses the `ServerHello` from the
//! bytes that come back. Nothing here uses a TLS library for the handshake
//! itself; that is the product. A `rustls` fallback is used *only* to recover
//! the certificate chain when TLS 1.3 encrypts it.
//!
//! # Design
//! - Pure `tls` parsers are the source of truth for fingerprinting.
//! - I/O is synchronous `std::net` with short poll timeouts, so a quiet peer
//!   does not burn the full budget.

mod cert_fetch;
mod dial;
mod raw;

use std::time::Duration;

use crate::error::{GripError, GripResult};
use crate::tls::ClientHelloBuilder;
use crate::tls::certificate::CertificateChain;
use crate::tls::client_hello::ClientHello;
use crate::tls::server_hello::ServerHello;

pub use dial::resolve_target;

/// Result of a live probe.
#[derive(Debug)]
pub struct ProbeResult {
    /// Parsed `ClientHello` we sent.
    pub client_hello: ClientHello,
    /// Raw bytes we sent.
    pub client_hello_raw: Vec<u8>,
    /// Parsed `ServerHello`.
    pub server_hello: ServerHello,
    /// Chain, if recovered (raw or `rustls` fallback).
    pub cert_chain: Option<CertificateChain>,
    /// Raw `ServerHello` record.
    pub server_hello_raw: Vec<u8>,
    /// Negotiated ALPN.
    pub negotiated_alpn: Option<String>,
}

/// Probe `target:port` with the default `ClientHello`.
///
/// See [`probe_with_verify`] for the `insecure` variant.
///
/// # Errors
///
/// Returns [`GripError::Network`] if DNS resolution or TCP connection
/// fails, or if no `ServerHello` is received. Returns [`GripError::Io`]
/// if setting socket timeouts fails.
pub fn probe(
    target: &str,
    port: u16,
    sni: Option<&str>,
    timeout_s: u64,
) -> GripResult<ProbeResult> {
    probe_with_verify(target, port, sni, timeout_s, false)
}

/// Probe with explicit certificate verification.
///
/// `insecure` disables cert verification in the `rustls` fallback.
///
/// # Errors
///
/// Returns [`GripError::Network`] if DNS resolution, TCP connection,
/// or the TLS handshake fails. Returns [`GripError::Io`] if socket
/// operations fail. Returns [`GripError::Other`] if the internally
/// crafted `ClientHello` cannot be re-parsed.
pub fn probe_with_verify(
    target: &str,
    port: u16,
    sni_override: Option<&str>,
    timeout_s: u64,
    insecure: bool,
) -> GripResult<ProbeResult> {
    let timeout = Duration::from_secs(timeout_s);
    let sni = sni_override.map(str::to_string).or_else(|| {
        target
            .parse::<std::net::IpAddr>()
            .is_err()
            .then(|| target.to_string())
    });

    let client_hello_raw = ClientHelloBuilder::new()
        .with_sni(sni.clone())
        .with_random(dial::random_32())
        .build();
    let client_hello = ClientHello::parse(&client_hello_raw)
        .map_err(|e| GripError::Other(format!("self ClientHello parse: {e}")))?;

    let addrs = dial::resolve_target(target, port)?;
    let mut stream = dial::dial(&addrs, timeout, target, port)?;

    // Short poll avoids burning the full timeout when the peer is done.
    let poll = timeout.min(Duration::from_millis(400));
    stream.set_read_timeout(Some(poll)).map_err(GripError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(GripError::Io)?;

    let raw = raw::drive(&mut stream, &client_hello_raw, timeout, poll)?;
    let server_hello = raw.server_hello.ok_or_else(|| {
        if raw.buf.is_empty() {
            GripError::Network(format!("no data from {target}:{port}"))
        } else {
            GripError::Network(format!(
                "no ServerHello in {} B from {target}:{port}",
                raw.buf.len()
            ))
        }
    })?;

    let negotiated_alpn = server_hello.extensions.iter().find_map(|e| match e {
        crate::tls::Extension::Alpn(v) => v.first().cloned(),
        _ => None,
    });

    // Prefer the raw chain; otherwise try rustls (TLS 1.3 encrypts it).
    let mut cert_chain = raw.cert_chain;
    if cert_chain.is_none() {
        let budget = timeout.min(Duration::from_secs(5));
        if let Some(chain) =
            cert_fetch::fetch_via_rustls(target, port, sni.as_deref(), budget, insecure)
        {
            cert_chain = Some(chain);
        }
    }

    Ok(ProbeResult {
        client_hello,
        client_hello_raw,
        server_hello,
        cert_chain,
        server_hello_raw: raw.server_hello_raw,
        negotiated_alpn,
    })
}
