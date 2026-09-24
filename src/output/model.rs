//! Output DTOs — serializable models for both human and JSON renderers.
//!
//! We decouple domain structs (`ClientHello`, `ServerHello`) from presentation.
//! The DTOs are plain data, `Serialize` only here, so domain evolution doesn't
//! break JSON schema without explicit migration.

use serde::Serialize;

/// Stored in [`Fingerprints::lookup`] / [`ClientEntry::client`] when
/// `--lookup` was requested but the database had no match.
///
/// `None` means lookup was never requested (renderers omit the row or show
/// "—"); `Some(UNCLASSIFIED)` means it ran and missed (renderers show the
/// word, muted). Exact matches carry the client name.
pub const UNCLASSIFIED: &str = "unclassified";

/// Negotiated connection info for live mode.
#[derive(Debug, Clone, Serialize)]
pub struct NegotiatedInfo {
    /// Negotiated TLS version (display string).
    pub tls_version: String,
    /// Versions offered by client (from `supported_versions`).
    pub offered_versions: Vec<String>,
    /// Cipher suite name and raw hex.
    pub cipher_suite: String,
    /// Raw cipher id.
    pub cipher_hex: String,
    /// Key exchange group (e.g. "X25519"), if known.
    pub key_exchange: Option<String>,
    /// Negotiated ALPN.
    pub alpn: Option<String>,
    /// SNI we sent.
    pub sni: Option<String>,
    /// Whether SNI was IP.
    pub sni_is_ip: bool,
}

/// Human-friendly certificate summary.
#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    /// Subject.
    pub subject: Option<String>,
    /// Issuer.
    pub issuer: Option<String>,
    /// SANs.
    pub sans: Vec<String>,
    /// Expiry formatted as "2026-11-15 (77 days)".
    pub expires: Option<String>,
    /// SHA-256 fingerprint colon-separated.
    pub sha256: Option<String>,
    /// SCT count.
    pub ct_logs: Option<String>, // "✓ 2 SCTs embedded" or "—"
}

/// Fingerprints for display.
#[derive(Debug, Clone, Serialize)]
pub struct Fingerprints {
    /// JA3 (MD5 hex) or None if disabled.
    pub ja3: Option<String>,
    /// JA4 string.
    pub ja4: Option<String>,
    /// JA4S string.
    pub ja4s: Option<String>,
    /// Known client lookup (e.g. "Chrome 120").
    pub lookup: Option<String>,
}

/// Live mode report — what `grip example.com` renders.
#[derive(Debug, Clone, Serialize)]
pub struct LiveReport {
    /// Target (host:port).
    pub target: String,
    /// Negotiated info.
    pub negotiated: NegotiatedInfo,
    /// Certificate summary (None if no cert parsed) — leaf.
    pub certificate: Option<CertSummary>,
    /// Full chain when `--cert-chain` is set (leaf + intermediates).
    pub cert_chain: Option<Vec<CertSummary>>,
    /// Fingerprints.
    pub fingerprints: Fingerprints,
    /// Raw hex dump (only if --raw).
    pub raw: Option<RawHex>,
    /// Verbose transparency info (timings, bytes) — only if --verbose.
    pub verbose_info: Option<VerboseInfo>,
}

/// Verbose transparency.
#[derive(Debug, Clone, Serialize)]
pub struct VerboseInfo {
    /// Handshake duration ms.
    pub handshake_ms: u128,
    /// Bytes sent (`ClientHello`).
    pub bytes_sent: usize,
    /// Bytes received (`ServerHello` + etc).
    pub bytes_received: usize,
    /// Resolved IPs.
    pub resolved_ips: Vec<String>,
    /// GREASE filtered count.
    pub grease_filtered: usize,
}

/// Raw hex dumps for --raw.
#[derive(Debug, Clone, Serialize)]
pub struct RawHex {
    /// `ClientHello` hex dump.
    pub client_hello_hex: String,
    /// `ServerHello` hex dump (hex).
    pub server_hello_hex: String,
    /// Parsed `ClientHello` summary (debug).
    pub client_hello_parsed: String,
}

/// Pcap analysis report.
#[derive(Debug, Clone, Serialize)]
pub struct PcapReport {
    /// Pcap file path.
    pub file: String,
    /// Total handshakes seen.
    pub total_handshakes: usize,
    /// Unique clients (unique (IP, JA4) combos or JA4 if --unique).
    pub unique_clients: usize,
    /// Per-client entries (already sorted/filtered per CLI).
    pub clients: Vec<ClientEntry>,
}

/// Entry per IP+JA4.
#[derive(Debug, Clone, Serialize)]
pub struct ClientEntry {
    /// Source IP.
    pub ip: String,
    /// JA4 fingerprint.
    pub ja4: String,
    /// JA3 fingerprint (optional).
    pub ja3: Option<String>,
    /// Client guess via lookup.
    pub client: Option<String>,
    /// Seen count.
    pub count: usize,
}
