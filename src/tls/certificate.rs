//! Certificate chain parsing.
//!
//! After `ServerHello` the server sends a `Certificate` handshake message.
//! For `grip` we only need the leaf + intermediates to display subject,
//! issuer, SANs, expiry, and to compute SHA-256 fingerprints. We delegate
//! ASN.1/DER parsing to `x509-parser` — hand-rolling ASN.1 is a classic
//! source of critical vulns.
//!
//! # Limits
//! We cap the chain at 10 certs and each cert at 16 KiB DER to bound
//! memory on adversarial inputs.

use crate::error::{GripError, GripResult};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Information extracted from a single certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Subject (e.g. `CN=example.com, O=Example`).
    pub subject: String,
    /// Issuer.
    pub issuer: String,
    /// Subject Alternative Names (DNS names + IPs).
    pub sans: Vec<String>,
    /// Not-after (expiry) in UTC.
    pub not_after: DateTime<Utc>,
    /// Not-before.
    pub not_before: DateTime<Utc>,
    /// SHA-256 fingerprint of the DER bytes (colon-separated hex).
    pub sha256_fingerprint: String,
    /// Number of embedded SCTs (Certificate Transparency) — extracted from
    /// the `1.3.6.1.4.1.11129.2.4.2` extension if present.
    pub sct_count: usize,
    /// Is self-signed?
    pub is_self_signed: bool,
}

/// A chain of certificates as sent by the server.
#[derive(Debug, Clone)]
pub struct CertificateChain(pub Vec<CertInfo>);

impl CertificateChain {
    /// Maximum certs in a chain we will parse.
    pub const MAX_CHAIN_LEN: usize = 10;
    /// Maximum DER bytes per cert.
    pub const MAX_CERT_SIZE: usize = 16 * 1024;

    /// Parse a TLS `Certificate` handshake message (including handshake
    /// header `0x0b`). `buf` may be the full handshake message or just
    /// the body after the 4-byte handshake header. The TLS `Certificate`
    /// format for TLS 1.2 is:
    /// `certs_len(3) || [cert_len(3) || cert_der]…`
    /// For TLS 1.3 it adds `request_context` before.
    ///
    /// We handle both by heuristics: if the first 3 bytes plus 3 == `buf.len()`
    /// we treat it as TLS 1.2 style.
    ///
    /// # Errors
    ///
    /// Returns [`GripError::Certificate`] if the handshake header is too short,
    /// the declared length exceeds the buffer, no certificates are found,
    /// a cert is too large, or X.509 parsing fails.
    pub fn parse_tls_certificate(buf: &[u8]) -> GripResult<Self> {
        // Strip handshake header if present (type 0x0b)
        let body = if !buf.is_empty() && buf[0] == 0x0b {
            if buf.len() < 4 {
                return Err(GripError::Certificate(
                    "Certificate handshake too short".to_string(),
                ));
            }
            let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
            if buf.len() < 4 + len {
                return Err(GripError::Certificate(
                    "Certificate length exceeds buffer".to_string(),
                ));
            }
            &buf[4..4 + len]
        } else {
            buf
        };

        // TLS 1.3 has request_context length byte before certs.
        // Detect: if body[0] + 1 + 3 == body.len() maybe 1.3 style.
        // For simplicity try both: if first byte small and remaining parses as cert list, treat as 1.3.
        let certs_bytes = if body.is_empty() {
            body
        } else {
            let ctx_len = body[0] as usize;
            if ctx_len + 1 + 3 <= body.len() {
                let after_ctx = &body[1 + ctx_len..];
                if after_ctx.len() >= 3 {
                    let list_len = ((after_ctx[0] as usize) << 16)
                        | ((after_ctx[1] as usize) << 8)
                        | (after_ctx[2] as usize);
                    if list_len + 3 == after_ctx.len() {
                        after_ctx
                    } else if body.len() >= 3 {
                        let list_len2 = ((body[0] as usize) << 16)
                            | ((body[1] as usize) << 8)
                            | (body[2] as usize);
                        if list_len2 + 3 == body.len() {
                            body
                        } else {
                            after_ctx
                        }
                    } else {
                        body
                    }
                } else {
                    body
                }
            } else {
                body
            }
        };

        if certs_bytes.len() < 3 {
            return Err(GripError::Certificate(
                "Certificate certs_len missing".to_string(),
            ));
        }
        let total_len = ((certs_bytes[0] as usize) << 16)
            | ((certs_bytes[1] as usize) << 8)
            | (certs_bytes[2] as usize);
        if total_len + 3 > certs_bytes.len() {
            return Err(GripError::Certificate(format!(
                "Certificate total_len {total_len} exceeds available {}",
                certs_bytes.len() - 3
            )));
        }
        let mut certs = Vec::new();
        let mut pos = 3;
        let end = 3 + total_len;
        while pos + 3 <= end {
            if certs.len() >= Self::MAX_CHAIN_LEN {
                break; // cap
            }
            let cert_len = ((certs_bytes[pos] as usize) << 16)
                | ((certs_bytes[pos + 1] as usize) << 8)
                | (certs_bytes[pos + 2] as usize);
            pos += 3;
            // For TLS 1.3 each cert has 2-byte extensions after DER — skip them.
            // We need to handle that: cert_len is DER len, then 2-byte ext len + ext bytes.
            if pos + cert_len > end && pos + cert_len > certs_bytes.len() {
                return Err(GripError::Certificate(format!(
                    "cert_len {cert_len} exceeds buffer"
                )));
            }
            if pos + cert_len > certs_bytes.len() {
                break;
            }
            if cert_len > Self::MAX_CERT_SIZE {
                return Err(GripError::Certificate(format!(
                    "cert too large: {cert_len}"
                )));
            }
            let der = &certs_bytes[pos..pos + cert_len];
            pos += cert_len;
            // TLS 1.3 per-cert extensions
            if pos + 2 <= end && pos + 2 <= certs_bytes.len() {
                // Peek if remaining bytes look like extensions length
                // For TLS 1.2 there are no per-cert extensions, so pos == end.
                // For 1.3, there is u16 ext_len.
                if pos < end {
                    let ext_len =
                        u16::from_be_bytes([certs_bytes[pos], certs_bytes[pos + 1]]) as usize;
                    if pos + 2 + ext_len <= end {
                        pos += 2 + ext_len;
                    }
                }
            }
            let info = parse_single_cert(der)?;
            certs.push(info);
        }
        if certs.is_empty() {
            return Err(GripError::Certificate(
                "no certificates in chain".to_string(),
            ));
        }
        Ok(Self(certs))
    }

    /// Convenience: leaf certificate (first in chain).
    #[must_use]
    pub fn leaf(&self) -> Option<&CertInfo> {
        self.0.first()
    }

    /// Build a chain from raw DER bytes (as returned by `rustls`).
    ///
    /// This is used as a fallback for TLS 1.3 where the `Certificate`
    /// message is encrypted and cannot be parsed from raw TCP bytes.
    /// Each DER is parsed via `x509-parser` and SHA-256 fingerprinted.
    ///
    /// # Errors
    ///
    /// Returns [`GripError::Certificate`] if the list is empty, exceeds
    /// `MAX_CHAIN_LEN`, a cert exceeds 64 KiB, or X.509 parsing fails.
    pub fn from_der_list(ders: &[Vec<u8>]) -> GripResult<Self> {
        if ders.is_empty() {
            return Err(GripError::Certificate(
                "no certificates from TLS handshake".to_string(),
            ));
        }
        if ders.len() > Self::MAX_CHAIN_LEN {
            return Err(GripError::Certificate(format!(
                "chain too long: {} > {}",
                ders.len(),
                Self::MAX_CHAIN_LEN
            )));
        }
        let mut certs = Vec::with_capacity(ders.len());
        for der in ders {
            if der.len() > Self::MAX_CERT_SIZE * 4 {
                // Allow slightly larger for rustls-fetched certs (some chains are >16 KiB)
                // but still cap at 64 KiB to avoid OOM.
                if der.len() > 64 * 1024 {
                    return Err(GripError::Certificate(format!(
                        "cert too large: {}",
                        der.len()
                    )));
                }
            }
            let info = parse_single_cert(der)?;
            certs.push(info);
        }
        Ok(Self(certs))
    }

    /// Number of certs in chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Is empty?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn parse_single_cert(der: &[u8]) -> GripResult<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| GripError::Certificate(format!("x509 parse: {e:?}")))?;

    let subject = cert.subject.to_string();
    let issuer = cert.issuer.to_string();

    let sans = extract_sans(&cert);

    let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .unwrap_or_else(Utc::now);
    let not_before = DateTime::<Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0)
        .unwrap_or_else(Utc::now);

    // SHA-256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(der);
    let hash = hasher.finalize();
    let sha256_fingerprint = hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    // SCT count from extension 1.3.6.1.4.1.11129.2.4.2
    let sct_count = count_scts(&cert, der);

    let is_self_signed = subject == issuer;

    Ok(CertInfo {
        subject,
        issuer,
        sans,
        not_after,
        not_before,
        sha256_fingerprint,
        sct_count,
        is_self_signed,
    })
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => sans.push((*s).to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else {
                        sans.push(hex::encode(ip));
                    }
                }
                _ => {}
            }
        }
    }
    sans
}

fn count_scts(cert: &X509Certificate<'_>, _der: &[u8]) -> usize {
    // OID for SCT list: 1.3.6.1.4.1.11129.2.4.2
    for ext in cert.extensions() {
        if ext.oid.to_string() == "1.3.6.1.4.1.11129.2.4.2" {
            // The extension value is an OCTET STRING containing a list.
            // Counting SCTs requires parsing the SignedCertificateTimestampList.
            // For v0.1.0 we do a heuristic: if the extension exists, assume at least 1,
            // and try to parse the inner length.
            // SCT list: total_len(2) || sct_len(2) || sct_data …
            // We'll just count by walking length prefixes if possible.
            let v = ext.value;
            if v.len() >= 2 {
                let total = u16::from_be_bytes([v[0], v[1]]) as usize;
                let mut pos = 2;
                let mut count = 0;
                while pos + 2 <= v.len() && pos < 2 + total {
                    if pos + 2 > v.len() {
                        break;
                    }
                    let sct_len = u16::from_be_bytes([v[pos], v[pos + 1]]) as usize;
                    if sct_len == 0 || pos + 2 + sct_len > v.len() {
                        break;
                    }
                    count += 1;
                    pos += 2 + sct_len;
                }
                if count > 0 {
                    return count;
                }
                return 1;
            }
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_fails() {
        let buf = [0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert!(CertificateChain::parse_tls_certificate(&buf).is_err());
    }
}
