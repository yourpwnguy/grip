//! TLS extensions parsing.
//!
//! Each extension is `type(2) || length(2) || data(length)` and they are
//! walked linearly.  We parse the extensions we care about for fingerprinting
//! and keep the rest as [`Extension::Unknown`] so future extensions don't
//! break us.
//!
//! # Fingerprinting relevance
//!
//! JA3/JA4 hash extensions, cipher suites, and signature algorithms.  The
//! helpers here expose those vectors in a structured form.

mod alpn;
mod common;
mod key_share;
mod sni;
mod versions;

use crate::error::{GripError, GripResult, ParseKind};

/// A parsed TLS extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// `0x0000` — Server Name Indication.
    Sni(String),
    /// `0x000a` — Supported Groups (elliptic curves).
    SupportedGroups(Vec<u16>),
    /// `0x000b` — EC Point Formats.
    EcPointFormats(Vec<u8>),
    /// `0x000d` — Signature Algorithms.
    SignatureAlgorithms(Vec<u16>),
    /// `0x0010` — Application-Layer Protocol Negotiation.
    Alpn(Vec<String>),
    /// `0x002b` — Supported Versions.
    SupportedVersions(Vec<u16>),
    /// `0x0033` — Key Share.
    KeyShare(Vec<KeyShareEntry>),
    /// Any other extension or a known one we chose to keep opaque.
    Unknown(u16, Vec<u8>),
}

/// Entry inside `KeyShare` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// Named group.
    pub group: u16,
    /// Public key bytes.
    pub key_exchange: Vec<u8>,
}

impl Extension {
    /// The numeric extension type id.
    #[must_use]
    pub const fn ext_type(&self) -> u16 {
        match self {
            Self::Sni(_) => 0x0000,
            Self::SupportedGroups(_) => 0x000a,
            Self::EcPointFormats(_) => 0x000b,
            Self::SignatureAlgorithms(_) => 0x000d,
            Self::Alpn(_) => 0x0010,
            Self::SupportedVersions(_) => 0x002b,
            Self::KeyShare(_) => 0x0033,
            Self::Unknown(t, _) => *t,
        }
    }
}

/// Parse a raw extensions block into [`Extension`] values.
///
/// `buf` must be exactly the extensions bytes (without the 2-byte length
/// prefix — the caller strips it).
///
/// Returns the extensions in wire order.
///
/// # Errors
///
/// - [`ParseKind::UnexpectedEof`] if an extension header is truncated.
/// - [`ParseKind::BadExtension`] if a known extension's payload is malformed.
///
/// Unknown extensions or known ones that fail to parse are kept as
/// [`Extension::Unknown`] so the handshake still reconstructs.
pub fn parse_extensions(buf: &[u8]) -> GripResult<Vec<Extension>> {
    let mut exts = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        if buf.len() - pos < 4 {
            return Err(GripError::parse(
                pos,
                ParseKind::UnexpectedEof {
                    needed: 4,
                    available: buf.len() - pos,
                },
            ));
        }
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if buf.len() - pos < ext_len {
            return Err(GripError::parse(
                pos,
                ParseKind::UnexpectedEof {
                    needed: ext_len,
                    available: buf.len() - pos,
                },
            ));
        }
        let data = &buf[pos..pos + ext_len];
        let ext = parse_single(ext_type, data)
            .unwrap_or_else(|_| Extension::Unknown(ext_type, data.to_vec()));
        exts.push(ext);
        pos += ext_len;
    }
    Ok(exts)
}

fn parse_single(ext_type: u16, data: &[u8]) -> Result<Extension, ParseKind> {
    Ok(match ext_type {
        0x0000 => Extension::Sni(sni::parse(data)?),
        0x000a => Extension::SupportedGroups(common::parse_u16_list(data)?),
        0x000b => Extension::EcPointFormats(common::parse_u8_list(data)?),
        0x000d => Extension::SignatureAlgorithms(common::parse_u16_list(data)?),
        0x0010 => Extension::Alpn(alpn::parse(data)?),
        0x002b => Extension::SupportedVersions(versions::parse(data)?),
        0x0033 => Extension::KeyShare(key_share::parse(data)?),
        _ => Extension::Unknown(ext_type, data.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sni_simple() {
        let mut data = vec![0x00, 0x0e, 0x00, 0x00, 0x0b];
        data.extend_from_slice(b"example.com");
        let ext = parse_single(0x0000, &data).unwrap();
        assert_eq!(ext, Extension::Sni("example.com".to_string()));
    }

    #[test]
    fn parse_supported_groups() {
        let data = [0x00, 0x04, 0x00, 0x1d, 0x00, 0x17];
        let ext = parse_single(0x000a, &data).unwrap();
        assert_eq!(ext, Extension::SupportedGroups(vec![0x001d, 0x0017]));
    }

    #[test]
    fn unknown_extension() {
        let ext = parse_single(0x9999, &[0x01, 0x02]).unwrap();
        assert_eq!(ext, Extension::Unknown(0x9999, vec![1, 2]));
    }

    #[test]
    fn parse_extensions_empty() {
        assert!(parse_extensions(&[]).unwrap().is_empty());
    }

    #[test]
    fn parse_extensions_roundtrip() {
        let sni_data = {
            let mut d = vec![0x00, 0x0e, 0x00, 0x00, 0x0b];
            d.extend_from_slice(b"example.com");
            d
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0000u16.to_be_bytes());
        buf.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&sni_data);
        let alpn_data = [0x00, 0x03, 0x02, b'h', b'2'];
        buf.extend_from_slice(&0x0010u16.to_be_bytes());
        buf.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&alpn_data);
        assert_eq!(parse_extensions(&buf).unwrap().len(), 2);
    }
}
