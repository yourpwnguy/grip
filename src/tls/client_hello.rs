//! `ClientHello` parsing.
//!
//! Wire format (after the 5-byte record header):
//! ```text
//! 0      Handshake Type 0x01
//! 1-3    Handshake Length (u24 BE)
//! 4-5    Client Version (legacy, usually 0x0303)
//! 6-37   Random (32 bytes)
//! 38     Session ID Length (1)
//! 39..   Session ID
//! ..     Cipher Suites Length (2)
//! ..     Cipher Suites (each 2)
//! ..     Compression Methods Length (1)
//! ..     Compression Methods
//! ..     Extensions Length (2) — may be absent if no extensions
//! ..     Extensions
//! ```
//! All length prefixes are validated. The raw bytes are retained for
//! `--raw` and for fingerprint hashing that needs the original.

use crate::error::{GripError, GripResult, ParseKind};
use crate::tls::extensions::{Extension, parse_extensions};
use crate::tls::record::{ContentType, TlsRecord};

/// Parsed `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Legacy version field (e.g. `0x0303`). Real version is via extensions.
    pub legacy_version: u16,
    /// 32 random bytes.
    pub random: [u8; 32],
    /// Session ID (may be empty for TLS 1.3).
    pub session_id: Vec<u8>,
    /// Cipher suites as sent (GREASE still present — callers filter).
    pub cipher_suites: Vec<u16>,
    /// Compression methods (usually `[0]`).
    pub compression_methods: Vec<u8>,
    /// Extensions in wire order.
    pub extensions: Vec<Extension>,
    /// Original bytes of the `ClientHello` handshake message (for `--raw`).
    pub raw: Vec<u8>,
}

impl ClientHello {
    /// Parse a `ClientHello` from raw bytes that may include record headers.
    ///
    /// `buf` can be either:
    /// - Just the handshake bytes (starting with `0x01`), or
    /// - A full TLS record (`0x16 0x03 ...`).
    ///
    /// The function detects the case automatically.
    ///
    /// # Errors
    /// Returns `GripError::Parse` if any length prefix is invalid or the
    /// handshake type is not `ClientHello`.
    pub fn parse(buf: &[u8]) -> GripResult<Self> {
        // If buf starts with 0x16, try record parsing.
        let handshake_bytes = if !buf.is_empty() && buf[0] == 0x16 {
            let (rec, _) = TlsRecord::parse(buf, 0)?;
            if rec.content_type != ContentType::Handshake {
                return Err(GripError::parse(
                    0,
                    ParseKind::Malformed("expected Handshake record".to_string()),
                ));
            }
            // Handshake message inside record payload: type + 3-byte len + body
            if rec.payload.is_empty() || rec.payload[0] != 0x01 {
                return Err(GripError::parse(
                    5,
                    ParseKind::Malformed(format!(
                        "expected ClientHello handshake type 0x01, got 0x{:02x}",
                        rec.payload.first().copied().unwrap_or(0)
                    )),
                ));
            }
            rec.payload
        } else {
            buf.to_vec()
        };

        Self::parse_handshake(&handshake_bytes)
    }

    fn parse_handshake(buf: &[u8]) -> GripResult<Self> {
        if buf.len() < 4 {
            return Err(GripError::parse(
                0,
                ParseKind::UnexpectedEof {
                    needed: 4,
                    available: buf.len(),
                },
            ));
        }
        if buf[0] != 0x01 {
            return Err(GripError::parse(
                0,
                ParseKind::Malformed(format!("handshake type 0x{:02x} != 0x01", buf[0])),
            ));
        }
        let hs_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        if buf.len() < 4 + hs_len {
            return Err(GripError::parse(
                1,
                ParseKind::UnexpectedEof {
                    needed: 4 + hs_len,
                    available: buf.len(),
                },
            ));
        }
        let body = &buf[4..4 + hs_len];
        let raw = buf[..4 + hs_len].to_vec();
        Self::parse_body(body, raw)
    }

    fn parse_body(body: &[u8], raw: Vec<u8>) -> GripResult<Self> {
        let mut pos = 0;

        // ClientVersion (2)
        if body.len() < 2 {
            return Err(GripError::parse(
                4,
                ParseKind::UnexpectedEof {
                    needed: 2,
                    available: body.len(),
                },
            ));
        }
        let legacy_version = u16::from_be_bytes([body[0], body[1]]);
        pos += 2;

        // Random (32)
        if body.len() < pos + 32 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 32,
                    available: body.len() - pos,
                },
            ));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&body[pos..pos + 32]);
        pos += 32;

        // Session ID
        if body.len() < pos + 1 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 1,
                    available: body.len() - pos,
                },
            ));
        }
        let session_id_len = body[pos] as usize;
        pos += 1;
        if body.len() < pos + session_id_len {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: session_id_len,
                    available: body.len() - pos,
                },
            ));
        }
        let session_id = body[pos..pos + session_id_len].to_vec();
        pos += session_id_len;

        // Cipher Suites
        if body.len() < pos + 2 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 2,
                    available: body.len() - pos,
                },
            ));
        }
        let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if !cs_len.is_multiple_of(2) {
            return Err(GripError::parse(
                4 + pos - 2,
                ParseKind::OddCipherSuiteLength(cs_len),
            ));
        }
        if body.len() < pos + cs_len {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: cs_len,
                    available: body.len() - pos,
                },
            ));
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for chunk in body[pos..pos + cs_len].as_chunks::<2>().0 {
            cipher_suites.push(u16::from_be_bytes(*chunk));
        }
        pos += cs_len;

        // Compression Methods
        if body.len() < pos + 1 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 1,
                    available: body.len() - pos,
                },
            ));
        }
        let comp_len = body[pos] as usize;
        pos += 1;
        if body.len() < pos + comp_len {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: comp_len,
                    available: body.len() - pos,
                },
            ));
        }
        let compression_methods = body[pos..pos + comp_len].to_vec();
        pos += comp_len;

        // Extensions (optional — if no bytes left, no extensions)
        let extensions = if pos < body.len() {
            if body.len() < pos + 2 {
                return Err(GripError::parse(
                    4 + pos,
                    ParseKind::UnexpectedEof {
                        needed: 2,
                        available: body.len() - pos,
                    },
                ));
            }
            let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if body.len() < pos + ext_total_len {
                return Err(GripError::parse(
                    4 + pos,
                    ParseKind::ExtensionsLengthMismatch {
                        declared: ext_total_len,
                        actual: body.len() - pos,
                    },
                ));
            }
            // Exact consumption check: extensions parsing must consume exactly ext_total_len
            let ext_bytes = &body[pos..pos + ext_total_len];
            let exts = parse_extensions(ext_bytes)?;
            // Future: if body has trailing bytes after extensions, it's an error
            if pos + ext_total_len != body.len() {
                return Err(GripError::parse(
                    4 + pos,
                    ParseKind::Malformed(format!(
                        "trailing bytes after extensions: {}",
                        body.len() - (pos + ext_total_len)
                    )),
                ));
            }
            exts
        } else {
            Vec::new()
        };

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
            raw,
        })
    }

    /// Return SNI value if present.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        for ext in &self.extensions {
            if let Extension::Sni(s) = ext {
                if s.is_empty() {
                    return None;
                }
                return Some(s.as_str());
            }
        }
        None
    }

    /// Return ALPN protocols if present.
    #[must_use]
    pub fn alpn(&self) -> Option<&[String]> {
        for ext in &self.extensions {
            if let Extension::Alpn(v) = ext {
                return Some(v);
            }
        }
        None
    }

    /// Real TLS version (checks `supported_versions`).
    #[must_use]
    pub fn real_version(&self) -> crate::tls::version::TlsVersion {
        crate::tls::version::real_version(self.legacy_version, &self.extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_client_hello() -> Vec<u8> {
        // Handshake: type 0x01, len 3 bytes, then body
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy
        body.extend_from_slice(&[0x42; 32]); // random
        body.push(0x00); // session_id len 0
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cs len 2
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // cipher
        body.push(0x01); // comp len 1
        body.push(0x00); // comp method 0
        // No extensions
        let hs_len = body.len();
        let mut hs = vec![
            0x01,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);
        // Wrap in record
        let mut rec = vec![
            0x16,
            0x03,
            0x01,
            ((hs.len() >> 8) & 0xff) as u8,
            (hs.len() & 0xff) as u8,
        ];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parse_minimal() {
        let buf = build_minimal_client_hello();
        let ch = ClientHello::parse(&buf).unwrap();
        assert_eq!(ch.legacy_version, 0x0303);
        assert_eq!(ch.cipher_suites, vec![0x1301]);
        assert_eq!(ch.compression_methods, vec![0x00]);
        assert!(ch.extensions.is_empty());
    }

    #[test]
    fn parse_rejects_short() {
        assert!(ClientHello::parse(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x01]).is_err());
    }

    #[test]
    fn sni_none_when_no_ext() {
        let buf = build_minimal_client_hello();
        let ch = ClientHello::parse(&buf).unwrap();
        assert_eq!(ch.sni(), None);
    }
}
