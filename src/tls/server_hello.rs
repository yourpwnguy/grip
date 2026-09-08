//! `ServerHello` parsing.
//!
//! Format is similar to `ClientHello` but `cipher_suite` is a single chosen
//! value (not a list) and the extensions are typically fewer. We also handle
//! TLS 1.3 `HelloRetryRequest` which is a `ServerHello` with a magic `random`.

use crate::error::{GripError, GripResult, ParseKind};
use crate::tls::extensions::{Extension, parse_extensions};
use crate::tls::record::{ContentType, TlsRecord};

/// Magic `random` for `HelloRetryRequest` (RFC 8446 §4.1.4).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parsed `ServerHello` (or `HelloRetryRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Legacy version.
    pub legacy_version: u16,
    /// Random bytes (or HRR magic).
    pub random: [u8; 32],
    /// Session ID echoed from `ClientHello`.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Compression method (usually `0`).
    pub compression_method: u8,
    /// Extensions.
    pub extensions: Vec<Extension>,
    /// True if this is a `HelloRetryRequest`.
    pub is_hello_retry_request: bool,
    /// Raw handshake bytes.
    pub raw: Vec<u8>,
}

impl ServerHello {
    /// Parse `ServerHello` from raw bytes (with or without record header).
    ///
    /// # Errors
    ///
    /// Returns [`GripError::Parse`] if the record header is malformed,
    /// the content type is not Handshake, the handshake type is not `0x02`,
    /// or any field is truncated or has an invalid length.
    pub fn parse(buf: &[u8]) -> GripResult<Self> {
        let handshake_bytes = if !buf.is_empty() && buf[0] == 0x16 {
            let (rec, _) = TlsRecord::parse(buf, 0)?;
            if rec.content_type != ContentType::Handshake {
                return Err(GripError::parse(
                    0,
                    ParseKind::Malformed("expected Handshake record".to_string()),
                ));
            }
            if rec.payload.is_empty() || rec.payload[0] != 0x02 {
                return Err(GripError::parse(
                    5,
                    ParseKind::Malformed(format!(
                        "expected ServerHello type 0x02, got 0x{:02x}",
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
        if buf[0] != 0x02 {
            return Err(GripError::parse(
                0,
                ParseKind::Malformed(format!("handshake type 0x{:02x} != 0x02", buf[0])),
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
        let is_hrr = random == HRR_RANDOM;

        if body.len() < pos + 1 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 1,
                    available: body.len() - pos,
                },
            ));
        }
        let sid_len = body[pos] as usize;
        pos += 1;
        if body.len() < pos + sid_len {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: sid_len,
                    available: body.len() - pos,
                },
            ));
        }
        let session_id = body[pos..pos + sid_len].to_vec();
        pos += sid_len;

        if body.len() < pos + 2 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 2,
                    available: body.len() - pos,
                },
            ));
        }
        let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
        pos += 2;

        if body.len() < pos + 1 {
            return Err(GripError::parse(
                4 + pos,
                ParseKind::UnexpectedEof {
                    needed: 1,
                    available: body.len() - pos,
                },
            ));
        }
        let compression_method = body[pos];
        pos += 1;

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
            let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if body.len() < pos + ext_len {
                return Err(GripError::parse(
                    4 + pos,
                    ParseKind::ExtensionsLengthMismatch {
                        declared: ext_len,
                        actual: body.len() - pos,
                    },
                ));
            }
            let exts = parse_extensions(&body[pos..pos + ext_len])?;
            // Strict: no trailing bytes
            if pos + ext_len != body.len() {
                return Err(GripError::parse(
                    4 + pos,
                    ParseKind::Malformed("trailing bytes after ServerHello extensions".to_string()),
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
            cipher_suite,
            compression_method,
            extensions,
            is_hello_retry_request: is_hrr,
            raw,
        })
    }

    /// Real negotiated version (checks `supported_versions` ext).
    #[must_use]
    pub fn real_version(&self) -> crate::tls::version::TlsVersion {
        crate::tls::version::real_version(self.legacy_version, &self.extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_server_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00); // session id len 0
        body.extend_from_slice(&0xc02fu16.to_be_bytes());
        body.push(0x00);
        // extensions: supported_versions 0x0304 (ServerHello style: 2 bytes directly)
        // We'll craft extensions block:
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x03, 0x04]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let hs_len = body.len();
        let mut hs = vec![
            0x02,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![
            0x16,
            0x03,
            0x03,
            ((hs.len() >> 8) & 0xff) as u8,
            (hs.len() & 0xff) as u8,
        ];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parse_server_hello() {
        let buf = build_server_hello();
        let sh = ServerHello::parse(&buf).unwrap();
        assert_eq!(sh.cipher_suite, 0xc02f);
        assert!(!sh.is_hello_retry_request);
        assert_eq!(sh.real_version(), crate::tls::version::TlsVersion::Tls13);
    }
}
