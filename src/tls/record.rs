//! TLS record layer.
//!
//! Every TLS message on the wire starts with a 5-byte header:
//! ```text
//! Byte 0      Content Type    0x16 = Handshake, 0x15 = Alert, 0x14 = ChangeCipherSpec, 0x17 = ApplicationData
//! Byte 1-2    Legacy Version  0x0303 (TLS 1.2 written here even for TLS 1.3)
//! Byte 3-4    Length          u16 BE, how many bytes follow
//! Byte 5+     Payload
//! ```
//! We parse and validate that header here. The payload is left opaque —
//! `client_hello` / `server_hello` parse it further.
//!
//! # Security
//! `length` is bounded to 16384 (RFC 8446 §5.1). Larger lengths are rejected
//! to prevent OOM on adversarial inputs.

use crate::error::{GripError, GripResult, ParseKind};

/// TLS content type (first byte of record header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `0x14` — `ChangeCipherSpec`.
    ChangeCipherSpec,
    /// `0x15` — Alert.
    Alert,
    /// `0x16` — Handshake (`ClientHello`, `ServerHello`, etc.).
    Handshake,
    /// `0x17` — `ApplicationData`.
    ApplicationData,
    /// Unknown type — preserved, not error, so we can skip it.
    Unknown(u8),
}

impl From<u8> for ContentType {
    fn from(b: u8) -> Self {
        match b {
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert,
            0x16 => Self::Handshake,
            0x17 => Self::ApplicationData,
            v => Self::Unknown(v),
        }
    }
}

impl From<ContentType> for u8 {
    fn from(c: ContentType) -> Self {
        match c {
            ContentType::ChangeCipherSpec => 0x14,
            ContentType::Alert => 0x15,
            ContentType::Handshake => 0x16,
            ContentType::ApplicationData => 0x17,
            ContentType::Unknown(v) => v,
        }
    }
}

/// A single TLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    /// Content type.
    pub content_type: ContentType,
    /// Legacy version (e.g. `0x0303`).
    pub legacy_version: u16,
    /// Payload bytes (exactly `length` bytes from the wire).
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// Maximum record payload length per RFC 8446 §5.1.
    pub const MAX_LENGTH: usize = 16384;

    /// Parse a single record from `buf` starting at `offset` for diagnostics.
    ///
    /// Returns the record and the number of bytes consumed (`5 + length`).
    /// If `buf` is too short, returns `GripError::Parse` with `UnexpectedEof`.
    ///
    /// # Errors
    /// - `UnexpectedEof` if `buf.len() < 5` or `< 5 + length`.
    /// - `BadLength` if `length > MAX_LENGTH`.
    pub fn parse(buf: &[u8], offset: usize) -> GripResult<(Self, usize)> {
        if buf.len() < 5 {
            return Err(GripError::parse(
                offset,
                ParseKind::UnexpectedEof {
                    needed: 5,
                    available: buf.len(),
                },
            ));
        }
        let content_type = ContentType::from(buf[0]);
        let legacy_version = u16::from_be_bytes([buf[1], buf[2]]);
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;

        if length > Self::MAX_LENGTH {
            return Err(GripError::parse(
                offset + 3,
                ParseKind::BadLength {
                    context: "record".to_string(),
                    length,
                },
            ));
        }
        if buf.len() < 5 + length {
            return Err(GripError::parse(
                offset,
                ParseKind::UnexpectedEof {
                    needed: 5 + length,
                    available: buf.len(),
                },
            ));
        }
        let payload = buf[5..5 + length].to_vec();
        let rec = Self {
            content_type,
            legacy_version,
            payload,
        };
        Ok((rec, 5 + length))
    }

    /// Parse all records in `buf` (e.g. a reassembled TCP stream).
    ///
    /// Stops at the first parse error. Unknown content types are returned as
    /// `TlsRecord` with `Unknown` — the caller decides whether to skip them.
    ///
    /// # Errors
    ///
    /// Returns [`GripError::Parse`] if any record is malformed (unexpected
    /// EOF or length exceeding `MAX_LENGTH`).
    pub fn parse_all(buf: &[u8]) -> GripResult<Vec<Self>> {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            // Need at least header.
            if buf.len() - pos < 5 {
                break; // trailing partial record — not an error for stream scanning
            }
            let (rec, consumed) = Self::parse(&buf[pos..], pos)?;
            records.push(rec);
            pos += consumed;
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let buf = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (rec, n) = TlsRecord::parse(&buf, 0).unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.legacy_version, 0x0303);
        assert_eq!(rec.payload, vec![1, 2, 3, 4, 5]);
        assert_eq!(n, 10);
    }

    #[test]
    fn reject_oversize() {
        let len = (TlsRecord::MAX_LENGTH + 1) as u16;
        let buf = [0x16, 0x03, 0x03, (len >> 8) as u8, (len & 0xff) as u8];
        assert!(TlsRecord::parse(&buf, 0).is_err());
    }

    #[test]
    fn truncated() {
        let buf = [0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02];
        assert!(TlsRecord::parse(&buf, 0).is_err());
    }

    #[test]
    fn parse_all_multiple() {
        let mut buf = Vec::new();
        for _ in 0..2 {
            buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb]);
        }
        let recs = TlsRecord::parse_all(&buf).unwrap();
        assert_eq!(recs.len(), 2);
    }
}
