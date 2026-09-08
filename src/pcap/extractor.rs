//! `ClientHello` extraction from reassembled streams.
//!
//! We walk the reassembled byte stream looking for TLS records (`0x16`)
//! and try to parse each as `ClientHello`. Non-Handshake records are
//! skipped. Partial trailing records are ignored.

use crate::tls::client_hello::ClientHello;
use crate::tls::record::{ContentType, TlsRecord};

/// Extract all `ClientHellos` found in a reassembled TCP stream.
///
/// Scans sequentially: at each `pos`, try to parse a TLS record. If it
/// succeeds and is a Handshake containing `ClientHello` (`0x01`), attempt
/// to parse it. On success, push and advance by record length. On any
/// failure, advance by 1 byte (byte-wise scan) to resync.
#[must_use]
pub fn extract_client_hellos(stream: &[u8]) -> Vec<ClientHello> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 5 <= stream.len() {
        // Quick filter: need 0x16 at record start and plausible version
        if stream[pos] != 0x16 {
            pos += 1;
            continue;
        }
        // Try record parse
        let rec_slice = &stream[pos..];
        let parsed = TlsRecord::parse(rec_slice, pos);
        match parsed {
            Ok((rec, consumed)) => {
                if rec.content_type == ContentType::Handshake
                    && !rec.payload.is_empty()
                    && rec.payload[0] == 0x01
                {
                    // Reconstruct full record bytes for ClientHello::parse (which expects record header)
                    let full_record = &stream[pos..pos + consumed];
                    if let Ok(ch) = ClientHello::parse(full_record) {
                        out.push(ch);
                    }
                }
                // Always advance by consumed on successful record parse, even if not ClientHello
                pos += consumed;
            }
            Err(_) => {
                // Not a valid record at pos, scan forward by 1
                pos += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ClientHelloBuilder;

    #[test]
    fn extract_single() {
        let bytes = ClientHelloBuilder::new()
            .with_sni(Some("example.com".to_string()))
            .build();
        let hellos = extract_client_hellos(&bytes);
        assert_eq!(hellos.len(), 1);
        assert_eq!(hellos[0].sni(), Some("example.com"));
    }

    #[test]
    fn extract_with_noise() {
        let ch_bytes = ClientHelloBuilder::new().build();
        let mut stream = vec![0x00, 0xff, 0xaa]; // noise
        stream.extend_from_slice(&ch_bytes);
        stream.extend_from_slice(&[0x00, 0x01]); // trailing noise
        let hellos = extract_client_hellos(&stream);
        assert_eq!(hellos.len(), 1);
    }

    #[test]
    fn extract_fragmented_stream() {
        // Simulate two ClientHellos back-to-back
        let b1 = ClientHelloBuilder::new()
            .with_sni(Some("a.com".to_string()))
            .build();
        let b2 = ClientHelloBuilder::new()
            .with_sni(Some("b.com".to_string()))
            .build();
        let mut stream = Vec::new();
        stream.extend_from_slice(&b1);
        stream.extend_from_slice(&b2);
        let hellos = extract_client_hellos(&stream);
        assert_eq!(hellos.len(), 2);
    }

    #[test]
    fn no_clienthello_returns_empty() {
        let stream = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(extract_client_hellos(stream).is_empty());
    }
}
