//! `ClientHello` builder for live probing.
//!
//! Crafting a `ClientHello` manually is error-prone: every vector has a
//! length prefix and the outer handshake/record headers each have their own.
//! A single byte off = server alert + silent close. This builder computes
//! all lengths in one place and is the **only** code that serializes a
//! `ClientHello` for transmission.

/// Builder for a TLS `ClientHello` byte array.
///
/// Uses the classic `grip` default that mimics a modern browser enough to
/// get a real `ServerHello`, but is simple enough to be stable. You can
/// override SNI, ALPN, cipher suites, etc. via the chainable setters.
#[derive(Debug, Clone)]
pub struct ClientHelloBuilder {
    legacy_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    sni: Option<String>,
    alpn: Vec<String>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    supported_versions: Vec<u16>,
    key_share_groups: Vec<u16>,
}

impl Default for ClientHelloBuilder {
    fn default() -> Self {
        // Fill random with deterministic bytes for reproducible fingerprints in tests.
        // In live mode caller overwrites with real randomness via `with_random`.
        let mut random = [0u8; 32];
        // Use a simple pattern; `net::connect` will replace with `rand`-like bytes
        // from `std::collections::hash_map::DefaultHasher` + time if needed.
        // For v0.1.0 we keep it simple: caller passes time-based random.
        for (i, b) in random.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9e);
        }
        Self {
            legacy_version: 0x0303,
            random,
            session_id: Vec::new(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c,
                0x009d, 0x002f, 0x0035,
            ],
            compression_methods: vec![0x00],
            sni: None,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            supported_groups: vec![0x001d, 0x0017, 0x0018], // x25519, p256, p384
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0807, 0x0501, 0x0808, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303], // TLS 1.3, 1.2
            key_share_groups: vec![0x001d],           // x25519
        }
    }
}

impl ClientHelloBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set SNI hostname (e.g. `"example.com"`). Pass `None` to omit.
    #[must_use]
    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni = sni;
        self
    }

    /// Override random bytes (should be 32 cryptographically random bytes in production).
    #[must_use]
    pub const fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = random;
        self
    }

    /// Override cipher suites.
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<u16>) -> Self {
        self.cipher_suites = suites;
        self
    }

    /// Override ALPN.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Build the on-wire bytes: TLS record + handshake + `ClientHello`.
    ///
    /// The returned `Vec<u8>` is ready to `write_all` to a `TcpStream`.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        // Build extensions block first so we know its total length.
        let extensions = self.build_extensions();
        let ext_total_len = extensions.len();

        // Build ClientHello body (without handshake header)
        let mut body = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for cs in &self.cipher_suites {
            body.extend_from_slice(&cs.to_be_bytes());
        }
        body.push(self.compression_methods.len() as u8);
        body.extend_from_slice(&self.compression_methods);
        // Extensions length + extensions (always include, even if empty, for clarity)
        body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake header: type 0x01 + 24-bit length
        let hs_len = body.len();
        let mut handshake = Vec::with_capacity(4 + hs_len);
        handshake.push(0x01);
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        // Record header: type 0x16 + legacy_version 0x0301 + length
        let rec_len = handshake.len();
        let mut record = Vec::with_capacity(5 + rec_len);
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(rec_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn build_extensions(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Every extension is `type(2) || len(2) || payload`, so this does the
        // framing and we just hand over the payload.
        let mut push = |ext_type: u16, data: &[u8]| {
            out.extend_from_slice(&ext_type.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        };

        // SNI (0x0000): list_len || name_type=0 || name_len || hostname
        if let Some(sni) = &self.sni {
            let host = sni.as_bytes();
            let mut data = Vec::new();
            data.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
            data.push(0x00);
            data.extend_from_slice(&(host.len() as u16).to_be_bytes());
            data.extend_from_slice(host);
            push(0x0000, &data);
        }

        // Supported Groups (0x000a)
        push(0x000a, &u16_list(&self.supported_groups));

        // EC Point Formats (0x000b): just "uncompressed"
        push(0x000b, &[0x01, 0x00]);

        // Signature Algorithms (0x000d)
        push(0x000d, &u16_list(&self.signature_algorithms));

        // ALPN (0x0010): list_len || [len || proto]*
        if !self.alpn.is_empty() {
            let mut inner = Vec::new();
            for proto in &self.alpn {
                inner.push(proto.len() as u8);
                inner.extend_from_slice(proto.as_bytes());
            }
            let mut data = Vec::with_capacity(inner.len() + 2);
            data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            data.extend_from_slice(&inner);
            push(0x0010, &data);
        }

        // Supported Versions (0x002b): 1-byte length prefix here, not 2
        let mut versions = Vec::new();
        versions.push((self.supported_versions.len() * 2) as u8);
        for v in &self.supported_versions {
            versions.extend_from_slice(&v.to_be_bytes());
        }
        push(0x002b, &versions);

        // Key Share (0x0033). The key bytes are a fixed dummy: we need a
        // structurally valid entry. The actual ECDH happens in nobody's favor.
        let mut ks = Vec::new();
        for g in &self.key_share_groups {
            ks.extend_from_slice(&g.to_be_bytes());
            ks.extend_from_slice(&32u16.to_be_bytes());
            ks.extend_from_slice(&[0x42; 32]);
        }
        let mut ks_data = Vec::with_capacity(ks.len() + 2);
        ks_data.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        ks_data.extend_from_slice(&ks);
        push(0x0033, &ks_data);

        out
    }
}

/// `len(2) || u16*`, the shape most extension payloads use.
fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 2 + 2);
    out.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::client_hello::ClientHello;

    #[test]
    fn builder_roundtrip() {
        let builder = ClientHelloBuilder::new().with_sni(Some("example.com".to_string()));
        let bytes = builder.build();
        // Must be parseable
        let ch = ClientHello::parse(&bytes).expect("parse built ClientHello");
        assert_eq!(ch.sni(), Some("example.com"));
        assert_eq!(ch.cipher_suites.len(), builder.cipher_suites.len());
        assert!(
            ch.extensions
                .iter()
                .any(|e| matches!(e, crate::tls::extensions::Extension::Sni(_)))
        );
    }

    #[test]
    fn record_length_correct() {
        let bytes = ClientHelloBuilder::new().build();
        // Check outer record length matches
        let rec_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert_eq!(rec_len, bytes.len() - 5);
    }
}
