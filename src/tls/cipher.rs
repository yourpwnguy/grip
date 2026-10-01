//! Cipher suite id to name mapping.
//!
//! IANA names for the cipher suites we care about. Unknown ids fall back to
//! hex at the call site, so we never fail on an unknown cipher.
//!

/// Return the IANA name for a cipher suite, or `None` if unknown.
///
/// The caller can fall back to `format!("0x{id:04x}")`.
///
/// # Example
/// ```
/// # use grip::tls::cipher::name;
/// assert_eq!(name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
/// assert_eq!(name(0x9999), None);
/// ```
#[must_use]
pub const fn name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_name() {
        assert_eq!(name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
    }

    #[test]
    fn unknown_name() {
        assert_eq!(name(0xffff), None);
    }
}
