//! Cipher suite constants and display helpers.
//!
//! We expose the IANA-registered cipher suite ids most commonly seen in
//! `ClientHellos`. Unknown ids are still handled (displayed as `0xXXXX`)
//! — we never fail on an unknown cipher, we just lack a friendly name.
//!
//! This module has no dependencies and is `no_std` compatible in principle.

/// Well-known cipher suite ids.
#[allow(missing_docs)]
pub mod id {
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b; // alias examples
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
}

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

/// Format a cipher suite id as either its IANA name or hex.
///
/// This is infallible and allocation-free for the hex case beyond the returned `String`.
#[must_use]
pub fn display(id: u16) -> String {
    name(id).map_or_else(|| format!("0x{id:04x}"), ToString::to_string)
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

    #[test]
    fn display_fallback() {
        assert_eq!(display(0xffff), "0xffff");
        assert_eq!(display(0x1301), "TLS_AES_128_GCM_SHA256");
    }
}
