//! TLS version handling.
//!
//! The `legacy_version` field in ClientHello/ServerHello lies for TLS 1.3:
//! it always reads `0x0303` (TLS 1.2). The real version is inside the
//! `supported_versions` extension (`0x002b`). If you infer version from
//! the legacy field you'll label every TLS 1.3 client as 1.2 — the most
//! common fingerprinting bug.
//!
//! This module centralizes that logic so parsers can't get it wrong.

use crate::tls::extensions::Extension;

/// TLS protocol version as seen on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TlsVersion {
    /// SSL 3.0 — `0x0300`, rarely seen.
    Ssl30,
    /// TLS 1.0 — `0x0301`.
    Tls10,
    /// TLS 1.1 — `0x0302`.
    Tls11,
    /// TLS 1.2 — `0x0303`.
    Tls12,
    /// TLS 1.3 — `0x0304`.
    Tls13,
    /// Unknown / future version.
    Unknown(u16),
}

impl TlsVersion {
    /// Convert a raw `u16` wire value to `TlsVersion`.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0300 => Self::Ssl30,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            other => Self::Unknown(other),
        }
    }

    /// Raw wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Ssl30 => 0x0300,
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
            Self::Unknown(v) => v,
        }
    }

    /// Two-digit string for JA4, e.g. `13` for TLS 1.3.
    ///
    /// Unknown versions map to `00`.
    #[must_use]
    pub const fn ja4_str(self) -> &'static str {
        match self {
            Self::Ssl30 => "30",
            Self::Tls10 => "10",
            Self::Tls11 => "11",
            Self::Tls12 => "12",
            Self::Tls13 => "13",
            Self::Unknown(_) => "00",
        }
    }

    /// Decimal string for JA3, e.g. `771` for TLS 1.2 (`0x0303`).
    #[must_use]
    pub fn ja3_decimal(self) -> String {
        self.as_u16().to_string()
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssl30 => write!(f, "SSL 3.0"),
            Self::Tls10 => write!(f, "TLS 1.0"),
            Self::Tls11 => write!(f, "TLS 1.1"),
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
            Self::Unknown(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

/// Determine the real TLS version from legacy field + extensions.
///
/// Checks `supported_versions` (type `0x002b`) first. For `ClientHello`,
/// that extension contains a list of versions the client offers; we pick
/// the highest. For `ServerHello` it contains the single negotiated version.
///
/// If the extension is absent, falls back to `legacy_version`.
#[must_use]
pub fn real_version(legacy_version: u16, extensions: &[Extension]) -> TlsVersion {
    for ext in extensions {
        if let Extension::SupportedVersions(versions) = ext
            && let Some(&max) = versions.iter().max()
        {
            return TlsVersion::from_u16(max);
        }
    }
    TlsVersion::from_u16(legacy_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::extensions::Extension;

    #[test]
    fn from_u16_roundtrip() {
        assert_eq!(TlsVersion::from_u16(0x0303), TlsVersion::Tls12);
        assert_eq!(TlsVersion::Tls13.as_u16(), 0x0304);
    }

    #[test]
    fn real_version_prefers_ext() {
        let exts = vec![Extension::SupportedVersions(vec![0x0303, 0x0304])];
        assert_eq!(real_version(0x0303, &exts), TlsVersion::Tls13);
    }

    #[test]
    fn real_version_fallback() {
        let exts = vec![];
        assert_eq!(real_version(0x0303, &exts), TlsVersion::Tls12);
    }

    #[test]
    fn ja4_str() {
        assert_eq!(TlsVersion::Tls13.ja4_str(), "13");
        assert_eq!(TlsVersion::Unknown(0x9999).ja4_str(), "00");
    }
}
