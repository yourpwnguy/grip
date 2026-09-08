//! Central error type for `grip`.
//!
//! All fallible operations return `GripResult<T>` which is `Result<T, GripError>`.
//! `GripError` is a single, exhaustive enum so callers can match on `ParseKind`
//! for precise diagnostics without stringly-typed errors. Library code never
//! uses `anyhow`; the CLI layer converts `GripError` into a user-facing
//! message with suggestions.

use std::io;

/// The kind of TLS parse failure — used inside `GripError::Parse` for
/// structured matching in tests and for precise user diagnostics.
///
/// We keep this non-exhaustive so we can add variants without a breaking
/// major bump, but for v0.1.0 the set below covers every length / format
/// violation the parsers check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseKind {
    /// Not enough bytes to satisfy a length prefix.
    UnexpectedEof {
        /// How many bytes were needed.
        needed: usize,
        /// How many were available.
        available: usize,
    },
    /// Record content type is not Handshake/Alert/etc.
    InvalidContentType(u8),
    /// Record length exceeds 16384 (RFC 8446 §5.1) or handshake length
    /// exceeds 24-bit capacity.
    BadLength {
        /// Human-readable context (e.g. "record", "handshake", "`cipher_suites`").
        context: String,
        /// The offending length value.
        length: usize,
    },
    /// Cipher suites length not divisible by 2.
    OddCipherSuiteLength(usize),
    /// Extensions length does not exactly consume remaining bytes.
    ExtensionsLengthMismatch {
        /// Declared length.
        declared: usize,
        /// Actual remaining bytes.
        actual: usize,
    },
    /// Extension type is known but its payload is malformed.
    BadExtension {
        /// Extension type id.
        ext_type: u16,
        /// Detail string.
        detail: String,
    },
    /// Generic malformed field.
    Malformed(String),
}

impl std::fmt::Display for ParseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof { needed, available } => write!(
                f,
                "unexpected EOF: needed {needed} bytes but only {available} available"
            ),
            Self::InvalidContentType(b) => write!(f, "invalid content type 0x{b:02x}"),
            Self::BadLength { context, length } => {
                write!(f, "bad length for {context}: {length}")
            }
            Self::OddCipherSuiteLength(l) => {
                write!(f, "cipher suites length {l} is not divisible by 2")
            }
            Self::ExtensionsLengthMismatch { declared, actual } => write!(
                f,
                "extensions length mismatch: declared {declared}, actual {actual}"
            ),
            Self::BadExtension { ext_type, detail } => {
                write!(f, "bad extension 0x{ext_type:04x}: {detail}")
            }
            Self::Malformed(s) => write!(f, "{s}"),
        }
    }
}

/// Top-level error for `grip`.
///
/// Every variant carries enough context to produce a helpful CLI message
/// without needing to downcast or inspect source chains. The `#[source]`
/// attributes preserve the underlying `io::Error` for debugging.
#[derive(Debug, thiserror::Error)]
pub enum GripError {
    /// I/O error from file or network.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// TLS parsing failed at a specific offset.
    #[error("TLS parse error at offset {offset}: {kind}")]
    Parse {
        /// Byte offset where parsing failed.
        offset: usize,
        /// Structured kind.
        kind: ParseKind,
    },

    /// Pcap file is malformed.
    #[error("pcap error: {0}")]
    Pcap(String),

    /// Network / TCP error (DNS, connect, read timeout).
    #[error("network error: {0}")]
    Network(String),

    /// Connection timed out.
    #[error("timeout after {timeout_secs}s connecting to {target}")]
    Timeout {
        /// Timeout in seconds.
        timeout_secs: u64,
        /// Target that timed out.
        target: String,
    },

    /// Invalid CLI argument or combination.
    #[error("invalid argument: {0}")]
    InvalidArg(String),

    /// Certificate parsing error.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// Generic internal error — should be rare.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias.
pub type GripResult<T> = Result<T, GripError>;

impl GripError {
    /// Helper for `Parse` variant without repeating struct literal.
    #[must_use]
    pub const fn parse(offset: usize, kind: ParseKind) -> Self {
        Self::Parse { offset, kind }
    }

    /// Helper for `Pcap` variant.
    #[must_use]
    pub fn pcap(msg: impl Into<String>) -> Self {
        Self::Pcap(msg.into())
    }

    /// Helper for `Network` variant.
    #[must_use]
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    /// Helper for `InvalidArg`.
    #[must_use]
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Self::InvalidArg(msg.into())
    }
}
