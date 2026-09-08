//! TLS parsing domain — raw byte handling with no I/O.
//!
//! This is the heart of `grip`. Every byte is read from the wire and
//! validated here; no TLS library does the work for us (except ASN.1 via
//! `x509-parser`). The modules are ordered by dependency:
//! `grease`/`cipher`/`version` are leaves, `record` and `extensions` are
//! mid-level, `client_hello`/`server_hello`/`certificate` compose them, and
//! `builder` is the inverse (serialization).

pub mod builder;
pub mod certificate;
pub mod cipher;
pub mod client_hello;
pub mod extensions;
pub mod grease;
pub mod record;
pub mod server_hello;
pub mod version;

// Re-exports for convenience.
pub use builder::ClientHelloBuilder;
pub use certificate::{CertInfo, CertificateChain};
pub use client_hello::ClientHello;
pub use extensions::{Extension, KeyShareEntry};
pub use grease::{filter_grease, is_grease};
pub use record::{ContentType, TlsRecord};
pub use server_hello::ServerHello;
pub use version::{TlsVersion, real_version};
