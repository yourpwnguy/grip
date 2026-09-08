//! Progress callbacks for the live probe.
//!
//! The handshake is a sequence of network round trips; this trait lets the
//! CLI stage drive its animation with real facts (the resolved IP, the cipher)
//! without the `net` crate depending on the `ui` crate.

use std::net::SocketAddr;

/// Events emitted as the handshake unfolds.
///
/// Every method has a default no-op, so callers that do not care can pass
/// [`NoProgress`] and ignore the mechanism entirely.
pub trait Progress {
    /// DNS resolved; `addr` is the first endpoint we will dial.
    fn resolved(&self, _addr: SocketAddr) {}
    /// TCP connected.
    fn connected(&self, _addr: SocketAddr) {}
    /// `ClientHello` written; `bytes` is its on-wire size.
    fn sent(&self, _bytes: usize) {}
    /// `ServerHello` parsed.
    fn server_hello(&self, _version: crate::tls::TlsVersion, _cipher: u16) {}
    /// About to fetch certificates; `via_fallback` indicates the `rustls`
    /// path.
    fn fetching_cert(&self, _via_fallback: bool) {}
    /// Certificate chain obtained.
    fn cert(&self, _len: usize) {}
}

/// A [`Progress`] that discards everything.
pub struct NoProgress;
impl Progress for NoProgress {}
