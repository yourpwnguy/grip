//! Raw handshake — read loop that captures `ServerHello` from the wire.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::error::GripResult;
use crate::tls::certificate::CertificateChain;
use crate::tls::record::{ContentType, TlsRecord};
use crate::tls::server_hello::ServerHello;

/// Outcome of the raw read loop.
pub struct RawOutcome {
    /// Parsed `ServerHello` (must be `Some` for success).
    pub server_hello: Option<ServerHello>,
    /// Raw bytes of that `ServerHello` record.
    pub server_hello_raw: Vec<u8>,
    /// Certificate chain if it arrived in the clear (TLS 1.2).
    pub cert_chain: Option<CertificateChain>,
    /// All bytes read (for fallback scans).
    pub buf: Vec<u8>,
}

/// Drive the raw `ClientHello` → `ServerHello` exchange.
///
/// `poll` is the socket `SO_RCVTIMEO`; the overall deadline is enforced by
/// `deadline = start + timeout`. TLS 1.3 is treated as terminal after
/// `ServerHello` because its `Certificate` is encrypted and will never appear
/// here — waiting only burns time.
pub fn drive(
    stream: &mut TcpStream,
    client_hello_raw: &[u8],
    timeout: Duration,
    _poll: Duration,
    progress: &dyn super::progress::Progress,
) -> GripResult<RawOutcome> {
    use crate::error::GripError;

    stream.write_all(client_hello_raw).map_err(GripError::Io)?;

    let start = Instant::now();
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let mut server_hello: Option<ServerHello> = None;
    let mut server_hello_raw = Vec::new();
    let mut cert_chain: Option<CertificateChain> = None;
    let mut raw_cert_bytes = Vec::new();

    loop {
        if start.elapsed() > timeout {
            break;
        }
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                let mut pos = 0;
                while pos + 5 <= buf.len() {
                    let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
                    if buf.len() < pos + 5 + rec_len {
                        break;
                    }
                    let rec_bytes = &buf[pos..pos + 5 + rec_len];
                    if let Ok((rec, _)) = TlsRecord::parse(rec_bytes, pos)
                        && rec.content_type == ContentType::Handshake
                        && !rec.payload.is_empty()
                    {
                        match rec.payload[0] {
                            0x02 if server_hello.is_none() => {
                                if let Ok(sh) = ServerHello::parse(rec_bytes) {
                                    progress.server_hello(sh.real_version(), sh.cipher_suite);
                                    server_hello_raw = rec_bytes.to_vec();
                                    server_hello = Some(sh);
                                }
                            }
                            0x0b => {
                                raw_cert_bytes.clone_from(&rec.payload);
                                if let Ok(chain) =
                                    CertificateChain::parse_tls_certificate(rec_bytes)
                                {
                                    cert_chain = Some(chain);
                                } else if let Ok(chain) =
                                    CertificateChain::parse_tls_certificate(&rec.payload)
                                {
                                    cert_chain = Some(chain);
                                }
                            }
                            _ => {}
                        }
                    }
                    if rec_bytes[0] == 0x15 {
                        break;
                    }
                    pos += 5 + rec_len;
                }
                if let Some(sh) = &server_hello {
                    let is_tls13 = sh.real_version() == crate::tls::TlsVersion::Tls13;
                    if cert_chain.is_some() || is_tls13 {
                        break;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if server_hello.is_some() {
                    break;
                }
            }
            Err(e) => return Err(crate::error::GripError::Io(e)),
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }

    // Fallback scan for a coalesced `Certificate` we may have missed.
    if cert_chain.is_none()
        && let Some(chain) = scan(&buf)
    {
        cert_chain = Some(chain);
    }
    // Raw `Certificate` bytes without a parseable chain are not useful — the
    // caller will try the `rustls` fallback.
    let _ = raw_cert_bytes;

    Ok(RawOutcome {
        server_hello,
        server_hello_raw,
        cert_chain,
        buf,
    })
}

fn scan(buf: &[u8]) -> Option<CertificateChain> {
    let mut pos = 0;
    while pos + 5 <= buf.len() {
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if buf.len() < pos + 5 + rec_len {
            break;
        }
        let rec_bytes = &buf[pos..pos + 5 + rec_len];
        if rec_bytes[0] == 0x16
            && rec_len >= 4
            && let Ok((rec, _)) = TlsRecord::parse(rec_bytes, pos)
            && rec.payload.first() == Some(&0x0b)
        {
            if let Ok(chain) = CertificateChain::parse_tls_certificate(rec_bytes) {
                return Some(chain);
            }
            if let Ok(chain) = CertificateChain::parse_tls_certificate(&rec.payload) {
                return Some(chain);
            }
        }
        pos += 5 + rec_len;
    }
    None
}
