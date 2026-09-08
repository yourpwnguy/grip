//! Certificate fallback — `rustls` handshake to recover the chain when the
//! raw capture cannot (TLS 1.3 encrypts `Certificate`).

use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::tls::certificate::CertificateChain;

use super::dial;

/// Fetch the chain via a real `rustls` handshake.
///
/// Returns `None` on any error so the raw probe still succeeds. The raw
/// bytes remain the source of truth for JA3/JA4; this is display-only.
pub fn fetch_via_rustls(
    target: &str,
    port: u16,
    sni: Option<&str>,
    timeout: Duration,
    insecure: bool,
) -> Option<CertificateChain> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};

    #[derive(Debug)]
    struct InsecureVerifier;
    impl ServerCertVerifier for InsecureVerifier {
        fn verify_server_cert(
            &self,
            _end: &CertificateDer<'_>,
            _inter: &[CertificateDer<'_>],
            _name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use rustls::SignatureScheme::{
                ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ECDSA_NISTP521_SHA512,
                ECDSA_SHA1_Legacy, ED448, ED25519, RSA_PKCS1_SHA1, RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
            };
            vec![
                RSA_PKCS1_SHA1,
                ECDSA_SHA1_Legacy,
                RSA_PKCS1_SHA256,
                ECDSA_NISTP256_SHA256,
                RSA_PKCS1_SHA384,
                ECDSA_NISTP384_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP521_SHA512,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                ED25519,
                ED448,
            ]
        }
    }

    let config = if insecure {
        let provider = rustls::crypto::ring::default_provider();
        ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = rustls::crypto::ring::default_provider();
        ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let host = sni.unwrap_or(target);
    let server_name = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(rustls::pki_types::IpAddr::try_from(ip.to_string().as_str()).ok()?)
    } else {
        ServerName::try_from(host.to_string()).ok()?
    };

    let addrs = dial::resolve_target(target, port).ok()?;
    let mut tcp: Option<TcpStream> = None;
    for addr in &addrs {
        if let Ok(s) = TcpStream::connect_timeout(addr, timeout) {
            tcp = Some(s);
            break;
        }
    }
    let mut tcp = tcp?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).ok()?;
    let start = Instant::now();
    while conn.is_handshaking() {
        if start.elapsed() > timeout {
            return None;
        }
        if conn.complete_io(&mut tcp).is_err() && conn.peer_certificates().is_none() {
            return None;
        }
        if conn.peer_certificates().is_some() {
            break;
        }
    }
    let certs = conn.peer_certificates()?.to_vec();
    if certs.is_empty() {
        return None;
    }
    let ders: Vec<Vec<u8>> = certs.into_iter().map(|c| c.to_vec()).collect();
    CertificateChain::from_der_list(&ders).ok()
}
