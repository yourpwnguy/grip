//! Human report rendering — composes [`crate::ui::panel`] boxes.
//!
//! The report is split by mode so each pipeline owns only the view it
//! renders. `live.rs` and `pcap.rs` take DTOs, never domain types, so every
//! pixel is snapshot-testable from canned data.

mod live;
mod pcap;
mod quiet;
mod raw;

pub use live::render_live;
pub use pcap::render_pcap;
pub use quiet::render_quiet;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::model::*;
    use crate::ui::theme::Palette;

    fn live_report() -> LiveReport {
        LiveReport {
            target: "example.com:443".to_string(),
            negotiated: NegotiatedInfo {
                tls_version: "TLS 1.3".to_string(),
                offered_versions: vec!["TLS 1.3".to_string(), "TLS 1.2".to_string()],
                cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
                cipher_hex: "0x1301".to_string(),
                key_exchange: Some("X25519".to_string()),
                alpn: Some("h2".to_string()),
                sni: Some("example.com".to_string()),
                sni_is_ip: false,
            },
            certificate: Some(CertSummary {
                subject: Some("CN=example.com".to_string()),
                issuer: Some("C=US, O=DigiCert, CN=DigiCert Global G3".to_string()),
                sans: vec![
                    "example.com".to_string(),
                    "www.example.com".to_string(),
                    "cdn.example.com".to_string(),
                    "api.example.com".to_string(),
                ],
                expires: Some("2026-11-15 (77 days)".to_string()),
                sha256: Some("a8:3f:c1:44:9e:02:bb:71".to_string()),
                ct_logs: Some("2 scts embedded".to_string()),
            }),
            cert_chain: None,
            fingerprints: Fingerprints {
                ja3: Some("cd08e31494f9531f560d64c695473da9".to_string()),
                ja4: Some("t13d1516h2_8daaf6152771_e5627ecdbbe6".to_string()),
                ja4s: Some("t13d020000_1301_1acd28cc39f1".to_string()),
                lookup: Some("Chrome 120".to_string()),
            },
            raw: None,
            verbose_info: None,
        }
    }

    fn out_live(r: &LiveReport) -> String {
        let mut b = Vec::new();
        render_live(r, &mut b, Palette::plain()).unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn live_report_is_plain_and_complete() {
        let s = out_live(&live_report());
        assert!(!s.contains('\x1b'));
        assert!(s.contains("negotiated"));
        assert!(s.contains("TLS_AES_128_GCM_SHA256"));
        assert!(s.contains("t13d1516h2_8daaf6152771_e5627ecdbbe6"));
        assert!(s.contains("matches Chrome 120"));
        assert!(s.contains("+1 more"));
        insta::assert_snapshot!(s);
    }

    #[test]
    fn missing_certificate_explains_itself() {
        let mut r = live_report();
        r.certificate = None;
        let s = out_live(&r);
        assert!(s.contains("not recovered"));
        assert!(s.contains("--no-verify"));
        insta::assert_snapshot!(s);
    }

    #[test]
    fn expired_certificate_is_marked() {
        let mut r = live_report();
        if let Some(c) = &mut r.certificate {
            c.expires = Some("2015-04-12 (expired 4162 days ago)".to_string());
        }
        assert!(out_live(&r).contains("expired"));
    }

    #[test]
    fn chain_and_telemetry_panels_appear() {
        let mut r = live_report();
        let leaf = r.certificate.clone().unwrap();
        r.cert_chain = Some(vec![leaf.clone(), leaf]);
        r.verbose_info = Some(VerboseInfo {
            handshake_ms: 42,
            bytes_sent: 204,
            bytes_received: 95,
            resolved_ips: vec!["93.184.216.34:443".to_string()],
            grease_filtered: 2,
        });
        let s = out_live(&r);
        assert!(s.contains("chain of trust"));
        assert!(s.contains("depth 1"));
        assert!(s.contains("telemetry"));
        assert!(s.contains("42 ms"));
        insta::assert_snapshot!(s);
    }

    #[test]
    fn colored_live_report_carries_ansi() {
        let mut b = Vec::new();
        render_live(&live_report(), &mut b, Palette::rich()).unwrap();
        assert!(String::from_utf8(b).unwrap().contains('\x1b'));
    }

    fn pcap_report(clients: Vec<ClientEntry>) -> PcapReport {
        let total = clients.iter().map(|c| c.count).sum();
        PcapReport {
            file: "capture.pcap".to_string(),
            total_handshakes: total,
            unique_clients: clients.len(),
            clients,
        }
    }

    #[test]
    fn pcap_table_is_ranked_and_plain() {
        let r = pcap_report(vec![
            ClientEntry {
                ip: "192.168.1.5".to_string(),
                ja4: "t13d1516h2_8daaf6152771_e5627ecdbbe6".to_string(),
                ja3: None,
                client: Some("Chrome 120".to_string()),
                count: 23,
            },
            ClientEntry {
                ip: "10.0.0.42".to_string(),
                ja4: "t10d1200h_c013c014c00a_a2a4a5a6a7a8".to_string(),
                ja3: None,
                client: None,
                count: 6,
            },
        ]);
        let mut b = Vec::new();
        render_pcap(&r, &mut b, Palette::plain()).unwrap();
        let s = String::from_utf8(b).unwrap();
        assert!(!s.contains('\x1b'));
        assert!(s.contains(" 1 "));
        assert!(s.contains("unclassified"));
        insta::assert_snapshot!(s);
    }

    #[test]
    fn empty_pcap_gives_guidance() {
        let mut b = Vec::new();
        render_pcap(&pcap_report(vec![]), &mut b, Palette::plain()).unwrap();
        let s = String::from_utf8(b).unwrap();
        assert!(s.contains("no client hellos recovered"));
    }

    #[test]
    fn quiet_is_exactly_one_line() {
        let mut b = Vec::new();
        render_quiet("t13d", &mut b).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "t13d\n");
    }
}
