//! CLI orchestration — the single place that sees `cli`, `net`, `pcap` and `ui`
//! together. Domain stays pure; this layer owns the stage.

mod helpers;
mod live;
mod pcap;

use std::io::Write;

use crate::cli::args::Cli;
use crate::cli::validate::{Mode, validate};
use crate::error::{GripError, GripResult};

pub use helpers::{LIVE_STEPS, PCAP_STEPS};

/// Run the CLI.
///
/// Opens the output sink first so a bad `-o` path fails before any network
/// or file work, then dispatches to the live or pcap pipeline.
///
/// # Errors
/// Propagates validation, I/O, network and parse failures; `main` maps them
/// to exit codes.
pub fn run(cli: &Cli) -> GripResult<()> {
    let mode = validate(cli)?;

    let mut writer: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(std::fs::File::create(path).map_err(GripError::Io)?),
        None => Box::new(std::io::stdout()),
    };

    match mode {
        Mode::Live { target } => live::run_live(cli, &target, &mut writer),
        Mode::Pcap { file } => pcap::run_pcap(cli, &file, &mut writer),
    }
}

#[cfg(test)]
mod tests {
    use super::helpers::{first_group, group_name, parse_target_and_port};
    use crate::tls::Extension;
    use crate::tls::extensions::KeyShareEntry;

    #[test]
    fn target_port_splitting() {
        assert_eq!(
            parse_target_and_port("example.com", 443),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_target_and_port("example.com:8443", 443),
            ("example.com".to_string(), 8443)
        );
        assert_eq!(
            parse_target_and_port("1.2.3.4:9001", 443),
            ("1.2.3.4".to_string(), 9001)
        );
    }

    #[test]
    fn ipv6_literals_are_not_split() {
        let (host, port) = parse_target_and_port("::1", 443);
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn non_numeric_suffix_is_not_a_port() {
        assert_eq!(
            parse_target_and_port("example.com:https", 443),
            ("example.com:https".to_string(), 443)
        );
    }

    #[test]
    fn group_names_cover_common_curves() {
        assert_eq!(group_name(0x001d), "X25519");
        assert_eq!(group_name(0x0017), "P-256");
        assert_eq!(group_name(0xabcd), "0xabcd");
    }

    #[test]
    fn first_group_prefers_supported_groups_then_key_share() {
        assert_eq!(
            first_group(&[Extension::SupportedGroups(vec![0x001d])]),
            Some(0x001d)
        );
        assert_eq!(
            first_group(&[Extension::KeyShare(vec![KeyShareEntry {
                group: 0x0017,
                key_exchange: vec![],
            }])]),
            Some(0x0017)
        );
        assert_eq!(first_group(&[]), None);
    }

    #[test]
    fn describe_lists_every_field() {
        let bytes = crate::tls::ClientHelloBuilder::new()
            .with_sni(Some("example.com".to_string()))
            .build();
        let ch = crate::tls::ClientHello::parse(&bytes).unwrap();
        let d = super::helpers::describe_client_hello(&ch);
        for field in [
            "content type",
            "legacy version",
            "real version",
            "session id",
            "cipher suites",
            "extensions",
            "grease",
        ] {
            assert!(d.contains(field), "missing {field}");
        }
    }
}
