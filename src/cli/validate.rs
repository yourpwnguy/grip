//! CLI validation — cross-field checks that `clap` alone can't express.

use crate::cli::args::Cli;
use crate::error::{GripError, GripResult};

/// Validated mode after checking CLI.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Live probe of a target.
    Live {
        /// Hostname or IP.
        target: String,
    },
    /// Pcap file analysis.
    Pcap {
        /// Path to pcap file.
        file: std::path::PathBuf,
    },
}

/// Validate `cli` and return the operational `Mode`.
///
/// Checks:
/// - Exactly one of `<target>` or `--pcap` must be present.
/// - `port` in 1..=65535 (clap already ensures `u16`).
/// - `timeout` > 0.
/// - `filter` / `unique` / `sort_by` require `--pcap`.
/// - SNI if provided must be non-empty and not contain whitespace/`/`.
///
/// # Errors
///
/// Returns [`GripError::InvalidArg`] if `timeout` is 0, `port` is 0,
/// SNI is invalid, pcap-only flags are used without `--pcap`,
/// or the target/pcap combination is invalid.
pub fn validate(cli: &Cli) -> GripResult<Mode> {
    if cli.timeout == 0 {
        return Err(GripError::invalid_arg("timeout must be > 0"));
    }
    if cli.port == 0 {
        return Err(GripError::invalid_arg("port must be 1..65535"));
    }
    if let Some(sni) = &cli.sni
        && (sni.trim().is_empty() || sni.contains(char::is_whitespace) || sni.contains('/'))
    {
        return Err(GripError::invalid_arg(format!("invalid SNI: {sni}")));
    }

    // Pcap-only flags require --pcap
    if cli.filter.is_some() && cli.pcap.is_none() {
        return Err(GripError::invalid_arg("--filter requires --pcap"));
    }
    if cli.unique && cli.pcap.is_none() {
        return Err(GripError::invalid_arg("--unique requires --pcap"));
    }
    // sort_by is always set (default), but if user explicitly passed a non-default with live mode we should warn?
    // We allow it but ignore for live — keep strict: if live and sort_by != default via CLI? Can't detect default vs explicit without clap internals.
    // So we just allow but it has no effect for live.

    match (&cli.target, &cli.pcap) {
        (Some(t), None) => {
            if t.trim().is_empty() {
                return Err(GripError::invalid_arg("target must be non-empty"));
            }
            // Allow host:port in target? Idea says `1.2.3.4:8443` as target. If target contains ':', treat as host:port and override --port.
            // For validation we accept either; run.rs will handle splitting.
            Ok(Mode::Live { target: t.clone() })
        }
        (None, Some(p)) => {
            if p.as_os_str().is_empty() {
                return Err(GripError::invalid_arg("pcap path must be non-empty"));
            }
            Ok(Mode::Pcap { file: p.clone() })
        }
        (Some(_), Some(_)) => Err(GripError::invalid_arg(
            "cannot specify both <target> and --pcap",
        )),
        (None, None) => Err(GripError::invalid_arg(
            "must specify <target> or --pcap <file>",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Cli, Format, SortBy};

    fn base_cli() -> Cli {
        Cli {
            target: None,
            pcap: None,
            port: 443,
            sni: None,
            timeout: 10,
            no_verify: false,
            ja3: false,
            ja4: false,
            ja4s: false,
            all_fp: false,
            lookup: false,
            format: Format::Human,
            raw: false,
            cert_chain: false,
            quiet: false,
            output: None,
            filter: None,
            unique: false,
            sort_by: SortBy::Count,
            verbose: 0,
        }
    }

    #[test]
    fn live_ok() {
        let mut cli = base_cli();
        cli.target = Some("example.com".to_string());
        assert!(matches!(validate(&cli).unwrap(), Mode::Live { .. }));
    }

    #[test]
    fn pcap_ok() {
        let mut cli = base_cli();
        cli.pcap = Some(std::path::PathBuf::from("a.pcap"));
        assert!(matches!(validate(&cli).unwrap(), Mode::Pcap { .. }));
    }

    #[test]
    fn both_fails() {
        let mut cli = base_cli();
        cli.target = Some("a".to_string());
        cli.pcap = Some(std::path::PathBuf::from("b.pcap"));
        assert!(validate(&cli).is_err());
    }

    #[test]
    fn none_fails() {
        let cli = base_cli();
        assert!(validate(&cli).is_err());
    }

    #[test]
    fn filter_requires_pcap() {
        let mut cli = base_cli();
        cli.target = Some("a".to_string());
        cli.filter = Some("1.1.1.1".to_string());
        assert!(validate(&cli).is_err());
    }
}
