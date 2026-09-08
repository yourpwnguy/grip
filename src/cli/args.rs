//! CLI definitions via `clap` derive.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// grip — TLS handshake inspector + fingerprinter
#[derive(Parser, Debug, Clone)]
#[command(
    name = "grip",
    version,
    about = "Inspect TLS handshakes and fingerprint clients (JA3/JA4/JA4S) — live or pcap"
)]
pub struct Cli {
    /// Domain or IP to inspect (e.g. example.com, 1.2.3.4:8443). Not used with --pcap.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    // ── Modes ──
    /// Analyze `ClientHellos` from a .pcap file
    #[arg(long, value_name = "FILE")]
    pub pcap: Option<PathBuf>,

    // ── Connection ──
    /// Target port
    #[arg(short, long, default_value_t = 443, value_name = "N")]
    pub port: u16,

    /// Override SNI hostname
    #[arg(long, value_name = "NAME")]
    pub sni: Option<String>,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub timeout: u64,

    /// Skip certificate verification (currently no verification is enforced; flag kept for compatibility)
    #[arg(long)]
    pub no_verify: bool,

    // ── Fingerprints ──
    /// Show JA3 fingerprint
    #[arg(long)]
    pub ja3: bool,

    /// Show JA4 fingerprint
    #[arg(long)]
    pub ja4: bool,

    /// Show JA4S server fingerprint
    #[arg(long)]
    pub ja4s: bool,

    /// Show all fingerprint variants
    #[arg(long)]
    pub all_fp: bool,

    /// Lookup fingerprint against known DB
    #[arg(long)]
    pub lookup: bool,

    // ── Output ──
    /// Output format: human (pretty) or json
    #[arg(long, value_enum, default_value_t = Format::Human, value_name = "FMT")]
    pub format: Format,

    /// Dump raw `ClientHello` + `ServerHello` hex
    #[arg(long)]
    pub raw: bool,

    /// Show full certificate chain (currently shows leaf; full chain planned)
    #[arg(long)]
    pub cert_chain: bool,

    /// Fingerprint only, no decoration
    #[arg(long)]
    pub quiet: bool,

    /// Write output to file
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    // ── Pcap options ──
    /// Only show this source IP (pcap mode)
    #[arg(long, value_name = "IP")]
    pub filter: Option<String>,

    /// Deduplicate, show each fingerprint once (pcap mode)
    #[arg(long)]
    pub unique: bool,

    /// Sort by: ip | fingerprint | count
    #[arg(long, value_enum, default_value_t = SortBy::Count, value_name = "FIELD")]
    pub sort_by: SortBy,

    // ── Verbosity / UI ──
    /// Verbose output — show live progress, timings, and transparency
    #[arg(long, short, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable cute progress animations
    #[arg(long)]
    pub no_progress: bool,
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable pretty output.
    Human,
    /// JSON output for scripting.
    Json,
}

/// Sort key for pcap output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortBy {
    /// Sort by IP address.
    Ip,
    /// Sort by fingerprint string.
    Fingerprint,
    /// Sort by hit count (descending, default).
    Count,
}

impl Cli {
    /// Whether any fingerprint flag was explicitly set.
    #[must_use]
    pub const fn any_fp_flag(&self) -> bool {
        self.ja3 || self.ja4 || self.ja4s || self.all_fp
    }

    /// Resolve which fingerprints to show.
    ///
    /// If no flag is set, live mode defaults to all; pcap defaults to JA4.
    #[must_use]
    pub const fn show_ja3(&self, is_live: bool) -> bool {
        if self.all_fp {
            return true;
        }
        if self.ja3 {
            return true;
        }
        if !self.any_fp_flag() && is_live {
            return true;
        }
        false
    }

    /// Whether to show JA4.
    #[must_use]
    pub const fn show_ja4(&self, is_live: bool) -> bool {
        if self.all_fp {
            return true;
        }
        if self.ja4 {
            return true;
        }
        if !self.any_fp_flag() {
            return true; // JA4 always shown
        }
        let _ = is_live;
        false
    }

    /// Whether to show JA4S.
    #[must_use]
    pub const fn show_ja4s(&self, is_live: bool) -> bool {
        if self.all_fp {
            return true;
        }
        if self.ja4s {
            return true;
        }
        if !self.any_fp_flag() && is_live {
            return true;
        }
        false
    }
}
