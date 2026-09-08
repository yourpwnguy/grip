//! Live pipeline — dial a target, capture the handshake, render.

use std::io::{IsTerminal, Write};
use std::time::Instant;

use crate::cli::args::Cli;
use crate::error::{GripError, GripResult};
use crate::ui::Stage;
use crate::ui::theme::Palette;

use super::helpers::{LIVE_STEPS, should_animate};

/// Bridge `crate::net::connect::Progress` events onto the live [`Stage`]
/// checklist, so the animation reflects the real handshake as it happens.
struct LiveProgress<'a> {
    stage: &'a Stage,
}

impl crate::net::connect::Progress for LiveProgress<'_> {
    fn resolved(&self, addr: std::net::SocketAddr) {
        self.stage.complete(0, addr.ip().to_string());
        self.stage.begin(1, format!("dialing {addr}"));
    }
    fn connected(&self, addr: std::net::SocketAddr) {
        self.stage.complete(1, format!("tcp up to {addr}"));
        self.stage.begin(2, "writing client hello");
    }
    fn sent(&self, bytes: usize) {
        self.stage.complete(2, format!("{bytes} B client hello"));
        self.stage.begin(3, "awaiting server hello");
    }
    fn server_hello(&self, version: crate::tls::TlsVersion, cipher: u16) {
        self.stage
            .complete(3, format!("{version}  cipher 0x{cipher:04x}"));
        self.stage.begin(4, "hashing ja3 / ja4 / ja4s");
    }
    fn fetching_cert(&self, via_fallback: bool) {
        let how = if via_fallback {
            "tls 1.3 encrypted — rustls fallback"
        } else {
            "reading from handshake"
        };
        self.stage.begin(5, how);
    }
    fn cert(&self, len: usize) {
        self.stage.complete(5, format!("{len} in chain"));
    }
}

/// Run the live probe and render the report.
pub fn run_live(cli: &Cli, target_raw: &str, w: &mut dyn Write) -> GripResult<()> {
    let (target, port) = super::helpers::parse_target_and_port(target_raw, cli.port);
    let endpoint = format!("{target}:{port}");
    let verbose = cli.verbose > 0;

    let mut stage = Stage::new(
        &LIVE_STEPS,
        Palette::detect(std::io::stderr().is_terminal()),
        should_animate(cli),
    );

    stage.begin(0, format!("looking up {target}"));
    if verbose {
        stage.log(format!(
            "resolve    querying dns for {target}, sni {}",
            cli.sni.as_deref().unwrap_or(&target)
        ));
    }

    let t0 = Instant::now();
    let probe = {
        let bridge = LiveProgress { stage: &stage };
        match crate::net::connect::probe_with_verify(
            &target,
            port,
            cli.sni.as_deref(),
            cli.timeout,
            cli.no_verify,
            &bridge,
        ) {
            Ok(p) => p,
            Err(e) => {
                stage.fail(1, e.to_string());
                stage.finish();
                return Err(e);
            }
        }
    };
    let handshake_ms = t0.elapsed().as_millis();

    // Fingerprint step completes here (no probe event of its own).
    let show_ja4 = cli.show_ja4(true);
    let ja4_preview = if show_ja4 {
        Some(crate::fp::compute_ja4(&probe.client_hello).to_string())
    } else {
        None
    };
    stage.complete(
        4,
        ja4_preview
            .clone()
            .unwrap_or_else(|| "computed".to_string()),
    );

    if verbose {
        stage.log(format!(
            "receive    {}, {} B in, {} ms",
            probe.server_hello.real_version(),
            probe.server_hello_raw.len(),
            handshake_ms
        ));
        if let Some(j) = &ja4_preview {
            stage.log(format!("fingerprint ja4 {j}"));
        }
        match &probe.cert_chain {
            Some(c) => stage.log(format!(
                "certificate {} in chain, leaf {}",
                c.len(),
                c.leaf().map_or("—", |l| l.subject.as_str())
            )),
            None => stage.log("certificate not recovered (tls 1.3 encrypts it; fallback failed)"),
        }
    }

    if probe.cert_chain.is_none() {
        stage.fail(5, "not recovered");
    }

    let report = super::helpers::build_live_report(cli, endpoint, &probe, handshake_ms, verbose);

    stage.finish();

    if cli.quiet {
        let f = &report.fingerprints;
        let show_ja3 = cli.show_ja3(true);
        let show_ja4 = cli.show_ja4(true);
        let pick = if show_ja4 {
            f.ja4.as_deref()
        } else if show_ja3 {
            f.ja3.as_deref()
        } else {
            f.ja4s.as_deref()
        };
        let value = pick.or(f.ja4.as_deref()).or(f.ja3.as_deref()).unwrap_or("");
        return crate::output::human::render_quiet(value, w).map_err(GripError::Io);
    }

    match cli.format {
        crate::cli::args::Format::Human => {
            let pal = super::helpers::report_palette(cli);
            crate::output::human::render_live(&report, w, pal).map_err(GripError::Io)
        }
        crate::cli::args::Format::Json => crate::output::json::render_json(&report, w),
    }
}
