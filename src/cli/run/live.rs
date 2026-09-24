//! Live pipeline — dial a target, capture the handshake, render.

use std::io::Write;
use std::time::Instant;

use crate::cli::args::Cli;
use crate::error::{GripError, GripResult};

/// Run the live probe and render the report.
pub fn run_live(cli: &Cli, target_raw: &str, w: &mut dyn Write) -> GripResult<()> {
    let (target, port) = super::helpers::parse_target_and_port(target_raw, cli.port);
    let endpoint = format!("{target}:{port}");
    let verbose = cli.verbose > 0;

    if verbose {
        eprintln!(
            "resolve    querying dns for {target}, sni {}",
            cli.sni.as_deref().unwrap_or(&target)
        );
    }

    let t0 = Instant::now();
    let probe = crate::net::connect::probe_with_verify(
        &target,
        port,
        cli.sni.as_deref(),
        cli.timeout,
        cli.no_verify,
    )?;
    let handshake_ms = t0.elapsed().as_millis();

    if verbose {
        eprintln!(
            "receive    {}, {} B in, {} ms",
            probe.server_hello.real_version(),
            probe.server_hello_raw.len(),
            handshake_ms
        );
        if cli.show_ja4(true) {
            let ja4 = crate::fp::compute_ja4(&probe.client_hello);
            eprintln!("fingerprint ja4 {ja4}");
        }
        match &probe.cert_chain {
            Some(c) => eprintln!(
                "certificate {} in chain, leaf {}",
                c.len(),
                c.leaf().map_or("—", |l| l.subject.as_str())
            ),
            None => eprintln!("certificate not recovered (tls 1.3 encrypts it; fallback failed)"),
        }
    }

    let report = super::helpers::build_live_report(cli, endpoint, &probe, handshake_ms, verbose);

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
            let width = super::helpers::report_width(cli);
            crate::output::human::render_live(&report, w, pal, width).map_err(GripError::Io)
        }
        crate::cli::args::Format::Json => crate::output::json::render_json(&report, w),
    }
}
