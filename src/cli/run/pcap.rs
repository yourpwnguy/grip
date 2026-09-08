//! Pcap pipeline — read a capture, reassemble TCP, rank fingerprints.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::time::Instant;

use crate::cli::args::Cli;
use crate::error::{GripError, GripResult};
use crate::fp::{compute_ja3, compute_ja4};
use crate::output::model::{ClientEntry, PcapReport};
use crate::pcap::{Reassembler, extract_client_hellos, open_file, parse_ipv4_tcp};
use crate::ui::Stage;
use crate::ui::theme::Palette;

use super::helpers::{PCAP_STEPS, should_animate};

/// Run the pcap analysis and render the report.
pub fn run_pcap(cli: &Cli, file: &std::path::Path, w: &mut dyn Write) -> GripResult<()> {
    let verbose = cli.verbose > 0;
    let mut stage = Stage::new(
        &PCAP_STEPS,
        Palette::detect(std::io::stderr().is_terminal()),
        should_animate(cli),
    );

    stage.begin(0, format!("opening {}", file.display()));
    let reader = match open_file(file) {
        Ok(r) => r,
        Err(e) => {
            stage.fail(0, e.to_string());
            stage.finish();
            return Err(e);
        }
    };
    let link_type = reader.header().network;

    let mut reassembler = Reassembler::default();
    let mut packets = 0usize;
    let mut tcp = 0usize;
    let t0 = Instant::now();

    for record in reader {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                stage.fail(0, e.to_string());
                stage.finish();
                return Err(e);
            }
        };
        packets += 1;
        if let Some(flow) = parse_ipv4_tcp(link_type, &record.data) {
            tcp += 1;
            reassembler.insert(flow.key, flow.segment);
        }
        if packets.is_multiple_of(256) {
            stage.detail(format!(
                "{packets} packets  {tcp} tcp  {} flows",
                reassembler.flow_count()
            ));
        }
    }
    stage.complete(0, format!("{packets} packets  {tcp} tcp"));
    stage.begin(1, format!("{} flows", reassembler.flow_count()));
    if verbose {
        stage.log(format!(
            "read       {packets} packets, {tcp} tcp, {} flows in {} ms",
            reassembler.flow_count(),
            t0.elapsed().as_millis()
        ));
    }

    let flow_count = reassembler.flow_count();
    stage.complete(1, format!("{flow_count} streams"));
    stage.begin(2, "scanning for client hellos");
    let mut entries: HashMap<(String, String), ClientEntry> = HashMap::new();
    let want_ja3 = cli.ja3 || cli.all_fp;
    let mut hello_count = 0usize;

    for key in reassembler.flow_keys() {
        let Some(stream) = reassembler.reassembled(&key) else {
            continue;
        };
        for ch in extract_client_hellos(&stream) {
            let ip = key.src_ip.to_string();
            if cli.filter.as_ref().is_some_and(|f| *f != ip) {
                continue;
            }
            hello_count += 1;
            let ja4 = compute_ja4(&ch).to_string();
            let entry = entries
                .entry((ip.clone(), ja4.clone()))
                .or_insert_with(|| ClientEntry {
                    ip,
                    ja4: ja4.clone(),
                    ja3: want_ja3.then(|| compute_ja3(&ch)),
                    client: cli
                        .lookup
                        .then(|| crate::fp::lookup::lookup_ja4(&ja4).map(str::to_string))
                        .flatten(),
                    count: 0,
                });
            entry.count += 1;
        }
    }
    stage.complete(2, format!("{hello_count} client hellos"));
    stage.begin(3, "grouping by fingerprint");

    let mut clients: Vec<ClientEntry> = if cli.unique {
        let mut by_fp: HashMap<String, ClientEntry> = HashMap::new();
        for e in entries.into_values() {
            let slot = by_fp.entry(e.ja4.clone()).or_insert_with(|| ClientEntry {
                count: 0,
                ..e.clone()
            });
            slot.count += e.count;
            if e.ip < slot.ip {
                slot.ip = e.ip;
            }
        }
        by_fp.into_values().collect()
    } else {
        entries.into_values().collect()
    };

    match cli.sort_by {
        crate::cli::args::SortBy::Count => {
            clients.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        }
        crate::cli::args::SortBy::Ip => clients.sort_by(|a, b| a.ip.cmp(&b.ip)),
        crate::cli::args::SortBy::Fingerprint => clients.sort_by(|a, b| a.ja4.cmp(&b.ja4)),
    }

    let report = PcapReport {
        file: file.display().to_string(),
        total_handshakes: clients.iter().map(|c| c.count).sum(),
        unique_clients: clients.len(),
        clients,
    };
    stage.complete(3, format!("{} unique clients", report.unique_clients));
    if verbose {
        stage.log(format!(
            "rank       {} handshakes, {} unique clients",
            report.total_handshakes, report.unique_clients
        ));
    }
    stage.finish();

    if cli.quiet {
        let ja3_only = cli.ja3 && !cli.ja4 && !cli.all_fp;
        for c in &report.clients {
            let line = if ja3_only {
                c.ja3.as_deref().unwrap_or(&c.ja4)
            } else {
                &c.ja4
            };
            writeln!(w, "{line}").map_err(GripError::Io)?;
        }
        return Ok(());
    }

    match cli.format {
        crate::cli::args::Format::Human => {
            let pal = if cli.output.is_some() {
                Palette::plain()
            } else {
                Palette::detect(std::io::stdout().is_terminal())
            };
            crate::output::human::render_pcap(&report, w, pal).map_err(GripError::Io)
        }
        crate::cli::args::Format::Json => crate::output::json::render_json(&report, w),
    }
}
