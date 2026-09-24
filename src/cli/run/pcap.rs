//! Pcap pipeline — read a capture, reassemble TCP, rank fingerprints.

use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

use crate::cli::args::Cli;
use crate::error::{GripError, GripResult};
use crate::fp::{compute_ja3, compute_ja4};
use crate::output::model::{ClientEntry, PcapReport};
use crate::pcap::{Reassembler, extract_client_hellos, open_file, parse_ipv4_tcp};

/// Run the pcap analysis and render the report.
pub fn run_pcap(cli: &Cli, file: &std::path::Path, w: &mut dyn Write) -> GripResult<()> {
    let verbose = cli.verbose > 0;

    let reader = open_file(file)?;
    let link_type = reader.header().network;

    let mut reassembler = Reassembler::default();
    let mut packets = 0usize;
    let mut tcp = 0usize;
    let t0 = Instant::now();

    for record in reader {
        let record = record?;
        packets += 1;
        if let Some(flow) = parse_ipv4_tcp(link_type, &record.data) {
            tcp += 1;
            reassembler.insert(flow.key, flow.segment);
        }
    }
    let flow_count = reassembler.flow_count();
    if verbose {
        eprintln!(
            "read       {packets} packets, {tcp} tcp, {flow_count} flows in {} ms",
            t0.elapsed().as_millis()
        );
    }

    let mut entries: HashMap<(String, String), ClientEntry> = HashMap::new();
    let want_ja3 = cli.ja3 || cli.all_fp;

    for key in reassembler.flow_keys() {
        let Some(stream) = reassembler.reassembled(&key) else {
            continue;
        };
        for ch in extract_client_hellos(&stream) {
            let ip = key.src_ip.to_string();
            if cli.filter.as_ref().is_some_and(|f| *f != ip) {
                continue;
            }
            let ja4 = compute_ja4(&ch).to_string();
            let entry = entries
                .entry((ip.clone(), ja4.clone()))
                .or_insert_with(|| ClientEntry {
                    ip,
                    ja4: ja4.clone(),
                    ja3: want_ja3.then(|| compute_ja3(&ch)),
                    client: cli.lookup.then(|| {
                        crate::fp::lookup::lookup_ja4(&ja4).map_or_else(
                            || crate::output::model::UNCLASSIFIED.to_string(),
                            str::to_string,
                        )
                    }),
                    count: 0,
                });
            entry.count += 1;
        }
    }

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
    if verbose {
        eprintln!(
            "rank       {} handshakes, {} unique clients",
            report.total_handshakes, report.unique_clients
        );
    }

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
            let pal = super::helpers::report_palette(cli);
            let width = super::helpers::report_width(cli);
            crate::output::human::render_pcap(&report, w, pal, width).map_err(GripError::Io)
        }
        crate::cli::args::Format::Json => crate::output::json::render_json(&report, w),
    }
}
