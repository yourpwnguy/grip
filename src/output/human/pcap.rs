//! Pcap report — ranked client table.

use std::io::Write;

use crate::output::model::PcapReport;
use crate::ui::panel::{self, Panel, Row, Tone};
use crate::ui::theme::{Palette, glyph, pal};

/// Render the pcap report.
///
/// # Errors
///
/// Returns an I/O error if writing to `w` fails.
pub fn render_pcap(report: &PcapReport, w: &mut dyn Write, p: Palette) -> std::io::Result<()> {
    let mut lines = panel::header(&report.file, "pcap analysis", p);
    let summary = Panel::new("summary")
        .accent(pal::CYAN)
        .row(Row::kv_tone(
            "clients",
            report.unique_clients.to_string(),
            Tone::Key,
        ))
        .row(Row::kv_tone(
            "handshakes",
            report.total_handshakes.to_string(),
            Tone::Plain,
        ));
    lines.push(String::new());
    lines.extend(summary.render(p));
    lines.push(String::new());

    if report.clients.is_empty() {
        lines.push(format!(
            "  {} {}",
            p.bold(glyph::WARN, pal::AMBER),
            p.paint("no client hellos recovered from this capture", pal::MIST)
        ));
        lines.push(format!(
            "  {}",
            p.dim(
                "the capture may hold no tls, or streams may be truncated",
                pal::STEEL
            )
        ));
        for l in &lines {
            writeln!(w, "{l}")?;
        }
        return Ok(());
    }

    lines.push(format!(
        "  {}  {:<15} {:<38} {:<14} {}",
        p.dim("  ", pal::STEEL),
        p.dim("source", pal::MIST),
        p.dim("ja4", pal::MIST),
        p.dim("client", pal::MIST),
        p.dim("seen", pal::MIST)
    ));
    lines.push(format!(
        "  {}",
        p.gradient(
            &glyph::H.to_string().repeat(panel::INNER + 2),
            pal::STEEL,
            pal::VOID
        )
    ));

    let max = report
        .clients
        .iter()
        .map(|c| c.count)
        .max()
        .unwrap_or(1)
        .max(1);
    for (i, c) in report.clients.iter().enumerate() {
        let rank = format!("{:>2}", i + 1);
        let width = 10;
        let filled = ((c.count * width) / max).max(1);
        let bar = format!(
            "{}{}",
            p.gradient(&"▰".repeat(filled), pal::MAGENTA, pal::CYAN),
            p.dim(&"▱".repeat(width - filled), pal::VOID)
        );
        lines.push(format!(
            "  {}  {:<15} {} {:<14} {} {}",
            p.dim(&rank, pal::STEEL),
            p.paint(&panel::truncate(&c.ip, 15), pal::CHROME),
            p.paint(
                &format!("{:<38}", panel::truncate(&c.ja4, 38)),
                pal::MAGENTA
            ),
            p.paint(
                &panel::truncate(c.client.as_deref().unwrap_or("unclassified"), 14),
                if c.client.is_some() {
                    pal::LIME
                } else {
                    pal::MIST
                }
            ),
            bar,
            p.dim(&format!("{:>4}", c.count), pal::MIST)
        ));
    }

    lines.push(String::new());
    lines.extend(panel::footer(
        0,
        &format!("{} unique fingerprints", report.unique_clients),
        p,
    ));
    for l in &lines {
        writeln!(w, "{l}")?;
    }
    Ok(())
}
