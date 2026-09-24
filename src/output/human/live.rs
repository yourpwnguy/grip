//! Live report — the `grip example.com` view.
//!
//! Sections are stacked tightly: a titled rule, then rows. The certificate
//! section absorbs the chain (`--cert-chain`), because intermediates are just
//! more certificates hanging off the leaf, and the fingerprints section
//! carries the client identity so the answer to "who is this?" never hides
//! in a footer.

use std::io::Write;

use crate::output::model::LiveReport;
use crate::ui::panel::{self, Panel, Row, Tone};
use crate::ui::theme::{Palette, glyph, pal};

/// Render the live report.
///
/// # Errors
///
/// Returns an I/O error if writing to `w` fails.
pub fn render_live(
    report: &LiveReport,
    w: &mut dyn Write,
    p: Palette,
    width: usize,
) -> std::io::Result<()> {
    let mut lines = panel::header(&report.target, "live handshake", p, width);
    lines.push(String::new());
    lines.extend(negotiated(report, p, width));
    lines.push(String::new());
    lines.extend(certificate(report, p, width));
    lines.push(String::new());
    lines.extend(fingerprints(report, p, width));
    if let Some(t) = telemetry(report, p, width) {
        lines.push(String::new());
        lines.extend(t);
    }
    let elapsed = report.verbose_info.as_ref().map_or(0, |v| v.handshake_ms);
    let foot = panel::footer(elapsed, "", p);
    if !foot.is_empty() {
        lines.push(String::new());
        lines.extend(foot);
    }
    for l in &lines {
        writeln!(w, "{l}")?;
    }
    if let Some(raw) = &report.raw {
        super::raw::render_raw(raw, w, p)?;
    }
    Ok(())
}

fn negotiated(report: &LiveReport, p: Palette, width: usize) -> Vec<String> {
    let n = &report.negotiated;
    let mut panel = Panel::new("negotiated")
        .accent(pal::CYAN)
        .row(Row::kv_tone("tls version", &n.tls_version, Tone::Key))
        .row(Row::kv_tone("cipher suite", &n.cipher_suite, Tone::Plain).note(n.cipher_hex.clone()));
    panel = panel
        .row_opt("key exchange", n.key_exchange.clone(), Tone::Plain)
        .row_opt("alpn", n.alpn.clone(), Tone::Plain);
    if let Some(sni) = &n.sni {
        let kind = if n.sni_is_ip {
            "ip literal"
        } else {
            "hostname"
        };
        panel = panel.row(Row::kv_tone("sni", sni, Tone::Plain).note(kind));
    }
    if !n.offered_versions.is_empty() {
        panel = panel.row(Row::kv_tone(
            "offered",
            n.offered_versions.join(&format!(" {} ", glyph::DOT)),
            Tone::Muted,
        ));
    }
    panel.render(p, width)
}

fn certificate(report: &LiveReport, p: Palette, width: usize) -> Vec<String> {
    let mut panel = Panel::new("certificate").accent(pal::AMBER);
    if let Some(c) = &report.certificate {
        panel = panel
            .row_opt("subject", c.subject.clone(), Tone::Key)
            .row_opt("issuer", c.issuer.clone(), Tone::Plain);
        if !c.sans.is_empty() {
            let shown = c
                .sans
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("  ");
            let extra = c.sans.len().saturating_sub(3);
            let row = Row::kv_tone("sans", shown, Tone::Plain);
            panel = panel.row(if extra > 0 {
                row.note(format!("+{extra} more"))
            } else {
                row
            });
        }
        if let Some(exp) = &c.expires {
            let tone = if exp.contains("expired") {
                Tone::Bad
            } else {
                Tone::Good
            };
            panel = panel.row(Row::kv_tone("expires", exp, tone));
        }
        // Colonless hex reads as one token and wraps without splitting a
        // byte pair across the visual break.
        panel = panel.row_opt(
            "sha-256",
            c.sha256.as_ref().map(|s| s.replace(':', "")),
            Tone::Muted,
        );
        panel = panel.row_opt("ct logs", c.ct_logs.clone(), Tone::Plain);
    } else {
        panel = panel
            .row(Row::kv_tone("status", "not recovered", Tone::Bad))
            .row(Row::Note(
                "tls 1.3 encrypts the certificate message; the verified fallback \
                 also failed — retry with --no-verify"
                    .to_string(),
            ));
    }
    // Intermediates ride in the same section: the leaf's `issuer` row is
    // already `chain 1`'s subject, so this reads as one continuous chain.
    if let Some(chain) = &report.cert_chain {
        for (depth, c) in chain.iter().enumerate().skip(1) {
            panel = panel.row(Row::kv_tone(
                format!("chain {depth}"),
                c.subject.clone().unwrap_or_else(|| "—".to_string()),
                Tone::Plain,
            ));
            if let Some(fp) = &c.sha256 {
                panel = panel.row(Row::Note(format!(
                    "{} {}",
                    glyph::LINK,
                    fp.replace(':', "")
                )));
            }
        }
    }
    panel.render(p, width)
}

fn fingerprints(report: &LiveReport, p: Palette, width: usize) -> Vec<String> {
    let f = &report.fingerprints;
    let mut panel = Panel::new("fingerprints").accent(pal::MAGENTA);
    let any = f.ja3.is_some() || f.ja4.is_some() || f.ja4s.is_some();
    if any {
        panel = panel
            .row_opt("ja3", f.ja3.clone(), Tone::Sig)
            .row_opt("ja4", f.ja4.clone(), Tone::Sig)
            .row_opt("ja4s", f.ja4s.clone(), Tone::Sig);
        // `None` means `--lookup` was never requested: omit the row rather
        // than advertising a miss. A requested miss renders muted.
        if let Some(name) = &f.lookup {
            let tone = if name == crate::output::model::UNCLASSIFIED {
                Tone::Muted
            } else {
                Tone::Good
            };
            panel = panel.row(Row::kv_tone("client", name, tone));
        }
    } else {
        panel = panel.row(Row::kv_tone("none", "use --all-fp", Tone::Muted));
    }
    panel.render(p, width)
}

fn telemetry(report: &LiveReport, p: Palette, width: usize) -> Option<Vec<String>> {
    let v = report.verbose_info.as_ref()?;
    let mut t = Panel::new("telemetry").accent(pal::AZURE);
    t = t
        .row(Row::kv_tone(
            "handshake",
            format!("{} ms", v.handshake_ms),
            Tone::Key,
        ))
        .row(
            Row::kv_tone("bytes", format!("{} out", v.bytes_sent), Tone::Plain)
                .note(format!("{} in", v.bytes_received)),
        )
        .row(Row::kv_tone(
            "grease",
            format!("{} filtered", v.grease_filtered),
            Tone::Muted,
        ));
    if !v.resolved_ips.is_empty() {
        t = t.row(Row::kv_tone(
            "resolved",
            v.resolved_ips.join("  "),
            Tone::Muted,
        ));
    }
    Some(t.render(p, width))
}
