//! Live report — the `grip example.com` view.

use std::io::Write;

use crate::output::model::LiveReport;
use crate::ui::panel::{self, Panel, Row, Tone};
use crate::ui::theme::{Palette, glyph, pal};

/// Render the live report.
///
/// # Errors
///
/// Returns an I/O error if writing to `w` fails.
pub fn render_live(report: &LiveReport, w: &mut dyn Write, p: Palette) -> std::io::Result<()> {
    let mut lines = panel::header(&report.target, "live handshake", p);
    lines.push(String::new());
    lines.extend(negotiated(report, p));
    lines.push(String::new());
    lines.extend(certificate(report, p));
    if let Some(chain) = chain(report, p) {
        lines.push(String::new());
        lines.extend(chain);
    }
    lines.push(String::new());
    lines.extend(fingerprints(report, p));
    if let Some(t) = telemetry(report, p) {
        lines.push(String::new());
        lines.extend(t);
    }
    let elapsed = report.verbose_info.as_ref().map_or(0, |v| v.handshake_ms);
    let note = report
        .fingerprints
        .lookup
        .as_deref()
        .unwrap_or("unclassified client");
    lines.push(String::new());
    lines.extend(panel::footer(elapsed, note, p));
    for l in &lines {
        writeln!(w, "{l}")?;
    }
    if let Some(raw) = &report.raw {
        super::raw::render_raw(raw, w, p)?;
    }
    Ok(())
}

fn negotiated(report: &LiveReport, p: Palette) -> Vec<String> {
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
    panel.render(p)
}

fn certificate(report: &LiveReport, p: Palette) -> Vec<String> {
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
        panel = panel
            .row_opt("sha-256", c.sha256.clone(), Tone::Muted)
            .row_opt("ct logs", c.ct_logs.clone(), Tone::Plain);
    } else {
        panel = panel
            .row(Row::kv_tone("status", "not recovered", Tone::Bad))
            .row(Row::Note(
                "tls 1.3 encrypts the certificate message; the verified".to_string(),
            ))
            .row(Row::Note(
                "fallback also failed — retry with --no-verify".to_string(),
            ));
    }
    panel.render(p)
}

fn chain(report: &LiveReport, p: Palette) -> Option<Vec<String>> {
    let chain = report.cert_chain.as_ref()?;
    if chain.len() <= 1 {
        return None;
    }
    let mut panel = Panel::new("chain of trust").accent(pal::AZURE);
    for (i, c) in chain.iter().enumerate() {
        let depth = if i == 0 { "leaf" } else { "issuer" };
        panel = panel.row(
            Row::kv_tone(
                depth,
                c.subject.clone().unwrap_or_else(|| "—".to_string()),
                if i == 0 { Tone::Key } else { Tone::Plain },
            )
            .note(format!("depth {i}")),
        );
        if let Some(fp) = &c.sha256 {
            panel = panel.row(Row::Note(format!("{} {fp}", glyph::LINK)));
        }
    }
    Some(panel.render(p))
}

fn fingerprints(report: &LiveReport, p: Palette) -> Vec<String> {
    let f = &report.fingerprints;
    let mut panel = Panel::new("fingerprints").accent(pal::MAGENTA);
    panel = panel
        .row_opt("ja3", f.ja3.clone(), Tone::Sig)
        .row_opt("ja4", f.ja4.clone(), Tone::Sig)
        .row_opt("ja4s", f.ja4s.clone(), Tone::Sig);
    if let Some(m) = &f.lookup {
        panel = panel.row(Row::Note(format!("matches {m}")));
    }
    if f.ja3.is_none() && f.ja4.is_none() && f.ja4s.is_none() {
        panel = panel.row(Row::kv_tone("none", "use --all-fp", Tone::Muted));
    }
    panel.render(p)
}

fn telemetry(report: &LiveReport, p: Palette) -> Option<Vec<String>> {
    let v = report.verbose_info.as_ref()?;
    let mut t = Panel::new("telemetry").accent(pal::STEEL);
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
    Some(t.render(p))
}
