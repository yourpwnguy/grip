//! Raw byte forensics for `--raw`.

use std::io::Write;

use crate::output::hex::hexdump;
use crate::ui::text::wrap;
use crate::ui::theme::{Palette, Rgb, glyph, pal};

/// Column the decoded values start at, which is where wrapped lines rejoin.
/// Two spaces, the leader glyph, a space, then an 18-wide key column.
const VALUE_COL: usize = 23;

/// Render raw `ClientHello` / `ServerHello` hex plus a decoded view of our own
/// `ClientHello`.
pub fn render_raw(
    raw: &crate::output::model::RawHex,
    w: &mut dyn Write,
    p: Palette,
    width: usize,
) -> std::io::Result<()> {
    writeln!(w)?;
    let ch = hex::decode(&raw.client_hello_hex).unwrap_or_default();
    let sh = hex::decode(&raw.server_hello_hex).unwrap_or_default();

    heading(w, "client hello", ch.len(), pal::CYAN, p)?;
    hexdump(&ch, w)?;

    writeln!(w)?;
    writeln!(w, "  {}", p.bold("decoded", pal::MIST))?;
    for line in raw.client_hello_parsed.lines() {
        decoded_row(w, line, p, width)?;
    }

    writeln!(w)?;
    heading(w, "server hello", sh.len(), pal::AMBER, p)?;
    hexdump(&sh, w)
}

/// `  label  N bytes`, the heading above each dump.
fn heading(
    w: &mut dyn Write,
    label: &str,
    len: usize,
    color: Rgb,
    p: Palette,
) -> std::io::Result<()> {
    let size = p.dim(&format!("{len} bytes"), pal::STEEL);
    writeln!(w, "  {}  {size}", p.bold(label, color))
}

/// One `key   value` line of the decoded view, wrapped rather than clipped.
///
/// `client_hello_parsed` arrives pre-joined as `key: value` lines because that
/// is the shape the JSON field has always had. Splitting it back apart here
/// keeps that schema stable.
fn decoded_row(w: &mut dyn Write, line: &str, p: Palette, width: usize) -> std::io::Result<()> {
    let (key, value) = line.split_once(": ").unwrap_or((line, ""));
    let avail = width.saturating_sub(VALUE_COL);
    let pad = " ".repeat(VALUE_COL);

    for (i, chunk) in wrap(value, avail).iter().enumerate() {
        let line = if i == 0 {
            format!(
                "  {} {:<18} {}",
                p.dim(glyph::LEAD, pal::STEEL),
                p.dim(key, pal::MIST),
                p.paint(chunk, pal::CHROME)
            )
        } else {
            format!("{pad}{}", p.paint(chunk, pal::CHROME))
        };
        writeln!(w, "{line}")?;
    }
    Ok(())
}
