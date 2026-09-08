//! Raw byte forensics for `--raw`.

use std::io::Write;

use crate::ui::theme::{Palette, glyph, pal};

/// Render raw `ClientHello` / `ServerHello` hex.
pub fn render_raw(
    raw: &crate::output::model::RawHex,
    w: &mut dyn Write,
    p: Palette,
) -> std::io::Result<()> {
    writeln!(w)?;
    let ch = hex::decode(&raw.client_hello_hex).unwrap_or_default();
    let sh = hex::decode(&raw.server_hello_hex).unwrap_or_default();

    writeln!(
        w,
        "  {}  {}",
        p.bold("client hello", pal::CYAN),
        p.dim(&format!("{} bytes", ch.len()), pal::STEEL)
    )?;
    crate::output::hex::hexdump(&ch, w)?;

    writeln!(w)?;
    writeln!(w, "  {}", p.bold("decoded", pal::MIST))?;
    for line in raw.client_hello_parsed.lines() {
        let (k, v) = line.split_once(": ").unwrap_or((line, ""));
        writeln!(
            w,
            "  {} {:<18} {}",
            p.dim(glyph::LEAD, pal::STEEL),
            p.dim(k, pal::MIST),
            p.paint(v, pal::CHROME)
        )?;
    }

    writeln!(w)?;
    writeln!(
        w,
        "  {}  {}",
        p.bold("server hello", pal::AMBER),
        p.dim(&format!("{} bytes", sh.len()), pal::STEEL)
    )?;
    crate::output::hex::hexdump(&sh, w)
}
