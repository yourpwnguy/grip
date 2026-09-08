//! `--quiet` — single value for piping.

use std::io::Write;

/// Machine-friendly single value.
///
/// # Errors
///
/// Returns an I/O error if writing to `w` fails.
pub fn render_quiet(fingerprint: &str, w: &mut dyn Write) -> std::io::Result<()> {
    writeln!(w, "{fingerprint}")
}
