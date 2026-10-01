//! Probing the terminal for report settings.
//!
//! Kept apart from DTO building because these two change for different
//! reasons: one is about where the bytes land, the other is about what the
//! handshake contained.

use std::io::IsTerminal;

use crate::ui::theme::Palette;

/// Palette for the report on stdout.
///
/// When `-o file` is given the report is a file, so color is suppressed to
/// keep the artifact clean.
pub fn report_palette(cli: &crate::cli::args::Cli) -> Palette {
    if cli.output.is_some() {
        return Palette::plain();
    }
    Palette::detect(std::io::stdout().is_terminal())
}

/// Render width for the human report.
///
/// `COLUMNS` wins when set (explicit override, handy in scripts and CI), then
/// the real terminal width, then [`crate::ui::panel::DEFAULT_WIDTH`]. Clamped
/// so a hostile or silly value cannot collapse the layout. File output is
/// deterministic: it always uses the default.
pub fn report_width(cli: &crate::cli::args::Cli) -> usize {
    use crate::ui::panel::{DEFAULT_WIDTH, MAX_WIDTH, MIN_WIDTH};
    if cli.output.is_some() {
        return DEFAULT_WIDTH;
    }
    let w = std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(cols, _)| usize::from(cols.0)))
        .unwrap_or(DEFAULT_WIDTH);
    w.clamp(MIN_WIDTH, MAX_WIDTH)
}
