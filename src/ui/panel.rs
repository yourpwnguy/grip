//! Panels — the aligned, boxed layout primitive for final output.
//!
//! Everything `grip` prints as a result goes through a [`Panel`]: a titled
//! box with a fixed inner width, a key column, and a value column. Centralising
//! the geometry here is what makes the report look designed rather than
//! assembled — every panel in every mode shares one set of rules.
//!
//! # Alignment
//! Padding is computed on **plain text**, then color is applied, because ANSI
//! escapes have zero display width but non-zero byte length; `{:<width}` on a
//! colored string pads by bytes and shears the right border. Values are
//! truncated by `char`, not by byte, so multi-byte subjects in certificates
//! cannot split a code point.
//!
//! We deliberately assume single-width glyphs. The design uses only
//! box-drawing and geometric characters (no emoji, which are double-width and
//! render inconsistently), so a `char` count is an exact display width here.

use std::fmt::Write;

use crate::ui::theme::{Palette, Rgb, glyph, pal};

/// Inner width of every panel, in columns (between the borders).
pub const INNER: usize = 66;
/// Width of the key column.
const KEY_W: usize = 16;
/// Left margin for the whole report.
const MARGIN: &str = "  ";

/// Emphasis for a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Ordinary value.
    Plain,
    /// Highlighted value (the thing you came to read).
    Key,
    /// Signature / fingerprint value.
    Sig,
    /// Good news.
    Good,
    /// Bad news.
    Bad,
    /// Muted supporting value.
    Muted,
}

impl Tone {
    const fn rgb(self) -> Rgb {
        match self {
            Self::Plain => pal::CHROME,
            Self::Key => pal::AMBER,
            Self::Sig => pal::MAGENTA,
            Self::Good => pal::LIME,
            Self::Bad => pal::RUST,
            Self::Muted => pal::MIST,
        }
    }
}

/// A row inside a panel.
#[derive(Debug, Clone)]
pub enum Row {
    /// `key   value` with an optional trailing annotation.
    Kv {
        /// Left column label.
        key: &'static str,
        /// Right column value.
        value: String,
        /// Emphasis for `value`.
        tone: Tone,
        /// Dim text appended after the value (units, hints, matches).
        note: Option<String>,
    },
    /// A full-width line of muted text, indented under the key column.
    Note(String),
    /// A full-width separator.
    Rule,
}

impl Row {
    /// Key/value row.
    #[must_use]
    pub fn kv(key: &'static str, value: impl Into<String>) -> Self {
        Self::Kv {
            key,
            value: value.into(),
            tone: Tone::Plain,
            note: None,
        }
    }

    /// Key/value row with emphasis.
    #[must_use]
    pub fn kv_tone(key: &'static str, value: impl Into<String>, tone: Tone) -> Self {
        Self::Kv {
            key,
            value: value.into(),
            tone,
            note: None,
        }
    }

    /// Attach a dim trailing annotation.
    #[must_use]
    pub fn note(mut self, text: impl Into<String>) -> Self {
        if let Self::Kv { note, .. } = &mut self {
            *note = Some(text.into());
        }
        self
    }
}

/// A titled box.
#[derive(Debug, Clone)]
pub struct Panel {
    title: &'static str,
    accent: Rgb,
    rows: Vec<Row>,
}

impl Panel {
    /// New panel with a cyan accent.
    #[must_use]
    pub const fn new(title: &'static str) -> Self {
        Self {
            title,
            accent: pal::CYAN,
            rows: Vec::new(),
        }
    }

    /// Override the accent used for the title and border gradient.
    #[must_use]
    pub const fn accent(mut self, rgb: Rgb) -> Self {
        self.accent = rgb;
        self
    }

    /// Append a row.
    #[must_use]
    pub fn row(mut self, row: Row) -> Self {
        self.rows.push(row);
        self
    }

    /// Append a row only when `value` is `Some`, so callers stay free of
    /// `if let` noise when assembling reports from optional fields.
    #[must_use]
    pub fn row_opt(self, key: &'static str, value: Option<impl Into<String>>, tone: Tone) -> Self {
        match value {
            Some(v) => self.row(Row::kv_tone(key, v, tone)),
            None => self,
        }
    }

    /// Render to lines. Empty panels render nothing at all, which keeps the
    /// report free of hollow boxes when a section has no data.
    #[must_use]
    pub fn render(&self, p: Palette) -> Vec<String> {
        if self.rows.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.rows.len() + 2);
        out.push(self.top(p));
        for row in &self.rows {
            out.push(line(row, p));
        }
        out.push(self.bottom(p));
        out
    }

    /// `╭─ title ─────╮` with a gradient rule fading from the accent to steel.
    fn top(&self, p: Palette) -> String {
        let label = format!(" {} ", self.title);
        // 2 for the corners, 1 for the leading rule segment.
        let fill = INNER.saturating_sub(label.chars().count() + 1);
        format!(
            "{MARGIN}{}{}{}{}{}",
            p.paint(&glyph::TL.to_string(), self.accent),
            p.paint(&glyph::H.to_string(), self.accent),
            p.bold(&label, self.accent),
            p.gradient(&glyph::H.to_string().repeat(fill), self.accent, pal::STEEL),
            p.dim(&glyph::TR.to_string(), pal::STEEL)
        )
    }

    fn bottom(&self, p: Palette) -> String {
        format!(
            "{MARGIN}{}{}{}",
            p.dim(&glyph::BL.to_string(), pal::STEEL),
            p.gradient(&glyph::H.to_string().repeat(INNER), pal::STEEL, self.accent),
            p.paint(&glyph::BR.to_string(), self.accent)
        )
    }
}

fn line(row: &Row, p: Palette) -> String {
    let (plain, painted) = match row {
        Row::Kv {
            key,
            value,
            tone,
            note,
        } => {
            let avail = INNER.saturating_sub(2 + KEY_W + 1);
            let note_len = note.as_ref().map_or(0, |n| n.chars().count() + 2);
            let value = truncate(value, avail.saturating_sub(note_len));

            let mut plain = format!("  {key:<KEY_W$} {value}");
            let mut painted = format!(
                "  {}{} {}",
                p.dim(key, pal::MIST),
                " ".repeat(KEY_W.saturating_sub(key.chars().count())),
                p.paint(&value, tone.rgb())
            );
            if let Some(n) = note {
                let _ = write!(plain, "  {n}");
                let _ = write!(painted, "  {}", p.dim(n, pal::STEEL));
            }
            (plain, painted)
        }
        Row::Note(text) => {
            let avail = INNER.saturating_sub(2 + KEY_W + 1);
            let text = truncate(text, avail);
            let plain = format!("  {:<KEY_W$} {text}", "");
            let painted = format!("  {:<KEY_W$} {}", "", p.dim(&text, pal::STEEL));
            (plain, painted)
        }
        Row::Rule => {
            let inner = glyph::H.to_string().repeat(INNER.saturating_sub(2));
            let plain = format!(" {inner} ");
            let painted = format!(" {} ", p.dim(&inner, pal::VOID));
            (plain, painted)
        }
    };

    // Pad from the plain width; the painted string carries invisible bytes.
    let pad = INNER.saturating_sub(plain.chars().count());
    format!(
        "{MARGIN}{}{painted}{}{}",
        p.dim(&glyph::V.to_string(), pal::STEEL),
        " ".repeat(pad),
        p.dim(&glyph::V.to_string(), pal::STEEL)
    )
}

/// Truncate to `max` display columns, marking elision with `…`.
#[must_use]
pub fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The report header: wordmark, target, and a gradient rule.
#[must_use]
pub fn header(target: &str, mode: &str, p: Palette) -> Vec<String> {
    let word = p.gradient("grip", pal::CYAN, pal::MAGENTA);
    let head = format!(
        "{MARGIN}{}  {}  {}  {}",
        p.bold(&word, pal::CHROME),
        p.dim(glyph::DOT, pal::STEEL),
        p.dim(mode, pal::MIST),
        p.bold(target, pal::CHROME)
    );
    let rule = format!(
        "{MARGIN}{}",
        p.gradient(
            &glyph::H.to_string().repeat(INNER + 2),
            pal::CYAN,
            pal::VOID
        )
    );
    vec![head, rule]
}

/// The report footer: the grip mark, elapsed time, and a closing note.
#[must_use]
pub fn footer(elapsed_ms: u128, note: &str, p: Palette) -> Vec<String> {
    let rule = format!(
        "{MARGIN}{}",
        p.gradient(
            &glyph::H.to_string().repeat(INNER + 2),
            pal::VOID,
            pal::MAGENTA
        )
    );
    let sig = p.bold(crate::ui::mascot::MARK, pal::LIME);
    let timing = if elapsed_ms > 0 {
        format!("{elapsed_ms} ms  {}  ", glyph::DOT)
    } else {
        String::new()
    };
    let line = format!(
        "{MARGIN}{sig}  {}{}",
        p.dim(&timing, pal::MIST),
        p.dim(note, pal::STEEL)
    );
    vec![rule, line]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn width_of(line: &str) -> usize {
        line.chars().count()
    }

    #[test]
    fn plain_panel_borders_align() {
        let panel = Panel::new("negotiated")
            .row(Row::kv("tls version", "TLS 1.3"))
            .row(Row::kv_tone("cipher", "TLS_AES_128_GCM_SHA256", Tone::Key).note("0x1301"))
            .row(Row::Rule)
            .row(Row::Note("supporting detail".to_string()));
        let lines = panel.render(Palette::plain());
        let expected = width_of(&lines[0]);
        for l in &lines {
            assert_eq!(width_of(l), expected, "line misaligned: {l:?}");
            assert!(!l.contains('\x1b'));
        }
    }

    #[test]
    fn colored_panel_has_same_visible_width_as_plain() {
        let build = || {
            Panel::new("certificate")
                .row(Row::kv("subject", "CN=example.com"))
                .row(Row::kv_tone("expires", "2026-11-15", Tone::Good).note("77 days"))
        };
        let plain = build().render(Palette::plain());
        let rich = build().render(Palette::rich());
        assert_eq!(plain.len(), rich.len());
        for (a, b) in plain.iter().zip(rich.iter()) {
            assert_eq!(width_of(a), width_of(&strip(b)), "visible width drift");
        }
    }

    #[test]
    fn empty_panel_renders_nothing() {
        assert!(Panel::new("x").render(Palette::plain()).is_empty());
    }

    #[test]
    fn row_opt_skips_none() {
        let p = Panel::new("x")
            .row_opt("a", Some("1"), Tone::Plain)
            .row_opt("b", None::<String>, Tone::Plain);
        // 1 row + 2 borders
        assert_eq!(p.render(Palette::plain()).len(), 3);
    }

    #[test]
    fn long_values_are_truncated_not_wrapped() {
        let long = "x".repeat(400);
        let lines = Panel::new("t")
            .row(Row::kv("k", long))
            .render(Palette::plain());
        assert_eq!(lines.len(), 3);
        assert_eq!(width_of(&lines[1]), width_of(&lines[0]));
        assert!(lines[1].contains('…'));
    }

    #[test]
    fn truncate_is_char_safe() {
        // Multi-byte input must not be split mid code point.
        let s = "ünïcødé-subject-name";
        let t = truncate(s, 6);
        assert_eq!(t.chars().count(), 6);
        assert!(t.ends_with('…'));
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn header_and_footer_shapes() {
        let h = header("example.com:443", "live", Palette::plain());
        assert_eq!(h.len(), 2);
        assert!(h[0].contains("grip"));
        assert!(h[0].contains("example.com:443"));
        let f = footer(42, "1 cert", Palette::plain());
        assert_eq!(f.len(), 2);
        assert!(f[1].contains("42 ms"));
    }

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut esc = false;
        for c in s.chars() {
            if esc {
                if c == 'm' {
                    esc = false;
                }
            } else if c == '\x1b' {
                esc = true;
            } else {
                out.push(c);
            }
        }
        out
    }
}
