//! Report layout — section headers, key/value rows, and word wrapping.
//!
//! `grip` reports have no boxes. A section is a titled gradient rule and its
//! rows hang beneath a fixed key column; structure comes from indentation and
//! color instead of borders, which keeps the report dense enough to read
//! without scrolling.
//!
//! # No truncation
//! Values are never cut. Long values — issuer DNs, SHA-256 fingerprints —
//! wrap onto continuation lines aligned with the value column, so every byte
//! of data the handshake produced reaches the terminal. Only the pcap table
//! truncates, and only because a table's columns must stay aligned.
//!
//! # Alignment
//! Padding is computed on **plain text**, then color is applied, because ANSI
//! escapes have zero display width but non-zero byte length; padding a
//! colored string by bytes shears the layout. Values wrap by `char`, not by
//! byte, so multi-byte subjects in certificates cannot split a code point.
//!
//! We deliberately assume single-width glyphs. The design uses only
//! box-drawing and geometric characters (no emoji, which are double-width and
//! render inconsistently), so a `char` count is an exact display width here.

use std::fmt::Write;

use crate::ui::theme::{Palette, Rgb, glyph, pal};

/// Narrowest render width, after clamping.
pub const MIN_WIDTH: usize = 64;
/// Widest render width, after clamping.
pub const MAX_WIDTH: usize = 160;
/// Width used when the terminal size is unknown (pipes, files, tests).
pub const DEFAULT_WIDTH: usize = 100;

/// Width of the key column.
const KEY_W: usize = 16;
/// Left margin for the whole report.
const MARGIN: &str = "  ";
/// Row indent: section titles sit at the margin, rows hang one step deeper.
const KEY_COL: usize = 4;
/// Column where values start.
const VALUE_COL: usize = KEY_COL + KEY_W + 1;

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

/// A row inside a section.
#[derive(Debug, Clone)]
pub enum Row {
    /// `key   value` with an optional trailing annotation.
    Kv {
        /// Left column label.
        key: String,
        /// Right column value.
        value: String,
        /// Emphasis for `value`.
        tone: Tone,
        /// Dim text appended after the value (units, hints, matches).
        note: Option<String>,
    },
    /// A full-width line of muted text, indented under the value column.
    Note(String),
}

impl Row {
    /// Key/value row.
    #[must_use]
    pub fn kv(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Kv {
            key: key.into(),
            value: value.into(),
            tone: Tone::Plain,
            note: None,
        }
    }

    /// Key/value row with emphasis.
    #[must_use]
    pub fn kv_tone(key: impl Into<String>, value: impl Into<String>, tone: Tone) -> Self {
        Self::Kv {
            key: key.into(),
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

    /// Render this row into `out`, wrapping long values instead of cutting
    /// them. All padding is computed on plain text before color is applied.
    fn push(&self, out: &mut Vec<String>, p: Palette, width: usize) {
        match self {
            Self::Kv {
                key,
                value,
                tone,
                note,
            } => {
                let avail = width.saturating_sub(VALUE_COL);
                let key_pad = " ".repeat(KEY_W.saturating_sub(key.chars().count()));
                let chunks = wrap(value, avail);

                // Padding comes from the plain pieces (key pad, chunk length);
                // color wraps them after the fact because ANSI has no width.
                for (i, chunk) in chunks.iter().enumerate() {
                    let line = if i == 0 {
                        format!(
                            "{MARGIN}{MARGIN}{}{key_pad} {}",
                            p.dim(key, pal::MIST),
                            p.paint(chunk, tone.rgb())
                        )
                    } else {
                        format!("{}{}", " ".repeat(VALUE_COL), p.paint(chunk, tone.rgb()))
                    };
                    out.push(line);
                }

                // The note rides on the last value line when there is room,
                // otherwise it gets a continuation line of its own.
                if let Some(n) = note {
                    let nl = n.chars().count();
                    let fits = chunks
                        .last()
                        .is_some_and(|c| c.chars().count() + 2 + nl <= avail);
                    if fits {
                        if let Some(last) = out.last_mut() {
                            let _ = write!(last, "  {}", p.dim(n, pal::STEEL));
                        }
                    } else {
                        out.push(format!("{}{}", " ".repeat(VALUE_COL), p.dim(n, pal::STEEL)));
                    }
                }
            }
            Self::Note(text) => {
                for chunk in wrap(text, width.saturating_sub(VALUE_COL)) {
                    out.push(format!(
                        "{}{}",
                        " ".repeat(VALUE_COL),
                        p.dim(&chunk, pal::MIST)
                    ));
                }
            }
        }
    }
}

/// A titled section.
#[derive(Debug, Clone)]
pub struct Panel {
    title: &'static str,
    accent: Rgb,
    rows: Vec<Row>,
}

impl Panel {
    /// New section with a cyan accent.
    #[must_use]
    pub const fn new(title: &'static str) -> Self {
        Self {
            title,
            accent: pal::CYAN,
            rows: Vec::new(),
        }
    }

    /// Override the accent used for the title and rule gradient.
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
    pub fn row_opt(
        self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
        tone: Tone,
    ) -> Self {
        match value {
            Some(v) => self.row(Row::kv_tone(key, v, tone)),
            None => self,
        }
    }

    /// Render to lines: one `title ──────` header followed by the rows.
    ///
    /// Empty sections render nothing at all, which keeps the report free of
    /// hollow headings when a section has no data.
    #[must_use]
    pub fn render(&self, p: Palette, width: usize) -> Vec<String> {
        if self.rows.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.rows.len() + 1);
        out.push(self.header(p, width));
        for row in &self.rows {
            row.push(&mut out, p, width);
        }
        out
    }

    /// `  title ──────` with a gradient rule fading from the accent to void.
    fn header(&self, p: Palette, width: usize) -> String {
        let rule_len = width.saturating_sub(MARGIN.len() + self.title.chars().count() + 1);
        let head = p.bold(self.title, self.accent);
        if rule_len == 0 {
            return format!("{MARGIN}{head}");
        }
        let rule = p.gradient(
            &glyph::H.to_string().repeat(rule_len),
            self.accent,
            pal::VOID,
        );
        format!("{MARGIN}{head} {rule}")
    }
}

/// Split `s` into lines of at most `max` display columns.
///
/// Wraps on whitespace where possible and hard-splits words longer than a
/// whole line (fingerprints and cipher names contain no spaces). Every
/// character survives except runs of whitespace collapse at wrap points.
#[must_use]
pub fn wrap(s: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return vec![s.to_string()];
    }
    if s.chars().count() <= max {
        return vec![s.to_string()];
    }

    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_len = 0usize;

    for word in s.split_whitespace() {
        let mut rest = word;

        if cur_len > 0 {
            let wl = rest.chars().count();
            if cur_len + 1 + wl <= max {
                cur.push(' ');
                cur.push_str(rest);
                cur_len += 1 + wl;
                continue;
            }
            if wl > max {
                // A word longer than a whole line fills the current line
                // with its head, then hard-splits below.
                let room = max.saturating_sub(cur_len + 1);
                if room > 0 {
                    let (head, tail) = split_at_char(rest, room);
                    cur.push(' ');
                    cur.push_str(head);
                    rest = tail;
                }
            }
            out.push(std::mem::take(&mut cur));
        }

        // `cur` is empty; `rest` may still be longer than one line.
        if rest.chars().count() <= max {
            cur.push_str(rest);
            cur_len = rest.chars().count();
            continue;
        }
        let mut chars = rest.chars();
        loop {
            let chunk: String = chars.by_ref().take(max).collect();
            if chars.as_str().is_empty() {
                cur_len = chunk.chars().count();
                cur = chunk;
                break;
            }
            out.push(chunk);
        }
    }

    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Split at char index `at` (or at the end if shorter).
fn split_at_char(s: &str, at: usize) -> (&str, &str) {
    match s.char_indices().nth(at) {
        Some((i, _)) => s.split_at(i),
        None => (s, ""),
    }
}

/// Truncate to `max` display columns, marking elision with `…`.
///
/// Only the pcap table uses this: its columns must stay aligned, and table
/// cells are already short. Everything else wraps via [`wrap`].
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

/// The report header: wordmark, mode, target, and a gradient rule.
#[must_use]
pub fn header(target: &str, mode: &str, p: Palette, width: usize) -> Vec<String> {
    let head_plain = format!("grip  {}  {mode}  {}  {target}", glyph::DOT, glyph::DOT);
    let mut line = format!(
        "{MARGIN}{}  {}  {}  {}",
        p.gradient("grip", pal::CYAN, pal::MAGENTA),
        p.dim(glyph::DOT, pal::STEEL),
        p.dim(mode, pal::MIST),
        p.bold(target, pal::CHROME)
    );
    let rule_len = width.saturating_sub(MARGIN.len() + head_plain.chars().count() + 1);
    if rule_len > 0 {
        let _ = write!(
            line,
            " {}",
            p.gradient(&glyph::H.to_string().repeat(rule_len), pal::CYAN, pal::VOID)
        );
    }
    vec![line]
}

/// The report footer: the grip mark, elapsed time, and a closing note.
///
/// Renders nothing when there is nothing to say — a footer with neither
/// timing nor a note is just noise at the bottom of the screen.
#[must_use]
pub fn footer(elapsed_ms: u128, note: &str, p: Palette) -> Vec<String> {
    if elapsed_ms == 0 && note.is_empty() {
        return Vec::new();
    }
    let mut line = format!("{MARGIN}{}", p.bold(crate::ui::mascot::MARK, pal::LIME));
    if elapsed_ms > 0 {
        let _ = write!(line, "  {}", p.dim(&format!("{elapsed_ms} ms"), pal::MIST));
    }
    if !note.is_empty() {
        if elapsed_ms > 0 {
            let _ = write!(line, "  {}", p.dim(glyph::DOT, pal::STEEL));
        }
        let _ = write!(line, "  {}", p.dim(note, pal::STEEL));
    }
    vec![line]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn width_of(line: &str) -> usize {
        line.chars().count()
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

    fn sample(width: usize) -> Vec<String> {
        Panel::new("negotiated")
            .row(Row::kv("tls version", "TLS 1.3"))
            .row(Row::kv_tone("cipher", "TLS_AES_128_GCM_SHA256", Tone::Key).note("0x1301"))
            .row(Row::Note(
                "a supporting note that is long enough to wrap over lines".to_string(),
            ))
            .render(Palette::plain(), width)
    }

    #[test]
    fn section_header_precedes_rows_and_stays_in_width() {
        let width = 60;
        let lines = sample(width);
        assert!(lines[0].trim_start().starts_with("negotiated"));
        assert!(lines[0].contains('─'), "header carries a rule");
        for l in &lines {
            assert!(width_of(l) <= width, "line exceeds width: {l:?}");
            assert!(!l.contains('\x1b'));
        }
    }

    #[test]
    fn colored_has_same_visible_width_as_plain() {
        let build = || {
            Panel::new("certificate")
                .row(Row::kv("subject", "CN=example.com"))
                .row(Row::kv_tone("expires", "2026-11-15", Tone::Good).note("77 days"))
        };
        let plain = build().render(Palette::plain(), 80);
        let rich = build().render(Palette::rich(), 80);
        assert_eq!(plain.len(), rich.len());
        for (a, b) in plain.iter().zip(rich.iter()) {
            assert_eq!(width_of(a), width_of(&strip(b)), "visible width drift");
        }
    }

    #[test]
    fn empty_panel_renders_nothing() {
        assert!(Panel::new("x").render(Palette::plain(), 80).is_empty());
    }

    #[test]
    fn row_opt_skips_none() {
        let p = Panel::new("x")
            .row_opt("a", Some("1"), Tone::Plain)
            .row_opt("b", None::<String>, Tone::Plain);
        // header + 1 row
        assert_eq!(p.render(Palette::plain(), 80).len(), 2);
    }

    #[test]
    fn long_values_wrap_not_truncate() {
        let long = "x".repeat(400);
        let lines = Panel::new("t")
            .row(Row::kv("k", long))
            .render(Palette::plain(), 60);
        assert!(lines.len() > 3, "value must spill to continuation lines");
        assert!(!lines.iter().any(|l| l.contains('…')), "no truncation");
        let body: String = lines.iter().skip(1).cloned().collect();
        assert_eq!(body.matches('x').count(), 400, "every char survives");
        for l in &lines {
            assert!(width_of(l) <= 60, "line exceeds width: {l:?}");
        }
    }

    #[test]
    fn notes_attach_or_wrap_without_loss() {
        let lines = Panel::new("t")
            .row(Row::kv_tone("sni", "example.com", Tone::Plain).note("hostname"))
            .render(Palette::plain(), 80);
        assert!(lines[1].ends_with("hostname"));

        let long_note = "n".repeat(200);
        let lines = Panel::new("t")
            .row(Row::kv("k", "v").note(long_note))
            .render(Palette::plain(), 50);
        let joined: String = lines.iter().skip(1).cloned().collect();
        assert_eq!(joined.matches('n').count(), 200, "note survives");
    }

    #[test]
    fn wrap_respects_max_and_preserves_words() {
        fn words(t: &str) -> Vec<&str> {
            t.split_whitespace().collect()
        }
        let s = "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC Intermediate CA - G3";
        let lines = wrap(s, 40);
        for l in &lines {
            assert!(l.chars().count() <= 40, "line too long: {l:?}");
        }
        let joined = lines.join(" ");
        assert_eq!(words(&joined), words(s));
    }

    #[test]
    fn wrap_hard_splits_words_longer_than_a_line() {
        let hex = "ab".repeat(64);
        let lines = wrap(&hex, 30);
        assert!(lines.iter().all(|l| l.chars().count() <= 30));
        assert_eq!(lines.concat(), hex);
        assert_eq!(wrap("short", 30), vec!["short".to_string()]);
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
    fn header_is_a_single_line() {
        let h = header("example.com:443", "live handshake", Palette::plain(), 80);
        assert_eq!(h.len(), 1);
        assert!(h[0].contains("grip"));
        assert!(h[0].contains("example.com:443"));
        assert!(width_of(&h[0]) <= 80);
    }

    #[test]
    fn footer_is_absent_when_empty_and_shows_data_when_not() {
        assert!(footer(0, "", Palette::plain()).is_empty());
        let f = footer(42, "3 unique fingerprints", Palette::plain());
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("42 ms"));
        assert!(f[0].contains("3 unique fingerprints"));
    }
}
