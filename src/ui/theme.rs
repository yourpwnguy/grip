//! Design system — truecolor palette, gradients, glyphs, box drawing.
//!
//! `grip` = a mechanical claw closing on a handshake. The palette is built
//! from that idea: cold hydraulic steel (slate/cyan) for structure, hot
//! amber/magenta for the moment of the grab, green for a clean catch.
//!
//! # Why hand-rolled ANSI instead of a styling crate
//! We need per-character gradients (each glyph a different color) for the
//! animated rules and the mascot. Style crates model "a style per span",
//! which forces one `format!` per character anyway. Emitting SGR sequences
//! directly is fewer allocations and gives exact control.
//!
//! Every function is a no-op when `Palette::plain()` is used, so piped
//! output and snapshot tests stay byte-stable.

use std::fmt::Write;

/// An RGB color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Linear interpolation towards `other` by `t` in `0.0..=1.0`.
    ///
    /// Used to build gradients across a run of characters. We interpolate in
    /// plain sRGB space: perceptually imperfect, but stable, branch-free, and
    /// indistinguishable at the small deltas we use.
    #[must_use]
    pub fn lerp(self, other: Self, t: f32) -> Self {
        let t = t.clamp(0.0, 1.0);
        let f = |a: u8, b: u8| -> u8 {
            let a = f32::from(a);
            let b = f32::from(b);
            (b - a).mul_add(t, a).round().clamp(0.0, 255.0) as u8
        };
        Self(f(self.0, other.0), f(self.1, other.1), f(self.2, other.2))
    }
}

/// The `grip` palette — hydraulic steel with a hot grab.
pub mod pal {
    use super::Rgb;

    /// Deep shadow, panel interior accents.
    pub const VOID: Rgb = Rgb(0x1b, 0x1f, 0x2a);
    /// Panel borders, inactive structure.
    pub const STEEL: Rgb = Rgb(0x3f, 0x4b, 0x63);
    /// Labels, secondary text.
    pub const MIST: Rgb = Rgb(0x8a, 0x9a, 0xb8);
    /// Primary values.
    pub const CHROME: Rgb = Rgb(0xdf, 0xe7, 0xf5);
    /// Cold accent — the claw at rest.
    pub const CYAN: Rgb = Rgb(0x35, 0xd7, 0xd0);
    /// Cool mid accent.
    pub const AZURE: Rgb = Rgb(0x4c, 0x9a, 0xf5);
    /// Hot accent — the moment of the grip.
    pub const AMBER: Rgb = Rgb(0xff, 0xb3, 0x47);
    /// Signature accent — fingerprints.
    pub const MAGENTA: Rgb = Rgb(0xe8, 0x5d, 0xd6);
    /// Clean catch.
    pub const LIME: Rgb = Rgb(0x6d, 0xe8, 0x8f);
    /// Warning.
    pub const RUST: Rgb = Rgb(0xff, 0x6b, 0x5f);
}

/// Whether colors are emitted. Cloneable, cheap, passed by value.
///
/// Holding this in a value (rather than reading env vars at each call site)
/// keeps rendering pure and makes tests trivially deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    color: bool,
}

impl Palette {
    /// Colored output.
    #[must_use]
    pub const fn rich() -> Self {
        Self { color: true }
    }

    /// No escape sequences at all — for pipes, files, and snapshot tests.
    #[must_use]
    pub const fn plain() -> Self {
        Self { color: false }
    }

    /// Detect from the environment: honours `NO_COLOR`, `FORCE_COLOR`, TTY.
    #[must_use]
    pub fn detect(is_tty: bool) -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::plain();
        }
        if std::env::var_os("FORCE_COLOR").is_some() {
            return Self::rich();
        }
        if is_tty { Self::rich() } else { Self::plain() }
    }

    /// True when escape codes are emitted.
    #[must_use]
    pub const fn is_color(self) -> bool {
        self.color
    }

    /// Paint `text` in `fg`.
    #[must_use]
    pub fn paint(self, text: &str, fg: Rgb) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[38;2;{};{};{}m{text}\x1b[0m", fg.0, fg.1, fg.2)
    }

    /// Paint `text` bold in `fg`.
    #[must_use]
    pub fn bold(self, text: &str, fg: Rgb) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1;38;2;{};{};{}m{text}\x1b[0m", fg.0, fg.1, fg.2)
    }

    /// Paint `text` dim in `fg`.
    #[must_use]
    pub fn dim(self, text: &str, fg: Rgb) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[2;38;2;{};{};{}m{text}\x1b[0m", fg.0, fg.1, fg.2)
    }

    /// Paint each character of `text` along a gradient from `from` to `to`.
    ///
    /// This is what makes the rules and the mascot feel alive: one SGR per
    /// glyph. Cost is O(chars) allocations into a single pre-sized `String`,
    /// which is irrelevant at our scale (a few hundred chars per frame) and
    /// is skipped entirely in plain mode.
    #[must_use]
    pub fn gradient(self, text: &str, from: Rgb, to: Rgb) -> String {
        if !self.color {
            return text.to_string();
        }
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return String::new();
        }
        let denom = (chars.len().saturating_sub(1)).max(1) as f32;
        // 20 bytes of SGR per char is a good upper bound; avoids reallocation.
        let mut out = String::with_capacity(chars.len() * 24 + 8);
        for (i, ch) in chars.iter().enumerate() {
            let c = from.lerp(to, i as f32 / denom);
            let _ = write!(out, "\x1b[38;2;{};{};{}m{ch}", c.0, c.1, c.2);
        }
        out.push_str("\x1b[0m");
        out
    }

    /// A gradient whose phase is shifted by `phase` — animates when called
    /// repeatedly with an increasing phase. Produces a travelling shimmer.
    #[must_use]
    pub fn gradient_shift(self, text: &str, from: Rgb, to: Rgb, phase: f32) -> String {
        if !self.color {
            return text.to_string();
        }
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return String::new();
        }
        let n = chars.len() as f32;
        let mut out = String::with_capacity(chars.len() * 24 + 8);
        for (i, ch) in chars.iter().enumerate() {
            // Triangle wave keeps both endpoints saturated instead of clipping.
            let raw = ((i as f32 / n) + phase).fract();
            let t = if raw < 0.5 {
                raw * 2.0
            } else {
                (1.0 - raw) * 2.0
            };
            let c = from.lerp(to, t);
            let _ = write!(out, "\x1b[38;2;{};{};{}m{ch}", c.0, c.1, c.2);
        }
        out.push_str("\x1b[0m");
        out
    }
}

/// Box drawing and marker glyphs. No emoji, no kaomoji — only geometry.
pub mod glyph {
    /// Top-left corner.
    pub const TL: char = '╭';
    /// Top-right corner.
    pub const TR: char = '╮';
    /// Bottom-left corner.
    pub const BL: char = '╰';
    /// Bottom-right corner.
    pub const BR: char = '╯';
    /// Horizontal rule.
    pub const H: char = '─';
    /// Vertical rule.
    pub const V: char = '│';
    /// Left tee.
    pub const TEE_L: char = '├';
    /// Right tee.
    pub const TEE_R: char = '┤';
    /// Step marker: done.
    pub const DONE: &str = "▰";
    /// Step marker: pending.
    pub const PENDING: &str = "▱";
    /// Inline separator.
    pub const DOT: &str = "·";
    /// Key/value leader.
    pub const LEAD: &str = "▏";
    /// Success mark.
    pub const OK: &str = "✔";
    /// Failure mark.
    pub const BAD: &str = "✘";
    /// Warning mark.
    pub const WARN: &str = "▲";
    /// Chain link.
    pub const LINK: &str = "└─";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_emits_no_escapes() {
        let p = Palette::plain();
        assert_eq!(p.paint("x", pal::CYAN), "x");
        assert_eq!(p.gradient("hello", pal::CYAN, pal::AMBER), "hello");
        assert_eq!(p.bold("x", pal::CYAN), "x");
    }

    #[test]
    fn rich_wraps_in_sgr() {
        let p = Palette::rich();
        let s = p.paint("x", Rgb(1, 2, 3));
        assert_eq!(s, "\x1b[38;2;1;2;3mx\x1b[0m");
    }

    #[test]
    fn lerp_endpoints_exact() {
        let a = Rgb(0, 0, 0);
        let b = Rgb(10, 20, 30);
        assert_eq!(a.lerp(b, 0.0), a);
        assert_eq!(a.lerp(b, 1.0), b);
        assert_eq!(a.lerp(b, 0.5), Rgb(5, 10, 15));
    }

    #[test]
    fn gradient_preserves_visible_text() {
        let p = Palette::rich();
        let s = p.gradient("abc", pal::CYAN, pal::AMBER);
        let stripped: String = strip_ansi(&s);
        assert_eq!(stripped, "abc");
    }

    #[test]
    fn gradient_shift_preserves_text() {
        let p = Palette::rich();
        let s = p.gradient_shift("abcdef", pal::CYAN, pal::MAGENTA, 0.3);
        assert_eq!(strip_ansi(&s), "abcdef");
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut in_esc = false;
        for c in s.chars() {
            if in_esc {
                if c == 'm' {
                    in_esc = false;
                }
            } else if c == '\x1b' {
                in_esc = true;
            } else {
                out.push(c);
            }
        }
        out
    }
}
