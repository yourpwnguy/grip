//! The mascot: **Nib**, a single grip mark.
//!
//! `grip` closes on a handshake and holds it. Rather than a multi-line claw
//! (which read as "trying too hard"), the mascot is one glyph that pulses
//! through a grab: a point that swells into a ring, fills solid, then eases
//! open again. It carries the tool's identity in one cell, animates cheaply,
//! and never disturbs column alignment.
//!
//! The resting form [`MARK`] is the locked grip — a filled diamond — used in
//! the banner and the closing summary.

use crate::ui::theme::{Rgb, pal};

/// Resting grip mark: a locked diamond.
pub const MARK: &str = "◆";

/// One grab cycle: dot → ring → filling → solid → ring → dot.
///
/// Read left to right it is the claw tightening; the loop makes it breathe
/// while a step is in flight. Every frame is a single column so the status
/// line never shifts.
pub const FRAMES: [&str; 6] = ["·", "◦", "◍", "◆", "◍", "◦"];

/// The active-frame glyph for animation tick `n`.
#[must_use]
pub const fn frame(n: usize) -> &'static str {
    FRAMES[n % FRAMES.len()]
}

/// Accent for animation tick `n`, warming as the grip tightens.
///
/// The color tracks the fill: cool cyan at the open dot, hot amber at the
/// solid core, so the pulse reads as pressure building rather than a plain
/// blink.
#[must_use]
pub fn accent(n: usize) -> Rgb {
    // Triangle over the 6-frame cycle: 0..=3 tighten, 3..=5 release.
    let i = n % FRAMES.len();
    let t = if i <= 3 {
        i as f32 / 3.0
    } else {
        (6 - i) as f32 / 3.0
    };
    pal::CYAN.lerp(pal::AMBER, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_single_column() {
        for f in FRAMES {
            assert_eq!(f.chars().count(), 1, "{f:?} must be one column");
        }
        assert_eq!(MARK.chars().count(), 1);
    }

    #[test]
    fn frame_and_accent_wrap() {
        assert_eq!(frame(0), frame(FRAMES.len()));
        assert_eq!(accent(0), accent(FRAMES.len()));
    }

    #[test]
    fn accent_peaks_at_solid_core() {
        // The solid frame (index 3) should be the warmest point.
        assert_eq!(accent(3), pal::AMBER);
        assert_eq!(accent(0), pal::CYAN);
    }
}
