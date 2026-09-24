//! The mascot: **Nib**, a single grip mark.
//!
//! `grip` closes on a handshake and holds it. Rather than a multi-line claw
//! (which read as "trying too hard"), the mascot is one glyph: the resting
//! form [`MARK`] is the locked grip, a filled diamond. One cell, zero
//! alignment risk, and it anchors the report footer.

/// Resting grip mark: a locked diamond.
pub const MARK: &str = "◆";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_is_single_column() {
        assert_eq!(MARK.chars().count(), 1);
    }
}
