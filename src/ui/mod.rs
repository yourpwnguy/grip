//! Presentation layer — the design system and the report layout.
//!
//! Nothing in `tls`, `fp`, `net`, or `pcap` may depend on this module: the
//! dependency edge points one way, from the interface into the domain. `cli`
//! drives the pipelines while work is in flight, and `output` composes
//! [`panel::Panel`]s for the final report.
//!
//! ## Layout
//! - [`theme`] — truecolor palette, gradients, glyph set. No emoji.
//! - [`mascot`] — *Nib*, the single-glyph grip mark.
//! - [`panel`] — section headers, aligned rows, and wrapping for the report.

pub mod mascot;
pub mod panel;
pub mod theme;

pub use panel::{Panel, Row, Tone};
pub use theme::Palette;
