//! Presentation layer — the design system, the mascot, and the animator.
//!
//! Nothing in `tls`, `fp`, `net`, or `pcap` may depend on this module: the
//! dependency edge points one way, from the interface into the domain. `cli`
//! drives the [`stage::Stage`] while work is in flight, and `output` composes
//! [`panel::Panel`]s for the final report.
//!
//! ## Layout
//! - [`theme`] — truecolor palette, gradients, glyph set. No emoji.
//! - [`mascot`] — *Nib*, the single-glyph grip mark and its pulse.
//! - [`stage`] — in-place animated build checklist on a painter thread.
//! - [`panel`] — aligned boxes for the final report.

pub mod mascot;
pub mod panel;
pub mod stage;
pub mod theme;

pub use panel::{Panel, Row, Tone};
pub use stage::Stage;
pub use theme::Palette;
