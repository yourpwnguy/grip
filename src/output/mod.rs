//! Presentation layer — DTOs + renderers.
//!
//! The only place that knows about `anstream`, `serde_json`, or terminal
//! layout. Core never imports this.

pub mod hex;
pub mod human;
pub mod json;
pub mod model;
pub mod writer;

pub use human::{render_live, render_pcap};
pub use model::{CertSummary, ClientEntry, Fingerprints, LiveReport, NegotiatedInfo, PcapReport};
