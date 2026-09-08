//! `grip` — TLS handshake inspector + fingerprinter.
//!
//! `grip` reads raw TLS bytes off a TCP socket (or pcap file) and parses
//! them without a TLS library, producing JA3/JA4/JA4S fingerprints and
//! certificate summaries.
//!
//! ## Two modes
//! - **Live** `grip example.com`: build a `ClientHello`, send it, parse
//!   `ServerHello` + Certificate, compute fingerprints.
//! - **Pcap** `grip --pcap capture.pcap`: reassemble TCP streams, extract
//!   every `ClientHello`, group by source IP + fingerprint.
//!
//! ## Architecture
//! Core crates (`tls`, `fp`) are pure functions over `&[u8]` with no I/O.
//! `pcap` and `net` handle I/O, `output` handles rendering, `cli` glues
//! everything. Dependency direction is strictly one-way, enforced by
//! `pub(crate)` visibility.
//!
//! ## Why raw bytes?
//! Calling `rustls::connect` and asking for the certificate hides the
//! handshake details we need for fingerprinting. `grip` crafts bytes by hand
//! so every length prefix is visible and every GREASE value is accounted for.
//!
//! # Examples
//! ```no_run
//! use grip::tls::ClientHelloBuilder;
//! use grip::fp::compute_ja4;
//! use grip::tls::ClientHello;
//!
//! let bytes = ClientHelloBuilder::new().with_sni(Some("example.com".to_string())).build();
//! let ch = ClientHello::parse(&bytes).unwrap();
//! let ja4 = compute_ja4(&ch);
//! println!("{ja4}");
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
#![allow(
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::similar_names
)]

pub mod cli;
pub mod db;
pub mod error;
pub mod fp;
pub mod net;
pub mod output;
pub mod pcap;
pub mod tls;
#[allow(missing_docs)]
pub mod ui;
pub mod util;

pub use error::{GripError, GripResult};
