//! Fingerprint computation — pure functions over parsed `ClientHello`/`ServerHello`.

pub mod ja3;
pub mod ja4;
pub mod ja4s;
pub mod lookup;

pub use ja3::compute_ja3;
pub use ja4::{Ja4, compute_ja4};
pub use ja4s::{Ja4s, compute_ja4s};
pub use lookup::{lookup_ja3, lookup_ja4};
