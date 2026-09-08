//! Embedded fingerprint DB.
//!
//! The actual `phf::Map`s are generated at build time into `$OUT_DIR/known_db.rs`.
//! This module just includes them.

pub mod known;
