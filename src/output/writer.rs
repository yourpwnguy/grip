//! Output writer abstraction — stdout vs file, color handling.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Return a writer for the output destination.
///
/// If `path` is `Some`, opens the file (creating/truncating). Otherwise
/// returns `stdout` in a `Box<dyn Write>`. The caller is responsible for
/// flushing. Colors are handled separately via `anstream`.
///
/// # Errors
///
/// Returns an I/O error if the file at `path` cannot be created.
pub fn writer_for(path: Option<&Path>) -> io::Result<Box<dyn Write>> {
    if let Some(p) = path {
        let f = File::create(p)?;
        Ok(Box::new(f))
    } else {
        Ok(Box::new(io::stdout()))
    }
}

/// Helper to write to a buffered writer and auto-flush for tests.
#[cfg(test)]
#[must_use]
pub const fn test_writer() -> Vec<u8> {
    Vec::new()
}
