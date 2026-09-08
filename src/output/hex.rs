//! Hex dump formatting for `--raw`.
//!
//! Format matches `idea.md` raw mode:
//! ```text
//! 0000  16 03 01 00 f1 01 00 00 ed 03 03 8b 4a 2c 19 f0 ...
//! ```

use std::io::Write;

/// Write a hex dump of `data` to `writer`.
///
/// Each line: `addr  hex_bytes` with 16 bytes per line, lower-case.
///
/// # Errors
///
/// Returns an I/O error if writing to `writer` fails.
pub fn hexdump(data: &[u8], writer: &mut dyn Write) -> std::io::Result<()> {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = i * 16;
        write!(writer, "{addr:04x}  ")?;
        for (j, b) in chunk.iter().enumerate() {
            if j > 0 {
                write!(writer, " ")?;
            }
            write!(writer, "{b:02x}")?;
        }
        writeln!(writer)?;
    }
    Ok(())
}

/// Hex dump to String.
#[must_use]
pub fn hexdump_to_string(data: &[u8]) -> String {
    let mut buf = Vec::new();
    let _ = hexdump(data, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump() {
        let data = (0u8..32).collect::<Vec<_>>();
        let s = hexdump_to_string(&data);
        assert!(s.contains("0000"));
        assert!(s.contains("0010"));
    }
}
