//! JSON rendering — single call to `serde_json`.

use serde::Serialize;

/// Render any `Serialize` as pretty JSON to `writer`.
///
/// # Errors
///
/// Returns [`GripError::Other`] if serialization fails.
/// Returns [`GripError::Io`] if the trailing newline write fails.
pub fn render_json<T: Serialize>(
    value: &T,
    writer: &mut dyn std::io::Write,
) -> crate::error::GripResult<()> {
    serde_json::to_writer_pretty(&mut *writer, value)
        .map_err(|e| crate::error::GripError::Other(e.to_string()))?;
    writeln!(writer).map_err(crate::error::GripError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Foo {
        a: u32,
    }

    #[test]
    fn json_renders() {
        let mut buf = Vec::new();
        render_json(&Foo { a: 42 }, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("42"));
    }
}
