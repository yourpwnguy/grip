//! Supported Versions (`0x002b`) parsing.
//!
//! `ClientHello`: `len(1) || versions*` (1-byte length prefix).
//! `ServerHello`: `version(2)` (single) or the same as `ClientHello`.
//! We handle both via heuristics and a small fallback.

use crate::error::ParseKind;

/// Parse `data` → version list.
pub fn parse(data: &[u8]) -> Result<Vec<u16>, ParseKind> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    // ClientHello style: 1-byte len prefix
    if !data.is_empty() {
        let list_len = data[0] as usize;
        if list_len + 1 == data.len() && list_len.is_multiple_of(2) {
            return Ok(data[1..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect());
        }
    }
    // ServerHello single version
    if data.len() == 2 {
        return Ok(vec![u16::from_be_bytes([data[0], data[1]])]);
    }
    // Fallback: raw u16 list without header (robustness, ≤20 B)
    if data.len().is_multiple_of(2) && data.len() <= 20 {
        return Ok(data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect());
    }
    Err(ParseKind::BadExtension {
        ext_type: 0x002b,
        detail: format!("supported_versions malformed len {}", data.len()),
    })
}
