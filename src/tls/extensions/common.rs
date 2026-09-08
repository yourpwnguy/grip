//! Small helpers shared by extension parsers.

use crate::error::ParseKind;

/// Parse a `u16` list: `len(2) || u16*`.
pub fn parse_u16_list(data: &[u8]) -> Result<Vec<u16>, ParseKind> {
    if data.len() < 2 {
        return Err(ParseKind::BadExtension {
            ext_type: 0xffff,
            detail: "u16 list too short".to_string(),
        });
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if len + 2 > data.len() {
        return Err(ParseKind::BadExtension {
            ext_type: 0xffff,
            detail: format!("u16 list len {len} exceeds data {}", data.len() - 2),
        });
    }
    if !len.is_multiple_of(2) {
        return Err(ParseKind::BadExtension {
            ext_type: 0xffff,
            detail: format!("u16 list len {len} not divisible by 2"),
        });
    }
    Ok(data[2..2 + len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect())
}

/// Parse a `u8` list: `len(1) || u8*` (EC point formats).
pub fn parse_u8_list(data: &[u8]) -> Result<Vec<u8>, ParseKind> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let len = data[0] as usize;
    if len + 1 > data.len() {
        return Err(ParseKind::BadExtension {
            ext_type: 0x000b,
            detail: format!("u8 list len {len} exceeds data {}", data.len() - 1),
        });
    }
    Ok(data[1..=len].to_vec())
}
