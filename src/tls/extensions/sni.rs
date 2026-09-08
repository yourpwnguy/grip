//! SNI (`0x0000`) parsing.

use crate::error::ParseKind;

/// Parse SNI `data` → hostname.
///
/// `data` is the extension payload: `list_len(2) || type(1)=0 || len(2) || name`.
pub fn parse(data: &[u8]) -> Result<String, ParseKind> {
    if data.len() < 2 {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0000,
            detail: "SNI too short for list length".to_string(),
        });
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0000,
            detail: format!("SNI list_len {list_len} exceeds data {}", data.len() - 2),
        });
    }
    if list_len < 3 {
        return Ok(String::new());
    }
    if data[2] != 0 {
        return Ok(String::new());
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0000,
            detail: "SNI name_len exceeds data".to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&data[5..5 + name_len]).to_string())
}
