//! Key Share (`0x0033`) parsing.
//!
//! `ClientHello`: `list_len(2) || entries*` where each entry is
//! `group(2) || key_len(2) || key`.
//! `ServerHello`: single `group(2) || key_len(2) || key` without outer length.
//! We handle both.

use super::KeyShareEntry;
use crate::error::ParseKind;

/// Parse `data` → key shares.
pub fn parse(data: &[u8]) -> Result<Vec<KeyShareEntry>, ParseKind> {
    if data.len() < 2 {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0033,
            detail: "key_share too short".to_string(),
        });
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    // ClientHello: list_len + 2 == data.len()
    if list_len + 2 == data.len() {
        return parse_list(data, 2, 2 + list_len);
    }
    if list_len + 2 > data.len() {
        // Not a valid list — try single entry
    } else if list_len + 2 < data.len() {
        // Could be list with trailing? Try list parse
        if let Ok(v) = parse_list(data, 2, 2 + list_len) {
            // Ensure it consumed exactly
            if v.iter().map(|e| 4 + e.key_exchange.len()).sum::<usize>() + 2 == data.len() {
                return Ok(v);
            }
        }
    }
    // ServerHello single entry
    if data.len() >= 4 {
        let group = u16::from_be_bytes([data[0], data[1]]);
        let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if 4 + key_len == data.len() {
            return Ok(vec![KeyShareEntry {
                group,
                key_exchange: data[4..].to_vec(),
            }]);
        }
    }
    Err(ParseKind::BadExtension {
        ext_type: 0x0033,
        detail: format!("key_share malformed len {}", data.len()),
    })
}

fn parse_list(data: &[u8], mut pos: usize, end: usize) -> Result<Vec<KeyShareEntry>, ParseKind> {
    let mut out = Vec::new();
    while pos + 4 <= end {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let key_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + key_len > end {
            return Err(ParseKind::BadExtension {
                ext_type: 0x0033,
                detail: "key_share key_len exceeds data".to_string(),
            });
        }
        out.push(KeyShareEntry {
            group,
            key_exchange: data[pos..pos + key_len].to_vec(),
        });
        pos += key_len;
    }
    Ok(out)
}
