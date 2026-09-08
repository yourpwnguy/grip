//! ALPN (`0x0010`) parsing.

use crate::error::ParseKind;

/// Parse ALPN `data` → protocol list.
pub fn parse(data: &[u8]) -> Result<Vec<String>, ParseKind> {
    if data.len() < 2 {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0010,
            detail: "ALPN too short".to_string(),
        });
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return Err(ParseKind::BadExtension {
            ext_type: 0x0010,
            detail: format!("ALPN list len {list_len} exceeds data"),
        });
    }
    let mut out = Vec::new();
    let mut pos = 2;
    let end = 2 + list_len;
    while pos < end {
        let str_len = data[pos] as usize;
        pos += 1;
        if pos + str_len > end {
            return Err(ParseKind::BadExtension {
                ext_type: 0x0010,
                detail: "ALPN string length exceeds list".to_string(),
            });
        }
        out.push(String::from_utf8_lossy(&data[pos..pos + str_len]).to_string());
        pos += str_len;
    }
    Ok(out)
}
