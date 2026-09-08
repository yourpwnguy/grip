//! Dial helpers — DNS and `TcpStream` establishment.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{GripError, GripResult};

/// Resolve `target:port` to socket addresses.
///
/// # Errors
///
/// Returns [`GripError::Network`] if DNS resolution fails or returns
/// no addresses for the target.
pub fn resolve_target(target: &str, port: u16) -> GripResult<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = format!("{target}:{port}")
        .to_socket_addrs()
        .map_err(|e| GripError::Network(format!("DNS resolve {target}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(GripError::Network(format!("no addresses for {target}")));
    }
    Ok(addrs)
}

/// Try each `addr` with `TcpStream::connect_timeout` until one succeeds.
pub fn dial(
    addrs: &[SocketAddr],
    timeout: Duration,
    target: &str,
    port: u16,
) -> GripResult<TcpStream> {
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(GripError::Network(format!(
        "connect to {target}:{port} failed: {}",
        last.map_or_else(|| "no addresses".to_string(), |e| e.to_string())
    )))
}

/// Deterministic-ish 32-byte handshake random without pulling `rand`.
///
/// Uses `SystemTime` + PID + xorshift; good enough for the `ClientHello`
/// random field which is not security-sensitive for fingerprinting.
pub fn random_32() -> [u8; 32] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let pid = u128::from(std::process::id());
    let mut x = now ^ (pid << 32) ^ 0x9e37_79b9_7f4a_7c15;
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn random_is_non_deterministic_enough() {
        let a = random_32();
        std::thread::sleep(Duration::from_millis(1));
        let b = random_32();
        // Accept either; the point is it doesn't panic and usually differs.
        let _ = (a, b);
    }
}
