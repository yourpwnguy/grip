//! TCP flow extraction.
//!
//! We parse IPv4 + TCP headers from the link-layer payload. Only IPv4 is
//! supported in v0.1.0; IPv6 packets are skipped with a `None` return.
//! IP fragmentation is not reassembled — we assume unfragmented captures
//! (documented limitation).

use std::net::Ipv4Addr;

/// 5-tuple flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IPv4.
    pub src_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination IPv4.
    pub dst_ip: Ipv4Addr,
    /// Destination port.
    pub dst_port: u16,
}

/// A TCP segment with its sequence number and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    /// Sequence number (host order).
    pub seq: u32,
    /// TCP payload bytes.
    pub payload: Vec<u8>,
}

/// Parse result for a single packet.
#[derive(Debug, Clone)]
pub struct TcpFlowPacket {
    /// Flow key.
    pub key: FlowKey,
    /// Segment.
    pub segment: TcpSegment,
    /// Direction: true if src is client (we track both directions separately).
    #[allow(dead_code)]
    _is_forward: bool,
}

/// Try to extract a `TcpFlowPacket` from a pcap packet's link-layer data.
///
/// `dlt` comes from the pcap global header's `network` (1 = Ethernet).
/// Returns `None` for non-IPv4/TCP or too-short packets.
#[must_use]
pub fn parse_ipv4_tcp(dlt: u32, packet: &[u8]) -> Option<TcpFlowPacket> {
    // Strip link-layer header to get IP packet.
    let ip_start = match dlt {
        1 => 14,   // DLT_EN10MB (Ethernet)
        101 => 0,  // DLT_RAW
        113 => 16, // DLT_LINUX_SLL (cooked)
        104 => 4,  // DLT_RAW alias?
        _ => {
            // Heuristic: if first nibble is 4 (IPv4 version), assume raw.
            if !packet.is_empty() && (packet[0] >> 4) == 4 {
                0
            } else {
                return None;
            }
        }
    };
    if packet.len() < ip_start + 20 {
        return None;
    }
    let ip = &packet[ip_start..];

    // IPv4 header: version(4) + ihl(4) in first byte
    let version_ihl = ip[0];
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if (version_ihl >> 4) != 4 || ihl < 20 || ip.len() < ihl {
        return None;
    }
    // Protocol at offset 9
    if ip[9] != 6 {
        return None; // not TCP
    }
    // Check for fragmented: flags+frag_offset at 6-7, MF or offset !=0 => skip
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if (frag & 0x3fff) != 0 {
        return None; // fragmented, not supported
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let tcp_start = ip_start + ihl;
    if packet.len() < tcp_start + 20 {
        return None;
    }
    let tcp = &packet[tcp_start..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset < 20 || tcp_start + data_offset > packet.len() {
        return None;
    }
    let payload = packet[tcp_start + data_offset..].to_vec();

    let key = FlowKey {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    };
    Some(TcpFlowPacket {
        key,
        segment: TcpSegment { seq, payload },
        _is_forward: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_eth_ipv4_tcp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet 14 bytes
        pkt.extend_from_slice(&[0xff; 6]); // dst mac
        pkt.extend_from_slice(&[0xaa; 6]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        // IPv4 header 20 bytes
        let total_len = 20 + 20 + payload.len();
        pkt.push(0x45); // version 4 ihl 5
        pkt.push(0x00); // dscp
        pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // id
        pkt.extend_from_slice(&[0x40, 0x00]); // flags/frag
        pkt.push(64); // ttl
        pkt.push(6); // protocol TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (ignored)
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        // TCP header 20 bytes
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        pkt.push(0x50); // data offset 5 + flags
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&[0x04, 0x00]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_eth() {
        let pkt = build_eth_ipv4_tcp(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            1000,
            b"hello",
        );
        let flow = parse_ipv4_tcp(1, &pkt).unwrap();
        assert_eq!(flow.key.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(flow.segment.payload, b"hello");
        assert_eq!(flow.segment.seq, 1000);
    }

    #[test]
    fn non_tcp_returns_none() {
        let mut pkt = build_eth_ipv4_tcp(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            1,
            2,
            0,
            b"",
        );
        // Corrupt protocol byte (offset 14+9=23)
        pkt[23] = 17; // UDP
        assert!(parse_ipv4_tcp(1, &pkt).is_none());
    }
}
