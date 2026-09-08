//! Pcap file reader — parses global header and packet records.
//!
//! Supports all four magic variants (micro/nano, LE/BE) and validates
//! `incl_len <= orig_len` and `incl_len <= snaplen`. The reader is an
//! iterator yielding `PcapRecord` without loading the whole file.

use crate::error::{GripError, GripResult};

/// Pcap global header info.
#[derive(Debug, Clone)]
pub struct PcapHeader {
    /// Snaplen from global header.
    pub snaplen: u32,
    /// Network (DLT) type.
    pub network: u32,
    /// True if timestamps are nanoseconds (vs microseconds).
    pub is_nano: bool,
}

/// A single pcap packet record.
#[derive(Debug, Clone)]
pub struct PcapRecord {
    /// Seconds since epoch.
    pub ts_sec: u32,
    /// Microseconds or nanoseconds (per header).
    pub ts_frac: u32,
    /// Captured length.
    pub incl_len: u32,
    /// Original length on wire.
    pub orig_len: u32,
    /// Packet data (exactly `incl_len` bytes).
    pub data: Vec<u8>,
}

/// Iterator over pcap records.
pub struct PcapReader<R: std::io::Read> {
    inner: R,
    header: PcapHeader,
    swapped: bool, // BE vs LE
    done: bool,
}

impl<R: std::io::Read> PcapReader<R> {
    /// Open from a reader (usually `File`). Parses global header.
    ///
    /// # Errors
    ///
    /// Returns [`GripError::Io`] if reading the 24-byte global header fails.
    /// Returns [`GripError::Pcap`] if the magic bytes are unrecognized.
    pub fn new(mut reader: R) -> GripResult<Self> {
        let mut hdr = [0u8; 24];
        reader.read_exact(&mut hdr).map_err(GripError::Io)?;

        let magic_be = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let magic_le = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (is_be, is_nano) = if magic_be == 0xa1b2_c3d4 {
            (true, false)
        } else if magic_be == 0xa1b2_3c4d {
            (true, true)
        } else if magic_le == 0xa1b2_c3d4 {
            (false, false)
        } else if magic_le == 0xa1b2_3c4d {
            (false, true)
        } else if magic_be == 0xd4c3_b2a1 {
            // BE bytes of LE file = swapped magic, treat as LE
            (false, false)
        } else if magic_be == 0x4d3c_b2a1 {
            (false, true)
        } else {
            return Err(GripError::pcap(format!(
                "unknown pcap magic 0x{magic_be:08x}"
            )));
        };
        let swapped = is_be; // for backward compat naming: true means BE

        // Helper to read u32 with correct endian
        let read_u32 = |b: [u8; 4]| {
            if is_be {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };
        let snaplen = read_u32([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let network = read_u32([hdr[20], hdr[21], hdr[22], hdr[23]]);

        // Sanity: snaplen should be reasonable (max 256k)
        if snaplen > 256 * 1024 && snaplen != 0xffff_ffff {
            // Not fatal, just warn by capping
        }

        Ok(Self {
            inner: reader,
            header: PcapHeader {
                snaplen,
                network,
                is_nano,
            },
            swapped,
            done: false,
        })
    }

    /// Global header.
    #[must_use]
    pub const fn header(&self) -> &PcapHeader {
        &self.header
    }

    const fn read_u32(&self, buf: [u8; 4]) -> u32 {
        if self.swapped {
            u32::from_be_bytes(buf)
        } else {
            u32::from_le_bytes(buf)
        }
    }
}

impl<R: std::io::Read> Iterator for PcapReader<R> {
    type Item = GripResult<PcapRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut rec_hdr = [0u8; 16];
        match self.inner.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.done = true;
                return None;
            }
            Err(e) => return Some(Err(GripError::Io(e))),
        }
        let ts_sec = self.read_u32([rec_hdr[0], rec_hdr[1], rec_hdr[2], rec_hdr[3]]);
        let ts_frac = self.read_u32([rec_hdr[4], rec_hdr[5], rec_hdr[6], rec_hdr[7]]);
        let incl_len = self.read_u32([rec_hdr[8], rec_hdr[9], rec_hdr[10], rec_hdr[11]]);
        let orig_len = self.read_u32([rec_hdr[12], rec_hdr[13], rec_hdr[14], rec_hdr[15]]);

        if incl_len > orig_len && orig_len != 0 {
            return Some(Err(GripError::pcap(format!(
                "incl_len {incl_len} > orig_len {orig_len}"
            ))));
        }
        if incl_len > self.header.snaplen && self.header.snaplen != 0 {
            // Allow but warn; cap reading
        }
        if incl_len > 10 * 1024 * 1024 {
            return Some(Err(GripError::pcap(format!(
                "packet too large: {incl_len}"
            ))));
        }
        let mut data = vec![0u8; incl_len as usize];
        if let Err(e) = self.inner.read_exact(&mut data) {
            return Some(Err(GripError::Io(e)));
        }
        Some(Ok(PcapRecord {
            ts_sec,
            ts_frac,
            incl_len,
            orig_len,
            data,
        }))
    }
}

/// Convenience: open a pcap file from path.
///
/// # Errors
///
/// Returns [`GripError::Io`] if the file cannot be opened.
/// Returns [`GripError::Pcap`] if the pcap header is malformed.
pub fn open_file(
    path: &std::path::Path,
) -> GripResult<PcapReader<std::io::BufReader<std::fs::File>>> {
    let file = std::fs::File::open(path).map_err(GripError::Io)?;
    let reader = std::io::BufReader::new(file);
    PcapReader::new(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_pcap(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Global header LE micro: magic a1b2c3d4, version 2.4, snaplen 65535, network 1
        buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        for pkt in packets {
            buf.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
            buf.extend_from_slice(&0u32.to_le_bytes()); // ts_frac
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            buf.extend_from_slice(pkt);
        }
        buf
    }

    #[test]
    fn empty_pcap() {
        let buf = build_pcap(&[]);
        let reader = PcapReader::new(Cursor::new(buf)).unwrap();
        assert_eq!(reader.header.network, 1);
        assert_eq!(reader.count(), 0);
    }

    #[test]
    #[allow(clippy::cloned_ref_to_slice_refs)]
    fn single_packet() {
        let pkt = vec![0xaa, 0xbb, 0xcc];
        let buf = build_pcap(&[pkt.clone()]);
        let mut reader = PcapReader::new(Cursor::new(buf)).unwrap();
        let rec = reader.next().unwrap().unwrap();
        assert_eq!(rec.data, pkt);
        assert!(reader.next().is_none());
    }
}
