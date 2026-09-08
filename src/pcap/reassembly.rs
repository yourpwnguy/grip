//! TCP stream reassembly.
//!
//! A `ClientHello` can span multiple TCP segments. We buffer segments per
//! flow keyed by `(src_ip, src_port, dst_ip, dst_port)` in sequence-number
//! order and expose the contiguous byte stream once we have it. This is the
//! hard part of pcap mode — if you just scan packets independently you miss
//! split handshakes and produce garbage fingerprints.
//!
//! # Design
//! Each flow keeps a `BTreeMap<u32, Vec<u8>>` of `seq -> payload`. We insert
//! segments by `seq`, coalesce duplicates/overlaps by keeping first-seen,
//! and produce `reassembled()` by walking from the lowest `seq` while the
//! next expected `seq` matches. Gaps are tolerated — we return the prefix
//! up to the first gap; gaps are logged as warnings by the caller.
//!
//! # Limits
//! To avoid OOM on adversarial pcaps we cap `max_flows` (default 10k) and
//! `max_bytes_per_flow` (1 MiB). Excess flows/bytes are dropped with a
//! warning.

use std::collections::{BTreeMap, HashMap};

use crate::pcap::tcp::{FlowKey, TcpSegment};

/// Per-flow state.
#[derive(Debug, Default)]
struct FlowState {
    segments: BTreeMap<u32, Vec<u8>>,
    /// Lowest seq seen (initialized on first segment).
    base_seq: Option<u32>,
    /// Total buffered bytes.
    buffered_bytes: usize,
}

/// TCP reassembler.
#[derive(Debug)]
pub struct Reassembler {
    flows: HashMap<FlowKey, FlowState>,
    /// Also track reverse direction keyed same way? For pcap we store
    /// directed flows; client->server only. That's fine because `ClientHello`
    /// is always client->server.
    max_flows: usize,
    max_bytes_per_flow: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            max_flows: 10_000,
            max_bytes_per_flow: 1024 * 1024,
        }
    }
}

impl Reassembler {
    /// Create with custom limits (for tests).
    #[must_use]
    pub fn with_limits(max_flows: usize, max_bytes_per_flow: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            max_bytes_per_flow,
        }
    }

    /// Insert a segment for a flow.
    ///
    /// Duplicate `seq` values are ignored (first wins). Overlaps are not
    /// coalesced beyond exact `seq` match — good enough for v0.1.0 since
    /// `ClientHello` segments rarely overlap partially.
    pub fn insert(&mut self, key: FlowKey, segment: TcpSegment) {
        if segment.payload.is_empty() {
            return;
        }
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            // Drop new flow — too many.
            return;
        }
        let state = self.flows.entry(key).or_default();
        if state.buffered_bytes + segment.payload.len() > self.max_bytes_per_flow {
            return;
        }
        if state.base_seq.is_none() {
            state.base_seq = Some(segment.seq);
        }
        // Keep first segment for a given seq; ignore duplicates.
        if state.segments.contains_key(&segment.seq) {
            return;
        }
        state.buffered_bytes += segment.payload.len();
        state.segments.insert(segment.seq, segment.payload);
    }

    /// Return the reassembled contiguous stream for `key`, if any.
    ///
    /// Walks from the lowest `seq` and concatenates payloads while the next
    /// `seq` exactly equals `expected = seq + payload.len()`. Stops at first gap.
    ///
    /// # Panics
    ///
    /// Panics if the segment list is non-empty but has no first element —
    /// this is unreachable because we check `is_empty()` before calling `unwrap()`.
    #[must_use]
    pub fn reassembled(&self, key: &FlowKey) -> Option<Vec<u8>> {
        let state = self.flows.get(key)?;
        if state.segments.is_empty() {
            return None;
        }
        let mut iter = state.segments.iter();
        let (first_seq, first_payload) = iter.next().unwrap();
        let mut out = Vec::with_capacity(state.buffered_bytes);
        let mut expected = *first_seq + first_payload.len() as u32;
        out.extend_from_slice(first_payload);
        for (seq, payload) in iter {
            if *seq != expected {
                break; // gap — stop
            }
            out.extend_from_slice(payload);
            expected = seq.wrapping_add(payload.len() as u32);
        }
        if out.is_empty() { None } else { Some(out) }
    }

    /// Iterate over all flow keys that have at least one segment.
    #[must_use]
    pub fn flow_keys(&self) -> Vec<FlowKey> {
        self.flows.keys().copied().collect()
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Reassembled streams for all flows (only those with contiguous prefix).
    #[must_use]
    pub fn all_reassembled(&self) -> HashMap<FlowKey, Vec<u8>> {
        let mut map = HashMap::new();
        for key in self.flows.keys() {
            if let Some(data) = self.reassembled(key) {
                map.insert(*key, data);
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> FlowKey {
        FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 1234,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        }
    }

    #[test]
    fn single_segment() {
        let mut r = Reassembler::default();
        r.insert(
            key(),
            TcpSegment {
                seq: 1000,
                payload: b"hello".to_vec(),
            },
        );
        assert_eq!(r.reassembled(&key()).unwrap(), b"hello");
    }

    #[test]
    fn out_of_order() {
        let mut r = Reassembler::default();
        r.insert(
            key(),
            TcpSegment {
                seq: 1005,
                payload: b"world".to_vec(),
            },
        );
        r.insert(
            key(),
            TcpSegment {
                seq: 1000,
                payload: b"hello".to_vec(),
            },
        );
        // With our simple logic we start from lowest seq (1000) and expect 1005 next, which matches
        assert_eq!(r.reassembled(&key()).unwrap(), b"helloworld");
    }

    #[test]
    fn gap_stops() {
        let mut r = Reassembler::default();
        r.insert(
            key(),
            TcpSegment {
                seq: 1000,
                payload: b"hello".to_vec(),
            },
        );
        r.insert(
            key(),
            TcpSegment {
                seq: 1010,
                payload: b"world".to_vec(),
            },
        ); // gap of 5
        assert_eq!(r.reassembled(&key()).unwrap(), b"hello"); // stops before gap
    }

    #[test]
    fn duplicate_ignored() {
        let mut r = Reassembler::default();
        r.insert(
            key(),
            TcpSegment {
                seq: 1000,
                payload: b"hello".to_vec(),
            },
        );
        r.insert(
            key(),
            TcpSegment {
                seq: 1000,
                payload: b"XXXXX".to_vec(),
            },
        );
        assert_eq!(r.reassembled(&key()).unwrap(), b"hello");
    }
}
