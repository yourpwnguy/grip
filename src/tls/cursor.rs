//! A bounds-checked reader for length-prefixed handshake fields.

use crate::error::{GripError, GripResult, ParseKind};

/// A walking reader over a handshake body.
///
/// Every field in a `ClientHello` or `ServerHello` is length-prefixed, so
/// hand-rolling each bounds check means writing the same four lines ten times
/// over. This does it once.
///
/// `base` is the offset errors get reported against. Pass the handshake header
/// length so the numbers line up with a full hex dump.
pub(super) struct Cursor<'a> {
    body: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    /// Start reading `body`, reporting errors as if they started at `base`.
    pub const fn new(body: &'a [u8], base: usize) -> Self {
        Self { body, pos: 0, base }
    }

    /// Make sure `n` more bytes are there, or bail with the current offset.
    const fn need(&self, n: usize) -> GripResult<()> {
        if self.remaining() < n {
            return Err(GripError::parse(
                self.base + self.pos,
                ParseKind::UnexpectedEof {
                    needed: n,
                    available: self.remaining(),
                },
            ));
        }
        Ok(())
    }

    /// Read `n` raw bytes and advance.
    pub fn take(&mut self, n: usize) -> GripResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.body[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a 1-byte length prefix.
    pub fn u8(&mut self) -> GripResult<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a 2-byte big-endian integer.
    pub fn u16(&mut self) -> GripResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read `n` bytes as an owned `Vec`.
    pub fn vec(&mut self, n: usize) -> GripResult<Vec<u8>> {
        Ok(self.take(n)?.to_vec())
    }

    /// Bytes left to read.
    pub const fn remaining(&self) -> usize {
        self.body.len().saturating_sub(self.pos)
    }

    /// Current absolute offset, for error sites that build their own kind.
    pub const fn offset(&self) -> usize {
        self.base + self.pos
    }
}
