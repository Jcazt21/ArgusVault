//! Bounds-checked binary reader used by every parser in the crate.
//! Never panics, never indexes directly: all access goes through `get`.

use crate::error::{Error, Result};

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::InvalidFormat)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::InvalidFormat)?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidFormat)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// One TLV record: `tag:u8 | len:u32 LE | value[len]`.
    pub(crate) fn record(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.u8()?;
        let len = usize::try_from(self.u32()?).map_err(|_| Error::InvalidFormat)?;
        Ok((tag, self.take(len)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_input_errors() {
        let mut r = Reader::new(&[1, 2]);
        assert!(r.u32().is_err());
        let mut r = Reader::new(&[7, 0xff, 0xff, 0xff, 0xff]);
        assert!(r.record().is_err());
    }
}
