//! Growable byte buffer that never leaves copies of its contents behind.
//!
//! `Vec<u8>` reallocates by copying into a new allocation and freeing the
//! old one **without wiping it**. `SecureBuf` grows manually: it allocates
//! the new buffer, copies, then zeroizes the old allocation before freeing.

use zeroize::Zeroize;

pub(crate) struct SecureBuf(Vec<u8>);

impl SecureBuf {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    /// Ensure room for `additional` more bytes without an unwiped realloc.
    pub(crate) fn reserve(&mut self, additional: usize) {
        let free = self.0.capacity() - self.0.len();
        if free >= additional {
            return;
        }
        let needed = self.0.len().saturating_add(additional);
        let new_cap = needed.max(self.0.capacity().saturating_mul(2)).max(64);
        let mut fresh = Vec::with_capacity(new_cap);
        fresh.extend_from_slice(&self.0);
        // Wipes the full old allocation (including spare capacity).
        self.0.zeroize();
        self.0 = fresh;
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    pub(crate) fn put_zeros(&mut self, n: usize) {
        self.reserve(n);
        self.0.resize(self.0.len() + n, 0);
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Mutable access for in-place AEAD. Callers must `reserve` first so the
    /// vector never reallocates on its own.
    pub(crate) fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuf(len={}, <redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_keeps_content() {
        let mut b = SecureBuf::with_capacity(1);
        for i in 0..1000u32 {
            b.put(&i.to_le_bytes());
        }
        b.put_zeros(3);
        assert_eq!(b.len(), 4003);
        assert_eq!(&b.as_slice()[4..8], &1u32.to_le_bytes());
    }
}
