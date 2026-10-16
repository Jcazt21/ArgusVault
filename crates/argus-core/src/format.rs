//! On-disk vault format, version 1.
//!
//! ```text
//! offset size  field
//! 0      8     magic       "ARGUSV01"
//! 8      2     version     u16 LE (= 1)
//! 10     1     kdf_id      u8     (1 = Argon2id v1.3)
//! 11     4     m_kib       u32 LE
//! 15     4     t_cost      u32 LE
//! 19     4     p_lanes     u32 LE
//! 23     32    salt
//! 55     24    nonce       fresh random value on every save
//! 79     4     ct_len      u32 LE
//! 83     ...   ciphertext  XChaCha20-Poly1305, AAD = bytes [0, 83)
//! ```
//!
//! The entire header is authenticated, so changing any field (including the
//! KDF parameters) makes decryption fail.

use crate::error::{Error, Result};
use crate::reader::Reader;

pub const MAGIC: [u8; 8] = *b"ARGUSV01";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 8 + 2 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 4;
/// Maximum plaintext size accepted (64 MiB).
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;
pub const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + TAG_LEN;
pub const MAX_FILE_LEN: usize = HEADER_LEN + MAX_CIPHERTEXT_LEN;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallel lanes.
    pub p_lanes: u32,
}

impl KdfParams {
    /// Hard floor (64 MiB, t=2). Files below it are rejected to prevent
    /// an attacker from downgrading the KDF by editing the header.
    pub const MIN: Self = Self { m_kib: 64 * 1024, t_cost: 2, p_lanes: 1 };
    /// Hard ceiling so a crafted file cannot exhaust memory (denial of service).
    pub const MAX: Self = Self { m_kib: 2 * 1024 * 1024, t_cost: 64, p_lanes: 16 };
    /// Default for new vaults, and the floor that [`crate::calibrate`] never goes below:
    /// 512 MiB, t=4, p=4. (Until 2026-10-16 it was 256 MiB, t=3; such vaults still open, because
    /// opening only checks `[MIN, MAX]`.)
    pub const DEFAULT: Self = Self { m_kib: 512 * 1024, t_cost: 4, p_lanes: 4 };

    /// Check the parameters are within `[MIN, MAX]`.
    ///
    /// # Errors
    /// [`Error::WeakKdfParams`] when out of range.
    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MIN.m_kib..=Self::MAX.m_kib).contains(&self.m_kib)
            && (Self::MIN.t_cost..=Self::MAX.t_cost).contains(&self.t_cost)
            && (Self::MIN.p_lanes..=Self::MAX.p_lanes).contains(&self.p_lanes)
            // Argon2 requirement: m >= 8 * p.
            && self.m_kib >= 8 * self.p_lanes;
        if ok {
            Ok(())
        } else {
            Err(Error::WeakKdfParams)
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ct_len: u32,
}

impl Header {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.push(KDF_ARGON2ID);
        out.extend_from_slice(&self.kdf.m_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.p_lanes.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct_len.to_le_bytes());
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<8>()? != MAGIC {
            return Err(Error::InvalidFormat);
        }
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if r.u8()? != KDF_ARGON2ID {
            return Err(Error::UnsupportedVersion);
        }
        let kdf = KdfParams { m_kib: r.u32()?, t_cost: r.u32()?, p_lanes: r.u32()? };
        kdf.validate()?;
        let salt = r.array()?;
        let nonce = r.array()?;
        let ct_len = r.u32()?;
        Ok(Self { kdf, salt, nonce, ct_len })
    }
}

/// Read just the KDF costs from the start of a vault file, without decrypting anything. The header
/// is not secret; this lets the caller check there is enough free memory before deriving the key.
///
/// # Errors
/// [`Error::InvalidFormat`] / [`Error::UnsupportedVersion`] / [`Error::WeakKdfParams`] when the
/// header is not a valid one.
pub fn peek_kdf(bytes: &[u8]) -> Result<KdfParams> {
    Ok(Header::parse(bytes.get(..HEADER_LEN).ok_or(Error::InvalidFormat)?)?.kdf)
}

/// A parsed vault file, borrowing from the raw bytes.
#[derive(Debug)]
pub(crate) struct ParsedFile<'a> {
    pub header: Header,
    /// Raw header bytes, used as AEAD associated data.
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// Split and validate a complete vault file. Does not decrypt.
pub(crate) fn parse_file(data: &[u8]) -> Result<ParsedFile<'_>> {
    if data.len() > MAX_FILE_LEN {
        return Err(Error::LimitExceeded);
    }
    let aad = data.get(..HEADER_LEN).ok_or(Error::InvalidFormat)?;
    let ciphertext = data.get(HEADER_LEN..).ok_or(Error::InvalidFormat)?;
    let header = Header::parse(aad)?;
    let ct_len = usize::try_from(header.ct_len).map_err(|_| Error::InvalidFormat)?;
    if !(TAG_LEN..=MAX_CIPHERTEXT_LEN).contains(&ct_len) || ct_len != ciphertext.len() {
        return Err(Error::InvalidFormat);
    }
    Ok(ParsedFile { header, aad, ciphertext })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header { kdf: KdfParams::DEFAULT, salt: [7; SALT_LEN], nonce: [9; NONCE_LEN], ct_len: 16 }
    }

    #[test]
    fn header_roundtrip() {
        let h = sample();
        let mut file = h.to_bytes();
        assert_eq!(file.len(), HEADER_LEN);
        file.extend_from_slice(&[0u8; 16]);
        let p = parse_file(&file).unwrap();
        assert_eq!(p.header, h);
        assert_eq!(p.ciphertext.len(), 16);
    }

    #[test]
    fn rejects_bad_magic_version_and_length() {
        let mut file = sample().to_bytes();
        file.extend_from_slice(&[0u8; 16]);

        let mut bad = file.clone();
        bad[0] ^= 1;
        assert!(matches!(parse_file(&bad), Err(Error::InvalidFormat)));

        let mut bad = file.clone();
        bad[8] = 2;
        assert!(matches!(parse_file(&bad), Err(Error::UnsupportedVersion)));

        let mut bad = file.clone();
        bad.push(0);
        assert!(matches!(parse_file(&bad), Err(Error::InvalidFormat)));

        assert!(parse_file(&file[..HEADER_LEN - 1]).is_err());
        assert!(parse_file(&[]).is_err());
    }

    #[test]
    fn rejects_kdf_downgrade() {
        let mut h = sample();
        h.kdf.m_kib = 1024;
        let mut file = h.to_bytes();
        file.extend_from_slice(&[0u8; 16]);
        assert!(matches!(parse_file(&file), Err(Error::WeakKdfParams)));
    }

    #[test]
    fn kdf_bounds() {
        assert!(KdfParams::MIN.validate().is_ok());
        assert!(KdfParams::MAX.validate().is_ok());
        assert!(KdfParams::DEFAULT.validate().is_ok());
        assert!(KdfParams { t_cost: 1, ..KdfParams::MIN }.validate().is_err());
        assert!(KdfParams { p_lanes: 0, ..KdfParams::MIN }.validate().is_err());
        assert!(KdfParams { m_kib: u32::MAX, ..KdfParams::MIN }.validate().is_err());
    }
}
