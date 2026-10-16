//! Key derivation: password (+ optional keyfile) -> 256-bit encryption key.

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::{Digest, FixedOutput, KeyInit, Mac};
use blake2::{Blake2b512, Blake2bMac};
use unicode_normalization::{is_nfc, UnicodeNormalization};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{KdfParams, SALT_LEN};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) type Key = Zeroizing<[u8; KEY_LEN]>;

/// Length-prefixed, domain-separated BLAKE2b-512 into `out` (64 bytes).
fn hash_labeled(label: &[u8], data: &[u8], out: &mut [u8; 64]) {
    let mut h = Blake2b512::new();
    h.update(label);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    Digest::finalize_into(h, GenericArray::from_mut_slice(out));
}

/// Hash `password` as Unicode NFC so the same text typed with different
/// input methods (precomposed vs. combining accents) derives the same key.
/// Already-NFC input (the common case) is hashed in place, without a copy.
fn hash_password(password: &str, out: &mut [u8; 64]) {
    if is_nfc(password) {
        hash_labeled(b"argus/v1/password", password.as_bytes(), out);
        return;
    }
    // NFC output is at most ~2x the UTF-8 length; reserve 3x so the buffer
    // is not reallocated (which would leave an unwiped copy behind).
    let mut normalized = Zeroizing::new(String::with_capacity(password.len().saturating_mul(3)));
    normalized.extend(password.nfc());
    hash_labeled(b"argus/v1/password", normalized.as_bytes(), out);
}

/// Derive the vault encryption key.
pub(crate) fn derive_key(
    password: &str,
    keyfile: Option<&[u8]>,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Key> {
    params.validate()?;

    let mut ikm = Zeroizing::new([0u8; 128]);
    {
        let (pw_part, kf_part) = ikm.split_at_mut(64);
        let pw_part: &mut [u8; 64] = pw_part.try_into().map_err(|_| Error::Kdf)?;
        hash_password(password, pw_part);
        if let Some(kf) = keyfile {
            let kf_part: &mut [u8; 64] = kf_part.try_into().map_err(|_| Error::Kdf)?;
            hash_labeled(b"argus/v1/keyfile", kf, kf_part);
        }
    }

    let argon_params = Params::new(params.m_kib, params.t_cost, params.p_lanes, Some(KEY_LEN))
        .map_err(|_| Error::WeakKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut master: Key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(ikm.as_slice(), salt, master.as_mut_slice())
        .map_err(|_| Error::Kdf)?;

    // Sub-key derivation, leaves room for future purpose-specific keys.
    let mut mac =
        <Blake2bMac<U32> as KeyInit>::new_from_slice(master.as_slice()).map_err(|_| Error::Kdf)?;
    mac.update(b"argus/v1/enc");
    let mut enc: Key = Zeroizing::new([0u8; KEY_LEN]);
    FixedOutput::finalize_into(mac, GenericArray::from_mut_slice(enc.as_mut_slice()));
    Ok(enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams::MIN;

    #[test]
    fn deterministic_and_input_sensitive() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key("pw", None, &salt, &P).unwrap();
        let b = derive_key("pw", None, &salt, &P).unwrap();
        assert_eq!(*a, *b);

        let other_pw = derive_key("pX", None, &salt, &P).unwrap();
        let other_salt = derive_key("pw", None, &[2u8; SALT_LEN], &P).unwrap();
        let with_kf = derive_key("pw", Some(b"key"), &salt, &P).unwrap();
        let empty_kf = derive_key("pw", Some(b""), &salt, &P).unwrap();
        for k in [&other_pw, &other_salt, &with_kf, &empty_kf] {
            assert_ne!(**k, *a);
        }
        assert_ne!(*with_kf, *empty_kf);
    }

    #[test]
    fn password_is_unicode_nfc_normalized() {
        let salt = [3u8; SALT_LEN];
        // "á" precomposed (U+00E1) vs. "a" + combining acute (U+0301).
        let composed = derive_key("pass\u{e1}word", None, &salt, &P).unwrap();
        let decomposed = derive_key("passa\u{301}word", None, &salt, &P).unwrap();
        assert_eq!(*composed, *decomposed);
        let different = derive_key("passaword", None, &salt, &P).unwrap();
        assert_ne!(*composed, *different);
    }

    #[test]
    fn rejects_weak_params() {
        let weak = KdfParams { m_kib: 8, t_cost: 1, p_lanes: 1 };
        assert!(matches!(derive_key("pw", None, &[0; SALT_LEN], &weak), Err(Error::WeakKdfParams)));
    }
}
