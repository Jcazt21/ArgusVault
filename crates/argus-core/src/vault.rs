//! High-level vault API: create, unlock, save, change credentials.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{
    self, Header, KdfParams, MAX_FILE_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, SALT_LEN, TAG_LEN,
};
use crate::kdf::{self, Key};
use crate::model::Vault;
use crate::{codec, fs_util, keyfile, rng};

/// Minimum master password length (in characters) for new vaults.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 10;

/// Unlock credentials. Wiped from memory on drop.
pub struct Credentials {
    password: Zeroizing<String>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("password", &"<redacted>")
            .field("keyfile", &self.keyfile.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Credentials {
    /// Password only.
    #[must_use]
    pub fn new(password: Zeroizing<String>) -> Self {
        Self { password, keyfile: None }
    }

    /// Password + keyfile read from `path`.
    ///
    /// # Errors
    /// Keyfile read errors.
    pub fn with_keyfile(password: Zeroizing<String>, path: &Path) -> Result<Self> {
        Ok(Self { password, keyfile: Some(keyfile::read(path)?) })
    }

    /// Password + raw keyfile bytes.
    #[must_use]
    pub fn with_keyfile_bytes(password: Zeroizing<String>, keyfile: Zeroizing<Vec<u8>>) -> Self {
        Self { password, keyfile: Some(keyfile) }
    }

    fn check_new_password(&self) -> Result<()> {
        if self.password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(Error::InvalidInput("master password must be at least 10 characters"));
        }
        Ok(())
    }

    fn derive(&self, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key> {
        kdf::derive_key(
            self.password.as_str(),
            self.keyfile.as_ref().map(|k| k.as_slice()),
            salt,
            params,
        )
    }
}

/// A decrypted vault held in memory together with its encryption key.
///
/// Dropping this value (i.e. locking) wipes the key and all entries.
pub struct UnlockedVault {
    /// Decrypted contents. Call [`UnlockedVault::save`] after modifying.
    pub vault: Vault,
    key: Key,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    path: PathBuf,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault", &self.vault)
            .field("key", &"<redacted>")
            .field("kdf", &self.kdf)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Create a new, empty vault at `path`. Refuses to overwrite.
    ///
    /// # Errors
    /// Weak password, existing file, KDF/RNG/I/O errors.
    pub fn create(path: &Path, creds: &Credentials, kdf: KdfParams) -> Result<Self> {
        creds.check_new_password()?;
        kdf.validate()?;
        if path.exists() {
            return Err(Error::InvalidInput("a file already exists at that location"));
        }
        let mut salt = [0u8; SALT_LEN];
        rng::fill(&mut salt)?;
        let key = creds.derive(&salt, &kdf)?;
        let uv = Self { vault: Vault::default(), key, kdf, salt, path: path.to_path_buf() };
        uv.save()?;
        Ok(uv)
    }

    /// The Argon2 costs stored in the vault file at `path`, read without decrypting, so the caller
    /// can check there is enough free memory ([`crate::calibrate::required_free_memory`]) before
    /// the slow, memory-hungry derivation.
    ///
    /// # Errors
    /// I/O errors, or a file that is not a valid vault header.
    pub fn peek_kdf_params(path: &Path) -> Result<KdfParams> {
        use std::io::Read;
        let mut header = [0u8; format::HEADER_LEN];
        std::fs::File::open(path)?.read_exact(&mut header).map_err(|_| Error::InvalidFormat)?;
        format::peek_kdf(&header)
    }

    /// Open and decrypt an existing vault.
    ///
    /// # Errors
    /// [`Error::AuthenticationFailed`] for wrong credentials or tampering;
    /// format, limit and I/O errors otherwise.
    pub fn open(path: &Path, creds: &Credentials) -> Result<Self> {
        let data = fs_util::read_limited(path, MAX_FILE_LEN)?;
        let parsed = format::parse_file(&data)?;
        let key = creds.derive(&parsed.header.salt, &parsed.header.kdf)?;
        let plaintext = decrypt(&key, &parsed.header.nonce, parsed.aad, parsed.ciphertext)?;
        // Authenticated plaintext that fails to parse means a bug or a
        // file written by a future version, never attacker-controlled data.
        let vault = codec::decode(&plaintext)?;
        Ok(Self {
            vault,
            key,
            kdf: parsed.header.kdf,
            salt: parsed.header.salt,
            path: path.to_path_buf(),
        })
    }

    /// Encrypt and atomically write the vault to disk (fresh nonce each time).
    ///
    /// # Errors
    /// Encoding, RNG and I/O errors.
    pub fn save(&self) -> Result<()> {
        let mut buf = codec::encode(&self.vault)?;
        if buf.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::LimitExceeded);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng::fill(&mut nonce)?;
        let ct_len = u32::try_from(buf.len() + TAG_LEN).map_err(|_| Error::LimitExceeded)?;
        let header = Header { kdf: self.kdf, salt: self.salt, nonce, ct_len }.to_bytes();

        // Reserve the tag space up front so the plaintext buffer is never
        // reallocated (and thus never copied unwiped) by the AEAD.
        buf.reserve(TAG_LEN);
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_slice()).map_err(|_| Error::Kdf)?;
        cipher
            .encrypt_in_place(XNonce::from_slice(&nonce), &header, buf.as_mut_vec())
            .map_err(|_| Error::LimitExceeded)?;

        let mut file = Vec::with_capacity(header.len() + buf.len());
        file.extend_from_slice(&header);
        file.extend_from_slice(buf.as_slice());
        fs_util::atomic_write(&self.path, &file)
    }

    /// Re-key the vault with new credentials and/or KDF parameters
    /// (new salt). The in-memory state is only updated if the save succeeds.
    /// The `.bak` file is replaced with the re-keyed vault (or removed), so
    /// the old credentials no longer open any file Argus keeps.
    ///
    /// # Errors
    /// Weak password, KDF/RNG/I/O errors. An I/O error after the save
    /// succeeded means the new credentials are active but the old backup
    /// could not be removed.
    pub fn change_credentials(&mut self, creds: &Credentials, kdf: KdfParams) -> Result<()> {
        creds.check_new_password()?;
        kdf.validate()?;
        let mut salt = [0u8; SALT_LEN];
        rng::fill(&mut salt)?;
        let new_key = creds.derive(&salt, &kdf)?;

        let old_key = std::mem::replace(&mut self.key, new_key);
        let old_kdf = std::mem::replace(&mut self.kdf, kdf);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        if let Err(e) = self.save() {
            self.key = old_key;
            self.kdf = old_kdf;
            self.salt = old_salt;
            return Err(e);
        }
        fs_util::replace_backup_with_current(&self.path)
    }

    /// Verify `creds` match the current key (e.g. before showing settings).
    /// Runs the full KDF, so it is deliberately slow.
    ///
    /// # Errors
    /// [`Error::AuthenticationFailed`] if they do not match.
    pub fn verify(&self, creds: &Credentials) -> Result<()> {
        let candidate = creds.derive(&self.salt, &self.kdf)?;
        if constant_time_eq(candidate.as_slice(), self.key.as_slice()) {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Explicitly lock: consumes and wipes everything.
    pub fn lock(self) {
        drop(self);
    }
}

fn decrypt(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Kdf)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buf)
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(buf)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_util::test_util::TempDir;
    use crate::model::Entry;

    const FAST: KdfParams = KdfParams::MIN;

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    #[test]
    fn peek_reads_the_kdf_costs_without_the_password() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let creds = Credentials::new(pw("correct horse battery"));
        UnlockedVault::create(&path, &creds, FAST).unwrap().lock();
        assert_eq!(UnlockedVault::peek_kdf_params(&path).unwrap(), FAST);

        // Not a vault, too short, missing: all errors, never a panic.
        let junk = dir.0.join("junk");
        std::fs::write(&junk, b"not a vault").unwrap();
        assert!(UnlockedVault::peek_kdf_params(&junk).is_err());
        assert!(UnlockedVault::peek_kdf_params(&dir.0.join("missing")).is_err());
    }

    #[test]
    fn create_save_open_roundtrip() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let creds = Credentials::new(pw("correct horse battery"));
        let mut uv = UnlockedVault::create(&path, &creds, FAST).unwrap();
        let mut e = Entry::new("Mail").unwrap();
        e.password = "s3cr3t".into();
        uv.vault.upsert(e).unwrap();
        uv.save().unwrap();
        uv.lock();

        let reopened = UnlockedVault::open(&path, &creds).unwrap();
        assert_eq!(reopened.vault.entries.len(), 1);
        assert_eq!(reopened.vault.entries[0].password, "s3cr3t");
        assert!(reopened.verify(&creds).is_ok());
        assert!(reopened.verify(&Credentials::new(pw("nope nope nope"))).is_err());
    }

    #[test]
    fn plaintext_not_on_disk() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let mut uv =
            UnlockedVault::create(&path, &Credentials::new(pw("correct horse battery")), FAST)
                .unwrap();
        let mut e = Entry::new("UniqueTitleMarker").unwrap();
        e.password = "UniquePasswordMarker".into();
        uv.vault.upsert(e).unwrap();
        uv.save().unwrap();
        let raw = std::fs::read(&path).unwrap();
        for needle in [&b"UniqueTitleMarker"[..], b"UniquePasswordMarker"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn wrong_password_and_keyfile_fail_identically() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let kf = Zeroizing::new(vec![42u8; 64]);
        let good = Credentials::with_keyfile_bytes(pw("correct horse battery"), kf.clone());
        UnlockedVault::create(&path, &good, FAST).unwrap();

        let wrong_pw = Credentials::with_keyfile_bytes(pw("correct horse batterY"), kf);
        let no_kf = Credentials::new(pw("correct horse battery"));
        let wrong_kf = Credentials::with_keyfile_bytes(
            pw("correct horse battery"),
            Zeroizing::new(vec![43u8; 64]),
        );
        for c in [&wrong_pw, &no_kf, &wrong_kf] {
            assert!(matches!(UnlockedVault::open(&path, c), Err(Error::AuthenticationFailed)));
        }
        assert!(UnlockedVault::open(&path, &good).is_ok());
    }

    #[test]
    fn tampering_is_detected() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let creds = Credentials::new(pw("correct horse battery"));
        UnlockedVault::create(&path, &creds, FAST).unwrap();
        let original = std::fs::read(&path).unwrap();

        // Salt, nonce, ciphertext body and tag positions.
        for pos in [30, 60, format::HEADER_LEN + 1, original.len() / 2, original.len() - 1] {
            let mut bad = original.clone();
            bad[pos] ^= 0x01;
            std::fs::write(&path, &bad).unwrap();
            let err = UnlockedVault::open(&path, &creds).unwrap_err();
            assert!(err.is_unlock_failure(), "pos {pos}: {err:?}");
        }
    }

    #[test]
    fn refuses_weak_password_and_overwrite() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        assert!(UnlockedVault::create(&path, &Credentials::new(pw("short")), FAST).is_err());
        UnlockedVault::create(&path, &Credentials::new(pw("correct horse battery")), FAST).unwrap();
        assert!(UnlockedVault::create(&path, &Credentials::new(pw("correct horse battery")), FAST)
            .is_err());
    }

    #[test]
    fn change_credentials_rekeys() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let old = Credentials::new(pw("correct horse battery"));
        let new = Credentials::with_keyfile_bytes(
            pw("another long passphrase"),
            Zeroizing::new(vec![1; 64]),
        );
        let mut uv = UnlockedVault::create(&path, &old, FAST).unwrap();
        uv.change_credentials(&new, FAST).unwrap();
        uv.lock();
        assert!(UnlockedVault::open(&path, &old).is_err());
        assert!(UnlockedVault::open(&path, &new).is_ok());
    }

    #[test]
    fn change_credentials_does_not_leave_old_key_backup() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let old = Credentials::new(pw("correct horse battery"));
        let new = Credentials::new(pw("another long passphrase"));
        let mut uv = UnlockedVault::create(&path, &old, FAST).unwrap();
        uv.save().unwrap();
        let bak = fs_util::backup_path(&path);
        assert!(UnlockedVault::open(&bak, &old).is_ok(), "precondition: backup exists");

        uv.change_credentials(&new, FAST).unwrap();
        uv.lock();
        assert!(matches!(UnlockedVault::open(&bak, &old), Err(Error::AuthenticationFailed)));
        assert!(UnlockedVault::open(&bak, &new).is_ok());
        assert!(UnlockedVault::open(&path, &new).is_ok());
    }

    #[test]
    fn same_password_in_nfc_and_nfd_opens_the_same_vault() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        // "contraseña" with ñ precomposed (U+00F1) vs. n + combining tilde (U+0303).
        let composed = Credentials::new(pw("contrase\u{f1}a-larga"));
        let decomposed = Credentials::new(pw("contrasen\u{303}a-larga"));
        UnlockedVault::create(&path, &composed, FAST).unwrap();
        assert!(UnlockedVault::open(&path, &decomposed).is_ok());
    }

    #[test]
    fn future_format_version_is_rejected() {
        let dir = TempDir::new();
        let path = dir.0.join("v.argus");
        let creds = Credentials::new(pw("correct horse battery"));
        UnlockedVault::create(&path, &creds, FAST).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        raw[8] = 2; // format version, little-endian u16 at offset 8
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(UnlockedVault::open(&path, &creds), Err(Error::UnsupportedVersion)));
    }

    #[test]
    fn ct_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
