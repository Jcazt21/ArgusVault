//! Plaintext (inner) serialization of a [`Vault`].
//!
//! Hand-written, strict TLV format. Rules enforced on decode:
//! * every length is bounds-checked; no panics on any input,
//! * unknown tags and duplicate fields are **rejected**,
//! * text must be valid UTF-8 and below [`MAX_FIELD_LEN`],
//! * padding (if present) must be the final record,
//! * entry ids must be unique.
//!
//! ```text
//! inner    := version:u16 LE, record*
//! record   := tag:u8, len:u32 LE, value[len]
//! top tags := 0x01 SETTINGS{...} | 0x02 ENTRY{...} | 0xFF PADDING
//! ```
//! The output is padded to a multiple of 4 KiB so the ciphertext size only
//! leaks a coarse estimate of the vault size.

use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, Settings, Vault, MAX_ENTRIES, MAX_FIELD_LEN};
use crate::reader::Reader;
use crate::securebuf::SecureBuf;
use crate::totp::{Algorithm, TotpConfig};

/// v2 adds the entry kind and host. v1 vaults are still read (all entries become websites) and
/// are written back as v2 on the next save.
const INNER_VERSION: u16 = 2;
const INNER_VERSION_V1: u16 = 1;
const PAD_BLOCK: usize = 4096;

const T_SETTINGS: u8 = 0x01;
const T_ENTRY: u8 = 0x02;
const T_PADDING: u8 = 0xFF;

const S_AUTO_LOCK: u8 = 0x01;
const S_CLIPBOARD: u8 = 0x02;
const S_LOCK_MIN: u8 = 0x03;

const E_ID: u8 = 0x01;
const E_TITLE: u8 = 0x02;
const E_USERNAME: u8 = 0x03;
const E_PASSWORD: u8 = 0x04;
const E_URL: u8 = 0x05;
const E_NOTES: u8 = 0x06;
const E_CREATED: u8 = 0x07;
const E_MODIFIED: u8 = 0x08;
const E_TOTP: u8 = 0x09;
const E_KIND: u8 = 0x0A;
const E_HOST: u8 = 0x0B;

const O_SECRET: u8 = 0x01;
const O_ALGORITHM: u8 = 0x02;
const O_DIGITS: u8 = 0x03;
const O_PERIOD: u8 = 0x04;

// ---------------------------------------------------------------- encode

fn put_record(w: &mut SecureBuf, tag: u8, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| Error::LimitExceeded)?;
    w.put(&[tag]);
    w.put(&len.to_le_bytes());
    w.put(value);
    Ok(())
}

fn encode_settings(s: &Settings) -> Result<SecureBuf> {
    let mut w = SecureBuf::with_capacity(64);
    put_record(&mut w, S_AUTO_LOCK, &s.auto_lock_secs.to_le_bytes())?;
    put_record(&mut w, S_CLIPBOARD, &s.clipboard_clear_secs.to_le_bytes())?;
    put_record(&mut w, S_LOCK_MIN, &[u8::from(s.lock_on_minimize)])?;
    Ok(w)
}

fn encode_totp(t: &TotpConfig) -> Result<SecureBuf> {
    let mut w = SecureBuf::with_capacity(t.secret().len() + 32);
    put_record(&mut w, O_SECRET, t.secret())?;
    put_record(&mut w, O_ALGORITHM, &[t.algorithm().to_u8()])?;
    put_record(&mut w, O_DIGITS, &[t.digits()])?;
    put_record(&mut w, O_PERIOD, &t.period().to_le_bytes())?;
    Ok(w)
}

fn encode_entry(e: &Entry) -> Result<SecureBuf> {
    e.validate()?;
    let size = e.title.len()
        + e.host.len()
        + e.username.len()
        + e.password.len()
        + e.url.len()
        + e.notes.len();
    let mut w = SecureBuf::with_capacity(size + 128);
    put_record(&mut w, E_ID, &e.id)?;
    put_record(&mut w, E_KIND, &[e.kind.to_u8()])?;
    put_record(&mut w, E_TITLE, e.title.as_bytes())?;
    put_record(&mut w, E_HOST, e.host.as_bytes())?;
    put_record(&mut w, E_USERNAME, e.username.as_bytes())?;
    put_record(&mut w, E_PASSWORD, e.password.as_bytes())?;
    put_record(&mut w, E_URL, e.url.as_bytes())?;
    put_record(&mut w, E_NOTES, e.notes.as_bytes())?;
    put_record(&mut w, E_CREATED, &e.created.to_le_bytes())?;
    put_record(&mut w, E_MODIFIED, &e.modified.to_le_bytes())?;
    if let Some(t) = &e.totp {
        put_record(&mut w, E_TOTP, encode_totp(t)?.as_slice())?;
    }
    Ok(w)
}

/// Serialize a vault into a zeroizing, padded buffer.
pub(crate) fn encode(vault: &Vault) -> Result<SecureBuf> {
    vault.settings.validate()?;
    if vault.entries.len() > MAX_ENTRIES {
        return Err(Error::LimitExceeded);
    }
    let mut w = SecureBuf::with_capacity(PAD_BLOCK);
    w.put(&INNER_VERSION.to_le_bytes());
    put_record(&mut w, T_SETTINGS, encode_settings(&vault.settings)?.as_slice())?;
    for e in &vault.entries {
        put_record(&mut w, T_ENTRY, encode_entry(e)?.as_slice())?;
    }
    // Padding record header is 5 bytes.
    let after_header = w.len() + 5;
    let pad = (PAD_BLOCK - after_header % PAD_BLOCK) % PAD_BLOCK;
    let pad_len = u32::try_from(pad).map_err(|_| Error::LimitExceeded)?;
    w.put(&[T_PADDING]);
    w.put(&pad_len.to_le_bytes());
    w.put_zeros(pad);
    Ok(w)
}

// ---------------------------------------------------------------- decode

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(Error::InvalidFormat);
    }
    *slot = Some(value);
    Ok(())
}

fn text(v: &[u8]) -> Result<String> {
    if v.len() > MAX_FIELD_LEN {
        return Err(Error::LimitExceeded);
    }
    // `to_owned` allocates exactly `len` bytes: no realloc copies.
    std::str::from_utf8(v).map(str::to_owned).map_err(|_| Error::InvalidFormat)
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into().map_err(|_| Error::InvalidFormat)
}

fn u32_of(v: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(fixed(v)?))
}

fn u64_of(v: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(fixed(v)?))
}

fn bool_of(v: &[u8]) -> Result<bool> {
    match fixed::<1>(v)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Error::InvalidFormat),
    }
}

fn decode_settings(buf: &[u8]) -> Result<Settings> {
    let (mut auto, mut clip, mut min) = (None, None, None);
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let (tag, v) = r.record()?;
        match tag {
            S_AUTO_LOCK => set_once(&mut auto, u32_of(v)?)?,
            S_CLIPBOARD => set_once(&mut clip, u32_of(v)?)?,
            S_LOCK_MIN => set_once(&mut min, bool_of(v)?)?,
            _ => return Err(Error::InvalidFormat),
        }
    }
    let s = Settings {
        auto_lock_secs: auto.ok_or(Error::InvalidFormat)?,
        clipboard_clear_secs: clip.ok_or(Error::InvalidFormat)?,
        lock_on_minimize: min.ok_or(Error::InvalidFormat)?,
    };
    s.validate().map_err(|_| Error::InvalidFormat)?;
    Ok(s)
}

fn decode_totp(buf: &[u8]) -> Result<TotpConfig> {
    let mut secret: Option<Zeroizing<Vec<u8>>> = None;
    let (mut alg, mut digits, mut period) = (None, None, None);
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let (tag, v) = r.record()?;
        match tag {
            O_SECRET => set_once(&mut secret, Zeroizing::new(v.to_vec()))?,
            O_ALGORITHM => set_once(&mut alg, Algorithm::from_u8(fixed::<1>(v)?[0])?)?,
            O_DIGITS => set_once(&mut digits, fixed::<1>(v)?[0])?,
            O_PERIOD => set_once(&mut period, u32_of(v)?)?,
            _ => return Err(Error::InvalidFormat),
        }
    }
    TotpConfig::new(
        secret.ok_or(Error::InvalidFormat)?,
        alg.ok_or(Error::InvalidFormat)?,
        digits.ok_or(Error::InvalidFormat)?,
        period.ok_or(Error::InvalidFormat)?,
    )
    .map_err(|_| Error::InvalidFormat)
}

fn decode_entry(buf: &[u8], version: u16) -> Result<Entry> {
    let mut id = None;
    let (mut title, mut user, mut pass, mut url, mut notes) = (None, None, None, None, None);
    let (mut created, mut modified, mut totp) = (None, None, None);
    let (mut kind, mut host) = (None, None);
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let (tag, v) = r.record()?;
        match tag {
            E_KIND if version >= INNER_VERSION => {
                set_once(&mut kind, EntryKind::from_u8(fixed::<1>(v)?[0])?)?;
            }
            E_HOST if version >= INNER_VERSION => set_once(&mut host, text(v)?)?,
            E_ID => set_once(&mut id, fixed::<16>(v)?)?,
            E_TITLE => set_once(&mut title, text(v)?)?,
            E_USERNAME => set_once(&mut user, text(v)?)?,
            E_PASSWORD => set_once(&mut pass, text(v)?)?,
            E_URL => set_once(&mut url, text(v)?)?,
            E_NOTES => set_once(&mut notes, text(v)?)?,
            E_CREATED => set_once(&mut created, u64_of(v)?)?,
            E_MODIFIED => set_once(&mut modified, u64_of(v)?)?,
            E_TOTP => set_once(&mut totp, decode_totp(v)?)?,
            _ => return Err(Error::InvalidFormat),
        }
    }
    let entry = Entry {
        id: id.ok_or(Error::InvalidFormat)?,
        // v2 writes the kind on every entry; a v2 entry without one is malformed.
        kind: if version >= INNER_VERSION {
            kind.ok_or(Error::InvalidFormat)?
        } else {
            EntryKind::Web
        },
        host: host.unwrap_or_default(),
        title: title.ok_or(Error::InvalidFormat)?,
        username: user.unwrap_or_default(),
        password: pass.unwrap_or_default(),
        url: url.unwrap_or_default(),
        notes: notes.unwrap_or_default(),
        totp,
        created: created.ok_or(Error::InvalidFormat)?,
        modified: modified.ok_or(Error::InvalidFormat)?,
    };
    entry.validate().map_err(|_| Error::InvalidFormat)?;
    Ok(entry)
}

/// Parse a decrypted plaintext buffer.
pub(crate) fn decode(buf: &[u8]) -> Result<Vault> {
    let mut r = Reader::new(buf);
    let version = r.u16()?;
    if version != INNER_VERSION && version != INNER_VERSION_V1 {
        return Err(Error::UnsupportedVersion);
    }
    let mut settings = None;
    let mut vault = Vault::default();
    let mut ids = HashSet::new();
    while !r.is_empty() {
        let (tag, v) = r.record()?;
        match tag {
            T_SETTINGS => set_once(&mut settings, decode_settings(v)?)?,
            T_ENTRY => {
                if vault.entries.len() >= MAX_ENTRIES {
                    return Err(Error::LimitExceeded);
                }
                let e = decode_entry(v, version)?;
                if !ids.insert(e.id) {
                    return Err(Error::InvalidFormat);
                }
                vault.entries.push(e);
            }
            T_PADDING if r.is_empty() => {}
            _ => return Err(Error::InvalidFormat),
        }
    }
    vault.settings = settings.ok_or(Error::InvalidFormat)?;
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_vault() -> Vault {
        let mut v = Vault::default();
        let mut e = Entry::new("GitHub").unwrap();
        e.username = "alice".into();
        e.password = "p@ss wörd 🔑".into();
        e.url = "https://github.com".into();
        e.notes = "line1\nline2".into();
        e.totp = Some(TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap());
        v.upsert(e).unwrap();
        v.upsert(Entry::new("Empty").unwrap()).unwrap();
        let mut srv = Entry::new("Prod RDP").unwrap();
        srv.kind = EntryKind::Server;
        srv.host = "srv-01.example.net:3390".into();
        srv.username = "CORP-admin".into();
        srv.password = "s3cret".into();
        v.upsert(srv).unwrap();
        v.settings.auto_lock_secs = 600;
        v
    }

    #[test]
    fn roundtrip_and_padding() {
        let v = sample_vault();
        let buf = encode(&v).unwrap();
        assert_eq!(buf.len() % PAD_BLOCK, 0);
        assert_eq!(decode(buf.as_slice()).unwrap(), v);
    }

    #[test]
    fn rejects_trailing_garbage_and_truncation() {
        let buf = encode(&sample_vault()).unwrap();
        let mut extra = buf.as_slice().to_vec();
        extra.push(0);
        assert!(decode(&extra).is_err());
        for cut in [0, 1, 2, 10, buf.len() / 2, buf.len() - 1] {
            assert!(decode(&buf.as_slice()[..cut]).is_err(), "cut at {cut} should fail");
        }
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut v = sample_vault();
        let id = v.entries[0].id;
        v.entries[1].id = id;
        let buf = encode(&v).unwrap();
        assert!(decode(buf.as_slice()).is_err());
    }

    #[test]
    fn both_kinds_roundtrip() {
        let v = decode(encode(&sample_vault()).unwrap().as_slice()).unwrap();
        let srv = v.entries.iter().find(|e| e.title == "Prod RDP").unwrap();
        assert_eq!(srv.kind, EntryKind::Server);
        assert_eq!(srv.host, "srv-01.example.net:3390");
        assert!(v.entries.iter().any(|e| e.kind == EntryKind::Web));
    }

    /// Hand-built inner buffer with one entry; `with_kind` adds the v2 kind record.
    fn hand_built(version: u16, kind_code: Option<u8>) -> Vec<u8> {
        let mut entry = SecureBuf::with_capacity(128);
        put_record(&mut entry, E_ID, &[7u8; 16]).unwrap();
        if let Some(code) = kind_code {
            put_record(&mut entry, E_KIND, &[code]).unwrap();
        }
        put_record(&mut entry, E_TITLE, b"x").unwrap();
        put_record(&mut entry, E_CREATED, &1u64.to_le_bytes()).unwrap();
        put_record(&mut entry, E_MODIFIED, &1u64.to_le_bytes()).unwrap();
        let mut w = SecureBuf::with_capacity(256);
        w.put(&version.to_le_bytes());
        put_record(&mut w, T_SETTINGS, encode_settings(&Settings::default()).unwrap().as_slice())
            .unwrap();
        put_record(&mut w, T_ENTRY, entry.as_slice()).unwrap();
        w.as_slice().to_vec()
    }

    #[test]
    fn unknown_entry_kind_is_rejected() {
        assert!(decode(&hand_built(INNER_VERSION, Some(0))).is_ok());
        assert!(decode(&hand_built(INNER_VERSION, Some(2))).is_err());
        assert!(decode(&hand_built(INNER_VERSION, Some(255))).is_err());
        // v2 requires the kind on every entry.
        assert!(decode(&hand_built(INNER_VERSION, None)).is_err());
    }

    #[test]
    fn v1_inner_format_still_opens_as_websites() {
        let v = decode(&hand_built(INNER_VERSION_V1, None)).unwrap();
        assert_eq!(v.entries[0].kind, EntryKind::Web);
        // The kind tag does not exist in v1.
        assert!(decode(&hand_built(INNER_VERSION_V1, Some(0))).is_err());
        // Anything newer is refused.
        assert!(matches!(decode(&hand_built(3, Some(0))), Err(Error::UnsupportedVersion)));
    }

    fn arb_text() -> impl Strategy<Value = String> {
        ".{0,64}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn roundtrip_arbitrary(
            fields in proptest::collection::vec((arb_text(), arb_text(), arb_text(), arb_text(), arb_text()), 0..8),
            auto in Settings::AUTO_LOCK_RANGE,
            clip in Settings::CLIPBOARD_RANGE,
            lock in any::<bool>(),
        ) {
            let mut v = Vault::default();
            v.settings = Settings { auto_lock_secs: auto, clipboard_clear_secs: clip, lock_on_minimize: lock };
            for (t, u, p, url, n) in fields {
                let mut e = Entry::new(format!("x{t}")).unwrap();
                e.username = u; e.password = p; e.url = url; e.notes = n;
                v.upsert(e).unwrap();
            }
            let buf = encode(&v).unwrap();
            prop_assert_eq!(decode(buf.as_slice()).unwrap(), v);
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode(&data);
        }

        #[test]
        fn bitflips_never_panic(pos in 0usize..4096, bit in 0u8..8) {
            let buf = encode(&sample_vault()).unwrap();
            let mut data = buf.as_slice().to_vec();
            if let Some(b) = data.get_mut(pos) { *b ^= 1 << bit; }
            let _ = decode(&data);
        }
    }
}
