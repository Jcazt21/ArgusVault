//! Entry points for `cargo-fuzz`. Only compiled with `--features fuzzing`.

/// Fuzz the outer file parser (no KDF involved).
pub fn parse_file(data: &[u8]) {
    let _ = crate::format::parse_file(data);
}

/// Fuzz the inner plaintext decoder, and check encode/decode stability.
pub fn decode_inner(data: &[u8]) {
    if let Ok(v) = crate::codec::decode(data) {
        let re = crate::codec::encode(&v).ok();
        let again = re.as_ref().and_then(|b| crate::codec::decode(b.as_slice()).ok());
        assert!(again.is_some(), "decoded vault must re-encode and re-decode");
    }
}

/// Fuzz TOTP / Base32 parsing.
pub fn parse_totp(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(c) = crate::totp::TotpConfig::parse(s) {
            let _ = c.code_at(1_700_000_000);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    #[test]
    fn dump_fuzz_seeds() {
        use std::fs;
        use std::path::Path;

        let corpus_dir = Path::new("../../fuzz/corpus");
        if !corpus_dir.exists() {
            let _ = fs::create_dir_all(corpus_dir);
        }

        // 1. decode_inner seeds
        let decode_inner_dir = corpus_dir.join("decode_inner");
        let _ = fs::create_dir_all(&decode_inner_dir);
        let empty_vault = crate::model::Vault::default();
        if let Ok(enc_empty) = crate::codec::encode(&empty_vault) {
            let _ = fs::write(decode_inner_dir.join("seed_empty.bin"), enc_empty.as_slice());
        }

        let mut sample_vault = crate::model::Vault::default();
        if let (Ok(mut entry1), Ok(mut entry2)) =
            (crate::model::Entry::new("Web Example"), crate::model::Entry::new("Server Example"))
        {
            entry1.username = "user@test.com".into();
            entry1.password = "SecretPass123!".into();
            entry1.url = "https://example.com".into();

            entry2.kind = crate::model::EntryKind::Server;
            entry2.host = "192.168.1.100".into();
            entry2.username = "admin".into();
            entry2.password = "S3rv3rP@ss!".into();

            if sample_vault.upsert(entry1).is_ok() && sample_vault.upsert(entry2).is_ok() {
                if let Ok(enc_sample) = crate::codec::encode(&sample_vault) {
                    let _ =
                        fs::write(decode_inner_dir.join("seed_sample.bin"), enc_sample.as_slice());
                }
            }
        }

        // 2. parse_file seeds
        let parse_file_dir = corpus_dir.join("parse_file");
        let _ = fs::create_dir_all(&parse_file_dir);
        let mut valid_file = Vec::new();
        valid_file.extend_from_slice(&crate::format::MAGIC);
        valid_file.extend_from_slice(&1u16.to_le_bytes());
        valid_file.push(crate::format::KDF_ARGON2ID);
        valid_file.extend_from_slice(&(512 * 1024u32).to_le_bytes());
        valid_file.extend_from_slice(&4u32.to_le_bytes());
        valid_file.extend_from_slice(&4u32.to_le_bytes());
        valid_file.extend_from_slice(&[0x42u8; crate::format::SALT_LEN]);
        valid_file.extend_from_slice(&[0x24u8; crate::format::NONCE_LEN]);
        let mock_ct_len = 16u32;
        valid_file.extend_from_slice(&mock_ct_len.to_le_bytes());
        valid_file.extend_from_slice(&[0xAAu8; 16]);
        let _ = fs::write(parse_file_dir.join("seed_valid_header.bin"), &valid_file);
    }
}
