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
