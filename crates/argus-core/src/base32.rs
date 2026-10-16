//! RFC 4648 Base32 (used for TOTP secrets).

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Upper bound on accepted input to keep work bounded.
pub const MAX_INPUT_LEN: usize = 1024;

/// Decode Base32. Case-insensitive; spaces, dashes and trailing `=` padding
/// are ignored.
///
/// # Errors
/// [`Error::InvalidInput`] on invalid characters, data after padding,
/// empty output or oversized input.
pub fn decode(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > MAX_INPUT_LEN {
        return Err(Error::InvalidInput("base32 input too long"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8 + 1));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = false;
    for c in input.bytes() {
        let v = match c {
            b' ' | b'-' => continue,
            b'=' => {
                padding = true;
                continue;
            }
            _ if padding => return Err(Error::InvalidInput("base32 data after padding")),
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(Error::InvalidInput("invalid base32 character")),
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("empty base32 secret"));
    }
    Ok(out)
}

/// Encode bytes as unpadded uppercase Base32.
#[must_use]
pub fn encode(data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(data.len().div_ceil(5) * 8));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: [(&str, &str); 6] = [
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];
        for (plain, enc) in cases {
            assert_eq!(decode(enc).unwrap().as_slice(), plain.as_bytes());
            assert_eq!(encode(plain.as_bytes()).as_str(), enc.trim_end_matches('='));
        }
    }

    #[test]
    fn lenient_formatting_and_errors() {
        assert_eq!(decode("mzxw 6ytb-oi").unwrap().as_slice(), b"foobar");
        assert!(decode("MZ1W").is_err());
        assert!(decode("MY==MY").is_err());
        assert!(decode("").is_err());
        assert!(decode(&"A".repeat(MAX_INPUT_LEN + 1)).is_err());
    }

    proptest! {
        #[test]
        fn roundtrip(data in proptest::collection::vec(any::<u8>(), 1..200)) {
            let enc = encode(&data);
            let dec = decode(&enc).unwrap();
            prop_assert_eq!(dec.as_slice(), data.as_slice());
        }

        #[test]
        fn never_panics(s in ".{0,300}") {
            let _ = decode(&s);
        }
    }
}
