//! Password and passphrase generator. Uses only the OS CSPRNG with
//! bias-free rejection sampling.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::rng;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &[u8] = b"Il1O0o";

pub const PASSWORD_LEN_RANGE: std::ops::RangeInclusive<usize> = 8..=128;
pub const PASSPHRASE_WORDS_RANGE: std::ops::RangeInclusive<usize> = 4..=20;

/// EFF large wordlist (7776 words), embedded at compile time.
/// SHA-256 of the file: ADDD35536511597A02FA0A9FF1E5284677B8883B83E986E43F15A3DB996B903E
const EFF_WORDLIST: &str = include_str!("../assets/eff_large_wordlist.txt");

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_WORDLIST
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(_, w)| w.trim()))
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// Options for random character passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // One independent UI toggle per field.
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    fn sets(&self) -> Vec<Vec<u8>> {
        [
            (self.lowercase, LOWER),
            (self.uppercase, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| {
            set.iter()
                .copied()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(c)))
                .collect()
        })
        .collect()
    }

    /// Approximate entropy in bits.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let pool: usize = self.sets().iter().map(Vec::len).sum();
        if pool == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let bits = self.length as f64 * (pool as f64).log2();
        bits
    }
}

/// Generate a random password. Every selected character class is
/// guaranteed to appear (by rejection, which keeps the distribution uniform
/// over all valid passwords).
///
/// # Errors
/// [`Error::InvalidInput`] for invalid options, [`Error::Rng`] on RNG failure.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    if !PASSWORD_LEN_RANGE.contains(&opts.length) {
        return Err(Error::InvalidInput("password length must be 8-128"));
    }
    let sets = opts.sets();
    if sets.is_empty() {
        return Err(Error::InvalidInput("select at least one character set"));
    }
    let pool: Vec<u8> = sets.iter().flatten().copied().collect();

    for _ in 0..1000 {
        let mut out = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            let c = *pool.get(rng::below(pool.len())?).ok_or(Error::Rng)?;
            out.push(char::from(c));
        }
        let all_present = sets.iter().all(|set| out.bytes().any(|b| set.contains(&b)));
        if all_present {
            return Ok(out);
        }
    }
    Err(Error::Rng)
}

/// Options for diceware-style passphrases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: char,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self { words: 6, separator: '-', capitalize: true, include_number: true }
    }
}

impl PassphraseOptions {
    /// Entropy in bits (separator and capitalization add none).
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let words = self.words as f64;
        #[allow(clippy::cast_precision_loss)]
        let list = wordlist().len() as f64;
        let mut bits = words * list.log2();
        if self.include_number {
            bits += (10.0 * words).log2();
        }
        bits
    }
}

/// Generate a passphrase from the EFF large wordlist.
///
/// # Errors
/// [`Error::InvalidInput`] for invalid options, [`Error::Rng`] on RNG failure.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !PASSPHRASE_WORDS_RANGE.contains(&opts.words) {
        return Err(Error::InvalidInput("word count must be 4-20"));
    }
    let list = wordlist();
    let number_at = if opts.include_number { Some(rng::below(opts.words)?) } else { None };
    let mut out = Zeroizing::new(String::with_capacity(opts.words * 12));
    for i in 0..opts.words {
        if i > 0 {
            out.push(opts.separator);
        }
        let word = *list.get(rng::below(list.len())?).ok_or(Error::Rng)?;
        let mut chars = word.chars();
        if let (true, Some(first)) = (opts.capitalize, chars.next()) {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        } else {
            out.push_str(word);
        }
        if number_at == Some(i) {
            let d = u32::try_from(rng::below(10)?).map_err(|_| Error::Rng)?;
            out.push(char::from_digit(d, 10).ok_or(Error::Rng)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_complete() {
        let w = wordlist();
        assert_eq!(w.len(), 7776);
        assert_eq!(w[0], "abacus");
        assert!(w.iter().all(|x| x.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
    }

    #[test]
    fn password_respects_options() {
        for _ in 0..200 {
            let opts =
                PasswordOptions { length: 12, exclude_ambiguous: true, ..Default::default() };
            let p = generate_password(&opts).unwrap();
            assert_eq!(p.len(), 12);
            assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(p.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(p.bytes().any(|b| b.is_ascii_digit()));
            assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
            assert!(!p.bytes().any(|b| AMBIGUOUS.contains(&b)));
        }
        let digits_only = PasswordOptions {
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&digits_only).unwrap().bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn password_rejects_bad_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&none).is_err());
        assert!(generate_password(&PasswordOptions { length: 4, ..Default::default() }).is_err());
        assert!(generate_password(&PasswordOptions { length: 500, ..Default::default() }).is_err());
    }

    #[test]
    fn passphrase_shape() {
        let opts = PassphraseOptions::default();
        let p = generate_passphrase(&opts).unwrap();
        assert_eq!(p.split('-').count(), 6);
        assert_eq!(p.bytes().filter(u8::is_ascii_digit).count(), 1);
        assert!(opts.entropy_bits() > 77.0);
    }

    #[test]
    fn outputs_differ() {
        let a = generate_password(&PasswordOptions::default()).unwrap();
        let b = generate_password(&PasswordOptions::default()).unwrap();
        assert_ne!(*a, *b);
    }
}
