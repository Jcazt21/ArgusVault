//! RFC 6238 TOTP, implemented in-house on top of the `RustCrypto` HMAC crates.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::base32;
use crate::error::{Error, Result};

/// Maximum accepted raw secret length.
pub const MAX_SECRET_LEN: usize = 256;

/// HMAC algorithm used for TOTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
            Self::Sha512 => 3,
        }
    }

    pub(crate) fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha512),
            _ => Err(Error::InvalidFormat),
        }
    }
}

/// TOTP configuration for one entry. The secret is wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TotpConfig {
    secret: Vec<u8>,
    #[zeroize(skip)]
    algorithm: Algorithm,
    digits: u8,
    period: u32,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl TotpConfig {
    /// Build and validate a configuration.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the secret is empty/too long, `digits` is
    /// not 6..=8 or `period` is not 1..=300.
    pub fn new(
        mut secret: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        digits: u8,
        period: u32,
    ) -> Result<Self> {
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(Error::InvalidInput("TOTP secret length"));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidInput("TOTP digits must be 6-8"));
        }
        if !(1..=300).contains(&period) {
            return Err(Error::InvalidInput("TOTP period must be 1-300 s"));
        }
        Ok(Self { secret: std::mem::take(&mut *secret), algorithm, digits, period })
    }

    /// Parse either a bare Base32 secret (SHA-1, 6 digits, 30 s) or an
    /// `otpauth://totp/...` URI.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] on malformed input.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.len() > 2048 {
            return Err(Error::InvalidInput("TOTP input too long"));
        }
        if input.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("otpauth://")) {
            return Self::parse_uri(input);
        }
        Self::new(base32::decode(input)?, Algorithm::Sha1, 6, 30)
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let rest = uri.get(10..).ok_or(Error::InvalidInput("otpauth URI"))?;
        let (kind, rest) = rest.split_once('/').ok_or(Error::InvalidInput("otpauth URI"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidInput("only TOTP is supported"));
        }
        let (_label, query) = rest.split_once('?').ok_or(Error::InvalidInput("otpauth URI"))?;

        let mut secret = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6u8;
        let mut period = 30u32;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k.eq_ignore_ascii_case("secret") {
                let cleaned =
                    Zeroizing::new(v.replace("%3D", "=").replace("%3d", "=").replace("%20", ""));
                secret = Some(base32::decode(&cleaned)?);
            } else if k.eq_ignore_ascii_case("algorithm") {
                algorithm = if v.eq_ignore_ascii_case("SHA1") {
                    Algorithm::Sha1
                } else if v.eq_ignore_ascii_case("SHA256") {
                    Algorithm::Sha256
                } else if v.eq_ignore_ascii_case("SHA512") {
                    Algorithm::Sha512
                } else {
                    return Err(Error::InvalidInput("unknown TOTP algorithm"));
                };
            } else if k.eq_ignore_ascii_case("digits") {
                digits = v.parse().map_err(|_| Error::InvalidInput("TOTP digits"))?;
            } else if k.eq_ignore_ascii_case("period") {
                period = v.parse().map_err(|_| Error::InvalidInput("TOTP period"))?;
            }
        }
        let secret = secret.ok_or(Error::InvalidInput("otpauth URI has no secret"))?;
        Self::new(secret, algorithm, digits, period)
    }

    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[must_use]
    pub fn digits(&self) -> u8 {
        self.digits
    }

    #[must_use]
    pub fn period(&self) -> u32 {
        self.period
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Secret as Base32, for display in the entry editor.
    #[must_use]
    pub fn secret_base32(&self) -> Zeroizing<String> {
        base32::encode(&self.secret)
    }

    /// Seconds until the current code expires.
    #[must_use]
    pub fn seconds_remaining(&self, unix_time: u64) -> u32 {
        let p = u64::from(self.period);
        // (p - t % p) is in 1..=p <= 300, always fits in u32.
        u32::try_from(p - unix_time % p).unwrap_or(self.period)
    }

    /// Code valid at `unix_time`.
    ///
    /// # Errors
    /// Only on internal HMAC failure, which cannot happen for valid configs.
    pub fn code_at(&self, unix_time: u64) -> Result<Zeroizing<String>> {
        let counter = (unix_time / u64::from(self.period)).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac::<Hmac<sha1::Sha1>>(&self.secret, &counter)?,
            Algorithm::Sha256 => hmac::<Hmac<sha2::Sha256>>(&self.secret, &counter)?,
            Algorithm::Sha512 => hmac::<Hmac<sha2::Sha512>>(&self.secret, &counter)?,
        };
        let last = *digest.last().ok_or(Error::Kdf)?;
        let offset = usize::from(last & 0x0f);
        let chunk: [u8; 4] =
            digest.get(offset..offset + 4).and_then(|s| s.try_into().ok()).ok_or(Error::Kdf)?;
        let bin = u32::from_be_bytes(chunk) & 0x7fff_ffff;
        let code = bin % 10u32.pow(u32::from(self.digits));
        Ok(Zeroizing::new(format!("{code:0width$}", width = usize::from(self.digits))))
    }
}

fn hmac<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::Kdf)?;
    m.update(msg);
    Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(secret: &[u8], alg: Algorithm) -> TotpConfig {
        TotpConfig::new(Zeroizing::new(secret.to_vec()), alg, 8, 30).unwrap()
    }

    /// RFC 6238 Appendix B test vectors.
    #[test]
    fn rfc6238_vectors() {
        let s1 = b"12345678901234567890";
        let s256 = b"12345678901234567890123456789012";
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in cases {
            assert_eq!(cfg(s1, Algorithm::Sha1).code_at(t).unwrap().as_str(), c1);
            assert_eq!(cfg(s256, Algorithm::Sha256).code_at(t).unwrap().as_str(), c256);
            assert_eq!(cfg(s512, Algorithm::Sha512).code_at(t).unwrap().as_str(), c512);
        }
    }

    #[test]
    fn parses_uri_and_bare_secret() {
        let c = TotpConfig::parse(
            "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(c.algorithm(), Algorithm::Sha256);
        assert_eq!(c.digits(), 8);
        assert_eq!(c.period(), 60);
        assert_eq!(c.secret_base32().as_str(), "JBSWY3DPEHPK3PXP");

        let bare = TotpConfig::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(bare.digits(), 6);
        assert_eq!(bare.period(), 30);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(TotpConfig::parse("otpauth://hotp/x?secret=JBSWY3DP").is_err());
        assert!(TotpConfig::parse("otpauth://totp/x?issuer=a").is_err());
        assert!(TotpConfig::parse("otpauth://totp/x?secret=JBSWY3DP&digits=9").is_err());
        assert!(TotpConfig::parse("otpauth://totp/x?secret=JBSWY3DP&period=0").is_err());
        assert!(TotpConfig::parse("not base32!").is_err());
    }

    #[test]
    fn remaining_seconds() {
        let c = cfg(b"12345678901234567890", Algorithm::Sha1);
        assert_eq!(c.seconds_remaining(0), 30);
        assert_eq!(c.seconds_remaining(29), 1);
        assert_eq!(c.seconds_remaining(30), 30);
    }

    #[test]
    fn debug_is_redacted() {
        let c = cfg(b"supersecretvalue", Algorithm::Sha1);
        assert!(!format!("{c:?}").contains("supersecret"));
    }
}
