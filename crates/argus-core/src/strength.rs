//! Lightweight master-password strength estimate (no external deps).
//!
//! This is a heuristic for UI feedback only: it estimates the character
//! pool, then penalizes repetition and common sequences.

/// Coarse strength level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl Strength {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::VeryWeak => "Very weak",
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very strong",
        }
    }

    /// 0..=4, for progress bars.
    #[must_use]
    pub fn score(self) -> u8 {
        self as u8
    }
}

/// Estimated entropy in bits.
#[must_use]
pub fn estimate_bits(password: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut symbol, mut other) =
        (false, false, false, false, false);
    for c in password.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            c if c.is_ascii() => symbol = true,
            _ => other = true,
        }
    }
    let pool = u32::from(lower) * 26
        + u32::from(upper) * 26
        + u32::from(digit) * 10
        + u32::from(symbol) * 33
        + u32::from(other) * 100;
    if pool == 0 {
        return 0.0;
    }

    // Effective length: characters that repeat the previous one or continue
    // an ascending/descending run count only half.
    let mut effective = 0.0f64;
    let mut prev: Option<u32> = None;
    for c in password.chars() {
        let cur = u32::from(c);
        let weak = prev.is_some_and(|p| p == cur || p + 1 == cur || cur + 1 == p);
        effective += if weak { 0.5 } else { 1.0 };
        prev = Some(cur);
    }
    effective * f64::from(pool).log2()
}

/// Map a password to a [`Strength`].
#[must_use]
pub fn evaluate(password: &str) -> Strength {
    let bits = estimate_bits(password);
    if bits < 40.0 {
        Strength::VeryWeak
    } else if bits < 60.0 {
        Strength::Weak
    } else if bits < 80.0 {
        Strength::Fair
    } else if bits < 100.0 {
        Strength::Strong
    } else {
        Strength::VeryStrong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert_eq!(evaluate(""), Strength::VeryWeak);
        assert_eq!(evaluate("aaaaaaaa"), Strength::VeryWeak);
        assert!(evaluate("abcdefgh12345678") < evaluate("q7#Rv!m2Lp9@xZ4w"));
        assert!(evaluate("Correct-Horse-Battery-Staple-Orbit-Lantern9") >= Strength::Strong);
    }
}
