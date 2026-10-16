//! Thin wrapper around the operating system CSPRNG (`BCryptGenRandom` on
//! Windows via `getrandom`). No userspace PRNG is used anywhere.

use crate::error::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Rng)
}

/// Uniform random `u32`.
fn next_u32() -> Result<u32> {
    let mut b = [0u8; 4];
    fill(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Uniform random integer in `0..n` using rejection sampling
/// (no modulo bias).
pub(crate) fn below(n: usize) -> Result<usize> {
    let n32 = u32::try_from(n).map_err(|_| Error::InvalidInput("range too large"))?;
    if n32 == 0 {
        return Err(Error::InvalidInput("empty range"));
    }
    let n64 = u64::from(n32);
    // Largest multiple of n that fits in 2^32.
    let limit = ((1u64 << 32) / n64) * n64;
    loop {
        let r = u64::from(next_u32()?);
        if r < limit {
            // r % n64 < n32 <= usize::MAX, conversion cannot fail.
            return usize::try_from(r % n64).map_err(|_| Error::Rng);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range() {
        for n in [1usize, 2, 3, 7, 10, 62, 94, 7776] {
            for _ in 0..500 {
                assert!(below(n).unwrap() < n);
            }
        }
    }

    #[test]
    fn below_rejects_zero() {
        assert!(below(0).is_err());
    }

    #[test]
    fn below_is_roughly_uniform() {
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            counts[below(6).unwrap()] += 1;
        }
        for c in counts {
            assert!((9_000..11_000).contains(&c), "skewed distribution: {counts:?}");
        }
    }
}
