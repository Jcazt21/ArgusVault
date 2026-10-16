//! Pick Argon2id costs that fit *this* machine, and check a vault fits before opening it.
//!
//! A fixed cost is a compromise: too cheap on a big PC, too heavy on a small one. When a vault is
//! created (or its credentials change) Argus looks at how much memory is free right now, measures
//! how fast this CPU runs Argon2id, and picks the **largest memory size that fits both**:
//!
//! * at most a quarter of the memory that is free (the derivation must not starve the rest of the
//!   system or be pushed to the page file, where key material could be written to disk), and
//! * with the minimum number of passes it still finishes within [`CEILING`].
//!
//! Sizes are powers of two from 64 MiB to 2 GiB. The number of passes is then raised until a
//! derivation takes about [`TARGET`]. The result is never below [`KdfParams::DEFAULT`] unless the
//! machine has too little free memory for it, in which case the costs are reduced to what fits and
//! [`Calibration::reduced`] says so, so the UI can warn.
//!
//! The chosen costs are stored in the (authenticated) header, so the vault opens anywhere that has
//! enough free memory ([`required_free_memory`]); opening never calibrates.

use std::time::{Duration, Instant};

use crate::error::Result;
use crate::format::{KdfParams, SALT_LEN};
use crate::kdf;

/// Time one key derivation should take on the machine that creates the vault.
pub const TARGET: Duration = Duration::from_millis(1500);
/// A memory size is only chosen if the minimum number of passes at that size stays under this.
pub const CEILING: Duration = Duration::from_millis(2000);
/// Most passes calibration will choose. Bounds the unlock time if the vault is later opened on a
/// much slower machine than the one that created it.
pub const MAX_T_COST: u32 = 10;
/// Largest share of the free memory a derivation may use, as a divisor (1/4).
pub const FREE_MEMORY_DIVISOR: u64 = 4;
/// Memory sizes calibration chooses from, largest first (KiB): 2 GiB down to 64 MiB.
const TIERS_KIB: [u32; 6] =
    [2048 * 1024, 1024 * 1024, 512 * 1024, 256 * 1024, 128 * 1024, 64 * 1024];
/// Largest size used to time the probe (KiB). Bigger sizes are extrapolated from it.
const PROBE_MAX_KIB: u32 = 256 * 1024;
/// Safety margin (percent) added when extrapolating beyond the probe size: memory-bound code does
/// not scale perfectly linearly.
const EXTRAPOLATION_MARGIN_PERCENT: u128 = 115;

/// Costs chosen for a new vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibration {
    pub params: KdfParams,
    /// The machine did not have enough free memory for [`KdfParams::DEFAULT`], so the vault is
    /// weaker than usual. Re-key it (change the master password) on a machine with more memory.
    pub reduced: bool,
}

/// Free memory (bytes) a vault with these costs needs in order to open: its Argon2 memory plus a
/// quarter on top for the process itself and bookkeeping.
#[must_use]
pub fn required_free_memory(params: &KdfParams) -> u64 {
    let bytes = u64::from(params.m_kib) * 1024;
    bytes + bytes / 4
}

/// Costs for a new vault on this machine. Runs one short probe derivation (a fraction of a
/// second), so call it off the UI thread.
///
/// `free_memory` is the memory (bytes) that can be used right now without paging; `None` (unknown)
/// is treated as "enough for [`KdfParams::DEFAULT`], nothing more".
///
/// # Errors
/// Only if the probe derivation itself fails (it cannot for valid parameters).
pub fn for_this_machine(free_memory: Option<u64>) -> Result<Calibration> {
    choose(free_memory, |params| {
        let start = Instant::now();
        kdf::derive_key("argus calibration probe", None, &[0u8; SALT_LEN], &params)?;
        Ok(start.elapsed())
    })
}

/// The calibration rule, with the clock injected so it can be tested without running Argon2.
fn choose(
    free_memory: Option<u64>,
    mut measure: impl FnMut(KdfParams) -> Result<Duration>,
) -> Result<Calibration> {
    let base = KdfParams::DEFAULT;
    let budget_kib =
        free_memory.map_or(u64::from(base.m_kib), |free| free / FREE_MEMORY_DIVISOR / 1024);

    // Time one derivation (two passes, the format's minimum) at a size that fits the budget.
    let probe_kib = u32::try_from(budget_kib.min(u64::from(PROBE_MAX_KIB)))
        .unwrap_or(PROBE_MAX_KIB)
        .max(KdfParams::MIN.m_kib);
    let probe = KdfParams { m_kib: probe_kib, t_cost: 2, ..base };
    let micros_per_pass = (measure(probe)?.as_micros() / 2).max(1);
    // Cost of one pass over `m_kib`, in microseconds.
    let pass_micros = |m_kib: u32| -> u128 {
        let scaled = micros_per_pass * u128::from(m_kib) / u128::from(probe_kib);
        let scaled =
            if m_kib > probe_kib { scaled * EXTRAPOLATION_MARGIN_PERCENT / 100 } else { scaled };
        scaled.max(1)
    };

    let fits_budget = |m_kib: u32| u64::from(m_kib) <= budget_kib;
    let fits_time =
        |m_kib: u32| pass_micros(m_kib) * u128::from(base.t_cost) <= CEILING.as_micros();

    // Largest default-or-bigger size that fits both memory and time; else the default if the memory
    // allows (a slow machine just takes its minimum number of passes); else whatever memory allows.
    let m_kib = TIERS_KIB
        .iter()
        .copied()
        .filter(|&m| m >= base.m_kib)
        .find(|&m| fits_budget(m) && fits_time(m))
        .or_else(|| fits_budget(base.m_kib).then_some(base.m_kib))
        .or_else(|| TIERS_KIB.iter().copied().find(|&m| fits_budget(m)))
        .unwrap_or(KdfParams::MIN.m_kib);

    let passes = TARGET.as_micros() / pass_micros(m_kib);
    let t_cost = u32::try_from(passes).unwrap_or(MAX_T_COST).clamp(base.t_cost, MAX_T_COST);
    Ok(Calibration {
        params: KdfParams { m_kib, t_cost, p_lanes: base.p_lanes },
        reduced: m_kib < base.m_kib,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    /// A fake machine where one pass over 512 MiB takes `pass_ms`.
    fn machine(pass_ms: u64) -> impl FnMut(KdfParams) -> Result<Duration> {
        move |p| {
            let micros = pass_ms * 1000 * u64::from(p.m_kib) / u64::from(KdfParams::DEFAULT.m_kib)
                * u64::from(p.t_cost);
            Ok(Duration::from_micros(micros))
        }
    }

    fn pick(free: Option<u64>, pass_ms: u64) -> Calibration {
        let c = choose(free, machine(pass_ms)).unwrap();
        assert!(c.params.validate().is_ok(), "{c:?}");
        c
    }

    #[test]
    fn plenty_of_memory_and_a_fast_cpu_use_the_biggest_size() {
        // 16 GiB free -> 4 GiB budget; 2 GiB at ~40 ms/pass * 4 * 1.15 stays under the ceiling.
        let c = pick(Some(16 * GIB), 10);
        assert_eq!(c.params.m_kib, 2048 * 1024);
        assert!(!c.reduced);
        assert!(c.params.t_cost >= 4 && c.params.t_cost <= MAX_T_COST);
    }

    #[test]
    fn memory_follows_what_is_free() {
        let sizes: Vec<u32> = [32 * GIB, 8 * GIB, 6 * GIB, 4 * GIB, 2 * GIB]
            .iter()
            .map(|&free| pick(Some(free), 10).params.m_kib)
            .collect();
        // Budget is a quarter of what is free: 8 GiB, 2 GiB, 1.5 GiB, 1 GiB, 512 MiB.
        assert_eq!(sizes, vec![2048 * 1024, 2048 * 1024, 1024 * 1024, 1024 * 1024, 512 * 1024]);
    }

    #[test]
    fn a_slow_cpu_gets_less_memory_but_never_below_the_default() {
        // 300 ms per 512 MiB pass: 1 GiB would need 4 * 600 * 1.15 ms = 2.8 s > ceiling. The
        // 512 MiB pass is extrapolated from a 256 MiB probe (x2, +15%), so ~345 ms: 4 passes.
        let c = pick(Some(16 * GIB), 300);
        assert_eq!(c.params, KdfParams::DEFAULT);
        // A bit faster (250 ms): 1 GiB still does not fit the time, so 512 MiB gets an extra pass
        // to reach the target time instead.
        let c = pick(Some(16 * GIB), 250);
        assert_eq!(c.params, KdfParams { t_cost: 5, ..KdfParams::DEFAULT });
        // Faster still (200 ms): 1 GiB with the minimum 4 passes fits, so memory is preferred.
        let c = pick(Some(16 * GIB), 200);
        assert_eq!(c.params, KdfParams { m_kib: 1024 * 1024, ..KdfParams::DEFAULT });
        // 900 ms per pass: even the default exceeds the target; it is still used with t=4.
        let c = pick(Some(16 * GIB), 900);
        assert_eq!(c.params, KdfParams::DEFAULT);
        assert!(!c.reduced);
    }

    #[test]
    fn unknown_free_memory_means_the_default_and_no_more() {
        let c = pick(None, 10);
        assert_eq!(c.params.m_kib, KdfParams::DEFAULT.m_kib);
        assert!(!c.reduced);
    }

    #[test]
    fn little_free_memory_reduces_the_costs_and_says_so() {
        // 1 GiB free -> 256 MiB budget.
        let c = pick(Some(GIB), 10);
        assert_eq!(c.params.m_kib, 256 * 1024);
        assert!(c.reduced);
        assert!(c.params.t_cost > KdfParams::DEFAULT.t_cost, "fewer MiB are paid back in passes");
    }

    #[test]
    fn a_nearly_full_machine_bottoms_out_at_the_format_minimum() {
        let c = pick(Some(100 * MIB), 10);
        assert_eq!(c.params.m_kib, KdfParams::MIN.m_kib);
        assert!(c.reduced);
    }

    #[test]
    fn passes_are_capped() {
        assert_eq!(pick(Some(16 * GIB), 1).params.t_cost, MAX_T_COST);
    }

    #[test]
    fn probe_failure_is_reported() {
        assert!(choose(Some(GIB), |_| Err(crate::error::Error::Kdf)).is_err());
    }

    #[test]
    fn opening_needs_a_quarter_more_than_the_argon2_memory() {
        assert_eq!(required_free_memory(&KdfParams::DEFAULT), 640 * MIB);
        let big = KdfParams { m_kib: 2048 * 1024, ..KdfParams::DEFAULT };
        assert_eq!(required_free_memory(&big), 2560 * MIB);
    }

    /// Real measurement on this machine. Slow (runs Argon2 at full size), so it is opt-in:
    /// `cargo test -p argus-core --release calibrate::tests::measure -- --ignored --nocapture`.
    #[test]
    #[ignore = "slow: runs real Argon2id at full size"]
    #[allow(clippy::print_stdout)]
    fn measure_this_machine() {
        for free in [Some(2 * GIB), Some(8 * GIB), Some(32 * GIB)] {
            let c = for_this_machine(free).unwrap();
            let start = Instant::now();
            kdf::derive_key("x", None, &[1u8; SALT_LEN], &c.params).unwrap();
            println!("free {free:?}: {c:?} -> one unlock takes {:?}", start.elapsed());
        }
    }
}
