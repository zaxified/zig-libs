// SPDX-License-Identifier: MIT
//! Shared `RoundingMode` enum — split out of `root.zig` so both the
//! fixed-scale `Decimal` (root.zig) and the arbitrary-precision `BigDecimal`
//! (big.zig) can import it without a circular file dependency.

/// IEEE 754-2008 / General Decimal Arithmetic rounding modes (the eight GDA
/// modes: the seven of Java plus `round_05up`). Clean-room from
/// the published definitions (Java `BigDecimal.RoundingMode` javadoc, IBM GDA
/// spec, Python `decimal` docs) — every mode is exact on the discarded
/// remainder, no floating point involved.
pub const RoundingMode = enum {
    /// Round to nearest; a tie goes to the even neighbour (banker's rounding,
    /// IEEE 754 roundTiesToEven, the GDA default). 2.5 → 2, 3.5 → 4, -2.5 → -2.
    half_even,
    /// Round to nearest; a tie goes away from zero (Excel ROUND, "school"
    /// rounding). 2.5 → 3, -2.5 → -3.
    half_up,
    /// Round to nearest; a tie goes toward zero. 2.5 → 2, -2.5 → -2.
    half_down,
    /// Round away from zero: any nonzero discarded fraction increments the
    /// magnitude. 2.1 → 3, -2.1 → -3.
    up,
    /// Round toward zero: truncate the discarded fraction. 2.9 → 2, -2.9 → -2.
    down,
    /// Round toward +infinity. 2.1 → 3, -2.9 → -2.
    ceiling,
    /// Round toward -infinity. 2.9 → 2, -2.1 → -3.
    floor,
    /// GDA `ROUND_05UP` (Python `ROUND_05UP`): truncate toward zero, then round
    /// **away from zero** only if the last kept digit is 0 or 5; otherwise stay
    /// truncated. Never a tie-break: a discarded fraction decides nothing but
    /// "nonzero or not". 1.001 → 1.01 and 1.051 → 1.06 at 2 places (last kept
    /// digit 0, 5 → away), but 1.011 → 1.01 (last kept digit 1 → toward zero);
    /// -1.001 → -1.01. Exact results are never changed. Its use is a double
    /// rounding guard: rounding to `n + 1` digits with it first and then to `n`
    /// with any other mode gives the single-rounding result.
    round_05up,

    /// The IEEE 754 / GDA default mode.
    pub const default: RoundingMode = .half_even;
};
