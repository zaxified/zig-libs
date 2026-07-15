// SPDX-License-Identifier: MIT
//! Shared `RoundingMode` enum — split out of `root.zig` so both the
//! fixed-scale `Decimal` (root.zig) and the arbitrary-precision `BigDecimal`
//! (big.zig) can import it without a circular file dependency.

/// IEEE 754-2008 / General Decimal Arithmetic rounding modes. Clean-room from
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

    /// The IEEE 754 / GDA default mode.
    pub const default: RoundingMode = .half_even;
};
