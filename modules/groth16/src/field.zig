// SPDX-License-Identifier: MIT
//! Field helpers over BN254's scalar field `Fr` (imported from the sibling
//! `bn254` module — this module never re-implements the field arithmetic).
//! `Fr` is where the R1CS witness scalars, QAP polynomial coefficients, and
//! proof randomizers `r,s` all live. Everything here is small mechanical
//! sugar around `bn254.Fr`'s existing API (`fromBytes`/`pow`/`inv`/…), NOT
//! new field math.

const std = @import("std");
const bn254 = @import("bn254");

pub const Fr = bn254.Fr;

/// Builds an `Fr` from a small unsigned integer (big-endian into the low
/// 8 bytes of the 32-byte container). Used for domain sizes `n`, the
/// multiplicative generator `5`, and small test constants — none of which
/// approach `r`, so the `fromBytes` canonical-range check never trips.
pub fn frFromU64(v: u64) Fr {
    var b = [_]u8{0} ** 32;
    std.mem.writeInt(u64, b[24..32], v, .big);
    return Fr.fromBytes(b) catch unreachable;
}

/// `a^e (mod r)` for a small `u64` exponent — thin wrapper over
/// `Fr.pow`, which takes a 32-byte big-endian exponent.
pub fn frPowU64(a: Fr, e: u64) Fr {
    var b = [_]u8{0} ** 32;
    std.mem.writeInt(u64, b[24..32], e, .big);
    return a.pow(b);
}

test "frFromU64 round-trips small integers and respects field arithmetic" {
    const two = frFromU64(2);
    const three = frFromU64(3);
    try std.testing.expect(two.add(three).eql(frFromU64(5)));
    try std.testing.expect(two.mul(three).eql(frFromU64(6)));
    try std.testing.expect(frFromU64(0).isZero());
    try std.testing.expect(frFromU64(1).eql(Fr.one));
}

test "frPowU64 matches repeated multiplication" {
    const a = frFromU64(7);
    try std.testing.expect(frPowU64(a, 0).eql(Fr.one));
    try std.testing.expect(frPowU64(a, 1).eql(a));
    try std.testing.expect(frPowU64(a, 3).eql(a.mul(a).mul(a)));
}
