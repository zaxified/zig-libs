// SPDX-License-Identifier: MIT

//! gadget — the **signed (balanced) gadget decomposition** used by the GGSW
//! external product and by LWE-to-LWE key switching.
//!
//! A torus element `x ∈ Z_{2^32}` is approximated by `ℓ` signed base-`B` digits
//! (`B = 2^b_bits`), each in the balanced range `[−B/2, B/2]`:
//!
//!     x ≈ Σ_{i=0}^{ℓ−1} d_i · (q / B^{i+1})
//!
//! keeping only the top `ℓ·b_bits` bits (round-to-nearest on the dropped tail,
//! a tie rounding up). The **balanced** digit range is what keeps the
//! external-product noise small (digits bounded by `B/2`, not `B`); a plain
//! unsigned decomposition would blow the noise budget — that is the
//! deliberately-broken positive control in the harness.
//!
//! ## Which digit at a tie — tfhe-rs's rule, recovered from its output
//!
//! A raw digit of exactly `B/2` can be written `+B/2` or `−B/2` (with a carry
//! into the next level); both recompose to the same value, but key switching
//! subtracts `digit · row`, so the choice decides the output bytes. This module
//! makes the choice tfhe-rs 1.8.1 makes, so that `keySwitch` is byte-identical
//! to tfhe-rs's on the same key and input (`interop_test.zig`). The rule was
//! derived from tfhe-rs's `SignedDecomposer` used as a black box — 40 000
//! decompositions over five `(B, ℓ)` shapes, ties planted at every level, no
//! source read — and matches all of them:
//!
//!   1. Round `x` to its top `L = ℓ·b_bits` bits: `state = ⌊x / 2^{32−L}⌉`,
//!      remembering the rounding bit `rb` (bit `31−L` of `x`).
//!   2. If the top bit of `state` is set and the value is *strictly* above
//!      `2^{L−1}` — the low `L−1` bits nonzero, or `rb` set — read `state` as
//!      the negative number `state − 2^L`.
//!   3. Peel digits least-significant first: `res = state mod B`; shift
//!      `state` right (arithmetically); carry iff `res > B/2`, or `res = B/2`
//!      and the next raw digit's top bit is set; `res −= carry·B`,
//!      `state += carry`.
//!
//! Rule 3 keeps the digits balanced between levels; rule 2 does the same for
//! the top level, which has no next digit to look at. All REAL/ungated and
//! branch-free: exact integer bit-fiddling on ciphertext coefficients (no
//! secrets).

const std = @import("std");
const torus = @import("torus.zig");

const T = torus.Torus;

/// Worst-case recomposition error `‖x − Σ d_i·q/B^{i+1}‖_∞` of the signed
/// decomposition: the dropped tail after rounding to `ℓ·b_bits` top bits,
/// bounded by `q / (2·B^ℓ) = 2^{31 − ℓ·b_bits}` (or `0` when the digits cover
/// all 32 bits). Comptime constant — the SPEC ledger cites it.
pub fn maxError(comptime b_bits: u6, comptime ell: usize) u64 {
    const rep_bits: u32 = @as(u32, b_bits) * @as(u32, @intCast(ell));
    if (rep_bits >= 32) return 0;
    return @as(u64, 1) << @intCast(31 - rep_bits);
}

/// Signed base-`2^b_bits` decomposition of `x` into `ell` balanced digits in
/// `[−B/2, B/2]`, `digits[0]` the most significant (weight `q/B`), with
/// tfhe-rs's tie rule (see the file comment). `b_bits·ell ≤ 32`.
pub fn decompose(comptime b_bits: u6, comptime ell: usize, x: T) [ell]i32 {
    comptime std.debug.assert(b_bits >= 1 and b_bits <= 31 and ell >= 1 and @as(u32, b_bits) * ell <= 32);
    const L: u6 = @intCast(@as(u32, b_bits) * ell);
    const ignored: u6 = 32 - L;
    const mask: i64 = (@as(i64, 1) << b_bits) - 1;
    const half: i64 = @as(i64, 1) << (b_bits - 1);

    // 1. Round to the top L bits; `rb` is the rounding bit.
    var state: u64 = undefined;
    var rb: u64 = 0;
    if (ignored == 0) {
        state = x;
    } else {
        const pre: u64 = @as(u64, x) >> (ignored - 1);
        rb = pre & 1;
        state = ((pre + 1) >> 1) & ((@as(u64, 1) << L) - 1);
    }
    // 2. Strictly above half the range ⇒ the negative representative.
    const top = (state >> (L - 1)) & 1;
    const rest = state & ((@as(u64, 1) << (L - 1)) - 1);
    const neg: u64 = top & @intFromBool((rest | rb) != 0);
    var st: i64 = @as(i64, @intCast(state)) - @as(i64, @intCast(neg << L));

    // 3. Balanced digits, least significant first.
    var digits: [ell]i32 = undefined;
    var i: usize = ell;
    while (i > 0) : (i -= 1) {
        var res: i64 = st & mask;
        st >>= b_bits;
        const carry: i64 = (((res - 1) | st) & res & half) >> (b_bits - 1);
        res -= carry << b_bits;
        st += carry;
        digits[i - 1] = @intCast(res);
    }
    return digits;
}

/// Exact inverse of `decompose` up to the dropped tail: `Σ d_i·q/B^{i+1}` as a
/// torus element (wrapping `u32`). `‖x − recompose(decompose(x))‖ ≤ maxError`.
pub fn recompose(comptime b_bits: u6, comptime ell: usize, digits: [ell]i32) T {
    var acc: T = 0;
    for (digits, 0..) |d, i| {
        const w = torus.gadgetWeight(b_bits, i);
        // signed digit → two's-complement u32; `*%` mod 2^32 is exact.
        const du: T = @bitCast(d);
        acc = acc +% (du *% w);
    }
    return acc;
}

const testing = std.testing;

test "signed decomposition round-trips within maxError, digits balanced" {
    const b_bits: u6 = 7;
    const ell: usize = 4; // covers top 28 bits ⇒ maxError = 2^3 = 8
    const B: i32 = 1 << b_bits;
    const half: i32 = B >> 1;
    var rng = std.Random.DefaultPrng.init(7);
    const rnd = rng.random();
    for (0..2000) |_| {
        const x = rnd.int(T);
        const d = decompose(b_bits, ell, x);
        for (d) |di| {
            try testing.expect(di >= -half and di <= half); // balanced range
        }
        const back = recompose(b_bits, ell, d);
        const err = @min(x -% back, back -% x); // |x − back| as unsigned distance
        try testing.expect(err <= maxError(b_bits, ell));
    }
}

test "exact-cover decomposition (b·ell = 32) has zero error" {
    const b_bits: u6 = 4;
    const ell: usize = 8;
    try testing.expectEqual(@as(u64, 0), maxError(b_bits, ell));
    var rng = std.Random.DefaultPrng.init(11);
    const rnd = rng.random();
    for (0..2000) |_| {
        const x = rnd.int(T);
        try testing.expectEqual(x, recompose(b_bits, ell, decompose(b_bits, ell, x)));
    }
}

test "KAT: tfhe-rs 1.8.1 SignedDecomposer digits (black-box samples)" {
    // From `tools/tfhers` (SignedDecomposer::decompose, levels printed most
    // significant first). Ties at the top level go both ways depending on
    // the rounding bit and the lower bits — rule 2 of the file comment.
    const cases = [_]struct { u32, [5]i32 }{
        .{ 0x0000_0000, .{ 0, 0, 0, 0, 0 } },
        .{ 0xffff_ffff, .{ 0, 0, 0, 0, 0 } },
        .{ 0x8000_0000, .{ 4, 0, 0, 0, 0 } },
        .{ 0x7fff_8000, .{ -4, 0, 0, 0, 0 } },
        .{ 0x1234_5678, .{ 1, -3, -4, 3, 2 } },
        .{ 0x0001_0000, .{ 0, 0, 0, 0, 1 } },
        .{ 0x0000_ffff, .{ 0, 0, 0, 0, 0 } },
        .{ 0xdead_beef, .{ -1, 0, -3, 3, -1 } },
        .{ 0x0003_0000, .{ 0, 0, 0, 0, 2 } },
    };
    for (cases) |c| try testing.expectEqual(c[1], decompose(3, 5, c[0]));
}
