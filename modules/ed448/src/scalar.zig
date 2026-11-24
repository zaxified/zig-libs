// SPDX-License-Identifier: MIT
//! Arithmetic modulo `L`, the prime order of the edwards448 base point's
//! subgroup (RFC 8032 §5.2's parameter table: `L = 2^446 -
//! 13818066809895115352007386748515426880336692474882178609894547503885`
//! — equivalently RFC 7748 §4.2's curve448 Montgomery `order` field,
//! confirmed identical at scaffold time; see `NOTICE`'s "Verification
//! performed" section). This is `ed448.zig`'s scalar field — DISTINCT
//! from `field.zig`'s `Fp448` base field (`GF(p)`) the curve's
//! COORDINATES live in; mirrors `std.crypto.ecc.Edwards25519.scalar`'s
//! role for Ed25519 one curve family up.
//!
//! **Status: implemented.** `CompressedScalar` (the 57-byte wire width),
//! `clamp` (RFC 8032 §5.2.5's key-generation pruning),
//! `rejectNonCanonical`, and the full mod-`L` arithmetic
//! (`reduceWide`/`add`/`mul`/`mulAdd`, all constant-time — fixed
//! iteration counts, branch-free conditional subtracts) are real.
//! Reduction folds the part above bit 448 by `2^448 == 4 * (2^446 - L)`
//! (`L` is `2^446` minus a 224-bit number), then three conditional subtracts.
//!
//! Zig std GAP: yes — `std.crypto.ecc.Edwards25519.scalar` supplies the
//! identical SHAPE of API (`reduce64`-style wide-hash reduction,
//! `mulAdd`, `clamp`) for the 25519 scalar field; this module is the same
//! shape over `L`'s different (446-bit) value and `ed448.zig`'s wider
//! 57-byte / 114-byte hash inputs (SHAKE256 rather than SHA-512).

const std = @import("std");

/// Fixed-size little-endian wire encoding of a scalar mod `L` — 57 bytes
/// (`b = 456` bits per RFC 8032 §5.2, NOT `field.zig`'s narrower 56-byte
/// `Fp448` width: `L < 2^446`, comfortably under 57 bytes, but RFC 8032
/// uses the SAME 57-byte container uniformly for both scalars and point
/// coordinates — see that module's own doc comment). This is also the
/// per-half width of an Ed448 signature (`R (57) || S (57)` = 114 bytes
/// total, `ed448.zig`).
pub const encoded_bytes = 57;

pub const ScalarError = error{NonCanonical};

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `L`, little-endian, 57 bytes (RFC 8032 §5.2 / RFC 7748 §4.2, confirmed
/// identical between the two RFCs' independently-stated forms — see
/// `NOTICE`). The high byte is always `0x00`: `L` is a 446-bit value
/// inside a 456-bit/57-byte container (RFC 8032's uniform scalar/point
/// width), so a canonical scalar's top 10 bits are always zero.
pub const l_bytes: [encoded_bytes]u8 = hexBytes(encoded_bytes, "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00");

/// A scalar mod `L`, in its 57-byte little-endian wire form. Unlike
/// `field.zig`'s `Fe` (limb-structured for fast field arithmetic), this
/// module stores scalars simply as their byte encoding — the
/// crypto-core pass may introduce an internal limb form for `reduce`/
/// `mulAdd`'s big-integer arithmetic (mirroring how
/// `std.crypto.ecc.Edwards25519.scalar` internally uses a `Scalar`/
/// `ScalarDouble` pair built on `std.crypto.ff`-style big-integer
/// helpers) without changing this public byte-array API.
pub const CompressedScalar = [encoded_bytes]u8;

pub const zero: CompressedScalar = @as([encoded_bytes]u8, @splat(0));

/// Check that a 57-byte scalar encoding is canonical (`< L`). REAL:
/// constant-time big-integer byte comparison against `l_bytes`
/// (little-endian; compare from the most-significant byte downward) —
/// same shape as `field.zig.Fe.rejectNonCanonical` and
/// `std.crypto.ecc.Edwards25519.scalar.rejectNonCanonical`.
pub fn rejectNonCanonical(s: CompressedScalar) ScalarError!void {
    var i: usize = encoded_bytes;
    var is_less: u8 = 0;
    var is_equal_so_far: u8 = 1;
    while (i > 0) {
        i -= 1;
        const b = s[i];
        const lb = l_bytes[i];
        const lt: u8 = @intFromBool(b < lb);
        const eq: u8 = @intFromBool(b == lb);
        is_less |= is_equal_so_far & lt;
        is_equal_so_far &= eq;
    }
    if (is_less == 0) return error.NonCanonical;
}

/// RFC 8032 §5.2.5's key-generation "prune" step, applied in place to a
/// 57-byte buffer (the low 57 bytes of a 114-byte `SHAKE256` digest):
/// "The two least significant bits of the first octet are cleared, all
/// eight bits of the last octet are cleared, and the highest bit of the
/// second to last octet is set." REAL — pure bit manipulation, no
/// modular arithmetic. NOTE this is a DIFFERENT operation from
/// `x448.zig`'s `clamp` (which operates on a 56-byte X448 scalar with a
/// different bit pattern entirely — do not conflate the two, despite
/// both being called "clamping"/"pruning" in their respective RFCs).
pub fn clamp(buf: *[encoded_bytes]u8) void {
    buf[0] &= 0b1111_1100;
    buf[encoded_bytes - 1] = 0;
    buf[encoded_bytes - 2] |= 0b1000_0000;
}

// ── internal limb machinery ─────────────────────────────────────────────
//
// Scalars are computed on as little-endian arrays of 56-bit `u64` limbs
// (same digit size as `field.zig`, chosen for the same headroom reason;
// reduction folds the high part by `2^448 mod L`, see `reduceLimbs`). A canonical
// scalar needs ceil(456/56) = 9 limbs; wide intermediates (the 114-byte
// digest, double-width products) use larger fixed limb counts.

const limb_bits = 56;
const limb_mask: u64 = (1 << limb_bits) - 1;
/// Limbs in a single (456-bit-container) scalar: 9 * 56 = 504 bits.
const num_limbs = 9;

/// Unpack little-endian bytes into 56-bit limbs (7 bytes per limb;
/// byte-aligned, no cross-limb bit splitting). `bytes.len` may be
/// anything `<= n_limbs * 7`.
fn limbsFromBytes(comptime n_limbs: usize, bytes: []const u8) [n_limbs]u64 {
    var limbs = @as([n_limbs]u64, @splat(0));
    for (bytes, 0..) |b, i| {
        limbs[i / 7] |= @as(u64, b) << @intCast(8 * (i % 7));
    }
    return limbs;
}

/// Pack 9 canonical (< 2^56 each, value < L) limbs back into the 57-byte
/// wire form.
fn limbsToBytes(limbs: [num_limbs]u64) CompressedScalar {
    var out = @as([encoded_bytes]u8, @splat(0));
    for (&out, 0..) |*b, i| {
        b.* = @truncate(limbs[i / 7] >> @intCast(8 * (i % 7)));
    }
    return out;
}

/// `L` in 9×56-bit limb form.
const l_limbs: [num_limbs]u64 = limbsFromBytes(num_limbs, &l_bytes);

/// `c` (a canonical multiple of `L`, or `L` itself) in 9×56-bit limb form.
fn constLimbs(comptime v: u512) [num_limbs]u64 {
    var out: [num_limbs]u64 = undefined;
    for (&out, 0..) |*limb, i| limb.* = @truncate((v >> (limb_bits * i)) & limb_mask);
    return out;
}

const l_int: u512 = std.mem.readInt(u456, &l_bytes, .little);
/// `2^448 mod L = 4 * (2^446 - L)`: `L = 2^446 - delta`, so `2^446 == delta`
/// and `2^448 == 4 * delta` (226 bits, five limbs). The reduction folds by it.
const fold_limbs: [5]u64 = blk: {
    const full = constLimbs((1 << 448) - 4 * l_int);
    std.debug.assert(full[5] == 0 and full[6] == 0 and full[7] == 0 and full[8] == 0);
    break :blk full[0..5].*;
};

/// Branch-free `if (v >= c) v -= c` over 9 canonical-width limbs (each
/// `< 2^56`), `c` a comptime constant below `2^448`. Same
/// trial-subtract-then-mask-select shape as `field.zig`'s `condSubP`.
fn condSubBy(comptime c: [num_limbs]u64, limbs: [num_limbs]u64) [num_limbs]u64 {
    var diff: [num_limbs]u64 = undefined;
    var borrow: u64 = 0;
    inline for (0..num_limbs) |i| {
        const t = limbs[i] -% c[i] -% borrow;
        borrow = t >> 63; // limbs < 2^56: bit 63 set iff the true result went negative
        diff[i] = t & limb_mask;
    }
    const keep: u64 = 0 -% borrow; // borrow == 1 -> v < c -> keep original
    var out: [num_limbs]u64 = undefined;
    inline for (0..num_limbs) |i| out[i] = (limbs[i] & keep) | (diff[i] & ~keep);
    return out;
}

/// `if (v >= L) v -= L` (`v < 2L`), branch-free.
fn condSubL(limbs: [num_limbs]u64) [num_limbs]u64 {
    return condSubBy(l_limbs, limbs);
}

/// One fold step of the reduction: `lo + hi * 2^448` with `lo` the low eight
/// limbs of `x` and `hi` the rest, replaced by the congruent `lo + hi * 4 *
/// delta` (`2^448 == 4 * delta mod L`), into `n_out` clean limbs. The caller's
/// bounds argument (see `reduceLimbs`) guarantees the result fits `n_out`
/// limbs, so the final carry is dropped. Fixed shape, no data-dependent
/// branch or index.
fn foldStep(comptime n_in: usize, comptime n_out: usize, x: [n_in]u64) [n_out]u64 {
    var cols = @as([n_out]u128, @splat(0));
    inline for (0..8) |i| cols[i] = x[i];
    inline for (8..n_in) |i| {
        inline for (0..5) |j| cols[i - 8 + j] += @as(u128, x[i]) * fold_limbs[j];
    }
    var out: [n_out]u64 = undefined;
    var carry: u128 = 0;
    inline for (0..n_out) |i| {
        const cur = cols[i] + carry;
        out[i] = @truncate(cur & limb_mask);
        carry = cur >> limb_bits;
    }
    return out;
}

const two_l_limbs = constLimbs(2 * l_int);

/// Constant-time reduction of a value `< 2^912` (17 limbs) mod `L`, by
/// folding the part above bit 448 with `2^448 == delta4`, `delta4 < 2^226`.
/// Bounds: the input's high part is `< 2^464`, so fold 1 gives `< 2^691`
/// (13 limbs); its high part is `< 2^243`, so fold 2 gives `< 2^470`; the
/// high part of that is `< 2^22`, so fold 3 gives `< 2^448 + 2^248`; fold 4
/// (high part 0 or 1, and then the low part is `< 2^248`) leaves `v < 2^448`.
/// As `2^448 = 4L + delta4`, three branch-free conditional subtractions (`2L`,
/// `L`, `L`) bring `v` below `L`. Every step runs identically for any input.
fn reduceLimbs(x: [17]u64) [num_limbs]u64 {
    const f1 = foldStep(17, 13, x);
    const f2 = foldStep(13, 9, f1);
    const f3 = foldStep(9, 9, f2);
    const f4 = foldStep(9, 9, f3);
    // f4[8] is zero: v < 2^448 (see the bounds above).
    return condSubL(condSubL(condSubBy(two_l_limbs, f4)));
}

/// Reduce a 114-byte (912-bit) `SHAKE256` digest modulo `L`, returning a
/// canonical 57-byte scalar (RFC 8032 §5.2.2's little-endian integer
/// convention extended to 114 octets). Constant-time (see
/// `reduceLimbs`). This is RFC 8032 §5.2.6 steps 2 and 4's nonce (`r`)
/// and challenge (`k`) derivation.
pub fn reduceWide(digest: [114]u8) CompressedScalar {
    // ceil(114 / 7) = 17 limbs (952 bits >= 912).
    return limbsToBytes(reduceLimbs(limbsFromBytes(17, &digest)));
}

/// `a + b (mod L)`, both inputs canonical (`< L`). Constant-time:
/// limb-wise add (no overflow possible — 56-bit limbs in u64) followed by
/// one branch-free conditional subtract (`a + b < 2L`).
pub fn add(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    const al = limbsFromBytes(num_limbs, &a);
    const bl = limbsFromBytes(num_limbs, &b);
    var sum: [num_limbs]u64 = undefined;
    var carry: u64 = 0;
    inline for (0..num_limbs) |i| {
        const cur = al[i] + bl[i] + carry;
        sum[i] = cur & limb_mask;
        carry = cur >> limb_bits;
    }
    // carry out of limb 8 is impossible: both inputs < L < 2^446.
    return limbsToBytes(condSubL(sum));
}

/// `a * b (mod L)`. Inputs need not be `< L` — any 456-bit value is
/// accepted and fully reduced (Ed448's clamped secret scalar is `2^447 +
/// 4t`, deliberately NOT reduced mod `L` before use — RFC 8032 §5.2.5).
/// Constant-time: fixed schoolbook multiply into u128 column
/// accumulators, then the fixed-shape folding reduction.
pub fn mul(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    const al = limbsFromBytes(num_limbs, &a);
    const bl = limbsFromBytes(num_limbs, &b);
    // 9×9 schoolbook into 17 columns; each column sums at most 9
    // products of 56-bit limbs (< 9 * 2^112 < 2^116, fits u128).
    var cols = @as([17]u128, @splat(0));
    inline for (0..num_limbs) |i| {
        inline for (0..num_limbs) |j| {
            cols[i + j] += @as(u128, al[i]) * bl[j];
        }
    }
    // Carry-propagate into 18 clean 56-bit limbs (the product of two
    // 456-bit values is < 2^912 < 2^1008 = 2^(18*56)).
    var t: [18]u64 = undefined;
    var carry: u128 = 0;
    inline for (0..17) |i| {
        const cur = cols[i] + carry;
        t[i] = @intCast(cur & limb_mask);
        carry = cur >> limb_bits;
    }
    t[17] = @intCast(carry);
    // t[17] is zero: the product is below 2^912 < 2^952.
    return limbsToBytes(reduceLimbs(t[0..17].*));
}

/// `a * b + c (mod L)` — RFC 8032 §5.2.6 step 5's `S = (r + k*s) mod L`
/// (`mulAdd(k, s, r)`), the single scalar-arithmetic operation Ed448
/// signing performs on SECRET material (`s`, the signing scalar).
/// Constant-time with respect to all three operands: composed of `mul`
/// and `add`, both constant-time (fixed iteration counts, branch-free
/// conditional subtracts). The doc-comment-sanctioned `add(mul(a,b), c)`
/// composition — a fused single-reduction variant remains a performance
/// follow-up, not a correctness or side-channel requirement.
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar) CompressedScalar {
    return add(mul(a, b), c);
}

// ── tests ────────────────────────────────────────────────────────────────

test "L is a 446-bit value inside the 57-byte / 456-bit container (top 10 bits zero)" {
    try std.testing.expectEqual(@as(u8, 0x00), l_bytes[encoded_bytes - 1]);
    try std.testing.expect(l_bytes[encoded_bytes - 2] < 0x40); // < 2^(446 - 8*55) = 2^6
}

test "rejectNonCanonical rejects L itself and accepts L-1 (REAL)" {
    try std.testing.expectError(error.NonCanonical, rejectNonCanonical(l_bytes));
    var l_minus_1 = l_bytes;
    l_minus_1[0] -= 1; // L's low byte is 0xf3, no borrow
    try rejectNonCanonical(l_minus_1);
}

test "rejectNonCanonical decides at the most significant differing byte" {
    // L with its top byte raised to 1 and its low byte lowered to 0 is
    // L - 0xf3 + 2^448 > L: non-canonical, although its low byte is below
    // L's. A compare that let any lower byte decide would accept it.
    var s = l_bytes;
    s[encoded_bytes - 1] = 1;
    s[0] = 0;
    try std.testing.expectError(error.NonCanonical, rejectNonCanonical(s));
}

test "clamp: RFC 8032 §5.2.5 pruning (REAL)" {
    var buf = @as([encoded_bytes]u8, @splat(0xff));
    clamp(&buf);
    try std.testing.expectEqual(@as(u8, 0xfc), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[encoded_bytes - 1]);
    try std.testing.expectEqual(@as(u8, 0xff), buf[encoded_bytes - 2]); // 0xff | 0x80 == 0xff
    var zbuf = @as([encoded_bytes]u8, @splat(0x00));
    clamp(&zbuf);
    try std.testing.expectEqual(@as(u8, 0x00), zbuf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), zbuf[encoded_bytes - 1]);
    try std.testing.expectEqual(@as(u8, 0x80), zbuf[encoded_bytes - 2]);
}

test "reduceWide: small values pass through; L and 2L reduce to zero; L+1 to one" {
    var digest = @as([114]u8, @splat(0));
    digest[0] = 1;
    var one = zero;
    one[0] = 1;
    try std.testing.expectEqualSlices(u8, &one, &reduceWide(digest));

    var l_wide = @as([114]u8, @splat(0));
    l_wide[0..encoded_bytes].* = l_bytes;
    try std.testing.expectEqualSlices(u8, &zero, &reduceWide(l_wide));

    var l_plus_1 = l_wide;
    l_plus_1[0] += 1; // L's low byte is 0xf3, no carry
    try std.testing.expectEqualSlices(u8, &one, &reduceWide(l_plus_1));

    // 2L: shift L left one bit across the wide buffer.
    var two_l = @as([114]u8, @splat(0));
    var carry: u8 = 0;
    for (l_wide, 0..) |b, i| {
        two_l[i] = (b << 1) | carry;
        carry = b >> 7;
    }
    try std.testing.expectEqualSlices(u8, &zero, &reduceWide(two_l));
}

test "add/mul/mulAdd: identities and wrap-around mod L" {
    var one = zero;
    one[0] = 1;
    var two = zero;
    two[0] = 2;
    var l_minus_1 = l_bytes;
    l_minus_1[0] -= 1;

    // (L-1) + 2 == 1 (wraps)
    try std.testing.expectEqualSlices(u8, &one, &add(l_minus_1, two));
    // (L-1) * (L-1) == 1 (both are -1 mod L)
    try std.testing.expectEqualSlices(u8, &one, &mul(l_minus_1, l_minus_1));
    // a * 1 == a
    try std.testing.expectEqualSlices(u8, &l_minus_1, &mul(l_minus_1, one));
    // mulAdd(a, b, c) == a*b + c: (L-1)*2 + 2 == L-2+2... i.e. -2+2 == 0
    try std.testing.expectEqualSlices(u8, &zero, &mulAdd(l_minus_1, two, two));
}

test "mul accepts any 456-bit operand (bits 448..455 included) and reduces it mod L" {
    const l: u1024 = std.mem.readInt(u456, &l_bytes, .little);
    var a: [encoded_bytes]u8 = undefined;
    var b: [encoded_bytes]u8 = undefined;
    for (&a, &b, 0..) |*x, *y, i| {
        x.* = @truncate(i * 29 + 0x91);
        y.* = @truncate(i * 53 + 0x5d);
    }
    a[encoded_bytes - 1] = 0xff;
    b[encoded_bytes - 1] = 0xa5;
    const want: u1024 = (@as(u1024, std.mem.readInt(u456, &a, .little)) * std.mem.readInt(u456, &b, .little)) % l;
    var wb: [encoded_bytes]u8 = undefined;
    std.mem.writeInt(u456, &wb, @intCast(want), .little);
    try std.testing.expectEqualSlices(u8, &wb, &mul(a, b));
}

test "reduceWide matches u1024 remainder on structured and pseudo-random digests" {
    const l: u1024 = l_int;
    var prng = std.Random.DefaultPrng.init(0x448);
    const rnd = prng.random();
    var n: usize = 0;
    while (n < 300) : (n += 1) {
        var digest: [114]u8 = undefined;
        rnd.bytes(&digest);
        switch (n % 6) {
            1 => @memset(digest[57..], 0xff),
            2 => @memset(digest[0..57], 0xff),
            3 => @memset(&digest, 0xff),
            4 => @memset(digest[28..], 0),
            5 => @memset(digest[8..], 0),
            else => {},
        }
        const want: u1024 = std.mem.readInt(u912, &digest, .little) % l;
        var wb: [encoded_bytes]u8 = @splat(0);
        std.mem.writeInt(u456, &wb, @intCast(want), .little);
        try std.testing.expectEqualSlices(u8, &wb, &reduceWide(digest));
    }
    // Multiples of L at the top of the range, with 0, 1 and L - 1 added.
    const top: u1024 = (@as(u1024, 1) << 912) - 1;
    var k: u1024 = top / l;
    var steps: usize = 0;
    while (steps < 4) : (steps += 1) {
        for ([_]u1024{ 0, 1, l - 1 }) |off| {
            const v = k * l + off;
            if (v > top) continue;
            var d: [114]u8 = undefined;
            std.mem.writeInt(u912, &d, @intCast(v), .little);
            var wb: [encoded_bytes]u8 = @splat(0);
            std.mem.writeInt(u456, &wb, @intCast(v % l), .little);
            try std.testing.expectEqualSlices(u8, &wb, &reduceWide(d));
        }
        k -= 1;
    }
}
