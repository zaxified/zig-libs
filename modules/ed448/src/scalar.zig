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
//! Reduction is a generic constant-time binary long division (`L` has no
//! Solinas structure to exploit, unlike `field.zig`'s `p`).
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

pub const zero: CompressedScalar = [_]u8{0} ** encoded_bytes;

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
// (same digit size as `field.zig`, chosen for the same headroom reason,
// though `L` has no Solinas structure to exploit — reduction here is a
// generic constant-time binary long division instead). A canonical
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
    var limbs = [_]u64{0} ** n_limbs;
    for (bytes, 0..) |b, i| {
        limbs[i / 7] |= @as(u64, b) << @intCast(8 * (i % 7));
    }
    return limbs;
}

/// Pack 9 canonical (< 2^56 each, value < L) limbs back into the 57-byte
/// wire form.
fn limbsToBytes(limbs: [num_limbs]u64) CompressedScalar {
    var out = [_]u8{0} ** encoded_bytes;
    for (&out, 0..) |*b, i| {
        b.* = @truncate(limbs[i / 7] >> @intCast(8 * (i % 7)));
    }
    return out;
}

/// `L` in 9×56-bit limb form.
const l_limbs: [num_limbs]u64 = limbsFromBytes(num_limbs, &l_bytes);

/// Branch-free `if (v >= L) v -= L` over 9 canonical-width limbs (each
/// `< 2^56`; the value may be up to `2L - 1 < 2^447`). Same
/// trial-subtract-then-mask-select shape as `field.zig`'s `condSubP`.
fn condSubL(limbs: [num_limbs]u64) [num_limbs]u64 {
    var diff: [num_limbs]u64 = undefined;
    var borrow: u64 = 0;
    inline for (0..num_limbs) |i| {
        const t = limbs[i] -% l_limbs[i] -% borrow;
        borrow = t >> 63; // limbs < 2^56: bit 63 set iff the true result went negative
        diff[i] = t & limb_mask;
    }
    const keep: u64 = 0 -% borrow; // borrow == 1 -> v < L -> keep original
    var out: [num_limbs]u64 = undefined;
    inline for (0..num_limbs) |i| out[i] = (limbs[i] & keep) | (diff[i] & ~keep);
    return out;
}

/// Constant-time binary reduction of an arbitrary-width little-endian
/// limb value mod `L`: classic shift-and-conditional-subtract long
/// division, one fixed iteration per input bit (MSB first). The running
/// remainder `r` satisfies `r < L` at every step, so `2r + bit < 2L`
/// and a single `condSubL` per step restores the invariant. Every
/// iteration executes identically regardless of data — no secret-
/// dependent branch, no early exit.
fn reduceLimbs(comptime n_limbs: usize, wide: [n_limbs]u64) [num_limbs]u64 {
    var r = [_]u64{0} ** num_limbs;
    var bit_index: usize = n_limbs * limb_bits;
    while (bit_index > 0) {
        bit_index -= 1;
        const bit: u64 = (wide[bit_index / limb_bits] >> @intCast(bit_index % limb_bits)) & 1;
        // r = 2r + bit (r < L < 2^446, so the shifted value < 2^447
        // stays comfortably inside 9 limbs with no carry-out).
        var carry: u64 = bit;
        for (&r) |*limb| {
            const cur = (limb.* << 1) | carry;
            carry = cur >> limb_bits;
            limb.* = cur & limb_mask;
        }
        r = condSubL(r);
    }
    return r;
}

/// Reduce a 114-byte (912-bit) `SHAKE256` digest modulo `L`, returning a
/// canonical 57-byte scalar (RFC 8032 §5.2.2's little-endian integer
/// convention extended to 114 octets). Constant-time (see
/// `reduceLimbs`). This is RFC 8032 §5.2.6 steps 2 and 4's nonce (`r`)
/// and challenge (`k`) derivation.
pub fn reduceWide(digest: [114]u8) CompressedScalar {
    // ceil(114 / 7) = 17 limbs (952 bits >= 912).
    return limbsToBytes(reduceLimbs(17, limbsFromBytes(17, &digest)));
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
/// accumulators, then the fixed-iteration binary reduction.
pub fn mul(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    const al = limbsFromBytes(num_limbs, &a);
    const bl = limbsFromBytes(num_limbs, &b);
    // 9×9 schoolbook into 17 columns; each column sums at most 9
    // products of 56-bit limbs (< 9 * 2^112 < 2^116, fits u128).
    var cols = [_]u128{0} ** 17;
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
    return limbsToBytes(reduceLimbs(18, t));
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

test "clamp: RFC 8032 §5.2.5 pruning (REAL)" {
    var buf = [_]u8{0xff} ** encoded_bytes;
    clamp(&buf);
    try std.testing.expectEqual(@as(u8, 0xfc), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[encoded_bytes - 1]);
    try std.testing.expectEqual(@as(u8, 0xff), buf[encoded_bytes - 2]); // 0xff | 0x80 == 0xff
    var zbuf = [_]u8{0x00} ** encoded_bytes;
    clamp(&zbuf);
    try std.testing.expectEqual(@as(u8, 0x00), zbuf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), zbuf[encoded_bytes - 1]);
    try std.testing.expectEqual(@as(u8, 0x80), zbuf[encoded_bytes - 2]);
}

test "reduceWide: small values pass through; L and 2L reduce to zero; L+1 to one" {
    var digest = [_]u8{0} ** 114;
    digest[0] = 1;
    var one = zero;
    one[0] = 1;
    try std.testing.expectEqualSlices(u8, &one, &reduceWide(digest));

    var l_wide = [_]u8{0} ** 114;
    l_wide[0..encoded_bytes].* = l_bytes;
    try std.testing.expectEqualSlices(u8, &zero, &reduceWide(l_wide));

    var l_plus_1 = l_wide;
    l_plus_1[0] += 1; // L's low byte is 0xf3, no carry
    try std.testing.expectEqualSlices(u8, &one, &reduceWide(l_plus_1));

    // 2L: shift L left one bit across the wide buffer.
    var two_l = [_]u8{0} ** 114;
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
