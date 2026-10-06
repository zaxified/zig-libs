// SPDX-License-Identifier: MIT

//! scalar — decaf448's scalar field wire codec (RFC 9496 §5.4): "the
//! scalars for the decaf448 group are integers modulo the order `l` of the
//! decaf448 group. Note that this is the SAME scalar field as edwards448,
//! allowing existing implementations to be reused" — `l` here is bit-for-bit
//! `ed448.scalar`'s `L` (RFC 8032 §5.2's edwards448 subgroup order; RFC 9496
//! restates the identical value in its own §5 prose). This file owns only
//! the WIDTH difference between the two RFCs' wire conventions:
//!
//!   - RFC 8032 (`ed448.scalar.CompressedScalar`) encodes a scalar as
//!     **57** little-endian bytes — the same 456-bit/57-byte container RFC
//!     8032 uses uniformly for both scalars AND point coordinates (`b =
//!     456` bits per that RFC's own parameter table), even though `L <
//!     2^446` never needs the top byte.
//!   - RFC 9496 §5.4 encodes the SAME-valued scalar as **56** little-endian
//!     bytes ("Scalars are encoded as 56-byte strings in little-endian
//!     order") — 448 bits is already enough room for a 446-bit value, no
//!     57th byte needed.
//!
//! Since `l`'s top 10 bits are zero (`ed448.scalar.l_bytes[56] == 0x00` by
//! construction — see that module's own "L is a 446-bit value inside the
//! 57-byte / 456-bit container" test), the two encodings carry IDENTICAL
//! bytes 0..55; byte 56 of the 57-byte form is always `0x00` for any
//! canonical (`< l`) scalar. Converting between them is therefore a pure
//! zero-pad / drop-the-always-zero-top-byte operation — mechanical, no
//! field-math core needed (unlike `element.zig`'s four stubs).
//!
//! `add`/`mul`/`rejectNonCanonical` below simply convert-then-delegate to
//! `ed448.scalar`'s already-real, already-KAT-validated mod-`L` arithmetic
//! — this file adds no numeric logic of its own, only the width bridge.

const std = @import("std");
const ed448 = @import("ed448");

/// 56-byte little-endian wire encoding of a decaf448 scalar (RFC 9496
/// §5.4) — narrower than `ed448.scalar.CompressedScalar`'s 57 bytes; see
/// the module doc comment for why the extra byte is never needed here.
pub const encoded_bytes = 56;
pub const CompressedScalar = [encoded_bytes]u8;

pub const zero: CompressedScalar = [_]u8{0} ** encoded_bytes;

pub const ScalarError = ed448.scalar.ScalarError;

/// Widen a decaf448 56-byte scalar to `ed448.scalar`'s 57-byte container
/// by appending one zero byte — REAL, pure byte copy (see module doc
/// comment: canonical `l`-scalars never populate that 57th byte).
pub fn toEd448(s: CompressedScalar) ed448.scalar.CompressedScalar {
    var out: ed448.scalar.CompressedScalar = undefined;
    out[0..encoded_bytes].* = s;
    out[encoded_bytes] = 0;
    return out;
}

/// Narrow an `ed448.scalar` 57-byte scalar to decaf448's 56-byte
/// container by dropping the top byte — REAL, pure byte copy, PROVIDED
/// the input is canonical (`< L`, so byte 56 is guaranteed `0x00` — see
/// module doc comment). Callers passing a non-canonical or deliberately
/// unreduced 57-byte value (e.g. `ed448`'s own clamped, unreduced signing
/// scalars — never a decaf448 concern, this module only ever receives
/// canonical `< L` scalars from its own `rejectNonCanonical`/arithmetic
/// below) would silently lose that top byte; nothing in THIS module ever
/// constructs such a value.
pub fn fromEd448(s: ed448.scalar.CompressedScalar) CompressedScalar {
    return s[0..encoded_bytes].*;
}

/// Check that a 56-byte scalar encoding is canonical (`< l`) — REAL,
/// delegates entirely to `ed448.scalar.rejectNonCanonical` via `toEd448`'s
/// zero-pad (that function's own byte-compare-against-`L` logic is
/// unaffected by an always-zero top byte on both sides).
pub fn rejectNonCanonical(s: CompressedScalar) ScalarError!void {
    return ed448.scalar.rejectNonCanonical(toEd448(s));
}

/// `a + b (mod l)` — REAL, delegates to `ed448.scalar.add` via `toEd448`/
/// `fromEd448`.
pub fn add(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return fromEd448(ed448.scalar.add(toEd448(a), toEd448(b)));
}

/// `a * b (mod l)` — REAL, delegates to `ed448.scalar.mul`.
pub fn mul(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return fromEd448(ed448.scalar.mul(toEd448(a), toEd448(b)));
}

/// `-a (mod l)`, `a` canonical (`< l`, the same contract as `add`).
/// Constant-time: a fixed 56-byte borrow-propagating subtraction `l - a`
/// (which lies in `[1, l]`), then `ed448.scalar.add`'s branch-free
/// conditional subtract folds the single out-of-range value `l` (from
/// `a == 0`) back to `0`.
pub fn negate(a: CompressedScalar) CompressedScalar {
    var diff: ed448.scalar.CompressedScalar = undefined;
    var borrow: u16 = 0;
    for (0..ed448.scalar.encoded_bytes) |i| {
        const ai: u16 = if (i < encoded_bytes) a[i] else 0;
        // Operands < 2^8, borrow <= 1: a negative true result wraps into
        // [0xff00, 0xffff] (bit 15 set); a non-negative one stays < 2^8.
        const d = @as(u16, ed448.scalar.l_bytes[i]) -% ai -% borrow;
        diff[i] = @truncate(d);
        borrow = d >> 15;
    }
    return fromEd448(ed448.scalar.add(diff, ed448.scalar.zero));
}

/// `a - b (mod l)`, both canonical. Constant-time (`negate` then `add`).
pub fn sub(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return add(a, negate(b));
}

/// `l - 2`, the Fermat exponent `invert` raises to (`l` is prime, so
/// `a^(l-2) == a^-1` for `a != 0`). `l`'s low byte is `0xf3`, so
/// subtracting 2 borrows from nothing.
const l_minus_2: CompressedScalar = blk: {
    var e = fromEd448(ed448.scalar.l_bytes);
    e[0] -= 2;
    break :blk e;
};

/// `a^-1 (mod l)` by Fermat's little theorem, `a^(l-2)`. Constant-time with
/// respect to `a`: plain left-to-right square-and-multiply over the PUBLIC,
/// fixed exponent `l - 2` — the only branch is on a bit of that constant,
/// and every step is `ed448.scalar.mul`, itself constant-time (fixed
/// schoolbook multiply plus fixed-iteration reduction).
///
/// `invert(0)` returns `0` (there is no inverse; `0^(l-2) == 0`). A caller
/// for which a zero scalar is an error must check for it — e.g. RFC 9497's
/// `Blind` redraws a zero blind before it is ever inverted.
pub fn invert(a: CompressedScalar) CompressedScalar {
    const a57 = toEd448(a);
    var acc = toEd448(one);
    var bit: usize = 8 * encoded_bytes;
    while (bit > 0) {
        bit -= 1;
        acc = ed448.scalar.mul(acc, acc);
        if ((l_minus_2[bit / 8] >> @intCast(bit % 8)) & 1 == 1) {
            acc = ed448.scalar.mul(acc, a57);
        }
    }
    return fromEd448(acc);
}

/// The scalar `1`.
pub const one: CompressedScalar = blk: {
    var s = zero;
    s[0] = 1;
    break :blk s;
};

/// Reduce an `n`-byte little-endian integer modulo `l` (`n <= 114`,
/// checked at compile time). Constant-time: zero-extends to 114 bytes
/// (value-preserving) and delegates to `ed448.scalar.reduceWide`'s
/// fixed-iteration binary reduction. `n = 64` is RFC 9497's decaf448
/// `HashToScalar` width (see `hash.hashToScalar`).
pub fn reduce(comptime n: usize, bytes: [n]u8) CompressedScalar {
    comptime if (n > 114) @compileError("scalar.reduce: at most 114 bytes");
    var wide = [_]u8{0} ** 114;
    wide[0..n].* = bytes;
    return fromEd448(ed448.scalar.reduceWide(wide));
}

/// Reduce a 114-byte little-endian integer (e.g. a SHAKE256 digest)
/// modulo `l` — the wide reduction RFC 8032 uses for edwards448 and the
/// one a uniform scalar is drawn from. With 912 input bits against a
/// 446-bit `l`, the distance from uniform is below `2^-466`.
pub fn fromWide(wide: [114]u8) CompressedScalar {
    return reduce(114, wide);
}

pub const RandomError = std.Io.RandomSecureError;

/// A uniformly random scalar: 114 bytes from `io.randomSecure` (the
/// fail-closed source — no silent fallback seed; see the `entropy` module's
/// doc comment for why the degrading `io.random` is not used for secrets),
/// wide-reduced by `fromWide`. Constant-time; may return `0` with
/// probability `~2^-446`. Errors are `randomSecure`'s own
/// (`EntropyUnavailable`, `Canceled`), passed through to the caller.
pub fn random(io: std.Io) RandomError!CompressedScalar {
    var buf: [114]u8 = undefined;
    try io.randomSecure(&buf);
    defer std.crypto.secureZero(u8, &buf);
    return fromWide(buf);
}

// ── tests ────────────────────────────────────────────────────────────────

test "toEd448/fromEd448 round-trip on zero and one" {
    try std.testing.expectEqual(@as(u8, 1), one[0]);
    try std.testing.expectEqualSlices(u8, &one, &fromEd448(toEd448(one)));
    try std.testing.expectEqualSlices(u8, &zero, &fromEd448(toEd448(zero)));
}

test "toEd448 always zero-pads byte 56" {
    var s = zero;
    s[55] = 0xff; // arbitrary high byte, still < l (l's byte 55 is 0x3f-ish)
    const wide = toEd448(s);
    try std.testing.expectEqual(@as(u8, 0), wide[56]);
}

test "l (== ed448's L), read back through the 56-byte width, matches ed448.scalar.l_bytes[0..56]" {
    // ed448.scalar.l_bytes[56] is documented as always 0x00 (446-bit value
    // in a 456-bit container) -- confirms the width-bridge premise this
    // whole file rests on.
    try std.testing.expectEqual(@as(u8, 0x00), ed448.scalar.l_bytes[56]);
    const l56 = fromEd448(ed448.scalar.l_bytes);
    try std.testing.expectEqualSlices(u8, ed448.scalar.l_bytes[0..56], &l56);
}

test "rejectNonCanonical rejects l itself (via the width bridge) and accepts l-1" {
    const l56 = fromEd448(ed448.scalar.l_bytes);
    try std.testing.expectError(error.NonCanonical, rejectNonCanonical(l56));
    var l_minus_1 = l56;
    l_minus_1[0] -= 1; // l's low byte is 0xf3 (matches ed448.scalar.l_bytes), no borrow
    try rejectNonCanonical(l_minus_1);
}

test "add/mul: identities, delegated correctly to ed448.scalar" {
    var two = zero;
    two[0] = 2;
    try std.testing.expectEqualSlices(u8, &two, &add(one, one));
    try std.testing.expectEqualSlices(u8, &one, &mul(one, one));
    try std.testing.expectEqualSlices(u8, &zero, &mul(one, zero));
}

// ── big-integer oracle (SELF-DERIVED) ───────────────────────────────────
//
// The tests below recompute each new operation with Zig's native wide
// integers (`u1024`, compiler-rt division) — a second, independent
// arithmetic that shares no code with `ed448.scalar`'s limb machinery. It is
// SELF-DERIVED (same repository, same compiler), not an external anchor; the
// external anchor for `invert`/`fromWide`-style reduction is RFC 9497's
// decaf448 OPRF vectors in `kat_test.zig`.

const Big = u1024;
const l_big: Big = std.mem.readInt(u456, &ed448.scalar.l_bytes, .little);

fn bigOf(s: CompressedScalar) Big {
    return std.mem.readInt(u448, &s, .little);
}

fn scalarOf(v: Big) CompressedScalar {
    std.debug.assert(v < l_big);
    var out: CompressedScalar = undefined;
    std.mem.writeInt(u448, &out, @intCast(v), .little);
    return out;
}

/// A canonical pseudo-random scalar from a fixed-seed PRNG (test fixture,
/// not a secret): reduce 114 random bytes through the ORACLE, not `fromWide`.
fn testScalar(r: std.Random) CompressedScalar {
    var wide: [114]u8 = undefined;
    r.bytes(&wide);
    return scalarOf(@as(Big, std.mem.readInt(u912, &wide, .little)) % l_big);
}

test "oracle: l read as an integer has 446 bits" {
    try std.testing.expectEqual(@as(u16, 446), 1024 - @clz(l_big));
}

test "negate/sub agree with the big-integer oracle (SELF-DERIVED)" {
    var prng = std.Random.DefaultPrng.init(0xdeca_f448);
    const r = prng.random();
    for (0..64) |_| {
        const a = testScalar(r);
        const b = testScalar(r);
        try std.testing.expectEqualSlices(u8, &scalarOf((l_big - bigOf(a)) % l_big), &negate(a));
        try std.testing.expectEqualSlices(u8, &scalarOf((bigOf(a) + l_big - bigOf(b)) % l_big), &sub(a, b));
        // identities
        try std.testing.expectEqualSlices(u8, &zero, &add(a, negate(a)));
        try std.testing.expectEqualSlices(u8, &a, &add(sub(a, b), b));
        try std.testing.expectEqualSlices(u8, &negate(sub(a, b)), &sub(b, a));
    }
}

test "negate/sub edge values: 0, 1, l-1" {
    const l_minus_1 = scalarOf(l_big - 1);
    try std.testing.expectEqualSlices(u8, &zero, &negate(zero));
    try std.testing.expectEqualSlices(u8, &l_minus_1, &negate(one));
    try std.testing.expectEqualSlices(u8, &one, &negate(l_minus_1));
    try std.testing.expectEqualSlices(u8, &zero, &sub(l_minus_1, l_minus_1));
    try std.testing.expectEqualSlices(u8, &l_minus_1, &sub(zero, one));
    try std.testing.expectEqualSlices(u8, &one, &sub(zero, l_minus_1));
}

test "invert: a * invert(a) == 1, and matches the big-integer oracle (SELF-DERIVED)" {
    var prng = std.Random.DefaultPrng.init(0x1a7e_4e45);
    const r = prng.random();
    for (0..4) |_| {
        const a = testScalar(r);
        const inv = invert(a);
        try std.testing.expectEqualSlices(u8, &one, &mul(a, inv));
        // oracle: a * inv == 1 (mod l), checked in u1024
        try std.testing.expectEqual(@as(Big, 1), (bigOf(a) * bigOf(inv)) % l_big);
    }
}

test "invert edge values: 0 -> 0, 1 -> 1, l-1 -> l-1, 2 -> (l+1)/2" {
    try std.testing.expectEqualSlices(u8, &zero, &invert(zero));
    try std.testing.expectEqualSlices(u8, &one, &invert(one));
    const l_minus_1 = scalarOf(l_big - 1);
    try std.testing.expectEqualSlices(u8, &l_minus_1, &invert(l_minus_1));
    var two = zero;
    two[0] = 2;
    try std.testing.expectEqualSlices(u8, &scalarOf((l_big + 1) / 2), &invert(two));
}

test "fromWide/reduce agree with the big-integer oracle (SELF-DERIVED)" {
    var prng = std.Random.DefaultPrng.init(0x00f1_0e1d);
    const r = prng.random();
    for (0..32) |_| {
        var wide: [114]u8 = undefined;
        r.bytes(&wide);
        const want = @as(Big, std.mem.readInt(u912, &wide, .little)) % l_big;
        try std.testing.expectEqualSlices(u8, &scalarOf(want), &fromWide(wide));
        const w64 = wide[0..64].*;
        const want64 = @as(Big, std.mem.readInt(u512, &w64, .little)) % l_big;
        try std.testing.expectEqualSlices(u8, &scalarOf(want64), &reduce(64, w64));
    }
    const ff = [_]u8{0xff} ** 114;
    const want_ff = ((@as(Big, 1) << 912) - 1) % l_big;
    try std.testing.expectEqualSlices(u8, &scalarOf(want_ff), &fromWide(ff));
    // l itself and 0 reduce to 0
    var l114 = [_]u8{0} ** 114;
    l114[0..57].* = ed448.scalar.l_bytes;
    try std.testing.expectEqualSlices(u8, &zero, &fromWide(l114));
    try std.testing.expectEqualSlices(u8, &zero, &fromWide([_]u8{0} ** 114));
}

test "random: canonical and (overwhelmingly) distinct" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = try random(io);
    const b = try random(io);
    try rejectNonCanonical(a);
    try rejectNonCanonical(b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b)); // collide w/ prob ~2^-446
}

test "random: entropy failure is reported, not papered over" {
    try std.testing.expectError(error.EntropyUnavailable, random(std.Io.failing));
}
