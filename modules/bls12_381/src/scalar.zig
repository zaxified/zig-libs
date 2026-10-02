// SPDX-License-Identifier: MIT
//! `Fr` — the BLS12-381 SCALAR field, `GF(r)` for the 255-bit prime group
//! order `r` of both `G1` and `G2` (NOT the base field `Fp` — see
//! `fp.zig`). This is the field that secret keys, message hashes reduced
//! for signing, and Shamir/FROST-style share values live in for anything
//! built on top of this module (BLS signatures, threshold BLS, KZG
//! openings — see `README.md`'s multi-part arc).
//!
//! **Status: implemented** — arithmetic is `montint.Field(r)`: Montgomery
//! form, built only from montint's constant-time primitives. Until
//! 2026-10-02 it delegated to `std.crypto.ff`, which is NOT constant-time
//! in ReleaseFast (ctgrind: `montgomeryMul`'s extra-reduction select and
//! `powWithEncodedExponent`'s window select compile to conditional jumps),
//! so every `mul` over a secret key or share leaked. `modulus` (the ff
//! value) and `FrError` stay for API compatibility; no arithmetic uses ff.

const std = @import("std");
const entropy = @import("entropy");
const montint = @import("montint");

/// Container width for `Fr`: 256 bits (32 bytes), the next byte-aligned
/// width above `r`'s actual 255 bits — mirrors `fp.zig`'s `modulus_bits`
/// choice for `Fp` (384 over 381).
pub const modulus_bits = 256;

const FfModulus = std.crypto.ff.Modulus(modulus_bits);

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The BLS12-381 scalar field modulus (the order of `G1`/`G2`/`Gt`),
/// big-endian, 32 bytes:
///
/// ```
/// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000
///       01
/// ```
///
/// Source: same defining BLS polynomial family as `fp.zig`'s `p` —
/// `r(z) = z^4 - z^2 + 1` for `z = -0xd201000000010000` — independently
/// re-derived and confirmed to match every cited reference (see
/// `NOTICE`).
pub const r_bytes: [32]u8 = hexBytes(32, "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// The BLS12-381 scalar field modulus, as a `std.crypto.ff.Modulus(256)`
/// instance, computed once at comptime. Kept for callers that read its
/// `bits()`; `Fr`'s arithmetic does not use it (see the module doc).
pub const modulus: FfModulus = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfModulus.fromBytes(&r_bytes, .big) catch
        @compileError("bls12_381: malformed scalar field modulus bytes");
};

pub const FrError = std.crypto.ff.OverflowError || std.crypto.ff.FieldElementError;

/// `r` as a `comptime_int`, re-derived from `r_bytes`.
const r_int: comptime_int = blk: {
    var x: comptime_int = 0;
    for (r_bytes) |b| x = x * 256 + @as(comptime_int, b);
    break :blk x;
};

/// The constant-time field `Fr` is a view of.
const F = montint.Field(r_int);

/// An element of the BLS12-381 scalar field `GF(r)`.
pub const Fr = struct {
    v: F,

    /// Fixed-size big-endian wire encoding: 32 bytes.
    pub const encoded_bytes = 32;

    pub const zero: Fr = .{ .v = F.zero };
    pub const one: Fr = .{ .v = F.one };

    /// Parses a big-endian 32-byte value, REJECTING anything `>= r`.
    /// Constant-time up to the accept/reject outcome.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FrError!Fr {
        return .{ .v = F.fromBytesBE(&bytes) catch return error.NonCanonical };
    }

    /// Serializes to big-endian 32 bytes. Constant time.
    pub fn toBytes(self: Fr) [encoded_bytes]u8 {
        return self.v.toBytesBE();
    }

    pub fn isZero(self: Fr) bool {
        return self.v.isZero();
    }

    pub fn eql(a: Fr, b: Fr) bool {
        return a.v.eql(b.v);
    }

    // ── field arithmetic (all constant time; montint.Field) ──────────────

    /// `a + b (mod r)`.
    pub fn add(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.add(b.v) };
    }

    /// `a - b (mod r)`.
    pub fn sub(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.sub(b.v) };
    }

    /// `-a (mod r)`.
    pub fn neg(a: Fr) Fr {
        return .{ .v = a.v.neg() };
    }

    /// `a * b (mod r)` (one Montgomery multiplication).
    pub fn mul(a: Fr, b: Fr) Fr {
        return .{ .v = a.v.mul(b.v) };
    }

    /// `a^2 (mod r)`.
    pub fn square(a: Fr) Fr {
        return .{ .v = a.v.sq() };
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Fermat, `a^(r-2) mod r`, constant-time in `a` (commonly SECRET here:
    /// a threshold share, a blinding scalar — `README.md`'s Part 6); the
    /// zero check is the only branch.
    pub fn inv(a: Fr) error{NotInvertible}!Fr {
        return .{ .v = try a.v.inv() };
    }

    /// `a^e (mod r)`, `e` a big-endian byte string. Constant time with
    /// respect to BOTH the base and the exponent (montint `powMont`: all
    /// 256 exponent bits processed); `e == 0` returns `one`.
    pub fn pow(a: Fr, e: [encoded_bytes]u8) Fr {
        return .{ .v = a.v.pow(&e) };
    }

    /// Reduces a wider byte string (e.g. a 32-, 48-, or 64-byte hash
    /// output — the common case when deriving a scalar from a hash per
    /// RFC 9380 §5/hash-to-field, or from BIP340-style `taggedHash`
    /// output as `bip340`/`adaptor`/`musig2` do for secp256k1) into an
    /// `Fr` element via `int(bytes) mod r` — a REDUCING conversion,
    /// unlike `fromBytes` (which REJECTS non-canonical input). A BLS
    /// `hash_to_field` draws MORE than 32 bytes per scalar (RFC 9380
    /// §5.3's `L` = 48 here) to bound the statistical bias. Constant time
    /// in the bytes (work depends on the length only). Inputs wider than
    /// 64 bytes are a caller bug (assert — the width is static at every
    /// call site).
    pub fn reduceWide(bytes: []const u8) Fr {
        std.debug.assert(bytes.len <= 64);
        return .{ .v = F.reduceBytesBE(bytes) };
    }

    /// A uniformly random scalar. Same rejection-sampling shape as
    /// `fp.zig`'s `Fp.random` (32 bytes here; `r`'s gap from `2^256` is
    /// even smaller in relative terms than `p`'s gap from `2^384`, so
    /// the rejection probability per draw is likewise negligible) — do
    /// NOT use `reduceWide` for this (that is a fine, spec-mandated
    /// reduction for HASH-DERIVED scalars, but reducing a raw same-width
    /// random sample biases the result the same way `Fp.random`'s doc
    /// comment warns against).
    ///
    /// Fail-closed (`entropy.fill`, not `io.random`): this is the draw
    /// `ibe.Scheme.setup` mints its MASTER secret key from, so a
    /// degraded seed here forfeits every identity key the authority will
    /// ever issue. `Fr` is a value, not an error union — there is no
    /// channel to report a weak draw on, so it aborts instead.
    pub fn random(io: std.Io) Fr {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            entropy.fill(io, &buf);
            return Fr.fromBytes(buf) catch continue; // >= r: reject, redraw
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "r is odd and 255 bits" {
    try std.testing.expect(r_bytes[31] & 1 == 1);
    try std.testing.expectEqual(@as(usize, 255), modulus.bits());
}

test "Fr.zero / Fr.one round-trip through bytes" {
    const z = Fr.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fr.one.toBytes();
    var expected = [_]u8{0} ** 32;
    expected[31] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fr.fromBytes rejects r itself (non-canonical) and accepts r-1" {
    try std.testing.expectError(error.NonCanonical, Fr.fromBytes(r_bytes));

    var r_minus_1 = r_bytes;
    r_minus_1[31] -= 1;
    _ = try Fr.fromBytes(r_minus_1); // must not error
}

test "Fr arithmetic identities: a + (-a) = 0, square == mul(a,a), (a+b)^2 law" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0xef;
    a_bytes[0] = 0x11; // large-ish, still < r (r's top byte is 0x73)
    const a = try Fr.fromBytes(a_bytes);
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[30] = 0xab;
    const b = try Fr.fromBytes(b_bytes);
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.square().eql(a.mul(a)));
    const two_ab = a.mul(b).add(a.mul(b));
    try std.testing.expect(a.add(b).square().eql(a.square().add(two_ab).add(b.square())));
}

test "Fr.inv: a * a^-1 == 1; inv(0) errors" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 42;
    const a = try Fr.fromBytes(a_bytes);
    try std.testing.expect(a.mul(try a.inv()).eql(Fr.one));
    try std.testing.expectError(error.NotInvertible, Fr.zero.inv());
}

test "Fr.pow: a^0 = 1, a^1 = a, a^2 = square" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 5;
    const a = try Fr.fromBytes(a_bytes);
    var e = [_]u8{0} ** 32;
    try std.testing.expect(a.pow(e).eql(Fr.one));
    e[31] = 1;
    try std.testing.expect(a.pow(e).eql(a));
    e[31] = 2;
    try std.testing.expect(a.pow(e).eql(a.square()));
}

test "Fr.reduceWide: r reduces to 0, r+1 to 1, canonical values unchanged, 64-byte KAT" {
    try std.testing.expect(Fr.reduceWide(&r_bytes).isZero());

    var r_plus_1 = r_bytes;
    r_plus_1[31] += 1; // r's low byte is 0x01, no carry
    try std.testing.expect(Fr.reduceWide(&r_plus_1).eql(Fr.one));

    var small = [_]u8{0} ** 32;
    small[31] = 0x7f;
    try std.testing.expect(Fr.reduceWide(&small).eql(try Fr.fromBytes(small)));

    // 64 bytes of 0xff mod r — independently computed with big-integer
    // arithmetic outside this module (see NOTICE's "Verification
    // performed").
    const wide = [_]u8{0xff} ** 64;
    var expected_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, "0748d9d99f59ff1105d314967254398f2b6cedcb87925c23c999e990f3f29c6c");
    try std.testing.expectEqualSlices(u8, &expected_bytes, &Fr.reduceWide(&wide).toBytes());
}

test "Fr.random produces canonical, distinct draws" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const a = Fr.random(io);
    const b = Fr.random(io);
    _ = try Fr.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}
