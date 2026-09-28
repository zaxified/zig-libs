// SPDX-License-Identifier: MIT

//! scalar — the NIST P-256 scalar field (arithmetic mod the group order
//! `n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`).
//!
//! ## Scope: std's arithmetic, this module's inverse
//!
//! Scalar-field `mul`/`add`/`sub`/codecs are a handful of operations per ECDSA
//! signature (~80 ns each on std's fiat Montgomery field) and `n` has no
//! exploitable special form, so this module keeps std's constant-time fiat
//! arithmetic for them. `Scalar` below is a thin wrapper over
//! `std.crypto.ecc.P256.scalar.Scalar` with the SAME public surface (so
//! `std.crypto.sign.ecdsa.Ecdsa(P256, Sha256)` and every consumer that spells
//! `P256.scalar.Scalar` / `rejectNonCanonical` / `fromBytes48` keep working
//! unchanged) — except `invert`.
//!
//! ⭐ **The inverse IS on the critical path, and SPEC/`gate.zig` claimed the
//! opposite until 2026-09-28.** std's `Scalar.invert` is Bernstein–Yang, but
//! fiat's `divstep` does ONE divstep per call over the full 5-limb vectors,
//! 741 calls: measured 40.7 µs on the i7-7920HQ, against ~41 µs for the whole
//! constant-time `k·G` — 45 % of a signature, and 9.7 % of an entire qap TLS
//! handshake in `perf`. `invert` therefore goes through `modinv.zig`'s
//! 62-bit-batched safegcd (~3 µs), pinned to std's inverse by the
//! differential below. The gate `fast_invert_implemented` restores std's.
//!
//! ## No GLV here — P-256 has no efficiently-computable endomorphism
//!
//! Unlike secp256k1 (k256), P-256 admits no `φ(x, y) = (β·x, y)` acting as `·λ`,
//! so there is no balanced-lattice `splitScalar` to decompose a scalar and no
//! half-length combine. Variable-base multiplies are plain windowed forms
//! (wNAF for public verify, constant-time windowed for secret), and the
//! signing `k·G` uses a fixed-base comb — see `group.zig`.

const std = @import("std");
const gate = @import("gate.zig");
const modinv = @import("modinv.zig");

const NonCanonicalError = std.crypto.errors.NonCanonicalError;

/// std's P-256 scalar module: the arithmetic underneath `Scalar`.
const Std = std.crypto.ecc.P256.scalar;
const StdScalar = Std.Scalar;

/// The scalar field (group) order `n`.
pub const field_order: u256 = Std.field_order;

pub const encoded_length = Std.encoded_length;
/// A compressed scalar, in canonical form.
pub const CompressedScalar = Std.CompressedScalar;

// ── the module-level (byte-encoded) operations std exposes, forwarded ────────

/// Reject a scalar whose encoding is not canonical (`>= n`).
pub const rejectNonCanonical = Std.rejectNonCanonical;
/// Reduce a 48-byte scalar to the field size.
pub const reduce48 = Std.reduce48;
/// Reduce a 64-byte scalar to the field size.
pub const reduce64 = Std.reduce64;
pub const mul = Std.mul;
pub const mulAdd = Std.mulAdd;
pub const add = Std.add;
pub const neg = Std.neg;
pub const sub = Std.sub;
pub const random = Std.random;

/// The safegcd constants for `n` (see `modinv.zig`).
const scalar_modinfo = modinv.ModInfo.init(field_order);

/// A scalar in unpacked representation — std's Montgomery-form scalar with
/// this module's fast constant-time inverse.
pub const Scalar = struct {
    inner: StdScalar,

    /// Zero.
    pub const zero = Scalar{ .inner = StdScalar.zero };
    /// One.
    pub const one = Scalar{ .inner = StdScalar.one };

    /// Unpack a serialized representation of a scalar (rejects `>= n`).
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        return .{ .inner = try StdScalar.fromBytes(s, endian) };
    }

    /// Reduce a 384-bit input to the field size.
    pub fn fromBytes48(s: [48]u8, endian: std.builtin.Endian) Scalar {
        return .{ .inner = StdScalar.fromBytes48(s, endian) };
    }

    /// Reduce a 512-bit input to the field size.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        return .{ .inner = StdScalar.fromBytes64(s, endian) };
    }

    /// Pack a scalar into bytes.
    pub fn toBytes(n: Scalar, endian: std.builtin.Endian) CompressedScalar {
        return n.inner.toBytes(endian);
    }

    /// Return true if the scalar is zero.
    pub fn isZero(n: Scalar) bool {
        return n.inner.isZero();
    }

    /// Return true if the scalar is odd.
    pub fn isOdd(n: Scalar) bool {
        return n.inner.isOdd();
    }

    /// Return true if a and b are equivalent.
    pub fn equivalent(a: Scalar, b: Scalar) bool {
        return a.inner.equivalent(b.inner);
    }

    /// Compute x+y (mod n).
    pub fn add(x: Scalar, y: Scalar) Scalar {
        return .{ .inner = x.inner.add(y.inner) };
    }

    /// Compute x-y (mod n).
    pub fn sub(x: Scalar, y: Scalar) Scalar {
        return .{ .inner = x.inner.sub(y.inner) };
    }

    /// Compute 2n (mod n).
    pub fn dbl(n: Scalar) Scalar {
        return .{ .inner = n.inner.dbl() };
    }

    /// Compute x*y (mod n).
    pub fn mul(x: Scalar, y: Scalar) Scalar {
        return .{ .inner = x.inner.mul(y.inner) };
    }

    /// Compute x^2 (mod n).
    pub fn sq(n: Scalar) Scalar {
        return .{ .inner = n.inner.sq() };
    }

    /// Compute x^n (mod n).
    pub fn pow(a: Scalar, comptime T: type, comptime e: T) Scalar {
        return .{ .inner = a.inner.pow(T, e) };
    }

    /// Compute -x (mod n).
    pub fn neg(n: Scalar) Scalar {
        return .{ .inner = n.inner.neg() };
    }

    /// Compute x^-1 (mod n); `invert(0) == 0`. Constant-time. The gated
    /// safegcd path (`modinv.zig`, ~3 µs) or std's fiat inverse (~41 µs).
    pub fn invert(n: Scalar) Scalar {
        if (comptime gate.fast_invert_implemented) {
            // std's scalar is Montgomery-form internally; its byte codec is the
            // canonical integer both ways, so this is domain-exact.
            const bytes = n.inner.toBytes(.little);
            var limbs: [4]u64 = undefined;
            inline for (0..4) |i| limbs[i] = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
            const inv = modinv.invert(limbs, scalar_modinfo);
            var out: CompressedScalar = undefined;
            inline for (0..4) |i| std.mem.writeInt(u64, out[8 * i ..][0..8], inv[i], .little);
            // Back into std's Montgomery form. `fromBytes` runs a canonicality
            // compare and branches on it (`common.zig:75`); the inverse is
            // canonical by construction, so the branch is never taken, but
            // memcheck still counts it — it is the one in-file context this
            // function adds to the ctgrind `sign` row, the same class as std's
            // own five (`scripts/checks/ctgrind-expected.tsv`). The reducing
            // codec `fromBytes48` was tried instead and is WORSE: it decodes
            // two halves through the same `fromBytes`, two compares.
            return .{ .inner = StdScalar.fromBytes(out, .little) catch unreachable };
        }
        return .{ .inner = n.inner.invert() };
    }

    /// std's inverse (fiat Bernstein–Yang), the ORACLE the gated inverse is
    /// pinned to. `pub` for the differential + bench.
    pub fn invertStd(n: Scalar) Scalar {
        return .{ .inner = n.inner.invert() };
    }

    /// Return true if n is a quadratic residue mod n.
    pub fn isSquare(n: Scalar) bool {
        return n.inner.isSquare();
    }

    /// Return a random scalar < n.
    pub fn random(io: std.Io) Scalar {
        return .{ .inner = StdScalar.random(io) };
    }
};

test "scalar order matches std.crypto.ecc.P256.scalar.field_order" {
    try std.testing.expectEqual(std.crypto.ecc.P256.scalar.field_order, field_order);
    // n < p (the two moduli are distinct — a common P-256 footgun).
    try std.testing.expect(field_order != @import("field.zig").field_order);
}

test "safegcd scalar inverse == std's inverse, random + edges (0 → 0)" {
    var prng = std.Random.DefaultPrng.init(0x5CA1_A6CD_9256);
    const rand = prng.random();
    const edges = [_]u256{
        0,          1,              2,         3,              field_order - 1,  field_order - 2,
        1 << 62,    (1 << 62) - 1,  1 << 124,  (1 << 124) - 1, 1 << 186,         1 << 248,
        (1 << 255), (1 << 255) - 1, (1 << 64), (1 << 128) - 1, field_order >> 1, (field_order >> 1) + 1,
    };
    for (edges) |x| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, x, .big);
        const a = try Scalar.fromBytes(b, .big);
        const got = a.invert();
        try std.testing.expectEqualSlices(u8, &a.invertStd().toBytes(.big), &got.toBytes(.big));
        if (x != 0) try std.testing.expect(a.mul(got).equivalent(Scalar.one));
    }
    try std.testing.expect(Scalar.zero.invert().isZero());
    for (0..4000) |_| {
        var b: [32]u8 = undefined;
        rand.bytes(&b);
        const a = Scalar.fromBytes(b, .big) catch continue;
        const got = a.invert();
        try std.testing.expectEqualSlices(u8, &a.invertStd().toBytes(.big), &got.toBytes(.big));
    }
}

test "the wrapper forwards std's arithmetic unchanged" {
    var prng = std.Random.DefaultPrng.init(0x5CA1_A12);
    const rand = prng.random();
    for (0..500) |_| {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rand.bytes(&ab);
        rand.bytes(&bb);
        const a = Scalar.fromBytes(ab, .big) catch continue;
        const b = Scalar.fromBytes(bb, .big) catch continue;
        const sa = StdScalar.fromBytes(ab, .big) catch unreachable;
        const sb = StdScalar.fromBytes(bb, .big) catch unreachable;
        try std.testing.expectEqual(sa.mul(sb).toBytes(.big), a.mul(b).toBytes(.big));
        try std.testing.expectEqual(sa.add(sb).toBytes(.big), a.add(b).toBytes(.big));
        try std.testing.expectEqual(sa.sub(sb).toBytes(.big), a.sub(b).toBytes(.big));
        try std.testing.expectEqual(sa.neg().toBytes(.big), a.neg().toBytes(.big));
        try std.testing.expectEqual(sa.sq().toBytes(.big), a.sq().toBytes(.big));
        var wide = [_]u8{0} ** 48;
        rand.bytes(&wide);
        try std.testing.expectEqual(StdScalar.fromBytes48(wide, .big).toBytes(.big), Scalar.fromBytes48(wide, .big).toBytes(.big));
        try std.testing.expectEqual(sa.isOdd(), a.isOdd());
    }
}
