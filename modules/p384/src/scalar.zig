// SPDX-License-Identifier: MIT

//! The P-384 scalar field, integers mod the group order
//! n = 0xff…ffc7634d81f4372ddf581a0db248b0a77aecec196accc52973.
//!
//! n has no special form: `mont.zig`'s Montgomery arithmetic (six 64-bit
//! limbs, R = 2^384) with n as the modulus. Every operation is branch-free in
//! its inputs; `invert` is Fermat (x^(n−2)) with a 4-bit window over the
//! PUBLIC exponent, so the table index is a constant, not a secret.
//!
//! The std-shaped surface mirrors `std.crypto.ecc.P384.scalar`: a `Scalar`
//! type plus `CompressedScalar` helpers, `encoded_length` = 48.

const std = @import("std");
const ct = @import("ct.zig");
const mont = @import("mont.zig");
const NonCanonicalError = std.crypto.errors.NonCanonicalError;

/// Length of a serialized scalar (bytes).
pub const encoded_length = 48;
/// A serialized scalar.
pub const CompressedScalar = [encoded_length]u8;

/// The group order n.
pub const field_order: u384 = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;

const Limbs = mont.Limbs;
const A = mont.Mont(field_order);

/// Load 48 bytes into limbs (little-endian limb order).
fn load(s: *const CompressedScalar, endian: std.builtin.Endian) Limbs {
    var r: Limbs = undefined;
    inline for (0..6) |i| r[i] = switch (endian) {
        .little => std.mem.readInt(u64, s[8 * i ..][0..8], .little),
        .big => std.mem.readInt(u64, s[40 - 8 * i ..][0..8], .big),
    };
    return r;
}

/// An element of Z/nZ, held in Montgomery form.
pub const Scalar = struct {
    m: Limbs,

    pub const zero: Scalar = .{ .m = @splat(0) };
    pub const one: Scalar = .{ .m = A.R1 };

    /// Decode a canonical scalar (< n); `error.NonCanonical` otherwise. The
    /// range check is branch-free; the verdict is declassified for ctgrind
    /// (the error reveals it) and branched on once.
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        var ok: u8 = 0;
        const r = fromBytesCt(&s, endian, &ok);
        ct.declassify(&ok);
        if (ok == 0) return error.NonCanonical;
        return r;
    }

    /// `fromBytes` without the branch: `ok.*` = 1 iff the input is < n.
    /// The returned scalar is the reduced value either way.
    pub fn fromBytesCt(s: *const CompressedScalar, endian: std.builtin.Endian, ok: *u8) Scalar {
        const l = load(s, endian);
        ok.* = A.lt(l);
        return .{ .m = A.mul(l, A.R2) };
    }

    /// Any 48-byte string, reduced mod n.
    pub fn fromBytesReduce(s: CompressedScalar, endian: std.builtin.Endian) Scalar {
        return .{ .m = A.mul(load(&s, endian), A.R2) };
    }

    /// A 64-byte string (e.g. a SHA-512 digest), reduced mod n: the low 48
    /// bytes times 1 plus the high 16 times 2^384, both in the domain.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        var lo: CompressedScalar = @splat(0);
        var hi: CompressedScalar = @splat(0);
        switch (endian) {
            .big => {
                lo = s[16..64].*;
                hi[32..48].* = s[0..16].*;
            },
            .little => {
                lo = s[0..48].*;
                hi[0..16].* = s[48..64].*;
            },
        }
        const l = fromBytesReduce(lo, endian);
        // The domain form of hi·2^384 = hi·R is hi·R²: the first product
        // gives hi·R (hi into the domain), the second multiplies by R.
        const h: Scalar = .{ .m = A.mul(A.mul(load(&hi, endian), A.R2), A.R2) };
        return l.add(h);
    }

    /// The canonical encoding.
    pub fn toBytes(a: Scalar, endian: std.builtin.Endian) CompressedScalar {
        const l = A.fromMont(a.m);
        var out: CompressedScalar = undefined;
        inline for (0..6) |i| switch (endian) {
            .little => std.mem.writeInt(u64, out[8 * i ..][0..8], l[i], .little),
            .big => std.mem.writeInt(u64, out[40 - 8 * i ..][0..8], l[i], .big),
        };
        return out;
    }

    pub fn isZero(a: Scalar) bool {
        var acc: u64 = 0;
        inline for (0..6) |i| acc |= a.m[i];
        return acc == 0;
    }

    /// 1 iff zero, no branch.
    pub fn isZeroCt(a: Scalar) u1 {
        var acc: u64 = 0;
        inline for (0..6) |i| acc |= a.m[i];
        return @truncate(((acc | (0 -% acc)) >> 63) ^ 1);
    }

    pub fn equivalent(a: Scalar, b: Scalar) bool {
        var acc: u64 = 0;
        inline for (0..6) |i| acc |= a.m[i] ^ b.m[i];
        return acc == 0;
    }

    pub fn add(a: Scalar, b: Scalar) Scalar {
        return .{ .m = A.add(a.m, b.m) };
    }

    pub fn sub(a: Scalar, b: Scalar) Scalar {
        return .{ .m = A.sub(a.m, b.m) };
    }

    pub fn neg(a: Scalar) Scalar {
        return zero.sub(a);
    }

    pub fn dbl(a: Scalar) Scalar {
        return a.add(a);
    }

    pub fn mul(a: Scalar, b: Scalar) Scalar {
        return .{ .m = A.mul(a.m, b.m) };
    }

    pub fn sq(a: Scalar) Scalar {
        return .{ .m = A.sq(a.m) };
    }

    /// a⁻¹ (0 for 0): a^(n−2), constant time in `a`.
    pub fn invert(a: Scalar) Scalar {
        const e: u384 = field_order - 2;
        var tbl: [16]Scalar = undefined;
        tbl[0] = one;
        tbl[1] = a;
        for (2..16) |i| tbl[i] = tbl[i - 1].mul(a);
        var r = one;
        var pos: usize = 96;
        while (pos > 0) {
            pos -= 1;
            r = r.sq().sq().sq().sq();
            // The exponent is a public constant: indexing by it is not a
            // secret-dependent access.
            const nib: u4 = @truncate(e >> @intCast(4 * pos));
            if (nib != 0) r = r.mul(tbl[nib]);
        }
        return r;
    }

    /// A uniformly random non-zero scalar. `io.randomSecure` is fail-closed
    /// (CONVENTIONS.md §2.2).
    pub fn random(io: std.Io) error{EntropyUnavailable}!Scalar {
        var b: CompressedScalar = undefined;
        defer std.crypto.secureZero(u8, &b);
        while (true) {
            io.randomSecure(&b) catch return error.EntropyUnavailable;
            var ok: u8 = 0;
            const s = fromBytesCt(&b, .big, &ok);
            ok &= ~@as(u8, s.isZeroCt());
            ct.declassify(&ok);
            if (ok != 0) return s;
        }
    }
};

/// Reject a scalar ≥ n.
pub fn rejectNonCanonical(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!void {
    _ = try Scalar.fromBytes(s, endian);
}

/// Reduce a 64-byte string mod n.
pub fn reduce64(s: [64]u8, endian: std.builtin.Endian) CompressedScalar {
    return Scalar.fromBytes64(s, endian).toBytes(endian);
}

/// (a · b) mod n.
pub fn mul(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// (a · b + c) mod n.
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    const x = (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian));
    return x.add(try Scalar.fromBytes(c, endian)).toBytes(endian);
}

/// (a + b) mod n.
pub fn add(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).add(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// −s mod n.
pub fn neg(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(s, endian)).neg().toBytes(endian);
}

/// (a − b) mod n.
pub fn sub(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).sub(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const NN: u1024 = field_order;

fn valueOf(a: Scalar) u1024 {
    return std.mem.readInt(u384, &a.toBytes(.big), .big);
}

fn scalarOf(v: u1024) Scalar {
    var b: CompressedScalar = undefined;
    std.mem.writeInt(u384, &b, @intCast(v % NN), .big);
    return Scalar.fromBytes(b, .big) catch unreachable;
}

test "scalar: constants" {
    try testing.expectEqual(@as(u64, 0), A.M[0] *% (0 -% A.M0INV) -% 1);
    try testing.expect(scalarOf(1).equivalent(Scalar.one));
    try testing.expectEqual(@as(u1024, 1), valueOf(Scalar.one));
}

test "scalar: differential against wide integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x3842);
    const r = prng.random();
    const edges = [_]u1024{ 0, 1, 2, NN - 1, NN - 2, NN / 2, 1 << 383, (1 << 256) - 1 };
    for (0..1500) |i| {
        var av: u1024 = undefined;
        var bv: u1024 = undefined;
        if (i < edges.len * edges.len) {
            av = edges[i % edges.len];
            bv = edges[i / edges.len];
        } else {
            av = r.int(u384) % NN;
            bv = r.int(u384) % NN;
        }
        const a = scalarOf(av);
        const b = scalarOf(bv);
        try testing.expectEqual(av * bv % NN, valueOf(a.mul(b)));
        try testing.expectEqual(av * av % NN, valueOf(a.sq()));
        try testing.expectEqual((av + bv) % NN, valueOf(a.add(b)));
        try testing.expectEqual((av + NN - bv) % NN, valueOf(a.sub(b)));
        try testing.expectEqual((NN - av) % NN, valueOf(a.neg()));
        try testing.expectEqual(av == 0, a.isZero());
        try testing.expectEqual(@intFromBool(av == 0), a.isZeroCt());
        // Wide reduction of an arbitrary 384-bit string, both endians.
        const w = r.int(u384);
        var wb: CompressedScalar = undefined;
        std.mem.writeInt(u384, &wb, w, .big);
        try testing.expectEqual(@as(u1024, w) % NN, valueOf(Scalar.fromBytesReduce(wb, .big)));
        std.mem.writeInt(u384, &wb, w, .little);
        try testing.expectEqual(@as(u1024, w) % NN, valueOf(Scalar.fromBytesReduce(wb, .little)));
        // And of a 512-bit string.
        const w2 = r.int(u512);
        var wb2: [64]u8 = undefined;
        std.mem.writeInt(u512, &wb2, w2, .big);
        try testing.expectEqual(@as(u1024, w2) % NN, valueOf(Scalar.fromBytes64(wb2, .big)));
        std.mem.writeInt(u512, &wb2, w2, .little);
        try testing.expectEqual(@as(u1024, w2) % NN, valueOf(Scalar.fromBytes64(wb2, .little)));
    }
}

test "scalar: invert" {
    var prng = std.Random.DefaultPrng.init(0x3843);
    const r = prng.random();
    try testing.expect(Scalar.zero.invert().isZero());
    for (0..20) |_| {
        const a = scalarOf(r.int(u384));
        if (a.isZero()) continue;
        try testing.expect(a.mul(a.invert()).equivalent(Scalar.one));
    }
}

test "scalar: fromBytes refuses n and above, accepts n − 1" {
    var b: CompressedScalar = undefined;
    std.mem.writeInt(u384, &b, field_order, .big);
    try testing.expectError(error.NonCanonical, Scalar.fromBytes(b, .big));
    std.mem.writeInt(u384, &b, field_order - 1, .big);
    _ = try Scalar.fromBytes(b, .big);
    std.mem.writeInt(u384, &b, std.math.maxInt(u384), .big);
    try testing.expectError(error.NonCanonical, Scalar.fromBytes(b, .big));
    var ok: u8 = 9;
    _ = Scalar.fromBytesCt(&b, .big, &ok);
    try testing.expectEqual(@as(u8, 0), ok);
}

test "scalar: std P384 scalar agrees on mul and invert" {
    const S = std.crypto.ecc.P384.scalar;
    var prng = std.Random.DefaultPrng.init(0x3844);
    for (0..20) |_| {
        var a: CompressedScalar = undefined;
        var b: CompressedScalar = undefined;
        prng.random().bytes(&a);
        prng.random().bytes(&b);
        a[0] = 0x7f;
        b[0] = 0x7f;
        try testing.expectEqualSlices(u8, &(try S.mul(a, b, .big)), &(try mul(a, b, .big)));
        const sa = try Scalar.fromBytes(a, .big);
        const sb = try S.Scalar.fromBytes(a, .big);
        try testing.expectEqualSlices(u8, &sb.invert().toBytes(.big), &sa.invert().toBytes(.big));
    }
}

test "scalar: zero tests read every limb (audit 2026-10-13)" {
    for (0..6) |i| {
        var s = Scalar.zero;
        s.m[i] = 1;
        try testing.expectEqual(@as(u1, 0), s.isZeroCt());
        try testing.expect(!s.isZero());
        try testing.expect(!s.equivalent(Scalar.zero));
    }
}
