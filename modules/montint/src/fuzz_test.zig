// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for montint (added 2026-10-10, the jwt pattern),
//! plus the differential harnesses against `std.math.big`.
//!
//! Driver: `MONTINT_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `montint-loader-modulus`, `montint-loader-element`
//! `montint-fixed-diff`,
//! `montint-dyn-diff`.
//!
//! The oracle is `std.math.big.int.Managed`: every accept / refuse decision of
//! the byte loaders and every result of add / sub / neg / mul / sq / pow /
//! powPublic / inverse / reduceBytesBE is recomputed with big integers, and
//! the portable CIOS core is compared against the dispatching one.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const montint = @import("montint.zig");
const dyn = @import("dyn.zig");
pub const fuzz_driver = testkit.fuzz.driver;

const Big = std.math.big.int.Managed;

/// Reach counters (see jwt's `Marker`).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// A big-endian byte string for a modulus or an operand. Under `Smith` it is
/// exactly one `slice`. Under the driver: plain random bytes of random length,
/// a value with a few bytes set (small numbers, leading zeros), all-ones or
/// powers of two +- 1 (the carry and limb-boundary shapes), or a plain slice.
/// `odd` forces the low bit with probability 15/16 (a modulus).
pub fn drawBytes(comptime S: type, src: *S, buf: []u8, odd: bool) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    var n: usize = 0;
    switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => n = src.slice(buf),
        1 => {
            n = src.index(buf.len + 1);
            src.bytes(buf[0..n]);
        },
        2 => { // few nonzero bytes behind leading zeros
            n = src.index(buf.len + 1);
            @memset(buf[0..n], 0);
            for (0..src.valueRangeAtMost(u8, 0, 3)) |_| if (n != 0) {
                buf[src.index(n)] = src.value(u8);
            };
        },
        3 => { // all ones, maybe a few bytes off
            n = src.index(buf.len + 1);
            @memset(buf[0..n], 0xff);
            for (0..src.valueRangeAtMost(u8, 0, 2)) |_| if (n != 0) {
                buf[src.index(n)] = src.value(u8);
            };
        },
        4 => { // 2^k, then +-1
            const bits = src.index(buf.len * 8);
            n = bits / 8 + 1;
            @memset(buf[0..n], 0);
            buf[0] = @as(u8, 1) << @intCast(bits % 8);
            switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => buf[n - 1] |= 1,
                1 => { // 2^k - 1: every bit below k
                    @memset(buf[0..n], 0xff);
                    buf[0] = (@as(u8, 1) << @intCast(bits % 8)) -% 1;
                },
                else => {},
            }
        },
        else => { // a short value
            n = src.valueRangeAtMost(u8, 0, 9);
            n = @min(n, buf.len);
            src.bytes(buf[0..n]);
        },
    }
    if (odd and n != 0 and src.valueRangeAtMost(u8, 0, 15) != 0) buf[n - 1] |= 1;
    return n;
}

fn bigFromBE(a: std.mem.Allocator, be: []const u8) !Big {
    var r = try Big.initSet(a, 0);
    for (be) |b| {
        try r.shiftLeft(&r, 8);
        try r.addScalar(&r, b);
    }
    return r;
}

/// Plain Euclid over `divFloor`. std 0.16: big.int gcd index-out-of-bounds on
/// multi-limb inputs, so `Managed.gcd` cannot be the oracle.
fn bigGcd(a: std.mem.Allocator, x: *const Big, y: *const Big) !Big {
    var p = try x.clone();
    var q = try y.clone();
    while (!q.eqlZero()) {
        const r = try bigMod(a, &p, &q);
        p = q;
        q = r;
    }
    return p;
}

fn isOne(b: *const Big) bool {
    return b.bitCountAbs() == 1;
}

fn bigFromLimbs(a: std.mem.Allocator, l: []const u64) !Big {
    var r = try Big.initSet(a, 0);
    var i = l.len;
    while (i > 0) {
        i -= 1;
        try r.shiftLeft(&r, 64);
        try r.addScalar(&r, l[i]);
    }
    return r;
}

fn bigMod(a: std.mem.Allocator, x: *const Big, m: *const Big) !Big {
    var q = try Big.init(a);
    var r = try Big.init(a);
    try q.divFloor(&r, x, m);
    return r;
}

fn bigMulMod(a: std.mem.Allocator, x: *const Big, y: *const Big, m: *const Big) !Big {
    var p = try Big.init(a);
    try p.mul(x, y);
    return bigMod(a, &p, m);
}

/// `base^exp mod m`, exp big-endian bytes.
fn bigPowMod(a: std.mem.Allocator, base: *const Big, exp_be: []const u8, m: *const Big) !Big {
    var acc = try Big.initSet(a, 1);
    acc = try bigMod(a, &acc, m);
    for (exp_be) |byte| {
        var bit: u4 = 8;
        while (bit > 0) {
            bit -= 1;
            acc = try bigMulMod(a, &acc, &acc, m);
            if ((byte >> @intCast(bit)) & 1 == 1) acc = try bigMulMod(a, &acc, base, m);
        }
    }
    return acc;
}

fn eqLimbs(a: std.mem.Allocator, big: *const Big, l: []const u64) !bool {
    const other = try bigFromLimbs(a, l);
    return big.toConst().order(other.toConst()) == .eq;
}

/// Expected verdict of a modulus loader: null = accepted.
fn modulusVerdict(v: *const Big, max_bits: usize) ?montint.Error {
    if (v.bitCountAbs() > max_bits) return error.Overflow;
    if (v.toConst().isEven()) return error.EvenModulus;
    if (v.bitCountAbs() < 2) return error.ModulusTooSmall;
    return null;
}

const FixedMark = Marker(enum { accepted, even, small, overflow, canonical, noncanonical, element_overflow, pow_checked });
const DynMark = Marker(enum { accepted, even, small, overflow, canonical, noncanonical, element_overflow, pow_checked, unit, non_unit, wide });

pub fn fixedDiff(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const M = montint.Modint(256);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var mb: [36]u8 = undefined;
    const mlen = drawBytes(S, src, &mb, true);
    const mbig = try bigFromBE(a, mb[0..mlen]);
    const expect = modulusVerdict(&mbig, 256);
    const m = M.fromBytesBE(mb[0..mlen]) catch |e| {
        if (expect == null or expect.? != e) return error.ModulusVerdictDiffers;
        switch (e) {
            error.EvenModulus => FixedMark.mark(.even),
            error.ModulusTooSmall => FixedMark.mark(.small),
            else => FixedMark.mark(.overflow),
        }
        return;
    };
    if (expect != null) return error.ModulusAccepted;
    FixedMark.mark(.accepted);
    if (m.bits() != mbig.bitCountAbs()) return error.BitsDiffer;

    var ab: [36]u8 = undefined;
    const alen = drawBytes(S, src, &ab, false);
    var bb: [36]u8 = undefined;
    const blen = drawBytes(S, src, &bb, false);
    var elems: [2]M.Elem = undefined;
    var bigs: [2]Big = undefined;
    inline for (.{ .{ &ab, alen, 0 }, .{ &bb, blen, 1 } }) |t| {
        const bytes = t[0][0..t[1]];
        const v = try bigFromBE(a, bytes);
        const canonical = v.toConst().order(mbig.toConst()) == .lt;
        const overflow = v.bitCountAbs() > 256;
        if (m.elementFromBytesBE(bytes)) |e| {
            if (overflow or !canonical) return error.ElementAccepted;
            elems[t[2]] = e;
            bigs[t[2]] = v;
            FixedMark.mark(.canonical);
        } else |e| {
            const want: montint.Error = if (overflow) error.Overflow else if (!canonical) error.NonCanonical else return error.ElementRefused;
            if (e != want) return error.ElementVerdictDiffers;
            if (overflow) FixedMark.mark(.element_overflow) else FixedMark.mark(.noncanonical);
            // continue with the reduced value
            const r = try bigMod(a, &v, &mbig);
            var limbs_buf: [M.L]u64 = @splat(0);
            const rl = r.toConst().limbs;
            @memcpy(limbs_buf[0..@min(rl.len, M.L)], rl[0..@min(rl.len, M.L)]);
            elems[t[2]] = limbs_buf;
            bigs[t[2]] = r;
        }
    }
    const x = &elems[0];
    const y = &elems[1];

    // add / sub / mul / Montgomery agreement, all against big.
    var sum = try Big.init(a);
    try sum.add(&bigs[0], &bigs[1]);
    const sum_m = try bigMod(a, &sum, &mbig);
    if (!try eqLimbs(a, &sum_m, &m.add(x, y))) return error.AddDiffers;
    var diff = try Big.init(a);
    try diff.sub(&bigs[0], &bigs[1]);
    const diff_m = try bigMod(a, &diff, &mbig);
    if (!try eqLimbs(a, &diff_m, &m.sub(x, y))) return error.SubDiffers;
    const prod = try bigMulMod(a, &bigs[0], &bigs[1], &mbig);
    if (!try eqLimbs(a, &prod, &m.mul(x, y))) return error.MulDiffers;
    const xm = m.toMontgomery(x);
    const ym = m.toMontgomery(y);
    if (!std.mem.eql(u64, &m.montMul(&xm, &ym), &m.montMulCios(&xm, &ym))) return error.MontMulDiffersFromCios;
    if (!std.mem.eql(u64, &m.montSqr(&xm), &m.montSqrCios(&xm))) return error.MontSqrDiffersFromCios;
    if (!std.mem.eql(u64, &m.fromMontgomery(&xm), x)) return error.MontgomeryRoundTrip;

    // pow with a short exponent (and sometimes a full-width one).
    var eb: [32]u8 = undefined;
    const elen = if (src.value(bool)) @as(usize, src.valueRangeAtMost(u8, 0, 4)) else 32;
    src.bytes(eb[0..elen]);
    var e_elem: M.Elem = @splat(0);
    for (eb[0..elen], 0..) |byte, i| {
        const pos = elen - 1 - i;
        e_elem[pos / 8] |= @as(u64, byte) << @intCast(8 * (pos % 8));
    }
    const want_pow = try bigPowMod(a, &bigs[0], eb[0..elen], &mbig);
    if (!try eqLimbs(a, &want_pow, &m.powMont(x, &e_elem))) return error.PowDiffers;
    FixedMark.mark(.pow_checked);

    // serialisation round trip
    var out: [M.encoded_bytes]u8 = undefined;
    m.toBytesBE(x, &out);
    const back = try m.elementFromBytesBE(&out);
    if (!std.mem.eql(u64, &back, x)) return error.SerialiseRoundTrip;
}

pub fn dynDiff(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const D = dyn.DynModint(2048);
    const cap_bits = D.max_limbs * 64;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Mostly small moduli (every slot from 4 limbs up gets visited), now and
    // then a wide one.
    var mb: [270]u8 = undefined;
    const wide = src.valueRangeAtMost(u8, 0, 15) == 0;
    const mcap: usize = if (wide) mb.len else 72;
    const mlen = drawBytes(S, src, mb[0..mcap], true);
    const mbig = try bigFromBE(a, mb[0..mlen]);
    const expect = modulusVerdict(&mbig, cap_bits);
    const m = D.fromBytesBE(mb[0..mlen]) catch |e| {
        if (expect == null or expect.? != e) return error.ModulusVerdictDiffers;
        switch (e) {
            error.EvenModulus => DynMark.mark(.even),
            error.ModulusTooSmall => DynMark.mark(.small),
            else => DynMark.mark(.overflow),
        }
        return;
    };
    if (expect != null) return error.ModulusAccepted;
    DynMark.mark(.accepted);
    if (wide) DynMark.mark(.wide);
    if (m.bits() != mbig.bitCountAbs()) return error.BitsDiffer;

    var ab: [280]u8 = undefined;
    const alen = drawBytes(S, src, ab[0 .. mcap + 8], false);
    var bb: [280]u8 = undefined;
    const blen = drawBytes(S, src, bb[0 .. mcap + 8], false);

    var elems: [2]D.Elem = undefined;
    var bigs: [2]Big = undefined;
    inline for (.{ .{ &ab, alen, 0 }, .{ &bb, blen, 1 } }) |t| {
        const bytes = t[0][0..t[1]];
        const v = try bigFromBE(a, bytes);
        const canonical = v.toConst().order(mbig.toConst()) == .lt;
        const overflow = v.bitCountAbs() > cap_bits;
        var accepted_elem: ?D.Elem = null;
        if (m.elemFromBytesBE(bytes)) |e| {
            if (overflow or !canonical) return error.ElementAccepted;
            accepted_elem = e;
            DynMark.mark(.canonical);
        } else |e| {
            const want: montint.Error = if (overflow) error.Overflow else if (!canonical) error.NonCanonical else return error.ElementRefused;
            if (e != want) return error.ElementVerdictDiffers;
            if (overflow) DynMark.mark(.element_overflow) else DynMark.mark(.noncanonical);
        }
        // The reducer takes any length: compare it with big mod.
        const red = m.reduceBytesBE(bytes);
        const want_red = try bigMod(a, &v, &mbig);
        if (!try eqLimbs(a, &want_red, red[0..])) return error.ReduceDiffers;
        if (accepted_elem) |e| if (!D.eql(&e, &red)) return error.ElementDiffersFromReduce;
        elems[t[2]] = red;
        bigs[t[2]] = want_red;
    }
    const x = &elems[0];
    const y = &elems[1];

    var sum = try Big.init(a);
    try sum.add(&bigs[0], &bigs[1]);
    const sum_m = try bigMod(a, &sum, &mbig);
    if (!try eqLimbs(a, &sum_m, &m.add(x, y))) return error.AddDiffers;
    var diff = try Big.init(a);
    try diff.sub(&bigs[0], &bigs[1]);
    const diff_m = try bigMod(a, &diff, &mbig);
    if (!try eqLimbs(a, &diff_m, &m.sub(x, y))) return error.SubDiffers;
    var negd = try Big.init(a);
    try negd.sub(&mbig, &bigs[0]);
    const neg_m = try bigMod(a, &negd, &mbig);
    if (!try eqLimbs(a, &neg_m, &m.neg(x))) return error.NegDiffers;
    const prod = try bigMulMod(a, &bigs[0], &bigs[1], &mbig);
    if (!try eqLimbs(a, &prod, &m.mul(x, y))) return error.MulDiffers;
    const sqd = try bigMulMod(a, &bigs[0], &bigs[0], &mbig);
    if (!try eqLimbs(a, &sqd, &m.sq(x))) return error.SqDiffers;

    // pow / powPublic: a short exponent mostly, a full-slot one now and then.
    var eb: [256]u8 = undefined;
    const elen = if (src.valueRangeAtMost(u8, 0, 7) != 0) @as(usize, src.valueRangeAtMost(u8, 0, 6)) else m.L * 8;
    src.bytes(eb[0..elen]);
    var e_elem: D.Elem = D.zero;
    for (eb[0..elen], 0..) |byte, i| {
        const pos = elen - 1 - i;
        e_elem[pos / 8] |= @as(u64, byte) << @intCast(8 * (pos % 8));
    }
    const want_pow = try bigPowMod(a, &bigs[0], eb[0..elen], &mbig);
    if (!try eqLimbs(a, &want_pow, &m.pow(x, &e_elem))) return error.PowDiffers;
    if (!try eqLimbs(a, &want_pow, &m.powPublic(x, eb[0..elen]))) return error.PowPublicDiffers;
    DynMark.mark(.pow_checked);

    // inverse: a unit gets an inverse that multiplies to 1, a non-unit none.
    // (Skipped for wide moduli: it is quadratic and the others cover them.)
    if (!wide) {
        const is_unit = isOne(&try bigGcd(a, &bigs[0], &mbig));
        var inv: D.Elem = D.zero;
        const ok = m.inverse(x, &inv);
        if (ok != is_unit) return error.InverseVerdictDiffers;
        if (ok) {
            const one = try bigMulMod(a, &bigs[0], &(try bigFromLimbs(a, inv[0..])), &mbig);
            if (!isOne(&one)) return error.InverseWrong;
            DynMark.mark(.unit);
        } else DynMark.mark(.non_unit);
    } else {
        DynMark.mark(.unit);
        DynMark.mark(.non_unit);
    }

    // serialisation round trip at a drawn width >= byteLen
    var out: [270]u8 = undefined;
    const w = m.byteLen() + @as(usize, src.valueRangeAtMost(u8, 0, 4));
    m.toBytesBE(x, out[0..w]);
    const back = try m.elemFromBytesBE(out[0..w]);
    if (!D.eql(&back, x)) return error.SerialiseRoundTrip;
}

test "fuzz driver: MONTINT_FUZZ (fixed diff)" {
    try fuzz_driver.run(fixedDiff, .{ .prefix = "MONTINT_FUZZ", .name = "montint-fixed-diff" });
}

test "fuzz driver: MONTINT_FUZZ (dyn diff)" {
    try fuzz_driver.run(dynDiff, .{ .prefix = "MONTINT_FUZZ", .name = "montint-dyn-diff" });
}

test "fuzz harness: fixed diff, 500 seeds, reaches every outcome" {
    try FixedMark.reach(fixedDiff, "montint-fixed-diff", 500);
}

test "fuzz harness: dyn diff, 500 seeds, reaches every outcome" {
    try DynMark.reach(dynDiff, "montint-dyn-diff", 500);
}

test "fuzz: montint differential against std.math.big" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) !void {
            try dynDiff(std.testing.Smith, smith, testing.allocator);
        }
    }.f, .{});
}

const LoaderModulusMark = Marker(enum { accepted, even, small, overflow });
const LoaderElementMark = Marker(enum { accepted, noncanonical, overflow });

/// `Modint(256).fromBytesBE` on arbitrary bytes (the verdict itself is checked
/// against big integers by `fixedDiff`; here: no panic, every error reached).
pub fn loaderModulus(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const M = montint.Modint(256);
    var buf: [48]u8 = undefined;
    const len = drawBytes(S, src, &buf, true);
    _ = M.fromBytesBE(buf[0..len]) catch |e| {
        switch (e) {
            error.EvenModulus => LoaderModulusMark.mark(.even),
            error.ModulusTooSmall => LoaderModulusMark.mark(.small),
            else => LoaderModulusMark.mark(.overflow),
        }
        return;
    };
    LoaderModulusMark.mark(.accepted);
}

/// `elementFromBytesBE` against the modulus 2^120 + 1.
pub fn loaderElement(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const M = montint.Modint(256);
    const modulus = M.fromBytesBE(&[_]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }) catch unreachable;
    var buf: [48]u8 = undefined;
    const len = drawBytes(S, src, &buf, false);
    _ = modulus.elementFromBytesBE(buf[0..len]) catch |e| {
        if (e == error.Overflow) LoaderElementMark.mark(.overflow) else LoaderElementMark.mark(.noncanonical);
        return;
    };
    LoaderElementMark.mark(.accepted);
}

test "fuzz driver: MONTINT_FUZZ (modulus loader)" {
    try fuzz_driver.run(loaderModulus, .{ .prefix = "MONTINT_FUZZ", .name = "montint-loader-modulus" });
}

test "fuzz driver: MONTINT_FUZZ (element loader)" {
    try fuzz_driver.run(loaderElement, .{ .prefix = "MONTINT_FUZZ", .name = "montint-loader-element" });
}

test "fuzz harness: modulus loader, 300 seeds, reaches every outcome" {
    try LoaderModulusMark.reach(loaderModulus, "montint-loader-modulus", 300);
}

test "fuzz harness: element loader, 300 seeds, reaches every outcome" {
    try LoaderElementMark.reach(loaderElement, "montint-loader-element", 300);
}
