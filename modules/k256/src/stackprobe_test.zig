// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `ecdsa_recover.sign` (A1/k256.md G2), kept in
//! the module per `CONVENTIONS.md` §9: the instrument that checks one module
//! lives with that module, not in an audit note.
//!
//! Method: paint a large stack window, call the signer at that depth, then
//! claim an equally large UNINITIALISED buffer at the same depth and count the
//! 32-byte needles in it. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe
//! fill `undefined` with 0xaa, so the scan cannot see a dead frame there (see
//! the skip in the test for the measurement).
//!
//! The needles are the RFC 6979 nonce in every representation the signing
//! path holds it in — big-endian bytes (`k_bytes`, the DRBG's `v`),
//! little-endian (`u256`/limb image, as `combMulBaseWithTable` decodes it),
//! the std scalar field's in-memory Montgomery image (`Scalar k`), and `k⁻¹`
//! (which reveals `k`) — plus the private key and `d`. Any one of them next to
//! the published signature yields the private key (`d = (s·k − e)·r⁻¹ mod n`).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks the nonce in a local, must find ≥ 1).
//! Without the positive control a scan that reads the wrong window reports the
//! same zero as a clean signer.

const std = @import("std");
const builtin = @import("builtin");
const ecdsa_recover = @import("ecdsa_recover.zig");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Scalar = scalarmod.Scalar;

const WINDOW = 256 * 1024;
const Needles = [needle_count][32]u8;
const needle_count = 8;
const needle_names = [needle_count][]const u8{
    "nonce k, big-endian",
    "nonce k, little-endian (u256 image)",
    "nonce k, Scalar in-memory (Montgomery)",
    "nonce k^-1, Scalar in-memory",
    "nonce k^-1, big-endian",
    "private key, big-endian",
    "private key, little-endian",
    "d, Scalar in-memory (Montgomery)",
};

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Count every needle in one uninitialised window claimed at the depth the
/// previous call used. Volatile reads so the buffer cannot be folded away.
noinline fn scan(needles: *const Needles) [needle_count]usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: [needle_count]usize = @splat(0);
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        for (needles, &hits) |*nd, *h| {
            var j: usize = 0;
            while (j < 32 and p[i + j] == nd[j]) : (j += 1) {}
            if (j == 32) h.* += 1;
        }
    }
    std.mem.doNotOptimizeAway(&buf);
    return hits;
}

/// How many bytes below the scan frame's top the previous call left different
/// from the paint — i.e. how deep its call tree reached. This sizes
/// `ecdsa_recover.sign_stack_burn`; it is printed, not asserted.
noinline fn dirtyDepth() usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i < WINDOW and p[i] == 0xC7) : (i += 1) {}
    std.mem.doNotOptimizeAway(&buf);
    return WINDOW - i;
}

noinline fn callSign(pk: [32]u8, h: [32]u8) ecdsa_recover.Signature {
    return ecdsa_recover.sign(pk, h) catch unreachable;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent(h: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h, &out, .{});
    return out;
}

/// Positive control: parks the nonce in a stack local and returns.
noinline fn callLeaky(k: [32]u8) u8 {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = k;
    std.mem.doNotOptimizeAway(&local);
    return local[100];
}

fn reduce32(b: [32]u8) Scalar {
    var wide: [48]u8 = [_]u8{0} ** 48;
    wide[16..48].* = b;
    return Scalar.fromBytes48(wide, .big);
}

/// RFC 6979 §3.2, re-derived here so the probe knows what to look for without
/// asking the module (which would itself leave copies).
fn nonceFor(privkey: [32]u8, hash32: [32]u8) [32]u8 {
    const h1 = reduce32(hash32).toBytes(.big);
    var v: [32]u8 = [_]u8{0x01} ** 32;
    var k: [32]u8 = [_]u8{0x00} ** 32;
    var buf: [97]u8 = undefined;
    for ([_]u8{ 0x00, 0x01 }) |sep| {
        buf[0..32].* = v;
        buf[32] = sep;
        buf[33..65].* = privkey;
        buf[65..97].* = h1;
        HmacSha256.create(&k, &buf, &k);
        HmacSha256.create(&v, &v, &k);
    }
    while (true) {
        HmacSha256.create(&v, &v, &k);
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero()) return v;
        } else |_| {}
        var b2: [33]u8 = undefined;
        b2[0..32].* = v;
        b2[32] = 0x00;
        HmacSha256.create(&k, &b2, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

fn le(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &be, .big), .little);
    return out;
}

fn memImage(s: Scalar) [32]u8 {
    return std.mem.asBytes(&s).*;
}

fn print(label: []const u8, hits: [needle_count]usize) void {
    std.debug.print("  {s}\n", .{label});
    for (needle_names, hits) |name, h| std.debug.print("    {s:<42} {d}\n", .{ name, h });
}

test "STACKPROBE (A1 G2): no RFC 6979 nonce or key residue on the dead stack after ecdsa_recover.sign" {
    // ReleaseFast/ReleaseSmall only. Debug AND ReleaseSafe fill `undefined`
    // with 0xaa, so the scan buffer never shows what the previous call left:
    // measured 2026-09-16 at ReleaseSafe, the positive control found 0 and the
    // whole window read as non-paint. The positive-control assertion below is
    // what caught that; a skip is the honest answer in those modes.
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    var privkey: [32]u8 = undefined;
    var hash: [32]u8 = undefined;
    for (&privkey, 0..) |*b, i| b.* = @intCast(0x40 +% i);
    for (&hash, 0..) |*b, i| b.* = @intCast(0x90 +% i);

    const k_be = nonceFor(privkey, hash);
    const k = try Scalar.fromBytes(k_be, .big);
    const kinv = k.invert();
    const d = try Scalar.fromBytes(privkey, .big);
    const needles: Needles = .{
        k_be,           le(k_be),           memImage(k),
        memImage(kinv), kinv.toBytes(.big), privkey,
        le(privkey),    memImage(d),
    };

    std.debug.print("\n=== STACKPROBE k256 G2 ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });

    paint();
    const inn = callInnocent(hash);
    std.mem.doNotOptimizeAway(&inn);
    const neg = scan(&needles);
    print("NEG control (sha256 of public data)", neg);

    paint();
    const lk = callLeaky(k_be);
    std.mem.doNotOptimizeAway(&lk);
    const pos = scan(&needles);
    print("POS control (nonce parked in a local)", pos);

    var total: [needle_count]usize = @splat(0);
    var reps: [5]usize = undefined;
    for (&reps) |*r| {
        paint();
        const sg = callSign(privkey, hash);
        std.mem.doNotOptimizeAway(&sg);
        const h = scan(&needles);
        var sum: usize = 0;
        for (&total, h) |*t, x| {
            t.* += x;
            sum += x;
        }
        r.* = sum;
    }
    print("ecdsa_recover.sign, summed over 5 repeats", total);
    std.debug.print("  all-needle residue per repeat: {any}\n", .{reps});

    paint();
    const sd = callSign(privkey, hash);
    std.mem.doNotOptimizeAway(&sd);
    std.debug.print("  stack bytes left non-paint below the call (burn included): {d}\n", .{dirtyDepth()});

    for (neg) |h| try std.testing.expectEqual(@as(usize, 0), h);
    try std.testing.expect(pos[0] >= 1); // the scan can see a parked nonce
    for (total) |h| try std.testing.expectEqual(@as(usize, 0), h);
}

// ── re-audit 2026-09-17 (A1 k256 R1): `Secp256k1.mul`, the ECDH path ─────────
//
// `mul` takes the SECRET scalar of `sphinx`'s per-hop DH and `bolt8`'s Noise
// DH. After the windowed multiply (F5, `1ce3087e`) the dead stack held the
// scalar's u256 (little-endian) image twice per call at ReleaseFast; the
// ladder before it held it once. Same method as the G2 probe above, one needle
// at a time, a point decoded at run time (not the comptime base point).

noinline fn scanOne(needle: *const [32]u8) usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        var j: usize = 0;
        while (j < 32 and p[i + j] == needle[j]) : (j += 1) {}
        if (j == 32) hits += 1;
    }
    std.mem.doNotOptimizeAway(&buf);
    return hits;
}

/// Returns the projective result as is: a consumer that returns right after
/// `mul` runs nothing that would overwrite its dead frames. (Encoding the
/// point here first — a field inversion — happens to overwrite them, and the
/// probe then reads 0 with or without the burn: measured 2026-09-17.)
noinline fn callMul(p: group.Secp256k1, s: [32]u8) group.Secp256k1 {
    return group.Secp256k1.mul(p, s, .big) catch unreachable;
}

test "STACKPROBE (A1 R1): no scalar residue on the dead stack after Secp256k1.mul" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("k256 stackprobe R1 point", &seed, .{});
    const enc = (try group.Secp256k1.combMulBase(seed, .big)).toCompressedSec1();
    var rt: [33]u8 = undefined;
    for (&rt, &enc) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    const p = try group.Secp256k1.fromSec1(&rt);

    var s: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("k256 stackprobe R1 secret scalar", &s, .{});
    s[0] &= 0x7f;
    const s_le = le(s);

    paint();
    std.mem.doNotOptimizeAway(callInnocent(seed));
    const neg = scanOne(&s) + scanOne(&s_le);
    paint();
    std.mem.doNotOptimizeAway(callLeaky(s_le));
    const pos = scanOne(&s_le);

    var be_hits: usize = 0;
    var le_hits: usize = 0;
    for (0..5) |_| {
        paint();
        std.mem.doNotOptimizeAway(callMul(p, s));
        le_hits += scanOne(&s_le);
        paint();
        std.mem.doNotOptimizeAway(callMul(p, s));
        be_hits += scanOne(&s);
    }
    paint();
    std.mem.doNotOptimizeAway(callMul(p, s));
    const depth = dirtyDepth();
    std.debug.print("\n=== STACKPROBE k256 R1 mul ({t}) NEG={d} POS={d} BE={d} LE={d} (5 calls each), non-paint below the call {d} B ===\n", .{ builtin.mode, neg, pos, be_hits, le_hits, depth });

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), be_hits);
    try std.testing.expectEqual(@as(usize, 0), le_hits);
}
