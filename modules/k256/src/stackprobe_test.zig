// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `ecdsa_recover.sign` (A1/k256.md G2), the ECDH
//! `Secp256k1.mul`, `sign.bip340Sign` and `Secp256k1.combMulBase`, kept in the
//! module per `CONVENTIONS.md` §9: the instrument that checks one module lives
//! with that module, not in an audit note.
//!
//! Method (2026-10-08): the direct-region engine of `p256`'s probe — a painted
//! region below the probe, the call run under a `PAD`-deep shim, a snapshot
//! scanned for needles — because the earlier form, which scanned a local
//! buffer below the call, was blind to the top few hundred bytes of the
//! measured call (the scanner's own frame). ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa and the paint is not what
//! a dead frame leaves there.
//!
//! The G2 needles are the RFC 6979 nonce in every representation the signing
//! path holds it in — big-endian bytes (`k_bytes`, the DRBG's `v`),
//! little-endian (`u256`/limb image, as `combMulBaseWithTable` decodes it),
//! the std scalar field's in-memory Montgomery image (`Scalar k`), and `k⁻¹`
//! (which reveals `k`) — plus the private key and `d`. Any one of them next to
//! the published signature yields the private key (`d = (s·k − e)·r⁻¹ mod n`).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks the secret in a local, must find ≥ 1).

const std = @import("std");
const builtin = @import("builtin");
const ecdsa_recover = @import("ecdsa_recover.zig");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");
const sign_mod = @import("sign.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Scalar = scalarmod.Scalar;

const WINDOW = 256 * 1024;

// ── the measured region (2026-10-08) ────────────────────────────────────────
//
// Direct-region engine, as `p256`'s probe: the region lies `PAD` bytes below
// the probe's own stack position and the measured call runs as `shim(call)`
// under a `PAD`-deep frame. The earlier "scan a local buffer" form
// was blind to the top few hundred bytes (the scanner's own header and
// locals), i.e. to the callers' and wrappers' frames. Calls are no-argument
// `noinline fn`s: inputs come from module-level `var`s and results go into
// module-level `var`s, so the harness's own locals never hold the secret.
const PAD = 2048;

var region_lo: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe, at the depth
/// `paint`/`shim`/`snapshot` start at.
noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe; `pad` is touched after the
/// call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

/// Zero the callee-saved registers before a measured call: they still hold the
/// test's own values (needles it just computed) and the call's prologue spills
/// them into its frame, where the scan would credit them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// Paint the region, run `call` under `shim`, snapshot the region into `snap`.
/// `inline`: the region top is computed in the caller's own frame, and as a
/// frame of its own it would run the call deeper than that top.
inline fn measure(call: *const fn () void) void {
    region_lo = stackHere() - PAD - WINDOW;
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
}

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Bytes below the region's top of the shallowest / deepest needle hit seen by
/// `countIn` since the last `resetDepths`.
var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn resetDepths() void {
    hit_min_depth = 0;
    hit_max_depth = 0;
}

/// Occurrences of the 32-byte `needle` in the last snapshot.
fn countIn(needle: *const [32]u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        if (snap[i] == needle[0] and std.mem.eql(u8, snap[i..][0..32], needle)) {
            hits += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
        }
    }
    return hits;
}

// ── controls and probed calls (all `noinline`, no arguments, static in/out) ──

var leak_src: [32]u8 = undefined;
var cur_pk: [32]u8 = undefined;
var cur_hash: [32]u8 = undefined;
var cur_aux: [32]u8 = undefined;
var cur_point: group.Secp256k1 = undefined;
var sig_sink: ecdsa_recover.Signature = undefined;
var hash_sink: [32]u8 = undefined;
var point_sink: group.Secp256k1 = undefined;
var bip340_sink: [64]u8 = undefined;
const bip340_msg = "k256 bip340Sign dead-stack probe";

noinline fn callSign() void {
    sig_sink = ecdsa_recover.sign(&cur_pk, cur_hash) catch unreachable;
    std.mem.doNotOptimizeAway(&sig_sink);
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    std.crypto.hash.sha2.Sha256.hash(&cur_hash, &hash_sink, .{});
    std.mem.doNotOptimizeAway(&hash_sink);
}

/// Positive control: parks the secret in a stack local and returns.
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
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

/// Sum of occurrences of every needle in the last snapshot; `hits[i]` gets the
/// per-needle count added.
fn countAll(needles: []const [32]u8, hits: []usize) usize {
    var sum: usize = 0;
    for (needles, hits) |*nd, *h| {
        const c = countIn(nd);
        h.* += c;
        sum += c;
    }
    return sum;
}

const needle_names = [_][]const u8{
    "nonce k, big-endian",
    "nonce k, little-endian (u256 image)",
    "nonce k, Scalar in-memory (Montgomery)",
    "nonce k^-1, Scalar in-memory",
    "nonce k^-1, big-endian",
    "private key, big-endian",
    "private key, little-endian",
    "d, Scalar in-memory (Montgomery)",
};

test "STACKPROBE (A1 G2): no RFC 6979 nonce or key residue on the dead stack after ecdsa_recover.sign" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    for (&cur_pk, 0..) |*b, i| b.* = @intCast(0x40 +% i);
    for (&cur_hash, 0..) |*b, i| b.* = @intCast(0x90 +% i);

    const k_be = nonceFor(cur_pk, cur_hash);
    const k = try Scalar.fromBytes(k_be, .big);
    const kinv = k.invert();
    const d = try Scalar.fromBytes(cur_pk, .big);
    const needles = [_][32]u8{
        k_be,           le(k_be),           memImage(k),
        memImage(kinv), kinv.toBytes(.big), cur_pk,
        le(cur_pk),     memImage(d),
    };
    leak_src = k_be;

    var scratch: [needles.len]usize = @splat(0);
    measure(callInnocent);
    const neg = countAll(&needles, &scratch);
    measure(callLeaky);
    const pos = countAll(&needles, &scratch);

    var total: [needles.len]usize = @splat(0);
    var sum: usize = 0;
    resetDepths();
    for (0..5) |_| {
        measure(callSign);
        sum += countAll(&needles, &total);
    }
    measure(callSign);
    const depth = dirtyDepth();

    // Printed only when an assertion below fails: the lane treats stderr from
    // a passing test as a FAIL (scripts/lib/test-lib.sh).
    errdefer {
        std.debug.print("\n=== STACKPROBE k256 G2 ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ builtin.mode, WINDOW / 1024, neg, pos, depth });
        for (needle_names, total) |name, h| std.debug.print("    {s:<42} {d} (5 calls)\n", .{ name, h });
        std.debug.print("    hits {d}..{d} B below the region top\n", .{ hit_min_depth, hit_max_depth });
    }

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1); // the scan can see a parked nonce
    try std.testing.expectEqual(@as(usize, 0), sum);
}

// ── re-audit 2026-09-15 (A1 k256 R1): `Secp256k1.mul`, the ECDH path ─────────
//
// `mul` takes the SECRET scalar of `sphinx`'s per-hop DH and `bolt8`'s Noise
// DH. After the windowed multiply (F5, `1ce3087e`) the dead stack held the
// scalar's u256 (little-endian) image twice per call at ReleaseFast; the
// ladder before it held it once. One needle at a time, a point decoded at run
// time (not the comptime base point).

var cur_scalar: [32]u8 = undefined;

/// Leaves the projective result as is: a consumer that returns right after
/// `mul` runs nothing that would overwrite its dead frames. (Encoding the
/// point here first — a field inversion — happens to overwrite them, and the
/// probe then reads 0 with or without the burn: measured 2026-09-15.)
noinline fn callMul() void {
    cur_point.mulInto(&point_sink, &cur_scalar, .big) catch unreachable;
    std.mem.doNotOptimizeAway(&point_sink);
}

test "STACKPROBE (A1 R1): no scalar residue on the dead stack after Secp256k1.mulInto" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("k256 stackprobe R1 point", &seed, .{});
    const enc = (try group.Secp256k1.combMulBase(seed, .big)).toCompressedSec1();
    var rt: [33]u8 = undefined;
    for (&rt, &enc) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    cur_point = try group.Secp256k1.fromSec1(&rt);

    std.crypto.hash.sha2.Sha256.hash("k256 stackprobe R1 secret scalar", &cur_scalar, .{});
    cur_scalar[0] &= 0x7f;
    const s_le = le(cur_scalar);
    cur_hash = seed;
    leak_src = s_le;

    measure(callInnocent);
    const neg = countIn(&cur_scalar) + countIn(&s_le);
    measure(callLeaky);
    const pos = countIn(&s_le);

    var be_hits: usize = 0;
    var le_hits: usize = 0;
    resetDepths();
    for (0..5) |_| {
        measure(callMul);
        le_hits += countIn(&s_le);
        be_hits += countIn(&cur_scalar);
    }
    measure(callMul);
    const depth = dirtyDepth();
    errdefer std.debug.print("\n=== STACKPROBE k256 R1 mul ({t}) NEG={d} POS={d} BE={d} LE={d} (5 calls), dirty {d} B, hits {d}..{d} B ===\n", .{ builtin.mode, neg, pos, be_hits, le_hits, depth, hit_min_depth, hit_max_depth });

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), be_hits);
    try std.testing.expectEqual(@as(usize, 0), le_hits);
}

// ── review 2026-10-08: `sign.bip340Sign` ─────────────────────────────────────
//
// The README's and the example's Schnorr signer, until now outside every
// probe (SPEC "Secret residue on the dead stack" listed it as not covered). The needles are BIP340's secrets re-derived here: the key, the
// effective scalar `d` and the nonce `k'`, in the representations the path
// holds them in.

fn taggedHash(comptime tag: []const u8, parts: []const []const u8) [32]u8 {
    var td: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tag, &td, .{});
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&td);
    h.update(&td);
    for (parts) |p| h.update(p);
    return h.finalResult();
}

noinline fn callBip340Sign() void {
    bip340_sink = sign_mod.bip340Sign(&cur_pk, bip340_msg, cur_aux) catch unreachable;
    std.mem.doNotOptimizeAway(&bip340_sink);
}

test "STACKPROBE (review 2026-10-08): no key or nonce residue on the dead stack after sign.bip340Sign" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    // Two keys, so both arms of the even-y select run: `d = d'` and `d = n − d'`.
    for ([_]u8{ 0x02, 0x03 }) |last| {
        cur_pk = @splat(0);
        cur_pk[0] = 0x21;
        cur_pk[31] = last;
        cur_aux = @splat(last);
        const sk = cur_pk;

        const dp = try Scalar.fromBytes(sk, .big);
        const P = (try group.Secp256k1.combMulBase(sk, .big)).affineCoordinates();
        const d = if (P.y.isOdd()) dp.neg() else dp;
        const px = P.x.toBytes(.big);
        const aux_h = taggedHash("BIP0340/aux", &.{&cur_aux});
        var t: [32]u8 = undefined;
        for (&t, d.toBytes(.big), aux_h) |*ti, di, ai| ti.* = di ^ ai;
        const rand = taggedHash("BIP0340/nonce", &.{ &t, &px, bip340_msg });
        const k0 = reduce32(rand);
        const needles = [_][32]u8{
            sk,                    le(sk),       memImage(d),            d.toBytes(.big),
            d.neg().toBytes(.big), t,            rand,                   k0.toBytes(.big),
            le(k0.toBytes(.big)),  memImage(k0), k0.neg().toBytes(.big), memImage(k0.neg()),
        };
        leak_src = needles[0];
        cur_hash = cur_aux;

        var scratch = [_]usize{0} ** needles.len;
        measure(callInnocent);
        const neg = countAll(&needles, &scratch);
        measure(callLeaky);
        const pos = countIn(&needles[0]);

        var hits = [_]usize{0} ** needles.len;
        resetDepths();
        for (0..5) |_| {
            measure(callBip340Sign);
            _ = countAll(&needles, &hits);
        }
        measure(callBip340Sign);
        const depth = dirtyDepth();
        errdefer std.debug.print("\n=== STACKPROBE k256 bip340Sign ({t}) key ..{x:0>2}: NEG={d} POS={d} per-needle={any} (5 calls), dirty {d} B, hits {d}..{d} B ===\n", .{ builtin.mode, last, neg, pos, hits, depth, hit_min_depth, hit_max_depth });

        try std.testing.expectEqual(@as(usize, 0), neg);
        try std.testing.expect(pos >= 1);
        for (hits) |h| try std.testing.expectEqual(@as(usize, 0), h);
    }
}

// ── review 2026-10-08: `Secp256k1.combMulBase` ───────────────────────────────
//
// The fixed-base multiply every key derivation runs on a SECRET scalar
// (bip32's `pubkeyFromPriv`, taproot's tweak, frost/dkg shares). `mul` burns
// its stack (A1 R1); `combMulBase` shares its recoding, so the same compiler
// copies of the wide shifts can be left behind. Measured before the fix
// (ReleaseFast): the little-endian image of the scalar, once per call.

noinline fn callCombMulBase() void {
    point_sink = group.Secp256k1.combMulBase(cur_scalar, .big) catch unreachable;
    std.mem.doNotOptimizeAway(&point_sink);
}

test "STACKPROBE (review 2026-10-08): no scalar residue on the dead stack after Secp256k1.combMulBase" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    std.crypto.hash.sha2.Sha256.hash("k256 stackprobe combMulBase secret scalar", &cur_scalar, .{});
    cur_scalar[0] &= 0x7f;
    const s_le = le(cur_scalar);
    const s_mem = memImage(try Scalar.fromBytes(cur_scalar, .big));
    cur_hash = @splat(0x5a);
    leak_src = s_le;

    measure(callInnocent);
    const neg = countIn(&cur_scalar) + countIn(&s_le) + countIn(&s_mem);
    measure(callLeaky);
    const pos = countIn(&s_le);

    var be_hits: usize = 0;
    var le_hits: usize = 0;
    var mem_hits: usize = 0;
    resetDepths();
    for (0..5) |_| {
        measure(callCombMulBase);
        be_hits += countIn(&cur_scalar);
        le_hits += countIn(&s_le);
        mem_hits += countIn(&s_mem);
    }
    measure(callCombMulBase);
    const depth = dirtyDepth();
    errdefer std.debug.print("\n=== STACKPROBE k256 combMulBase ({t}) NEG={d} POS={d} BE={d} LE={d} MEM={d} (5 calls), dirty {d} B, hits {d}..{d} B ===\n", .{ builtin.mode, neg, pos, be_hits, le_hits, mem_hits, depth, hit_min_depth, hit_max_depth });

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), be_hits);
    try std.testing.expectEqual(@as(usize, 0), le_hits);
    try std.testing.expectEqual(@as(usize, 0), mem_hits);
}
