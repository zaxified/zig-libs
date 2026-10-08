// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `sign` (audit 2026-10-08), kept in the
//! module per `CONVENTIONS.md` §9. Method (2026-10-08): the direct-region
//! engine of `p256`'s `stackprobe_test.zig` (painted region below the probe,
//! call under a `PAD`-deep shim, snapshot scanned for 32-byte needles) — the
//! earlier "scan a local buffer" form was blind to the top few
//! hundred bytes of the measured call. ReleaseFast/ReleaseSmall only (Debug
//! and ReleaseSafe fill `undefined`); the push lane runs it in ReleaseFast.
//!
//! The needles: the secret key `d'` and `n-d'` (the effective `d = g·gacc·d'`
//! is one of them in an untweaked session), both secret nonces `k1'`, `k2'`
//! and their negations, in big-endian, little-endian and `Scalar` images.
//! Either nonce next to the published partial signature yields the key.
//!
//! ⛔ A zero is only readable next to the NEGATIVE control (public data only,
//! must find 0) and the POSITIVE control (parks `d'` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const musig2 = @import("root.zig");
const bip340 = @import("bip340");
const k256 = @import("k256");
const Scalar = k256.Secp256k1.scalar.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 18;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "d', big-endian",    "d', little-endian",    "d', Scalar in-memory",
    "n-d', big-endian",  "n-d', little-endian",  "n-d', Scalar in-memory",
    "k1', big-endian",   "k1', little-endian",   "k1', Scalar in-memory",
    "n-k1', big-endian", "n-k1', little-endian", "n-k1', Scalar in-memory",
    "k2', big-endian",   "k2', little-endian",   "k2', Scalar in-memory",
    "n-k2', big-endian", "n-k2', little-endian", "n-k2', Scalar in-memory",
};

const msg = "musig2 sign dead-stack probe message";

/// Two probe-local keys, each signing alone (u = 1) and with a fixed partner.
const cases = [_]struct { sk: [32]u8, rand: [32]u8 }{
    .{ .sk = keyEndingIn(0x02), .rand = @splat(0x5e) },
    .{ .sk = keyEndingIn(0x03), .rand = @splat(0xa1) },
};

fn keyEndingIn(last: u8) [32]u8 {
    var sk: [32]u8 = @splat(0);
    sk[0] = 0x10;
    sk[31] = last;
    return sk;
}

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

var leak_src: [32]u8 = undefined;
var cur_rand: [32]u8 = undefined;
var hash_sink: [32]u8 = undefined;

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    std.crypto.hash.sha2.Sha256.hash(&cur_rand, &hash_sink, .{});
    std.mem.doNotOptimizeAway(&hash_sink);
}

/// Positive control: parks a secret in a stack local and returns.
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Sum of occurrences of every needle in the last snapshot; `hits` gets the
/// per-needle counts added.
fn countAll(needles: *const Needles, hits: *[needle_count]usize) usize {
    var sum: usize = 0;
    for (needles, hits) |*nd, *h| {
        const c = countIn(nd);
        h.* += c;
        sum += c;
    }
    return sum;
}

fn le(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &be, .big), .little);
    return out;
}

fn memImage(s: Scalar) [32]u8 {
    return std.mem.asBytes(&s).*;
}

fn three(s: Scalar) [3][32]u8 {
    return .{ s.toBytes(.big), le(s.toBytes(.big)), memImage(s) };
}

fn needlesFor(sk_bytes: [32]u8, sn: musig2.SecNonce) !Needles {
    const d = try Scalar.fromBytes(sk_bytes, .big);
    const k1 = try sn.k1Scalar();
    const k2 = try sn.k2Scalar();
    const parts = [_][3][32]u8{ three(d), three(d.neg()), three(k1), three(k1.neg()), three(k2), three(k2.neg()) };
    var out: Needles = undefined;
    for (parts, 0..) |p, i| out[3 * i ..][0..3].* = p;
    return out;
}

/// The session and the nonce live in static memory, which the stack scan
/// never reads: the probe measures what `sign` leaves, not the harness's
/// own copies. `sign` consumes `probe_secnonce`, so it is refilled from
/// `probe_fresh` (also static) before every call.
var probe_fresh: musig2.SecNonce = undefined;
var probe_secnonce: musig2.SecNonce = undefined;
var probe_sk: bip340.SecretKey = undefined;
var probe_ctx: musig2.SessionContext = undefined;
var probe_pks: [2]musig2.PlainPublicKey = undefined;

var psig_sink: musig2.PartialSignature = undefined;

noinline fn callSign() void {
    probe_secnonce = probe_fresh;
    psig_sink = musig2.sign(&probe_secnonce, &probe_sk, probe_ctx) catch unreachable;
    std.mem.doNotOptimizeAway(&psig_sink);
}

test "STACKPROBE (audit 2026-10-08): no key or nonce residue on the dead stack after sign()" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const io = std.testing.io;
    const partner_sk = [_]u8{0x6B} ** 32;
    const partner_pk = musig2.PlainPublicKey{ .bytes = (try k256.Secp256k1.combMulBase(partner_sk, .big)).toCompressedSec1() };
    const partner = try musig2.nonceGen(partner_sk, partner_pk.bytes, null, msg, null, [_]u8{0x77} ** 32, io);

    for (cases) |case| {
        probe_sk = try bip340.SecretKey.fromBytes(case.sk);
        const pk = musig2.PlainPublicKey{ .bytes = (try k256.Secp256k1.combMulBase(case.sk, .big)).toCompressedSec1() };
        probe_pks = .{ pk, partner_pk };
        musig2.keySort(&probe_pks);
        const ng = try musig2.nonceGen(case.sk, pk.bytes, null, msg, null, case.rand, io);
        probe_fresh = ng.secnonce;
        probe_ctx = .{ .aggnonce = try musig2.nonceAgg(&.{ ng.pubnonce, partner.pubnonce }), .pubkeys = &probe_pks, .msg = msg };
        const needles = try needlesFor(case.sk, probe_fresh);

        cur_rand = case.rand;
        leak_src = needles[0];

        var scratch: [needle_count]usize = @splat(0);
        measure(callInnocent);
        const neg = countAll(&needles, &scratch);
        measure(callLeaky);
        const pos = countIn(&needles[0]);

        var total: [needle_count]usize = @splat(0);
        var sum: usize = 0;
        resetDepths();
        for (0..5) |_| {
            measure(callSign);
            sum += countAll(&needles, &total);
        }
        measure(callSign);
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE musig2 sign ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={d} POS(d')={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ case.sk[31], neg, pos, depth, hit_min_depth, hit_max_depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<26} {d} (5 calls)\n", .{ name, h });
            }
        }
        try std.testing.expectEqual(@as(usize, 0), neg);
        try std.testing.expect(pos >= 1);
        try std.testing.expectEqual(@as(usize, 0), sum);
    }
}
