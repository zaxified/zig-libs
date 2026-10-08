// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `sign` (audit 2026-10-08), kept in the
//! module per `CONVENTIONS.md` §9. Same method as `bip340`'s and `adaptor`'s
//! `stackprobe_test.zig`: paint a large stack window, sign at that depth,
//! then claim an equally large UNINITIALISED buffer at the same depth and
//! count 32-byte needles in it. ReleaseFast/ReleaseSmall only (Debug and
//! ReleaseSafe fill `undefined`); the push lane runs it in ReleaseFast.
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

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

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

/// How deep the previous call dirtied the stack below the scan frame's top.
/// Sizes `root.zig`'s `sign_stack_burn`; printed, not asserted.
noinline fn dirtyDepth() usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i < WINDOW and p[i] == 0xC7) : (i += 1) {}
    std.mem.doNotOptimizeAway(&buf);
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent(h: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h, &out, .{});
    return out;
}

/// Positive control: parks a secret in a stack local and returns.
noinline fn callLeaky(secret: [32]u8) u8 {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = secret;
    std.mem.doNotOptimizeAway(&local);
    return local[100];
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

noinline fn callSign() void {
    probe_secnonce = probe_fresh;
    const psig = musig2.sign(&probe_secnonce, probe_sk, probe_ctx) catch unreachable;
    std.mem.doNotOptimizeAway(&psig);
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

        paint();
        std.mem.doNotOptimizeAway(callInnocent(case.rand));
        const neg = scan(&needles);

        paint();
        std.mem.doNotOptimizeAway(callLeaky(needles[0]));
        const pos = scan(&needles);

        var total: [needle_count]usize = @splat(0);
        for (0..5) |_| {
            paint();
            callSign();
            for (&total, scan(&needles)) |*t, x| t.* += x;
        }
        paint();
        callSign();
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE musig2 sign ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={any} POS(d')={d} dirty below the call={d} B\n", .{ case.sk[31], neg, pos[0], depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<26} {d} (5 calls)\n", .{ name, h });
            }
        }
        for (neg) |h| try std.testing.expectEqual(@as(usize, 0), h);
        try std.testing.expect(pos[0] >= 1);
        for (total) |h| try std.testing.expectEqual(@as(usize, 0), h);
    }
}
