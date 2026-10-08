// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `tweakSecretKey` (review 2026-10-08), kept in
//! the module per `CONVENTIONS.md` §9. Same method as `bip340`'s
//! `stackprobe_test.zig`: paint a large stack window, call the function at
//! that depth, then claim an equally large UNINITIALISED buffer at the same
//! depth and count 32-byte needles in it. ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa, so the scan cannot see a
//! dead frame there (the push lane runs it in ReleaseFast: `test.sh`'s
//! `run_rf_only`).
//!
//! The needles are the internal key, its even-y normalisation `d` and `n-d`,
//! and the tweaked key `q`, each big-endian, little-endian and as the
//! `Scalar` in-memory image.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const taproot = @import("root.zig");
const bip340 = @import("bip340");
const Scalar = @import("k256").Secp256k1.scalar.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 15;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "secret key, big-endian",
    "secret key, little-endian",
    "secret key, Scalar in-memory",
    "d, big-endian",
    "d, little-endian",
    "d, Scalar in-memory",
    "n-d, big-endian",
    "n-d, little-endian",
    "n-d, Scalar in-memory",
    "q, big-endian",
    "q, little-endian",
    "q, Scalar in-memory",
    "n-q, big-endian",
    "n-q, little-endian",
    "n-q, Scalar in-memory",
};

/// Two probe-local keys (not from any wallet or vector), so both arms of the
/// even-y normalisation run.
const cases = [_][32]u8{ keyEndingIn(0x02), keyEndingIn(0x03) };
const merkle_root: [32]u8 = @splat(0x6d);

fn keyEndingIn(last: u8) [32]u8 {
    var sk: [32]u8 = @splat(0);
    sk[0] = 0x2a;
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
/// Printed, not asserted.
noinline fn dirtyDepth() usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i < WINDOW and p[i] == 0xC7) : (i += 1) {}
    std.mem.doNotOptimizeAway(&buf);
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    std.mem.doNotOptimizeAway(taproot.tapTweakHash(@splat(0x11), merkle_root));
}

/// Positive control: parks a secret in a stack local and returns.
noinline fn callLeaky(secret: *const [32]u8) void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = secret.*;
    std.mem.doNotOptimizeAway(&local);
}

fn le(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &be, .big), .little);
    return out;
}

fn three(be: [32]u8) [3][32]u8 {
    const s = Scalar.fromBytes(be, .big) catch unreachable;
    return .{ be, le(be), std.mem.asBytes(&s).* };
}

fn needlesFor(sk_bytes: [32]u8) !Needles {
    var kp = try bip340.KeyPair.fromSecretKey(try bip340.SecretKey.fromBytes(sk_bytes));
    defer kp.deinit();
    const d = try Scalar.fromBytes(kp.secret, .big);
    var q: [32]u8 = undefined;
    const sk = try bip340.SecretKey.fromBytes(sk_bytes);
    try taproot.tweakSecretKey(&sk, merkle_root, &q);
    const qs = try Scalar.fromBytes(q, .big);
    return three(sk_bytes) ++ three(kp.secret) ++ three(d.neg().toBytes(.big)) ++
        three(q) ++ three(qs.neg().toBytes(.big));
}

/// Where the probed call puts its secret result: a global, so this wrapper's
/// own frame (inside the scanned window) holds no copy.
var sink_q: [32]u8 = undefined;
var probe_sk: bip340.SecretKey = undefined;

noinline fn callTweak() void {
    taproot.tweakSecretKey(&probe_sk, merkle_root, &sink_q) catch unreachable;
    std.crypto.secureZero(u8, &sink_q);
}

test "STACKPROBE (review 2026-10-08): no key residue on the dead stack after tweakSecretKey()" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    for (cases) |case| {
        probe_sk = try bip340.SecretKey.fromBytes(case);
        const needles = try needlesFor(case);

        paint();
        callInnocent();
        const neg = scan(&needles);

        paint();
        callLeaky(&needles[3]);
        const pos = scan(&needles);

        var total: [needle_count]usize = @splat(0);
        for (0..5) |_| {
            paint();
            callTweak();
            for (&total, scan(&needles)) |*t, x| t.* += x;
        }
        paint();
        callTweak();
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE taproot tweakSecretKey ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={any} POS(d)={d} dirty below the call={d} B\n", .{ case[31], neg, pos[3], depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
            }
        }
        for (neg) |h| try std.testing.expectEqual(@as(usize, 0), h);
        try std.testing.expect(pos[3] >= 1);
        for (total) |h| try std.testing.expectEqual(@as(usize, 0), h);
    }
}
