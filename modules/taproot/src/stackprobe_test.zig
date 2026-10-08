// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `tweakSecretKey` (review 2026-10-08), kept in
//! the module per `CONVENTIONS.md` §9. Method (2026-10-08): the direct-region
//! engine of `p256`'s `stackprobe_test.zig` (painted region below the probe,
//! call under a `PAD`-deep shim, snapshot scanned for 32-byte needles) — the
//! earlier "scan a local buffer" form was blind to the top few
//! hundred bytes of the measured call. ReleaseFast/ReleaseSmall only — Debug
//! and ReleaseSafe fill `undefined` with 0xaa (the push lane runs it in
//! ReleaseFast: `test.sh`'s `run_rf_only`).
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
var hash_sink: [32]u8 = undefined;

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    hash_sink = taproot.tapTweakHash(@splat(0x11), merkle_root);
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

fn three(be: [32]u8) [3][32]u8 {
    const s = Scalar.fromBytes(be, .big) catch unreachable;
    return .{ be, le(be), std.mem.asBytes(&s).* };
}

fn needlesFor(sk_bytes: [32]u8) !Needles {
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &(try bip340.SecretKey.fromBytes(sk_bytes)));
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

        leak_src = needles[3];

        var scratch: [needle_count]usize = @splat(0);
        measure(callInnocent);
        const neg = countAll(&needles, &scratch);
        measure(callLeaky);
        const pos = countIn(&needles[3]);

        var total: [needle_count]usize = @splat(0);
        var sum: usize = 0;
        resetDepths();
        for (0..5) |_| {
            measure(callTweak);
            sum += countAll(&needles, &total);
        }
        measure(callTweak);
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE taproot tweakSecretKey ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={d} POS(d)={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ case[31], neg, pos, depth, hit_min_depth, hit_max_depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
            }
        }
        try std.testing.expectEqual(@as(usize, 0), neg);
        try std.testing.expect(pos >= 1);
        try std.testing.expectEqual(@as(usize, 0), sum);
    }
}
