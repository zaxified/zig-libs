// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `preSign` (audit 2026-10-08), kept in the
//! module per `CONVENTIONS.md` §9. Method (2026-10-08): the direct-region
//! engine of `p256`'s `stackprobe_test.zig` (painted region below the probe,
//! call under a `PAD`-deep shim, snapshot scanned for 32-byte needles) — the
//! earlier "scan a local buffer" form was blind to the top few
//! hundred bytes of the measured call. ReleaseFast/ReleaseSmall only — Debug
//! and ReleaseSafe fill `undefined` with 0xaa (the push lane runs it in
//! ReleaseFast: `test.sh`'s `run_rf_only`).
//!
//! The needles are every secret `preSign` derives, in every representation
//! its steps hold it in: the effective scalar `d` and `n-d`, the masked key
//! `t_pad = d xor H(aux)` (the key itself to anyone who knows `aux`), the
//! nonce hash `rand`, both nonce candidates `k0` and `n-k0`, and the secret
//! key. A nonce next to the published pre-signature yields the key, exactly
//! as for a plain signature.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks `d` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const adaptor = @import("root.zig");
const bip340 = @import("bip340");
const Scalar = @import("k256").Secp256k1.scalar.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 14;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "d, big-endian",
    "d, little-endian",
    "d, Scalar in-memory",
    "n-d, big-endian",
    "t_pad = d xor H(aux)",
    "rand = H(t_pad||P||T||m)",
    "k0, big-endian",
    "k0, little-endian",
    "k0, Scalar in-memory",
    "n-k0, big-endian",
    "n-k0, little-endian",
    "n-k0, Scalar in-memory",
    "secret key, big-endian",
    "secret key, little-endian",
};

const msg = "adaptor preSign dead-stack probe message";

/// Two probe-local keys (not from any wallet or vector): one odd-y `d'·G`
/// (effective scalar `n - d'`), one even. Both arms of the normalization.
const cases = [_]struct { sk: [32]u8, aux: [32]u8 }{
    .{ .sk = keyEndingIn(0x02), .aux = @splat(0x5e) },
    .{ .sk = keyEndingIn(0x03), .aux = @splat(0xa1) },
};

fn keyEndingIn(last: u8) [32]u8 {
    var sk: [32]u8 = @splat(0);
    sk[0] = 0x10;
    sk[31] = last;
    return sk;
}

/// The adaptor point every probed call pre-signs under: public, fixed.
var probe_t: adaptor.AdaptorPoint = undefined;

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
var cur_sk: bip340.SecretKey = undefined;
var cur_aux: [32]u8 = undefined;
var hash_sink: [32]u8 = undefined;

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    std.crypto.hash.sha2.Sha256.hash(&cur_aux, &hash_sink, .{});
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

/// `preSign`'s steps 1-4 re-derived from the exported pieces, so the probe
/// knows what to look for. Runs before `paint`.
fn needlesFor(sk_bytes: [32]u8, aux: [32]u8) !Needles {
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &(try bip340.SecretKey.fromBytes(sk_bytes)));
    defer kp.deinit();
    const d = try Scalar.fromBytes(kp.secret, .big);
    const aux_hash = bip340.taggedHash(adaptor.aux_tag, &aux);
    var t_pad: [32]u8 = undefined;
    for (&t_pad, kp.secret, aux_hash) |*ti, di, ai| ti.* = di ^ ai;
    var nh = bip340.hash.taggedHasher(adaptor.nonce_tag);
    nh.update(&t_pad);
    nh.update(&kp.public.x);
    nh.update(&probe_t.toBytes());
    nh.update(msg);
    const rand = nh.finalResult();
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = rand;
    const k0 = Scalar.fromBytes48(wide, .big);
    const k_neg = k0.neg();
    return .{
        kp.secret,             le(kp.secret),           memImage(d),
        d.neg().toBytes(.big), t_pad,                   rand,
        k0.toBytes(.big),      le(k0.toBytes(.big)),    memImage(k0),
        k_neg.toBytes(.big),   le(k_neg.toBytes(.big)), memImage(k_neg),
        sk_bytes,              le(sk_bytes),
    };
}

var presign_io: std.Io = undefined;
var presign_sink: adaptor.PreSignature = undefined;

noinline fn callPreSign() void {
    presign_sink = adaptor.preSign(&cur_sk, msg, cur_aux, probe_t, presign_io) catch unreachable;
    std.mem.doNotOptimizeAway(&presign_sink);
}

test "STACKPROBE (audit 2026-10-08): no key or nonce residue on the dead stack after preSign()" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    presign_io = th.io();
    probe_t = try adaptor.AdaptorPoint.fromSecret(@splat(0x37));

    for (cases) |case| {
        cur_sk = try bip340.SecretKey.fromBytes(case.sk);
        cur_aux = case.aux;
        const needles = try needlesFor(case.sk, case.aux);
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
            measure(callPreSign);
            sum += countAll(&needles, &total);
        }
        measure(callPreSign);
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE adaptor preSign ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={d} POS(d)={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ case.sk[31], neg, pos, depth, hit_min_depth, hit_max_depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
            }
        }
        try std.testing.expectEqual(@as(usize, 0), neg);
        try std.testing.expect(pos >= 1);
        try std.testing.expectEqual(@as(usize, 0), sum);
    }
}
