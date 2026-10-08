// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `sign` (A1/bip340.md F2), kept in the module
//! per `CONVENTIONS.md` §9: the instrument that checks one module lives with
//! that module, not in an audit note.
//!
//! Method (2026-10-08): the direct-region engine of `p256`'s probe (painted
//! region below the probe, call under a `PAD`-deep shim, snapshot scanned for
//! 32-byte needles) — the earlier "scan a local buffer" form was
//! blind to the top few hundred bytes of the measured call. ReleaseFast/
//! ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with 0xaa.
//!
//! The needles are every secret `sign` derives, in every representation the
//! signing path holds it in: the effective scalar `d` and `n-d`, the nonce
//! material `t` and `rand`, both nonce candidates `k'` and `n-k'`, and the
//! secret key — big-endian bytes, little-endian (the `u256` image
//! `combMulBase` decodes) and the scalar field's in-memory image. Any nonce
//! next to the published signature yields the private key.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks `d` in a local, must find it). Without
//! the positive control a scan that reads the wrong window reports the same
//! zero as a clean signer.
//!
//! `expectNoResidue` is shared: this file checks the public `sign`, and
//! `root.zig` checks `computeAndBurn` alone — with no step-10 `verify` after
//! it, whose frames overwrite the same region and would hide a missing burn
//! (they did hide the original residue from 2026-09-11 on).

const std = @import("std");
const builtin = @import("builtin");
const bip340 = @import("root.zig");
const Scalar = @import("k256").Secp256k1.scalar.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 14;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "d, big-endian",
    "d, little-endian",
    "d, Scalar in-memory",
    "n-d, big-endian",
    "t = d xor H(aux)",
    "rand = H(t || P || m)",
    "k', big-endian",
    "k', little-endian",
    "k', Scalar in-memory",
    "n-k', big-endian",
    "n-k', little-endian",
    "n-k', Scalar in-memory",
    "secret key, big-endian",
    "secret key, little-endian",
};

/// The message every probed call signs.
pub const msg = "bip340 F2 dead-stack probe message";

/// Two audit-local keys (not from any wallet or BIP340 vector): the first has
/// an odd-y `d'·G`, so the effective scalar is `n - d'`; the second an even
/// one, so it is `d'` itself. Both paths of `KeyPair.fromSecretKey`'s select.
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

/// BIP340 steps 1-5, re-derived from the module's exported pieces so the
/// probe knows what to look for. Runs before `paint`, so its own copies are
/// painted over before the measured call.
fn needlesFor(sk_bytes: [32]u8, aux: [32]u8) !Needles {
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &(try bip340.SecretKey.fromBytes(sk_bytes)));
    defer kp.deinit();
    const d = try Scalar.fromBytes(kp.secret, .big);
    const aux_hash = bip340.taggedHash(bip340.hash.aux_tag, &aux);
    var t: [32]u8 = undefined;
    for (&t, kp.secret, aux_hash) |*ti, di, ai| ti.* = di ^ ai;
    var nh = bip340.hash.taggedHasher(bip340.hash.nonce_tag);
    nh.update(&t);
    nh.update(&kp.public.x);
    nh.update(msg);
    const rand = nh.finalResult();
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = rand;
    const k = Scalar.fromBytes48(wide, .big);
    const k_neg = k.neg();
    return .{
        kp.secret,             le(kp.secret),           memImage(d),
        d.neg().toBytes(.big), t,                       rand,
        k.toBytes(.big),       le(k.toBytes(.big)),     memImage(k),
        k_neg.toBytes(.big),   le(k_neg.toBytes(.big)), memImage(k_neg),
        sk_bytes,              le(sk_bytes),
    };
}

/// Measure `call` (a no-argument `noinline fn` reading `cur_sk`/`cur_aux`)
/// five times per key beside a negative and a positive control, and fail on
/// any secret found.
fn runCases(label: []const u8, call: *const fn () void) !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    for (cases, 0..) |case, ci| {
        cur_case = ci;
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
            measure(call);
            sum += countAll(&needles, &total);
        }
        measure(call);
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE bip340 F2: {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={d} POS(d)={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ case.sk[31], neg, pos, depth, hit_min_depth, hit_max_depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
            }
        }
        try std.testing.expectEqual(@as(usize, 0), neg);
        try std.testing.expect(pos >= 1); // the scan can see a parked secret
        try std.testing.expectEqual(@as(usize, 0), sum);
    }
}

var cur_case: usize = 0;

/// Shared with `root.zig`, which checks `computeAndBurn` alone through a
/// `fn (*const SecretKey, *const [32]u8) void`: a thunk passes pointers to the
/// statics (by value, the thunk's own argument copies were counted).
pub fn expectNoResidue(label: []const u8, comptime call: fn (*const bip340.SecretKey, *const [32]u8) void) !void {
    const T = struct {
        noinline fn run() void {
            call(&cur_sk, &cur_aux);
        }
    };
    try runCases(label, T.run);
}

var sign_io: std.Io = undefined;

noinline fn callSign() void {
    sig_sink = bip340.sign(&cur_sk, msg, cur_aux, sign_io) catch unreachable;
    std.mem.doNotOptimizeAway(&sig_sink);
}

var sig_sink: [64]u8 = undefined;

test "STACKPROBE (A1 F2): no key or nonce residue on the dead stack after sign()" {
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    sign_io = th.io();
    try runCases("sign", callSign);
}

/// Key pairs for `callSignWithKeyPair`, built before the probe paints, in
/// static memory: the probe measures what signing leaves behind, not the
/// caller's own copy of the pair.
var probe_pairs: [cases.len]bip340.KeyPair = undefined;

noinline fn callSignWithKeyPair() void {
    sig_sink = bip340.signWithKeyPair(&probe_pairs[cur_case], msg, cur_aux, sign_io) catch unreachable;
    std.mem.doNotOptimizeAway(&sig_sink);
}

test "STACKPROBE: no key or nonce residue on the dead stack after signWithKeyPair()" {
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    sign_io = th.io();
    for (cases, &probe_pairs) |case, *kp| try bip340.KeyPair.fromSecretKey(kp, &(try bip340.SecretKey.fromBytes(case.sk)));
    defer for (&probe_pairs) |*kp| kp.deinit();
    try runCases("signWithKeyPair", callSignWithKeyPair);
}

var kp_sink: bip340.KeyPair = undefined;

noinline fn callKeyPairFromSecretKey() void {
    bip340.KeyPair.fromSecretKey(&kp_sink, &cur_sk) catch unreachable;
    std.mem.doNotOptimizeAway(&kp_sink.public);
    kp_sink.deinit();
}

// `signWithKeyPair` moves steps 1-2 out of `sign`'s burned frame into the
// caller's own `KeyPair.fromSecretKey` call, so that call is now a signing
// path of its own and gets the same probe.
test "STACKPROBE: no key residue on the dead stack after KeyPair.fromSecretKey()" {
    try runCases("KeyPair.fromSecretKey", callKeyPairFromSecretKey);
}
