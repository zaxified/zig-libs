// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `generateNonces`, `round1Commit` and
//! `round2Sign` (audit 2026-10-08), kept in the module per `CONVENTIONS.md`
//! §9. Method (2026-10-08): the direct-region engine of `p256`'s
//! `stackprobe_test.zig` (painted region below the probe, call under a
//! `PAD`-deep shim, snapshot scanned for 32-byte needles) — the earlier "scan a
//! local buffer" form was blind to the top few hundred bytes of the
//! measured call. ReleaseFast/ReleaseSmall only (Debug and ReleaseSafe fill
//! `undefined`); the push lane runs it in ReleaseFast.
//!
//! The needles: the signing share `sk_i` and `n-sk_i`, the hiding and the
//! binding nonce and their negations, in big-endian, little-endian and
//! `Scalar` images. A nonce next to the published signature share yields
//! `lambda_i·sk_i`, i.e. the share.
//!
//! ⛔ A zero is only readable next to the NEGATIVE control (public data only,
//! must find 0) and the POSITIVE control (parks `sk_i` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const frost = @import("root.zig");
const Scalar = frost.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 18;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "sk_i, big-endian",      "sk_i, little-endian",      "sk_i, Scalar in-memory",
    "n-sk_i, big-endian",    "n-sk_i, little-endian",    "n-sk_i, Scalar in-memory",
    "hiding, big-endian",    "hiding, little-endian",    "hiding, Scalar in-memory",
    "n-hiding, big-endian",  "n-hiding, little-endian",  "n-hiding, Scalar in-memory",
    "binding, big-endian",   "binding, little-endian",   "binding, Scalar in-memory",
    "n-binding, big-endian", "n-binding, little-endian", "n-binding, Scalar in-memory",
};

const msg = "frost round2Sign dead-stack probe message";

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
    std.crypto.hash.sha2.Sha256.hash(&p_hr, &hash_sink, .{});
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

/// Everything the calls read lives in static memory, which the stack scan
/// never reads: the probe measures what the calls leave, not the harness's
/// own copies.
var p_share: frost.SigningShare = undefined;
var p_id: frost.Identifier = undefined;
var p_gpk: frost.GroupPublicKey = undefined;
var p_nonces: frost.SigningNonces = undefined;
var p_list: [2]frost.SigningCommitments = undefined;
var p_hr: [32]u8 = undefined;
var p_br: [32]u8 = undefined;

var share_sink: frost.SignatureShare = undefined;
var pair_sink: frost.NonceCommitmentPair = undefined;
var nonces_sink: frost.SigningNonces = undefined;

noinline fn callSign() void {
    share_sink = frost.round2Sign(std.testing.allocator, p_id, &p_share, p_gpk, &p_nonces, msg, &p_list) catch unreachable;
    std.mem.doNotOptimizeAway(&share_sink);
}

noinline fn callCommit() void {
    pair_sink = frost.round1Commit(&p_nonces) catch unreachable;
    std.mem.doNotOptimizeAway(&pair_sink);
}

noinline fn callGenerate() void {
    frost.generateNonces(&nonces_sink, &p_share, p_hr, p_br);
    std.mem.doNotOptimizeAway(&nonces_sink);
    nonces_sink.deinit();
}

fn expectNoResidue(label: []const u8, call: *const fn () void) !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const coeffs = [_]Scalar{Scalar.fromBytes48([_]u8{0x31} ** 48, .big)};
    const dealt = try frost.trustedDealerKeygen(gpa, Scalar.fromBytes48([_]u8{0x29} ** 48, .big), &coeffs, 3, 2);
    defer gpa.free(dealt.shares);
    defer gpa.free(dealt.vss_commitment);
    p_gpk = dealt.group_public_key;

    var nonces: [2]frost.SigningNonces = undefined;
    for (dealt.shares[0..2], &nonces, &p_list, 0..) |sh, *n, *entry, i| {
        frost.generateNonces(n, &sh.signing_share, @splat(@intCast(0x40 + i)), @splat(@intCast(0x50 + i)));
        const pair = try frost.round1Commit(n);
        entry.* = .{ .identifier = sh.identifier, .hiding = pair.hiding, .binding = pair.binding };
    }
    frost.sortCommitmentsByIdentifier(&p_list);
    p_id = dealt.shares[0].identifier;
    p_share = dealt.shares[0].signing_share;
    p_nonces = nonces[0];
    p_hr = @splat(0x40);
    p_br = @splat(0x50);

    const sk = p_share.scalar();
    const parts = [_][3][32]u8{ three(sk), three(sk.neg()), three(p_nonces.hiding), three(p_nonces.hiding.neg()), three(p_nonces.binding), three(p_nonces.binding.neg()) };
    var needles: Needles = undefined;
    for (parts, 0..) |p, i| needles[3 * i ..][0..3].* = p;

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
        std.debug.print("\n=== STACKPROBE frost {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
        std.debug.print("  NEG={d} POS(sk_i)={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ neg, pos, depth, hit_min_depth, hit_max_depth });
        for (needle_names, total) |name, h| {
            if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), sum);
}

test "STACKPROBE (audit 2026-10-08): no share or nonce residue on the dead stack after round2Sign()" {
    try expectNoResidue("round2Sign", callSign);
}

test "STACKPROBE (audit 2026-10-08): no nonce residue on the dead stack after round1Commit()" {
    try expectNoResidue("round1Commit", callCommit);
}

test "STACKPROBE (audit 2026-10-08): no share or nonce residue on the dead stack after generateNonces()" {
    try expectNoResidue("generateNonces", callGenerate);
}
