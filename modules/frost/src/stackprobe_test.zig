// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `generateNonces`, `round1Commit` and
//! `round2Sign` (audit 2026-10-08), kept in the module per `CONVENTIONS.md`
//! §9. Same method as `bip340`'s, `adaptor`'s and `musig2`'s
//! `stackprobe_test.zig`: paint a large stack window, call at that depth,
//! then claim an equally large UNINITIALISED buffer at the same depth and
//! count 32-byte needles in it. ReleaseFast/ReleaseSmall only (Debug and
//! ReleaseSafe fill `undefined`); the push lane runs it in ReleaseFast.
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
/// Sizes `root.zig`'s stack burns; printed, not asserted.
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

noinline fn callSign() void {
    const share = frost.round2Sign(std.testing.allocator, p_id, p_share, p_gpk, &p_nonces, msg, &p_list) catch unreachable;
    std.mem.doNotOptimizeAway(&share);
}

noinline fn callCommit() void {
    const pair = frost.round1Commit(&p_nonces) catch unreachable;
    std.mem.doNotOptimizeAway(&pair);
}

noinline fn callGenerate() void {
    var n = frost.generateNonces(p_share, p_hr, p_br);
    std.mem.doNotOptimizeAway(&n);
    n.deinit();
}

fn expectNoResidue(label: []const u8, comptime call: fn () void) !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const coeffs = [_]Scalar{Scalar.fromBytes48([_]u8{0x31} ** 48, .big)};
    const dealt = try frost.trustedDealerKeygen(gpa, Scalar.fromBytes48([_]u8{0x29} ** 48, .big), &coeffs, 3, 2);
    defer gpa.free(dealt.shares);
    defer gpa.free(dealt.vss_commitment);
    p_gpk = dealt.group_public_key;

    var nonces: [2]frost.SigningNonces = undefined;
    for (dealt.shares[0..2], &nonces, &p_list, 0..) |sh, *n, *entry, i| {
        n.* = frost.generateNonces(sh.signing_share, @splat(@intCast(0x40 + i)), @splat(@intCast(0x50 + i)));
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

    paint();
    std.mem.doNotOptimizeAway(callInnocent(p_hr));
    const neg = scan(&needles);

    paint();
    std.mem.doNotOptimizeAway(callLeaky(needles[0]));
    const pos = scan(&needles);

    var total: [needle_count]usize = @splat(0);
    for (0..5) |_| {
        paint();
        call();
        for (&total, scan(&needles)) |*t, x| t.* += x;
    }
    paint();
    call();
    const depth = dirtyDepth();

    // Printed only when an assertion below fails: the lane treats stderr
    // from a passing test as a FAIL (scripts/lib/test-lib.sh).
    errdefer {
        std.debug.print("\n=== STACKPROBE frost {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
        std.debug.print("  NEG={any} POS(sk_i)={d} dirty below the call={d} B\n", .{ neg, pos[0], depth });
        for (needle_names, total) |name, h| {
            if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
        }
    }
    for (neg) |h| try std.testing.expectEqual(@as(usize, 0), h);
    try std.testing.expect(pos[0] >= 1);
    for (total) |h| try std.testing.expectEqual(@as(usize, 0), h);
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
