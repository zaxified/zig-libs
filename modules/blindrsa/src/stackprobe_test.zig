// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `blind` (audit findings B6 and B9), kept in
//! the module per `CONVENTIONS.md` §9.
//!
//! Method (as `bip340`'s, `bulletproofs`' and `xmss`'s probes): paint a stack
//! window, call `blind` at that depth, then copy an equally large
//! UNINITIALISED buffer claimed there to the heap BEFORE anything else runs,
//! and search the copy. ReleaseFast/ReleaseSmall only: Debug and ReleaseSafe
//! fill `undefined` with 0xaa, so a dead frame is not readable there.
//!
//! ⛔ Why the copy, and why this probe replaced the in-`root.zig` one it grew
//! from: that version scanned the live stack and built its needles in the
//! SAME frame, inside the window it was scanning — so it counted its own
//! needle buffers. Measured while fixing B6: it reported 2 / 2 / 1 hits where
//! this one reports what the call actually left.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees the secret, must find 0) and a
//! POSITIVE control (the same value parked in a local, must be found).
//!
//! `DeadStackFixedRandom` pins every random draw to the RFC's `r`, so the
//! blinding factor AND `maskedInvert`'s mask `u` are both that value, which
//! makes `v = r·u mod n = r² mod n` — the value the variable-time Euclid
//! arena actually chews on — computable here without instrumenting the module.

const std = @import("std");
const builtin = @import("builtin");
const brsa = @import("root.zig");
const kat = @import("kat_vectors.zig");
const rsa = @import("rsa");

/// Wider than the deepest burn, or a burn that outgrows the window would
/// read as "clean" for the wrong reason.
const WINDOW = 1024 * 1024;
/// The KAT modulus is as wide as its `r`.
const MAX = kat.r.len;
/// Mirrors `root.zig`'s `sign_stack_burn`, for reading the offsets below.
const sign_burn_bytes = 512 * 1024;

var dead: *[WINDOW]u8 = undefined;
var pk: rsa.PublicKey = undefined;
var ctx: brsa.Context = undefined;
var blinded: [MAX]u8 = undefined;
var sk: rsa.SecretKey = undefined;
var signed: [MAX]u8 = undefined;

const DeadStackFixedRandom = struct {
    val: []const u8,
    fn fill(self: *const @This(), buf: []u8) void {
        @memset(buf, 0);
        if (buf.len >= self.val.len) {
            @memcpy(buf[buf.len - self.val.len ..], self.val);
        } else {
            @memcpy(buf, self.val[self.val.len - buf.len ..]);
        }
    }
};

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Copy the uninitialised window at the depth the previous call used to the
/// heap. Volatile reads so the buffer cannot be folded away.
noinline fn snapshot() void {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    for (dead, 0..) |*d, i| d.* = p[i];
    std.mem.doNotOptimizeAway(&buf);
}

noinline fn runBlind() void {
    var fixed = DeadStackFixedRandom{ .val = &kat.r };
    const random = std.Random.init(&fixed, DeadStackFixedRandom.fill);
    _ = brsa.blind(pk, std.crypto.hash.sha2.Sha384, &kat.a1.prepared_msg, kat.a1.salt.len, random, &ctx, &blinded) catch unreachable;
}

noinline fn runSign() void {
    var fixed = DeadStackFixedRandom{ .val = &kat.r };
    const random = std.Random.init(&fixed, DeadStackFixedRandom.fill);
    _ = brsa.blindSign(&sk, pk, random, &kat.a1.blinded_msg, &signed) catch unreachable;
}

/// Control for the key needles: makes the SAME by-value copy of `sk` the
/// call does, and nothing else. Whatever this leaves is the probe's own
/// parameter copy, not something `blindSign` left behind.
noinline fn copyKeyOnly() void {
    var local = sk;
    std.mem.doNotOptimizeAway(&local);
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks `r`'s leading bytes in a stack local.
noinline fn callLeaky() void {
    var local: [1024]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = kat.r[0..32].*;
    std.mem.doNotOptimizeAway(&local);
}

/// Offsets of every hit, shallowest first, as "a, b, c". Offset 0 is the TOP
/// of the window (the caller's frames); the deepest bytes are the burn's. A
/// hit above the burn is a copy the callee cannot reach; one below it is
/// residue the burn failed to clear.
fn hitOffsets(needle: []const u8, buf: []u8) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    var i: usize = 0;
    var n: usize = 0;
    while (i + needle.len <= WINDOW) : (i += 1) {
        if (std.mem.eql(u8, dead[i..][0..needle.len], needle)) {
            w.print("{s}{d}", .{ if (n == 0) "" else ", ", i }) catch break;
            n += 1;
        }
    }
    if (n == 0) w.print("none", .{}) catch {};
    return w.buffered();
}

fn count(needle: []const u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= WINDOW) : (i += 1) {
        if (std.mem.eql(u8, dead[i..][0..needle.len], needle)) hits += 1;
    }
    return hits;
}

/// Bytes below the snapshot frame's top the previous call left different from
/// the paint, burn included. Sizes `blind_stack_burn`; printed, not asserted.
fn dirtyBytes() usize {
    var i: usize = 0;
    while (i < WINDOW and dead[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

test "STACKPROBE (A1 B6/B9): blind() leaves no r and no masked v on the dead stack" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    dead = try gpa.create([WINDOW]u8);
    defer gpa.destroy(dead);
    pk = try kat.publicKey();

    // Needle A: `r` big-endian — the `r_bytes` buffer `blindCore` wipes. This
    // is B9's anchor: delete that `secureZero` and it comes back.
    const r_be = kat.r[0..32];
    // Needle B: `r` as `ff.Fe` holds it — little-endian u64 limbs, i.e. the
    // byte reversal of the big-endian value. This is what B6 found unwiped.
    var r_rev: [MAX]u8 = undefined;
    for (kat.r, 0..) |c, idx| r_rev[MAX - 1 - idx] = c;
    const r_le = r_rev[0..32];

    std.debug.print("\n=== STACKPROBE blindrsa B6/B9 ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });

    paint();
    callInnocent();
    snapshot();
    const neg = count(r_be) + count(r_le);
    paint();
    callLeaky();
    snapshot();
    const pos = count(r_be);
    std.debug.print("  NEG control {d}, POS control (r parked) {d}\n", .{ neg, pos });
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);

    for (0..3) |round| {
        paint();
        runBlind();
        snapshot();

        // Needles C/D: the masked `v = r·u mod n` that `maskedInvert` feeds to
        // `feInvert`'s variable-time Euclid arena — B9's second half, which
        // never had an anchor. Computed AFTER the snapshot, so it cannot
        // contaminate the window it is searched in.
        const r_fe = rsa.Fe.fromBytes(pk.n, &kat.r, .big) catch unreachable;
        const v_fe = pk.n.mul(r_fe, r_fe);
        var v_be: [MAX]u8 = undefined;
        v_fe.toBytes(&v_be, .big) catch unreachable;
        var v_le: [MAX]u8 = undefined;
        for (v_be, 0..) |c, idx| v_le[MAX - 1 - idx] = c;

        const hits_r_be = count(r_be);
        const hits_r_le = count(r_le);
        const hits_v_be = count(v_be[0..32]);
        const hits_v_le = count(v_le[0..32]);
        std.debug.print("  blind #{d}: r big-endian={d} r limbs={d} v=r^2 big-endian={d} v limbs={d}; dirty below the call {d} B\n", .{
            round, hits_r_be, hits_r_le, hits_v_be, hits_v_le, dirtyBytes(),
        });

        try std.testing.expectEqual(@as(usize, 0), hits_r_be);
        try std.testing.expectEqual(@as(usize, 0), hits_r_le);
        try std.testing.expectEqual(@as(usize, 0), hits_v_be);
        try std.testing.expectEqual(@as(usize, 0), hits_v_le);
    }

    // `blindSign` is the other half of B6: its own `b`/`b_inv` go through the
    // same `maskedInvert`, and the CRT private op runs on the key itself.
    // Under the fixed random `b` is again `kat.r`, so the same needles apply.
    // `p`/`q` are measured too -- they belong to `rsa`, not here, so they are
    // printed until there is a number to stand behind.
    sk = try kat.secretKey();
    var p_rev: [kat.p.len]u8 = undefined;
    for (kat.p, 0..) |c, idx| p_rev[kat.p.len - 1 - idx] = c;
    var q_rev: [kat.q.len]u8 = undefined;
    for (kat.q, 0..) |c, idx| q_rev[kat.q.len - 1 - idx] = c;
    paint();
    copyKeyOnly();
    snapshot();
    var offbuf: [256]u8 = undefined;
    std.debug.print("  key-copy control: p={d} q={d}; p limb hits at {s}\n", .{
        count(kat.p[0..32]) + count(p_rev[0..32]),
        count(kat.q[0..32]) + count(q_rev[0..32]),
        hitOffsets(p_rev[0..32], &offbuf),
    });

    for (0..3) |round| {
        paint();
        runSign();
        snapshot();

        const r_fe = rsa.Fe.fromBytes(pk.n, &kat.r, .big) catch unreachable;
        const v_fe = pk.n.mul(r_fe, r_fe);
        var v_be: [MAX]u8 = undefined;
        v_fe.toBytes(&v_be, .big) catch unreachable;
        var v_le: [MAX]u8 = undefined;
        for (v_be, 0..) |c, idx| v_le[MAX - 1 - idx] = c;

        const hits_b_be = count(r_be);
        const hits_b_le = count(r_le);
        const hits_v_be = count(v_be[0..32]);
        const hits_v_le = count(v_le[0..32]);
        const hits_p = count(kat.p[0..32]) + count(p_rev[0..32]);
        const hits_q = count(kat.q[0..32]) + count(q_rev[0..32]);
        var ob: [256]u8 = undefined;
        std.debug.print("  blindSign #{d}: b big-endian={d} b limbs={d} v=b^2 big-endian={d} v limbs={d}; key p={d} q={d}; p limb hits at {s}; dirty below the call {d} B (burn starts at {d})\n", .{
            round,        hits_b_be,                hits_b_le, hits_v_be,
            hits_v_le,    hits_p,                   hits_q,    hitOffsets(p_rev[0..32], &ob),
            dirtyBytes(), WINDOW - sign_burn_bytes,
        });

        try std.testing.expectEqual(@as(usize, 0), hits_b_be);
        try std.testing.expectEqual(@as(usize, 0), hits_b_le);
        try std.testing.expectEqual(@as(usize, 0), hits_v_be);
        try std.testing.expectEqual(@as(usize, 0), hits_v_le);
        // B20: the key's prime factors. These were 2 hits each while
        // `blindSign` took `rsa.SecretKey` BY VALUE -- an ABI copy made in
        // the CALLER's frame, which no burn in the callee can reach. The
        // key-copy control above is their positive control: it still finds
        // 1 each, so a zero here is the call being clean, not the scan
        // going blind.
        try std.testing.expectEqual(@as(usize, 0), hits_p);
        try std.testing.expectEqual(@as(usize, 0), hits_q);
    }
}
