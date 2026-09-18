// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `sign` (A1/bip340.md F2), kept in the module
//! per `CONVENTIONS.md` §9: the instrument that checks one module lives with
//! that module, not in an audit note.
//!
//! Method (same as `k256`'s `stackprobe_test.zig`): paint a large stack
//! window, call the signer at that depth, then claim an equally large
//! UNINITIALISED buffer at the same depth and count 32-byte needles in it.
//! ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with
//! 0xaa, so the scan cannot see a dead frame there.
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

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Count every needle in one uninitialised window claimed at the depth the
/// previous call used. Volatile reads so the buffer cannot be folded away.
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

/// How many bytes below the scan frame's top the previous call left different
/// from the paint — how deep its call tree reached, burn included. Sizes
/// `root.zig`'s `sign_stack_burn`; printed, not asserted.
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

/// BIP340 steps 1-5, re-derived from the module's exported pieces so the
/// probe knows what to look for. Runs before `paint`, so its own copies are
/// painted over before the measured call.
fn needlesFor(sk_bytes: [32]u8, aux: [32]u8) !Needles {
    var kp = try bip340.KeyPair.fromSecretKey(try bip340.SecretKey.fromBytes(sk_bytes));
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

/// Paint, `call`, scan — five times per key — beside a negative and a
/// positive control, and fail on any secret found. `call` signs `msg` with
/// the given key and aux; it must be `noinline` so its frames sit below the
/// caller at the depth `scan` claims.
pub fn expectNoResidue(label: []const u8, comptime call: fn (bip340.SecretKey, [32]u8) void) !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    for (cases) |case| {
        const sk = try bip340.SecretKey.fromBytes(case.sk);
        const needles = try needlesFor(case.sk, case.aux);

        paint();
        std.mem.doNotOptimizeAway(callInnocent(case.aux));
        const neg = scan(&needles);

        paint();
        std.mem.doNotOptimizeAway(callLeaky(needles[0]));
        const pos = scan(&needles);

        var total: [needle_count]usize = @splat(0);
        for (0..5) |_| {
            paint();
            call(sk, case.aux);
            for (&total, scan(&needles)) |*t, x| t.* += x;
        }
        paint();
        call(sk, case.aux);
        const depth = dirtyDepth();

        // Printed only when an assertion below fails: the lane treats stderr
        // from a passing test as a FAIL (scripts/lib/test-lib.sh).
        errdefer {
            std.debug.print("\n=== STACKPROBE bip340 F2: {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
            std.debug.print("  key ..{x:0>2}: NEG={any} POS(d)={d} dirty below the call={d} B\n", .{ case.sk[31], neg, pos[0], depth });
            for (needle_names, total) |name, h| {
                if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
            }
        }
        for (neg) |h| try std.testing.expectEqual(@as(usize, 0), h);
        try std.testing.expect(pos[0] >= 1); // the scan can see a parked secret
        for (total) |h| try std.testing.expectEqual(@as(usize, 0), h);
    }
}

var sign_io: std.Io = undefined;

noinline fn callSign(sk: bip340.SecretKey, aux: [32]u8) void {
    const sig = bip340.sign(sk, msg, aux, sign_io) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

test "STACKPROBE (A1 F2): no key or nonce residue on the dead stack after sign()" {
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    sign_io = th.io();
    try expectNoResidue("sign", callSign);
}
