// SPDX-License-Identifier: MIT

//! Tests that came out of the 2026-11-27 whole-module mutation run: each one
//! pins behaviour a mutant of `scheme.zig` / `suite.zig` could change without
//! an existing test noticing. Expected values come from the RFC 8391 / the
//! documented contract, never from running the code.

const std = @import("std");
const xmss = @import("root.zig");

const MX = xmss.XmssSha2(4, 0xDDDDDDDD); // 16 one-time keys

fn mutKeyPair(kp: *MX.KeyPair) void {
    const n = xmss.n;
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @truncate(i + 11);
    for (&sk_prf, 0..) |*b, i| b.* = @truncate(i + 111);
    for (&pub_seed, 0..) |*b, i| b.* = @truncate(i + 211);
    MX.keyGen(kp, &sk_seed, &sk_prf, &pub_seed);
}

/// A persist hook that looks at the handle's guard while it is called: the
/// hook runs inside `sign`'s critical section (documented: the guard is held
/// across `write`), so the guard must read as taken.
const GuardProbe = struct {
    handle: *MX.SigningKey,
    io: ?std.Io,
    calls: usize = 0,
    busy_inside: bool = false,
    io_mu_taken_inside: bool = false,

    fn write(ctx: *anyopaque, _: u32) anyerror!void {
        const self: *GuardProbe = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.busy_inside = self.handle.busy.load(.acquire);
        if (self.handle.io_mu.tryLock()) {
            self.handle.io_mu.unlock(self.io.?);
        } else {
            self.io_mu_taken_inside = true;
        }
    }
};

test "mutation 2026-11-27: SigningKey holds its spin guard across the persist hook and releases it after" {
    var kp: MX.KeyPair = undefined;
    mutKeyPair(&kp);
    var handle: MX.SigningKey = undefined;
    var probe: GuardProbe = .{ .handle = &handle, .io = std.testing.io }; // used only to unlock a mutex the probe itself took
    MX.SigningKey.init(&handle, &kp.sk, .{ .ctx = &probe, .write = GuardProbe.write });
    var sig: [MX.signature_length]u8 = undefined;
    try std.testing.expect(!handle.busy.load(.acquire));
    try handle.sign(&sig, "guarded");
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expect(probe.busy_inside);
    // Nothing else holds the Io guard on this path, and the spin guard is free again.
    try std.testing.expect(!probe.io_mu_taken_inside);
    try std.testing.expect(!handle.busy.load(.acquire));
    try handle.sign(&sig, "guarded again");
    try std.testing.expectEqual(@as(u32, 2), handle.index());
}

test "mutation 2026-11-27: SigningKey with Persist.io holds the Io guard across the hook and releases it after" {
    const io = std.testing.io;
    var kp: MX.KeyPair = undefined;
    mutKeyPair(&kp);
    var handle: MX.SigningKey = undefined;
    var probe: GuardProbe = .{ .handle = &handle, .io = io };
    MX.SigningKey.init(&handle, &kp.sk, .{ .ctx = &probe, .write = GuardProbe.write, .io = io });
    var sig: [MX.signature_length]u8 = undefined;
    try handle.sign(&sig, "guarded");
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expect(probe.io_mu_taken_inside);
    try std.testing.expect(!probe.busy_inside); // the spin guard is the other path's
    // Released: the next signer can take it, and does.
    try std.testing.expect(handle.io_mu.tryLock());
    handle.io_mu.unlock(io);
    try handle.sign(&sig, "guarded again");
    try std.testing.expectEqual(@as(u32, 2), handle.index());
}

test "mutation 2026-11-27: the traversal state stays in lockstep with idx (BdsState.covered_idx doc)" {
    // `covered_idx` is "the leaf that `auth` authenticates, kept equal to
    // SecretKey.idx". It is what lets sequential signing skip the O(2^h)
    // resync, so a lag is a cost bug that no output byte shows.
    var kp: MX.KeyPair = undefined;
    mutKeyPair(&kp);
    var sig: [MX.signature_length]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), kp.sk.bds.covered_idx);
    var k: u32 = 0;
    while (k < MX.max_signatures) : (k += 1) {
        try MX.sign(&kp.sk, &sig, "lockstep");
        try std.testing.expectEqual(k + 1, kp.sk.idx);
        try std.testing.expectEqual(kp.sk.idx, kp.sk.bds.covered_idx);
    }
}

test "mutation 2026-11-27: SigningKey.zeroize wipes the seeds of the handle and leaves the public state" {
    var kp: MX.KeyPair = undefined;
    mutKeyPair(&kp);
    var handle: MX.SigningKey = undefined;
    MX.SigningKey.init(&handle, &kp.sk, null);
    const root = handle.sk.root;
    try std.testing.expect(!std.mem.allEqual(u8, &handle.sk.sk_seed, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &handle.sk.sk_prf, 0));
    handle.zeroize();
    try std.testing.expect(std.mem.allEqual(u8, &handle.sk.sk_seed, 0));
    try std.testing.expect(std.mem.allEqual(u8, &handle.sk.sk_prf, 0));
    try std.testing.expectEqualSlices(u8, &root, &handle.sk.root);
}

fn restoredAt(comptime X: type, kp: *const X.KeyPair, start: u32) X.SecretKey {
    // What a caller restoring a persisted key writes: the seeds and the index,
    // no traversal state.
    return .{
        .idx = start,
        .sk_seed = kp.sk.sk_seed,
        .sk_prf = kp.sk.sk_prf,
        .pub_seed = kp.sk.pub_seed,
        .root = kp.sk.root,
        .bds = .{},
    };
}

fn restoreEveryIndex(comptime X: type) !void {
    var kp: X.KeyPair = undefined;
    const n = xmss.n;
    X.keyGen(&kp, &@as([n]u8, @splat(21)), &@as([n]u8, @splat(22)), &@as([n]u8, @splat(23)));
    var sig: [X.signature_length]u8 = undefined;
    var scratch: [X.h][n]u8 = undefined;
    var start: u32 = 0;
    while (start < X.max_signatures) : (start += 1) {
        var sk = restoredAt(X, &kp, start);
        // The resync must leave a state that keeps producing correct paths
        // for the leaves AFTER the restore point, not only for this one.
        var k = start;
        while (k < X.max_signatures and k < start + 4) : (k += 1) {
            try X.sign(&sk, &sig, "restored");
            try std.testing.expect(X.verify(kp.pk, "restored", &sig));
            try std.testing.expectEqual(k + 1, sk.idx);
            // RFC 8391 4.1.9 buildAuth: the path is a function of the tree and the leaf only.
            X.buildAuth(&sk.sk_seed, &sk.pub_seed, k, &scratch);
            try std.testing.expectEqualSlices(u8, std.mem.asBytes(&scratch), sig[sig.len - X.h * n ..]);
        }
    }
}

test "mutation 2026-11-27: a key restored at any index resyncs to paths that stay correct for the following leaves" {
    try restoreEveryIndex(MX);
    try restoreEveryIndex(xmss.XmssSha2(5, 0xDDDDDDD1));
}
