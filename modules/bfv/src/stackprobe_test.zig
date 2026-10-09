// SPDX-License-Identifier: MIT

//! Dead-stack probe for every secret-touching entry point (`testkit.stackprobe`):
//! residue below each burn, and the secret key / relinearisation key bytes as
//! needles in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime
//! skip, so the body is type-checked in every mode). Probed at `bfv_toy`
//! (N = 1024, two limbs, a 16 KiB ring); the burns scale with the ring, so the
//! bigger sets carry proportionally larger ones (`burn.rings`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 1024 * 1024 });

const B = root.Bfv(root.params.bfv_toy);

var kp: B.KeyPair = undefined;
var kp2: B.KeyPair = undefined;
var rlk: B.RelinKey = undefined;
var ct: B.Ciphertext = undefined;
var pt: B.Plaintext = undefined;

fn skBytes(k: *const B.KeyPair) []const u8 {
    return std.mem.sliceAsBytes(&k.sk.s.limbs);
}

test "STACKPROBE: no secret key residue after any entry point" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const inst = try B.init();
    inst.keyGen(io, &kp);
    pt = B.Plaintext.zero(root.params.bfv_toy.t);
    pt.coeffs[0] = 3;
    pt.coeffs[1] = 1;
    ct = inst.encrypt(&kp.pk, &pt, io);

    // `keyGen` writes the secret through `kp2`: its bytes are read after the call.
    _ = try P.run("keyGen", B.keyGen, .{ &inst, io, &kp2 }, &[_][]const u8{skBytes(&kp2)}, .{});
    _ = try P.run("genRelinKey", B.genRelinKey, .{ &inst, &kp.sk, io, &rlk }, &[_][]const u8{ skBytes(&kp), std.mem.sliceAsBytes(&rlk.b[0].limbs) }, .{});
    _ = try P.run("decrypt", B.decrypt, .{ &inst, &kp.sk, &ct }, &[_][]const u8{skBytes(&kp)}, .{});
    _ = try P.run("noiseBudget", B.noiseBudget, .{ &inst, &kp.sk, &ct }, &[_][]const u8{skBytes(&kp)}, .{});
}

// ── security-grade set (N = 8192, 4 limbs): burns `rings(Ring, 16)` ≈ 4 MiB ──
//
// A `Ring` is 256 KiB here and the bodies keep several on their stack, so the
// probe runs on a 256 MiB thread like `kat_test.zig`'s end-to-end test, with an
// 8 MiB window. Needles: the first 4 KiB of the secret key (the whole key is
// 256 KiB, past the needle table); the residue rule covers every byte.

const SEC = root.params.sec_n8192_logq218;
const BS = root.Bfv(SEC);
const PS = sp.Probe(.{ .window = 8 << 20, .repeats = 1 });

var s_kp: BS.KeyPair = undefined;
var s_kp2: BS.KeyPair = undefined;
var s_rlk: BS.RelinKey = undefined;
var s_ct: BS.Ciphertext = undefined;

fn secSk(k: *const BS.KeyPair) []const u8 {
    return std.mem.sliceAsBytes(&k.sk.s.limbs)[0..4096];
}

fn secProbe(slot: *?anyerror) void {
    secProbeInner() catch |e| {
        slot.* = e;
    };
}

fn secProbeInner() !void {
    var prng = std.Random.DefaultPrng.init(0x5EC0_57AC);
    const rnd = prng.random();
    const inst = try BS.init();
    inst.keyGenForTest(rnd, &s_kp);
    var p = BS.Plaintext.zero(SEC.t);
    p.coeffs[0] = 7;
    s_ct = inst.encryptForTest(&s_kp.pk, &p, rnd);
    _ = try PS.run("sec keyGenForTest", BS.keyGenForTest, .{ &inst, rnd, &s_kp2 }, &[_][]const u8{secSk(&s_kp2)}, .{});
    _ = try PS.run("sec genRelinKeyForTest", BS.genRelinKeyForTest, .{ &inst, &s_kp.sk, rnd, &s_rlk }, &[_][]const u8{secSk(&s_kp)}, .{});
    _ = try PS.run("sec decrypt", BS.decrypt, .{ &inst, &s_kp.sk, &s_ct }, &[_][]const u8{secSk(&s_kp)}, .{});
    _ = try PS.run("sec noiseBudget", BS.noiseBudget, .{ &inst, &s_kp.sk, &s_ct }, &[_][]const u8{secSk(&s_kp)}, .{});
}

test "STACKPROBE: security-grade set — no secret key residue below the 4 MiB burns" {
    try sp.skipUnlessOptimized();
    var slot: ?anyerror = null;
    const th = try std.Thread.spawn(.{ .stack_size = 256 << 20 }, secProbe, .{&slot});
    th.join();
    if (slot) |e| return e;
}
