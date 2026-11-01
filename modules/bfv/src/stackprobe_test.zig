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

// The secret `s` is TERNARY (coefficients 0, 1, q-1): no 16-byte window of its
// limbs has the 8 distinct bytes a needle needs, so the probe cannot see `s`
// itself. What the bodies leave in dead frames is `NTT(s)` (every `Ring.mul`
// transforms its operands), which is uniform-looking mod q: that is the needle.
var s_ntt: B.Ring = undefined;

fn skNtt(k: *const B.KeyPair, inst: *const B) []const u8 {
    s_ntt = k.sk.s;
    s_ntt.toNtt(&inst.engines);
    return std.mem.sliceAsBytes(&s_ntt.limbs);
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

    // `keyGen` draws a fresh `s` from the OS on every call, so NTT(s) is not
    // known before the call and no needle can be listed (the ternary `s` itself
    // is invisible, see `skNtt`): only the residue rule covers it.
    _ = try P.run("keyGen", B.keyGen, .{ &inst, io, &kp2 }, &[_][]const u8{}, .{});
    const sn = skNtt(&kp, &inst);
    _ = try P.run("genRelinKey", B.genRelinKey, .{ &inst, &kp.sk, io, &rlk }, &[_][]const u8{ sn, std.mem.sliceAsBytes(&rlk.b[0].limbs) }, .{});
    _ = try P.run("decrypt", B.decrypt, .{ &inst, &kp.sk, &ct }, &[_][]const u8{sn}, .{});
    _ = try P.run("noiseBudget", B.noiseBudget, .{ &inst, &kp.sk, &ct }, &[_][]const u8{sn}, .{});
}

// ── security-grade set (N = 8192, 4 limbs): burns `rings(Ring, 16)` ≈ 4 MiB ──
//
// A `Ring` is 256 KiB here and the bodies keep several on their stack, so the
// probe runs on a 256 MiB thread like `kat_test.zig`'s end-to-end test, with an
// 8 MiB window. Needles: the first 4 KiB of NTT(s) (the whole transform is
// 256 KiB, past the needle table; `s` itself is ternary and so invisible, see
// `skNtt` above); the residue rule covers every byte.

const SEC = root.params.sec_n8192_logq218;
const BS = root.Bfv(SEC);
const PS = sp.Probe(.{ .window = 8 << 20, .repeats = 1 });

var s_kp: BS.KeyPair = undefined;
var s_kp2: BS.KeyPair = undefined;
var s_kp3: BS.KeyPair = undefined;
var sec_ntt: BS.Ring = undefined;
var s_rlk: BS.RelinKey = undefined;
var s_ct: BS.Ciphertext = undefined;

fn secSk(k: *const BS.KeyPair, inst: *const BS) []const u8 {
    sec_ntt = k.sk.s;
    sec_ntt.toNtt(&inst.engines);
    return std.mem.sliceAsBytes(&sec_ntt.limbs)[0..4096];
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
    // The probed `keyGenForTest` draws from `rnd`'s current state, once
    // (`repeats = 1`): replay it from a copy of the generator to learn the `s`
    // it will produce, and list NTT(s) as the needle.
    var replay = prng;
    inst.keyGenForTest(replay.random(), &s_kp3);
    _ = try PS.run("sec keyGenForTest", BS.keyGenForTest, .{ &inst, rnd, &s_kp2 }, &[_][]const u8{secSk(&s_kp3, &inst)}, .{});
    const sn = secSk(&s_kp, &inst);
    _ = try PS.run("sec genRelinKeyForTest", BS.genRelinKeyForTest, .{ &inst, &s_kp.sk, rnd, &s_rlk }, &[_][]const u8{sn}, .{});
    _ = try PS.run("sec decrypt", BS.decrypt, .{ &inst, &s_kp.sk, &s_ct }, &[_][]const u8{sn}, .{});
    _ = try PS.run("sec noiseBudget", BS.noiseBudget, .{ &inst, &s_kp.sk, &s_ct }, &[_][]const u8{sn}, .{});
}

test "STACKPROBE: security-grade set — no secret key residue below the 4 MiB burns" {
    try sp.skipUnlessOptimized();
    var slot: ?anyerror = null;
    const th = try std.Thread.spawn(.{ .stack_size = 256 << 20 }, secProbe, .{&slot});
    th.join();
    if (slot) |e| return e;
}
