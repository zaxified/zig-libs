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
