// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `signPrehash` and
//! `signPrehashDigest` (HashSLH-DSA), which `stackprobe_test.zig` does not
//! call: residue below each burn, the secret key (SK.seed, SK.prf) as needles.
//! SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f. ReleaseFast/ReleaseSmall only.
//! Coverage sweep 2026-11-26.

const std = @import("std");
const engine = @import("engine.zig");
const params = @import("params.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 1024 * 1024, .max_windows = 1 << 17 });

fn Suite(comptime Pm: params.Params, comptime name: []const u8) type {
    return struct {
        const S = engine.SlhDsa(Pm);
        var seed: [3 * S.n]u8 = undefined;
        var kp: S.KeyPair = undefined;
        var sig: [S.signature_length]u8 = undefined;
        var digest: [32]u8 = undefined;

        fn signPhW(out: *[S.signature_length]u8, sk: *const S.SecretKey) !void {
            return S.signPrehash(out, "slhdsa probe2 message", sk, "ctx", .sha2_256, null);
        }
        fn signPhDigestW(out: *[S.signature_length]u8, sk: *const S.SecretKey) !void {
            return S.signPrehashDigest(out, &digest, sk, "ctx", .sha2_256, null);
        }

        fn probe() !void {
            var h: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash("slhdsa probe2 seed " ++ name, &h, .{});
            seed = h[0 .. 3 * S.n].*;
            S.keyGen(&kp, &seed);
            std.crypto.hash.sha2.Sha256.hash("slhdsa probe2 message", &digest, .{});
            // SK.seed ‖ SK.prf: the first two n-byte thirds of the keygen seed.
            const secrets = [_][]const u8{seed[0 .. 2 * S.n]};
            _ = try P.run(name ++ " signPrehash", signPhW, .{ &sig, &kp.sk }, &secrets, .{});
            _ = try P.run(name ++ " signPrehashDigest", signPhDigestW, .{ &sig, &kp.sk }, &secrets, .{});
        }
    };
}

test "STACKPROBE: signPrehash / signPrehashDigest leave no SLH-DSA secret key on the dead stack" {
    try sp.skipUnlessOptimized();
    try Suite(params.sha2_128f, "sha2-128f").probe();
    try Suite(params.shake_128f, "shake-128f").probe();
}
