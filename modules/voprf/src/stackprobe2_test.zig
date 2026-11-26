// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the batch evaluators
//! `stackprobe_test.zig` does not call — `blindEvaluateBatch`,
//! `blindEvaluateVerifiableBatch`, `blindEvaluatePoprfBatch` and the three
//! servers' `blindEvaluateBatch` — for every group. Residue below each burn;
//! needles: the server's secret scalar and the proof nonce `r`.
//! ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const voprf = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });
const n_batch = 3;

fn Suite(comptime Pr: type, comptime name: []const u8) type {
    return struct {
        var kp: Pr.KeyPair = undefined;
        var r: [Pr.Ns]u8 = undefined;
        var blinded: [n_batch]Pr.Element = undefined;
        var evaluated: [n_batch]Pr.Element = undefined;
        var oprf: Pr.OprfServer = undefined;
        var vs: Pr.VoprfServer = undefined;
        var ps: Pr.PoprfServer = undefined;

        fn oprfBatch(s: *const Pr.OprfServer) !void {
            return s.blindEvaluateBatch(&blinded, &evaluated);
        }
        fn voprfBatch(s: *const Pr.VoprfServer) !void {
            _ = try s.blindEvaluateBatch(&blinded, &evaluated, &r);
        }
        fn poprfBatch(s: *const Pr.PoprfServer) !void {
            _ = try s.blindEvaluateBatch(&blinded, "probe info", &evaluated, &r);
        }
        fn modBatch(sk: *const [Pr.Ns]u8) !void {
            return Pr.blindEvaluateBatch(sk, &blinded, &evaluated);
        }
        fn modVBatch(sk: *const [Pr.Ns]u8) !void {
            _ = try Pr.blindEvaluateVerifiableBatch(sk, kp.pk, &blinded, &evaluated, &r);
        }
        fn modPBatch(sk: *const [Pr.Ns]u8) !void {
            _ = try Pr.blindEvaluatePoprfBatch(sk, &blinded, "probe info", &evaluated, &r);
        }

        fn probe() !void {
            var seed: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("voprf probe2 seed " ++ name, &seed, .{});
            try Pr.deriveKeyPair(.voprf, &seed, "probe", &kp);
            var aux: Pr.KeyPair = undefined;
            std.crypto.hash.sha2.Sha256.hash("voprf probe2 r " ++ name, &seed, .{});
            try Pr.deriveKeyPair(.voprf, &seed, "r", &aux);
            r = aux.sk; // a valid non-zero scalar
            for (&blinded, 0..) |*b, i| {
                std.crypto.hash.sha2.Sha256.hash("voprf probe2 blind " ++ name, &seed, .{});
                seed[0] +%= @intCast(i);
                var bk: Pr.KeyPair = undefined;
                try Pr.deriveKeyPair(.oprf, &seed, "blind", &bk);
                b.* = try Pr.blind(.voprf, "probe input", &bk.sk);
            }
            std.crypto.hash.sha2.Sha256.hash("voprf probe2 server " ++ name, &seed, .{});
            try Pr.OprfServer.deriveInto(&oprf, &seed, "probe");
            try Pr.VoprfServer.deriveInto(&vs, &seed, "probe");
            try Pr.PoprfServer.deriveInto(&ps, &seed, "probe");

            _ = try P.run(name ++ " blindEvaluateBatch", modBatch, .{&kp.sk}, &.{&kp.sk}, .{});
            _ = try P.run(name ++ " blindEvaluateVerifiableBatch", modVBatch, .{&kp.sk}, &.{ &kp.sk, &r }, .{});
            _ = try P.run(name ++ " blindEvaluatePoprfBatch", modPBatch, .{&kp.sk}, &.{ &kp.sk, &r }, .{});
            _ = try P.run(name ++ " OprfServer.blindEvaluateBatch", oprfBatch, .{&oprf}, &.{&oprf.sk}, .{});
            _ = try P.run(name ++ " VoprfServer.blindEvaluateBatch", voprfBatch, .{&vs}, &.{ &vs.key_pair.sk, &r }, .{});
            _ = try P.run(name ++ " PoprfServer.blindEvaluateBatch", poprfBatch, .{&ps}, &.{ &ps.key_pair.sk, &r }, .{});
        }
    };
}

test "STACKPROBE: batch evaluators leave no server key or proof nonce on the dead stack" {
    try sp.skipUnlessOptimized();
    try Suite(voprf.Ristretto255Sha512, "ristretto255").probe();
    try Suite(voprf.P256Sha256, "P-256").probe();
    try Suite(voprf.P384Sha384, "P-384").probe();
    try Suite(voprf.P521Sha512, "P-521").probe();
}
