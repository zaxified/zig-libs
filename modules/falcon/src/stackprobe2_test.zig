// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for
//! `generateKeyPair`, `signRandomized` and `signPadded`, Falcon-512 and -1024.
//! ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`).
//!
//! What it adds to `stackprobe_test.zig`: that probe needs a model of every
//! secret it looks for, and has none for the big-integer limbs of the
//! NTRUSolve recursion below the top level (depth > 0). The engine's residue
//! rule needs no model: any byte that is neither paint nor zero deeper than
//! the burn's top is a frame the burn did not reach, whatever it held — every
//! recursion level's limbs included. The needles here are the outputs only
//! (`F`, `G` of the key, read after the call).

const std = @import("std");
const falcon = @import("root.zig");
const sign = @import("sign.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });

var rng_state: sign.ShakePrng = undefined;

fn Suite(comptime is1024: bool) type {
    return struct {
        const SigningKey = if (is1024) falcon.SigningKey1024 else falcon.SigningKey;
        const PublicKey = if (is1024) falcon.PublicKey1024 else falcon.PublicKey;
        const generate = if (is1024) falcon.generateKeyPair1024 else falcon.generateKeyPair;
        const signFn = if (is1024) falcon.signRandomized1024 else falcon.signRandomized;
        const paddedFn = if (is1024) falcon.signPadded1024 else falcon.signPadded;
        const padded_len = if (is1024) falcon.padded_sig_length_1024 else falcon.padded_sig_length;
        const cap = if (is1024) falcon.max_sig_field_length_1024 else falcon.max_sig_field_length;
        const tag = if (is1024) "-1024" else "-512";

        var sk: SigningKey = undefined;
        var pk: PublicKey = undefined;
        var nonce: [falcon.nonce_length]u8 = undefined;
        var sig: [cap]u8 = undefined;
        var padded: [padded_len]u8 = undefined;

        fn probe() !void {
            rng_state.init("falcon stackprobe2 keygen seed" ++ tag);
            _ = try P.run("generateKeyPair" ++ tag, generate, .{ rng_state.random(), &sk, &pk }, &.{ std.mem.asBytes(&sk.big_f), std.mem.asBytes(&sk.big_g) }, .{});
            rng_state.init("falcon stackprobe2 sign seed" ++ tag);
            _ = try P.run("signRandomized" ++ tag, signFn, .{ &sk, @as([]const u8, "falcon dead-stack probe message"), rng_state.random(), &nonce, @as([]u8, &sig) }, &.{ std.mem.asBytes(&sk.big_f), std.mem.asBytes(&sk.big_g) }, .{});
            // `signPadded`: the same signer, padded layout (2026-11-27 coverage sweep).
            rng_state.init("falcon stackprobe2 padded seed" ++ tag);
            _ = try P.run("signPadded" ++ tag, paddedFn, .{ &sk, @as([]const u8, "falcon dead-stack probe message"), rng_state.random(), &padded }, &.{ std.mem.asBytes(&sk.big_f), std.mem.asBytes(&sk.big_g) }, .{});
        }
    };
}

test "STACKPROBE: falcon keygen and signing leave no frame below their burn (every NTRUSolve level)" {
    try sp.skipUnlessOptimized();
    try Suite(false).probe();
    try Suite(true).probe();
}
