// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the entry
//! points burned in the 2026-10-09 sweep: `Pke.keygen` (out form), `prng.Xof.init`
//! and `prng.hashI`. (The KEM entry points stay covered by the older
//! `stackprobe_test.zig`.) ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const Pke = root.Hqc128.Pke;

// Windows above the deepest burn: 64 KiB for the PKE keygen (HQC-128), 8 KiB
// for the 4 KiB primitive burns.
const Big = sp.Probe(.{ .window = 160 * 1024 });
const Small = sp.Probe(.{ .window = 16 * 1024 });

var seed: [32]u8 = undefined;
var kp: Pke.KeyPair = undefined;
var i_out: [64]u8 = undefined;

test "STACKPROBE: hqc Pke.keygen / Xof.init / hashI leave no secret in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("hqc probe seed", &seed, .{});

    _ = try Big.run("Pke.keygen", Pke.keygen, .{ &kp, &seed }, &[_][]const u8{ &seed, &kp.dk }, .{});
    // `Xof.init` returns its absorbed state by value (the caller's object);
    // only the library's own frames are checked, so no needles.
    _ = try Small.run("prng.Xof.init", root.prng.Xof.init, .{@as([]const u8, &seed)}, &.{}, .{});
    _ = try Small.run("prng.hashI", root.prng.hashI, .{ &i_out, @as([]const u8, &seed) }, &[_][]const u8{ &seed, &i_out }, .{});
}
