// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `bls_sig.keyGenV4` (the draft-04
//! KeyGen), which `stackprobe_test.zig` does not call: residue below its burn;
//! the IKM and the derived secret scalar as needles. ReleaseFast/ReleaseSmall
//! only. Coverage sweep 2026-11-26.

const std = @import("std");
const bls_sig = @import("bls_sig.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 512 * 1024 });

var ikm: [48]u8 = undefined;
var sk: bls_sig.SecretKey = undefined;

test "STACKPROBE: keyGenV4 leaves no IKM or secret scalar on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha3.Shake256.hash("bls12_381 probe2 ikm", &ikm, .{});
    try bls_sig.keyGenV4(&sk, &ikm, "probe info");
    const sk_img = std.mem.toBytes(sk);
    _ = try P.run("keyGenV4", bls_sig.keyGenV4, .{ &sk, @as([]const u8, &ikm), @as([]const u8, "probe info") }, &.{ &ikm, &sk_img }, .{});
}
