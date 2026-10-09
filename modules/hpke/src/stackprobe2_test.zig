// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `suite.labeledExtract` and
//! `suite.labeledExpand`, burned 2026-10-09 (the KEM / key-schedule entry
//! points are in `stackprobe_test.zig`). Per-derivation calls: tight burn
//! (`kdf_burn`). ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const suite = @import("suite.zig");
const sp = @import("testkit").stackprobe;

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const P = sp.Probe(.{ .window = 32 * 1024 });

var ikm: [32]u8 = undefined;
var prk: [Hkdf.prk_length]u8 = undefined;
var okm: [32]u8 = undefined;
const sid = "HPKE\x00\x20\x00\x01\x00\x01";

fn extract(out: *[Hkdf.prk_length]u8, i: *const [32]u8) void {
    suite.labeledExtract(Hkdf, out, sid, "", "secret", i);
}

fn expand(out: *[32]u8, p: *const [Hkdf.prk_length]u8) !void {
    try suite.labeledExpand(Hkdf, sid, p, "key", "info", out);
}

test "STACKPROBE: labeledExtract and labeledExpand leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("hpke probe2 ikm", &ikm, .{});
    _ = try P.run("labeledExtract", extract, .{ &prk, &ikm }, &.{ &ikm, &prk }, .{});
    _ = try P.run("labeledExpand", expand, .{ &okm, &prk }, &.{ &prk, &okm }, .{});
}
