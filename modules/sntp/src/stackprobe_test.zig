// SPDX-License-Identifier: MIT

//! Dead-stack probe for the keyed entry points `Auth.compute`, `sign`, `verify`
//! (`testkit.stackprobe`): residue below each burn, and the pre-shared key as a
//! needle in any frame, for all six algorithms. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode). Shown red with the burn removed: see the module CHANGELOG entry.

const std = @import("std");
const sntp = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

const key32: [32]u8 = .{ 0x91, 0x3c, 0xe7, 0x58, 0xa2, 0x0d, 0x6b, 0xf4, 0x17, 0xc9, 0x82, 0x35, 0xde, 0x4a, 0x70, 0xb3, 0x29, 0xf1, 0x6e, 0x8c, 0x03, 0xd5, 0xa7, 0x4b, 0xe0, 0x62, 0x9f, 0x1a, 0xc4, 0x38, 0x7d, 0xb6 };
var payload: [sntp.packet_len]u8 = undefined;
var mac: [sntp.Auth.max_mac_len]u8 = undefined;
var wire: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = undefined;

test "STACKPROBE: no NTP MAC key residue after compute / sign / verify, any algorithm" {
    try sp.skipUnlessOptimized();
    for (&payload, 0..) |*b, i| b.* = @intCast(i * 5 + 1);
    inline for (@typeInfo(sntp.MacAlgorithm).@"enum".field_names) |name| {
        const alg = @field(sntp.MacAlgorithm, name);
        const klen: usize = switch (alg) {
            .aes128_cmac => 16,
            .aes256_cmac, .md5, .sha1, .sha256, .sha512 => 32,
        };
        const k = key32[0..klen];
        const a: sntp.Auth = .{ .algorithm = alg, .key_id = 7, .key = k };
        _ = try P.run("Auth.compute " ++ name, sntp.Auth.compute, .{ a, 4, &payload, &mac }, &.{k}, .{});
        _ = try P.run("Auth.sign " ++ name, sntp.Auth.sign, .{ a, 4, &payload, &wire }, &.{k}, .{});
        const n = sntp.packet_len + 4 + a.macLen(4);
        _ = try P.run("Auth.verify " ++ name, sntp.Auth.verify, .{ a, 4, wire[0..n] }, &.{k}, .{});
    }
}
