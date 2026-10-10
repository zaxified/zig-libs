// SPDX-License-Identifier: MIT

//! Dead-stack probe for the key-schedule entry points (`testkit.stackprobe`):
//! residue below each burn, and the key and the context written as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [24]u8 = undefined;
var enc: root.Aes192EncryptCtx = undefined;
var dec: root.Aes192DecryptCtx = undefined;

test "STACKPROBE: no key or round-key residue after initEncInto / initDecInto" {
    try sp.skipUnlessOptimized();
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("aes192 probe key", &full, .{});
    key = full[0..24].*;
    // The schedules are written by the calls under test; the probe searches
    // the stack for any 16-byte run of them, and for the key itself.
    const secrets = [_][]const u8{ &key, std.mem.asBytes(&enc.key_schedule), std.mem.asBytes(&dec.key_schedule) };
    _ = try P.run("initEncInto", root.Aes192.initEncInto, .{ &enc, &key }, &secrets, .{});
    _ = try P.run("initDecInto", root.Aes192.initDecInto, .{ &dec, &key }, &secrets, .{});
    try std.testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&dec.key_schedule), 0));
}
