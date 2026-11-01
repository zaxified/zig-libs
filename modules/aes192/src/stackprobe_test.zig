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
    // `asBytes(&enc)` includes the packed keys on the bitsliced backend.
    // Each call lists only the schedule it writes: before `initDecInto` has
    // run, `dec` is still all zero (too uniform to be a needle), so listing it
    // for `initEncInto` made the probe warn that it could not see it.
    const enc_secrets = [_][]const u8{ &key, std.mem.asBytes(&enc) };
    const dec_secrets = [_][]const u8{ &key, std.mem.asBytes(&enc), std.mem.asBytes(&dec) };
    _ = try P.run("initEncInto", root.Aes192.initEncInto, .{ &enc, &key }, &enc_secrets, .{});
    _ = try P.run("initDecInto", root.Aes192.initDecInto, .{ &dec, &key }, &dec_secrets, .{});
    try std.testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&dec.key_schedule), 0));
}
