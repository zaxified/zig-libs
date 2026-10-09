// SPDX-License-Identifier: MIT

//! `testkit.stackprobe` probe of the pointer-keyed entry points (`xorInto`,
//! `streamInto`, `encryptInto`, `decryptInto`), residue below the burn and the
//! key as a needle in any frame. The older `stackprobe_test.zig` stays as it
//! was. ReleaseFast only (`skipUnlessOptimized`, a runtime skip). Short
//! (std-delegated) and wide messages, per-message burns (2 / 4 KiB, TIGHT).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const C = root.ChaCha20;
const A = root.ChaCha20Poly1305;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var ct: [2048]u8 = undefined;
var pt: [2048]u8 = undefined;
var tag: [16]u8 = undefined;
const msg: [2048]u8 = @splat(0x5a);
const nonce: [12]u8 = @splat(9);
const ad = "dead-stack probe";

test "STACKPROBE: no ChaCha20 key residue after the pointer-keyed entry points" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("chachapoly probe key", &key, .{});
    const ks = &[_][]const u8{&key};

    inline for (.{ 32, 1000 }) |len| {
        const l = std.fmt.comptimePrint("{d}", .{len});
        _ = try P.run("xorInto " ++ l, C.xorInto, .{ ct[0..len], msg[0..len], 1, &key, nonce }, ks, .{});
        _ = try P.run("streamInto " ++ l, C.streamInto, .{ ct[0..len], 1, &key, nonce }, ks, .{});
        _ = try P.run("encryptInto " ++ l, A.encryptInto, .{ ct[0..len], &tag, msg[0..len], ad, nonce, &key }, ks, .{});
        _ = try P.run("decryptInto " ++ l, A.decryptInto, .{ pt[0..len], ct[0..len], tag, ad, nonce, &key }, ks, .{});
        try std.testing.expectEqualSlices(u8, msg[0..len], pt[0..len]);
    }
}
