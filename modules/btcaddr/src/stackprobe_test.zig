// SPDX-License-Identifier: MIT

//! Dead-stack probe for `wifEncode` (`testkit.stackprobe`): residue below the
//! burn, and the private key and the WIF output as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var out: [root.max_wif_len]u8 = undefined;

test "STACKPROBE: no private-key residue after wifEncode" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("btcaddr probe key", &key, .{});
    const secrets = [_][]const u8{ &key, &out };

    _ = try P.run("wifEncode compressed", root.wifEncode, .{ &key, true, root.Network.mainnet, @as([]u8, &out) }, &secrets, .{});
    _ = try P.run("wifEncode uncompressed", root.wifEncode, .{ &key, false, root.Network.testnet, @as([]u8, &out) }, &secrets, .{});
}
