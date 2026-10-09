// SPDX-License-Identifier: MIT

//! Dead-stack probe for `standard.encodeSecret` on `testkit.stackprobe` (the
//! older `stackprobe_test.zig` covers the other entry points): residue below
//! the burn, and the raw key and its `whsec_` text as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var out: [root.standard.secret_prefix.len + 44]u8 = undefined;

test "STACKPROBE: no key residue after standard.encodeSecret" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("webhooksig probe encode key", &key, .{});
    const secrets = [_][]const u8{ &key, &out };
    _ = try P.run("standard.encodeSecret", root.standard.encodeSecret, .{ @as([]u8, &out), @as([]const u8, &key) }, &secrets, .{});
}
