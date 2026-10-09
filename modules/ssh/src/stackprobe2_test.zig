// SPDX-License-Identifier: MIT

//! Dead-stack probe for `userauth.PasswordCheck.check` on `testkit.stackprobe`
//! (the older `stackprobe_test.zig` covers the key paths): residue below the
//! burn, and the presented password as a needle in any frame -- including the
//! frames of the hook, which runs under the burn. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode).

const std = @import("std");
const userauth = @import("userauth.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var password: [32]u8 = undefined;
var expected: [32]u8 = undefined;

fn hook(ctx: *anyopaque, user: []const u8, pw: []const u8) bool {
    _ = ctx;
    _ = user;
    if (pw.len != expected.len) return false;
    return std.crypto.timing_safe.eql([32]u8, pw[0..32].*, expected);
}

test "STACKPROBE: no password residue after PasswordCheck.check" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ssh probe password", &password, .{});
    expected = password;
    var ctx: u8 = 0;
    const check: userauth.PasswordCheck = .{ .ctx = &ctx, .checkFn = hook };
    const secrets = [_][]const u8{&password};

    _ = try P.run("PasswordCheck.check", userauth.PasswordCheck.check, .{ check, @as([]const u8, "probe-user"), @as([]const u8, &password) }, &secrets, .{});
}
