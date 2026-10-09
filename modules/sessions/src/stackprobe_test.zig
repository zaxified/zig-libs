// SPDX-License-Identifier: MIT

//! Dead-stack probe for `Csrf.token` / `Csrf.verify` (`testkit.stackprobe`):
//! residue below each burn, and the CSRF key as a needle in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). The token itself is public (it goes to the
//! client), so only the key is a needle.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var guard: root.Csrf = undefined;
var tok: [root.csrf_token_hex_len]u8 = undefined;
const session_id: []const u8 = "sess-0123456789abcdef";

test "STACKPROBE: no CSRF key residue after Csrf.token / Csrf.verify" {
    try sp.skipUnlessOptimized();
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("sessions csrf probe key", &key, .{});
    guard = .{ .key = key };
    std.crypto.secureZero(u8, &key);
    const secrets = [_][]const u8{&guard.key};

    _ = try P.run("Csrf.token", root.Csrf.token, .{ &guard, session_id, &tok }, &secrets, .{});
    var good: [root.csrf_token_hex_len]u8 = tok;
    _ = try P.run("Csrf.verify valid", root.Csrf.verify, .{ &guard, session_id, @as([]const u8, &good) }, &secrets, .{});
    good[0] = if (good[0] == '0') '1' else '0';
    _ = try P.run("Csrf.verify forged", root.Csrf.verify, .{ &guard, session_id, @as([]const u8, &good) }, &secrets, .{});
}
