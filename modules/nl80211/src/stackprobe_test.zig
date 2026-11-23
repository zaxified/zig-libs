// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `connect.pmkFromPassphrase`:
//! the passphrase and the PMK (and PBKDF2's U blocks, which end in it) must not
//! survive below the call, and nothing may be left under its burn.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const connect = @import("connect.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

const passphrase = "correct horse battery staple, ninety-two";
const ssid = "probe-network";
var pmk_ref: [32]u8 = undefined;
var pmk_out: [32]u8 = undefined;

test "STACKPROBE: pmkFromPassphrase leaves no passphrase or PMK on the dead stack" {
    try sp.skipUnlessOptimized();
    try std.crypto.pwhash.pbkdf2(&pmk_ref, passphrase, ssid, 4096, std.crypto.auth.hmac.HmacSha1);
    _ = try P.run("pmkFromPassphrase", connect.pmkFromPassphrase, .{ &pmk_out, passphrase, ssid }, &.{ passphrase, &pmk_ref }, .{});
    try std.testing.expectEqualSlices(u8, &pmk_ref, &pmk_out);
}
