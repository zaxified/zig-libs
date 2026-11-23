// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `ScramClient.clientFinal`:
//! the salted password and the client/server keys derived from it must not
//! survive below the call, and nothing may be left under its burn.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const auth = @import("auth.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

// RFC 7677 §3's exchange with a longer password (a 6-byte "pencil" is below
// the needle window).
const password = "a long enough SCRAM password for needles";
const server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

var sc: auth.ScramClient = undefined;
var out: [256]u8 = undefined;

fn final() !void {
    _ = try sc.clientFinal(&out, server_first, password);
}

test "STACKPROBE: ScramClient.clientFinal leaves no salted password or key on the dead stack" {
    try sp.skipUnlessOptimized();
    var salt: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&salt, "W22ZaJ0SNY7soEsUEjb6gQ==");
    var salted: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, password, &salt, 4096, HmacSha256);
    var client_key: [32]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted);
    var server_key: [32]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted);
    var stored_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&client_key, &stored_key, .{});

    sc = try auth.ScramClient.init(std.testing.allocator, "user", "rOprNGfwEbeRWgbNEkqO");
    defer sc.deinit();
    var first: [64]u8 = undefined;
    _ = try sc.clientFirst(&first);
    _ = try P.run("ScramClient.clientFinal", final, .{}, &.{ password, &salted, &client_key, &server_key, &stored_key }, .{});
}
