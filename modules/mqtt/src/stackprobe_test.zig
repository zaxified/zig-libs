// SPDX-License-Identifier: MIT

//! Dead-stack probe for the credential-carrying encoders (`testkit.stackprobe`):
//! residue below the burn, and the CONNECT password / AUTH data as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode).

const std = @import("std");
const packet = @import("packet.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var password: [32]u8 = undefined;
var auth_data: [32]u8 = undefined;
var buf: [160]u8 = undefined;

test "STACKPROBE: no password residue after encodePacket of CONNECT / AUTH" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("mqtt probe password", &password, .{});
    std.crypto.hash.sha2.Sha256.hash("mqtt probe auth data", &auth_data, .{});
    const secrets = [_][]const u8{ &password, &auth_data, &buf };

    const conn: packet.Packet = .{ .connect = .{
        .client_id = "probe-client",
        .username = "probe-user",
        .password = &password,
    } };
    _ = try P.run("encodePacket CONNECT 3.1.1", packet.encodePacket, .{ @as([]u8, &buf), packet.Version.v3_1_1, conn }, &secrets, .{});

    const conn5: packet.Packet = .{ .connect = .{
        .client_id = "probe-client",
        .username = "probe-user",
        .password = &password,
        .version = .v5,
        .properties = .{ .authentication_method = "SCRAM-SHA-1", .authentication_data = &auth_data },
    } };
    _ = try P.run("encodePacket CONNECT 5.0 + auth data", packet.encodePacket, .{ @as([]u8, &buf), packet.Version.v5, conn5 }, &secrets, .{});

    const auth: packet.Packet = .{ .auth = .{
        .reason_code = .continue_authentication,
        .properties = .{ .authentication_method = "SCRAM-SHA-1", .authentication_data = &auth_data },
    } };
    _ = try P.run("encodePacket AUTH", packet.encodePacket, .{ @as([]u8, &buf), packet.Version.v5, auth }, &secrets, .{});
}
