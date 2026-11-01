// SPDX-License-Identifier: MIT

//! Dead-stack probe for the credential-carrying encoders (`testkit.stackprobe`):
//! residue below the burn, and the CONNECT password / AUTH data as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode).

const std = @import("std");
const acl = @import("acl.zig");
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

// 7 bytes ("hunter2") is shorter than a needle window and the probe cannot see
// it, so the password is a 20-byte one and its `$7$` line is built at run time.
var line_buf: [256]u8 = undefined;
var line_len: usize = 0;

fn verifyBob(pw: []const u8) bool {
    var entries: [1]acl.Entry = undefined;
    const pws = acl.Passwords.parse(line_buf[0..line_len], &entries) catch return false;
    return pws.verify("bob", pw);
}

var pw_buf: [20]u8 = undefined;

test "STACKPROBE: no password residue after acl.Passwords.verify" {
    try sp.skipUnlessOptimized();
    pw_buf = "hunter2-probe-secret".*;
    const prefix = "bob:";
    @memcpy(line_buf[0..prefix.len], prefix);
    const hash = try acl.formatHash(line_buf[prefix.len .. line_buf.len - 1], &pw_buf, "probe-salt-12", 1000);
    line_len = prefix.len + hash.len;
    line_buf[line_len] = '\n';
    line_len += 1;
    const Pv = sp.Probe(.{ .window = 64 * 1024 });
    _ = try Pv.run("acl.Passwords.verify", verifyBob, .{@as([]const u8, &pw_buf)}, &.{&pw_buf}, .{});
}
