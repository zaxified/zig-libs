// SPDX-License-Identifier: MIT

//! Dead-stack probe for the USM key paths (`testkit.stackprobe`): residue below
//! each burn, and the passwords, the user key, the localized keys and the
//! decrypted plaintext as needles in any frame. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode).

const std = @import("std");
const usm = @import("usm.zig");
const priv = @import("priv.zig");
const des = @import("des.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

const engine_id = [_]u8{ 0x80, 0x00, 0x1f, 0x88, 0x80, 0xe9, 0x63, 0x00, 0x00, 0xd6, 0x1f, 0x4d, 0x56 };

var password: [24]u8 = undefined;
var user_key: [64]u8 = undefined;
var local_key: [64]u8 = undefined;
var key16: [16]u8 = undefined;
var des_key: [8]u8 = undefined;
var plain: [32]u8 = undefined;
var cipher: [40]u8 = undefined;
var decrypted: [40]u8 = undefined;
var message: [64]u8 = undefined;
var salt_source: priv.SaltSource = undefined;

fn fill(dst: []u8, label: []const u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &h, .{});
    @memcpy(dst, h[0..dst.len]);
}

test "STACKPROBE: no key residue after the USM key, digest and privacy paths" {
    try sp.skipUnlessOptimized();
    fill(&password, "snmp probe password");
    fill(&key16, "snmp probe priv key");
    fill(&des_key, "snmp probe des key");
    fill(&plain, "snmp probe plaintext");
    const secrets = [_][]const u8{ &password, &user_key, &local_key, &key16, &des_key, &plain, &decrypted };
    const proto: usm.AuthProtocol = .hmac_sha1;

    // Key derivation (one-shot).
    _ = try P.run("passwordToUserKey", usm.passwordToUserKey, .{ proto, @as([]const u8, &password), @as([]u8, &user_key) }, &secrets, .{});
    _ = try P.run("localizeKey", usm.localizeKey, .{ proto, @as([]const u8, user_key[0..proto.keyLen()]), @as([]const u8, &engine_id), @as([]u8, &local_key) }, &secrets, .{});
    _ = try P.run("passwordToKey", usm.passwordToKey, .{ proto, @as([]const u8, &password), @as([]const u8, &engine_id), @as([]u8, &local_key) }, &secrets, .{});

    // Digest: a message with a 12-byte zero auth field at `off`, preceded by its `04 0c` header.
    const off = 20;
    @memset(&message, 0x5a);
    message[off - 2] = 0x04;
    message[off - 1] = 12;
    @memset(message[off..][0..12], 0);
    const lk: []const u8 = local_key[0..proto.keyLen()];
    _ = try P.run("computeDigestInto", usm.computeDigestInto, .{ proto, lk, @as([]const u8, &message), @as(usize, off), @as([]u8, user_key[32..]) }, &secrets, .{});
    _ = try P.run("sign", usm.sign, .{ proto, lk, @as([]u8, &message), @as(usize, off) }, &secrets, .{});
    const params: usm.UsmSecurityParameters = .{
        .engine_id = &engine_id,
        .engine_boots = 1,
        .engine_time = 2,
        .user_name = "probe",
        .auth_params = message[off..][0..12],
        .priv_params = &.{},
    };
    _ = try P.run("verify", usm.verify, .{ proto, lk, @as([]const u8, &message), params }, &secrets, .{});

    // Privacy: AES-CFB and DES-CBC, encrypt then decrypt what it produced.
    var local_priv: [16]u8 = undefined;
    @memcpy(&local_priv, &key16);
    for ([_]priv.PrivProtocol{ .aes128_cfb, .des_cbc }) |pp| {
        salt_source = priv.SaltSource.counter(0x1122334455667788);
        _ = try P.run("priv.encrypt", priv.encrypt, .{ pp, @as([]const u8, &local_priv), @as(u32, 3), @as(u32, 4), &salt_source, @as([]const u8, &plain), @as([]u8, &cipher) }, &secrets, .{});
        salt_source = priv.SaltSource.counter(0x1122334455667788);
        const enc = try priv.encrypt(pp, &local_priv, 3, 4, &salt_source, &plain, &cipher);
        _ = try P.run("priv.decrypt", priv.decrypt, .{ pp, @as([]const u8, &local_priv), @as(u32, 3), @as(u32, 4), @as([]const u8, &enc.salt), @as([]const u8, enc.ciphertext), @as([]u8, &decrypted) }, &secrets, .{});
        try std.testing.expectEqualSlices(u8, &plain, decrypted[0..plain.len]);
    }

    // DES by itself.
    const iv: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    _ = try P.run("Des.init", des.Des.init, .{@as(*const [8]u8, &des_key)}, &secrets, .{});
    _ = try P.run("des.cbcEncrypt", des.cbcEncrypt, .{ @as(*const [8]u8, &des_key), iv, @as([]const u8, &plain), @as([]u8, &cipher) }, &secrets, .{});
    _ = try P.run("des.cbcDecrypt", des.cbcDecrypt, .{ @as(*const [8]u8, &des_key), iv, @as([]const u8, cipher[0..plain.len]), @as([]u8, &decrypted) }, &secrets, .{});
}
