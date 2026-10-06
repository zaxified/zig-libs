// SPDX-License-Identifier: MIT

//! **External anchor for the handshake and data plane: real exchanges with
//! the Linux kernel's WireGuard, replayed.**
//!
//! `testdata/kernel_handshake.zig` was taken by `tools/interop.zig` (`unshare
//! -rn zig build interop-wireguard -- --capture`) against `wireguard.ko` in a
//! user + network namespace. Our side used only fixed keys, ephemerals,
//! indices and the KAT timestamp (the constants of `handshake.zig`'s KAT), so
//! here, with no kernel, no root and no socket, this module must:
//!
//! - **A (the kernel initiated):** accept the kernel's initiation, produce
//!   exactly the response the kernel accepted, and open the keepalive the
//!   kernel sent under the derived keys;
//! - **B (we initiated):** produce exactly the initiation the kernel accepted
//!   (which is byte-for-byte the KAT's `msg1` -- see `handshake.zig`), accept
//!   the kernel's response, seal exactly the ICMP echo request the kernel
//!   decrypted and answered, and open the kernel's echo reply.
//!
//! This is what `handshake.zig`'s root-only live test proves, minus the root:
//! that test skips in every lane without euid 0, this one runs everywhere.

const std = @import("std");
const testing = std.testing;
const hs = @import("handshake.zig");
const transport = @import("transport.zig");
const rec = @import("testdata/kernel_handshake.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// The capture's fixed side: `handshake.zig`'s KAT constants.
const si_priv = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const sr_priv = hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
const ei_priv = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const er_priv = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
const psk: hs.PresharedKey = @splat(0x55);
const timestamp = hex("400000005e6b0d3d0e2f6b4a");
const idx_i: u32 = 0x11111111;
const idx_r: u32 = 0x22222222;
const now_s: u64 = 1_000;
const ping_payload = "zig-libs wg ping";

fn keypair(priv: [32]u8) hs.Keypair {
    return hs.Keypair.fromPrivateKey(priv) catch unreachable;
}

test "kernel replay A: the kernel's initiation is answered with the response it accepted; its keepalive opens" {
    var h: hs.Handshake = .{
        .static_keypair = keypair(sr_priv),
        .remote_static_public = keypair(si_priv).public,
        .preshared_key = psk,
        .local_ephemeral = keypair(er_priv),
        .local_index = idx_r,
    };
    var msg1: hs.MessageInitiation = undefined;
    _ = try std.fmt.hexToBytes(std.mem.asBytes(&msg1), rec.a_initiation);
    try h.consumeInitiation(msg1);
    // The kernel's static key came out of its encrypted static field.
    try testing.expectEqual(keypair(si_priv).public, h.remote_static_public);

    const msg2 = try h.createResponse(testing.io);
    var want2: [@sizeOf(hs.MessageResponse)]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want2, rec.a_response);
    try testing.expectEqualSlices(u8, &want2, std.mem.asBytes(&msg2));

    var session = h.transportSession(false, now_s);
    var ka: [transport.sealedLen(0)]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ka, rec.a_keepalive);
    var empty: [0]u8 = .{};
    const r = try session.recv.open(&empty, &ka, now_s);
    try testing.expectEqual(@as(usize, 0), r.len);
    try testing.expectEqual(@as(u64, 0), r.counter);
}

fn ipChecksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) sum += std.mem.readInt(u16, bytes[i..][0..2], .big);
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

/// The ICMP echo request the capture tunnelled (`tools/interop.zig` builds
/// the same one): 10.77.0.2 -> 10.77.0.1, id 0x4242, seq 1.
fn echoRequest() [20 + 8 + ping_payload.len]u8 {
    var p: [20 + 8 + ping_payload.len]u8 = @splat(0);
    p[0] = 0x45;
    std.mem.writeInt(u16, p[2..4], p.len, .big);
    std.mem.writeInt(u16, p[4..6], 0x1234, .big);
    p[8] = 64;
    p[9] = 1;
    p[12..16].* = .{ 10, 77, 0, 2 };
    p[16..20].* = .{ 10, 77, 0, 1 };
    std.mem.writeInt(u16, p[10..12], ipChecksum(p[0..20]), .big);
    p[20] = 8;
    std.mem.writeInt(u16, p[24..26], 0x4242, .big);
    std.mem.writeInt(u16, p[26..28], 1, .big);
    @memcpy(p[28..], ping_payload);
    std.mem.writeInt(u16, p[22..24], ipChecksum(p[20..]), .big);
    return p;
}

test "kernel replay B: our initiation and ping are the bytes the kernel accepted; its echo reply opens" {
    var h: hs.Handshake = .{
        .static_keypair = keypair(si_priv),
        .remote_static_public = keypair(sr_priv).public,
        .preshared_key = psk,
        .local_ephemeral = keypair(ei_priv),
        .local_index = idx_i,
    };
    const msg1 = try h.createInitiation(testing.io, timestamp);
    var want1: [@sizeOf(hs.MessageInitiation)]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want1, rec.b_initiation);
    try testing.expectEqualSlices(u8, &want1, std.mem.asBytes(&msg1));

    var msg2: hs.MessageResponse = undefined;
    _ = try std.fmt.hexToBytes(std.mem.asBytes(&msg2), rec.b_response);
    try h.consumeResponse(msg2);
    try testing.expectEqual(msg2.sender_index, h.remote_index);

    var session = h.transportSession(true, now_s);
    const ping = echoRequest();
    var sealed: [transport.sealedLen(ping.len)]u8 = undefined;
    _ = try session.send.seal(&sealed, &ping, now_s);
    var want_ping: [sealed.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_ping, rec.b_ping);
    try testing.expectEqualSlices(u8, &want_ping, &sealed);

    var pong: [rec.b_pong.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pong, rec.b_pong);
    var plain: [256]u8 = undefined;
    const r = try session.recv.open(&plain, &pong, now_s);
    const ip = plain[0..r.len];
    // An ICMP echo reply 10.77.0.1 -> 10.77.0.2 carrying our payload, with
    // both checksums the kernel computed holding -- decrypted, not guessed.
    try testing.expect(ip.len >= 28 + ping_payload.len);
    const total = std.mem.readInt(u16, ip[2..4], .big);
    try testing.expectEqual(@as(u16, 28 + ping_payload.len), total);
    try testing.expectEqual(@as(u8, 1), ip[9]);
    try testing.expectEqualSlices(u8, &.{ 10, 77, 0, 1 }, ip[12..16]);
    try testing.expectEqualSlices(u8, &.{ 10, 77, 0, 2 }, ip[16..20]);
    try testing.expectEqual(@as(u16, 0), ipChecksum(ip[0..20]));
    try testing.expectEqual(@as(u8, 0), ip[20]); // echo reply
    try testing.expectEqual(@as(u16, 0), ipChecksum(ip[20..total]));
    try testing.expectEqual(@as(u16, 0x4242), std.mem.readInt(u16, ip[24..26], .big));
    try testing.expectEqualStrings(ping_payload, ip[28..total]);
    // Padded to 16 by the kernel (whitepaper §5.4.6): our open keeps it.
    try testing.expectEqual(@as(usize, 48), r.len);
}
