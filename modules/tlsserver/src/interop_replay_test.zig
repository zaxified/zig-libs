// SPDX-License-Identifier: MIT

//! Replays the OpenSSL `s_client` and Go crypto/tls client sessions
//! `tools/interop.zig --capture` recorded (`interop_vectors.zig`): a server with the recorded
//! configuration and seed is driven through `Connection` over a reader
//! holding exactly the octets OpenSSL sent, runs the same application
//! protocol (receive "ping\n", answer "pong\n" — after a KeyUpdate asking
//! for one back, in the `key_update` cases — close_notify, read to the
//! client's close_notify), and must write exactly the octets OpenSSL
//! accepted — its NewSessionTickets included, and, in the `resumed` cases,
//! a resumption of the ticket a recorded earlier case issued; with client
//! authentication, the client certificate the server ends up with. A
//! change to anything the server puts on the wire — or to what
//! it accepts — fails here, in every test lane, with neither OpenSSL nor Go
//! around.

const std = @import("std");
const testing = std.testing;
const rsa = @import("rsa");
const record = @import("record.zig");
const inbound = @import("inbound.zig");
const server_mod = @import("server.zig");
const Connection = @import("connection.zig").Connection;
const certs = @import("test_certs.zig");
const vectors = @import("interop_vectors.zig");
const clientauth = @import("clientauth.zig");
const client_certs = @import("client_certs.zig");
const tlsresume = @import("tlsresume");

fn clock(_: ?*anyopaque) i64 {
    return vectors.clock_ms;
}

fn replay(gpa: std.mem.Allocator, v: vectors.Case) !void {
    var p256 = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(certs.p256_scalar);
    var p384 = try std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(certs.p384_scalar);
    var ed = try std.crypto.sign.Ed25519.SecretKey.fromBytes(certs.ed25519_secret);
    const rsa_key = try gpa.create(rsa.SecretKey);
    defer gpa.destroy(rsa_key);
    try rsa.SecretKey.fromDer(rsa_key, &certs.rsa2048_pkcs1);
    var chain: [1][]const u8 = undefined;
    const ck: server_mod.CertifiedKey = switch (v.cert) {
        .p256 => blk: {
            chain[0] = &certs.p256_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p256 = &p256 } };
        },
        .p384 => blk: {
            chain[0] = &certs.p384_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p384 = &p384 } };
        },
        .ed25519 => blk: {
            chain[0] = &certs.ed25519_cert;
            break :blk .{ .chain = &chain, .key = .{ .ed25519 = &ed } };
        },
        .rsa2048 => blk: {
            chain[0] = &certs.rsa2048_cert;
            break :blk .{ .chain = &chain, .key = .{ .rsa = rsa_key } };
        },
    };
    var suites: [8]record.CipherSuite = undefined;
    for (v.suites, 0..) |s, i| suites[i] = @fromBackingInt(s);
    var csprng = std.Random.DefaultCsprng.init(@splat(v.seed));
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(1, &vectors.stek_key, @divFloor(vectors.clock_ms, 1000));
    const stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing) = .{ .ring = &ring };
    const tickets: server_mod.Tickets = .{ .ticketer = stek.ticketer(), .clock = .{ .now_ms = clock } };
    const verifier: clientauth.X509Verifier = .{ .gpa = gpa, .anchors = &.{&client_certs.ca_cert} };
    const client_auth: server_mod.ClientAuth = .{ .verifier = verifier.verifier(), .mandatory = v.client_auth == .mandatory, .clock = .{ .now_ms = clock } };
    const cfg: server_mod.Config = .{
        .certificate = .{ .fixed = &ck },
        .cipher_suites = suites[0..v.suites.len],
        .groups = v.groups,
        .alpn_protocols = v.alpn,
        .random = csprng.random(),
        .tickets = if (v.tickets) &tickets else null,
        .client_auth = if (v.client_auth != .off) &client_auth else null,
    };

    // The reader holds the whole recording in a buffer big enough for a
    // record (Connection's requirement).
    const in_buf = try gpa.alloc(u8, @max(v.client.len, record.max_record_len));
    defer gpa.free(in_buf);
    @memcpy(in_buf[0..v.client.len], v.client);
    var reader: std.Io.Reader = .fixed(in_buf[0..v.client.len]);
    reader.buffer = in_buf;
    var written: std.Io.Writer.Allocating = .init(gpa);
    defer written.deinit();
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, server_mod.minOutputLen(&cfg, &ck) + 4096);
    defer gpa.free(out);

    var c: Connection = .init(&cfg, &reader, &written.writer, joiner, out);
    defer c.deinit();
    try c.handshake();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    while (!std.mem.endsWith(u8, got.items, "ping\n")) {
        const d = (try c.read()) orelse return error.ClosedBeforePing;
        try got.appendSlice(gpa, d);
    }
    // The client's KeyUpdate (no reply due; s_client's comes with
    // "again\n") arrived before the server's close_notify in the
    // recording; reading it after makes the same octets out.
    const asked = c.server.client_application_secret;
    if (v.key_update) try c.keyUpdate(.update_requested);
    try c.writeAll("pong\n");
    try c.close();
    var after: std.ArrayList(u8) = .empty;
    defer after.deinit(gpa);
    while (try c.read()) |d| try after.appendSlice(gpa, d);
    if (v.key_update) {
        try testing.expect(!std.mem.eql(u8, &asked, &c.server.client_application_secret));
        if (after.items.len != 0) try testing.expectEqualStrings("again\n", after.items);
    } else try testing.expectEqual(@as(usize, 0), after.items.len);
    try testing.expectEqualStrings("ping\n", got.items);
    testing.expectEqualSlices(u8, v.server, written.written()) catch |err| {
        std.debug.print("case {s}: the server's octets differ from the recording\n", .{v.name});
        return err;
    };
    if (v.alpn.len != 0) try testing.expect(c.server.alpn != null);
    try testing.expectEqual(v.resumed, c.server.isResumed());
    const want_peer: ?[]const u8 = switch (v.client_cert) {
        .none => null,
        .p256 => &client_certs.p256_cert,
        .rsa2048 => &client_certs.rsa2048_cert,
        .ed25519 => &client_certs.ed25519_cert,
    };
    if (want_peer) |p| try testing.expectEqualSlices(u8, p, c.server.peerCertificate().?) else try testing.expectEqual(null, c.server.peerCertificate());
}

test "OpenSSL and Go client sessions replay byte-exact through Connection" {
    for (vectors.cases) |v| {
        replay(testing.allocator, v) catch |err| {
            std.debug.print("case {s}: {t}\n", .{ v.name, err });
            return err;
        };
    }
}

test "a recording with one octet of OpenSSL's flipped is refused" {
    // The client's Finished sits in the last records before the
    // application data; flipping the final octet of the recording hits
    // the client's close_notify (sealed) instead: bad_record_mac either way.
    const v = vectors.cases[1];
    try testing.expectEqualStrings("p256-aes128", v.name);
    const flipped = try testing.allocator.dupe(u8, v.client);
    defer testing.allocator.free(flipped);
    flipped[flipped.len - 1] ^= 1;
    var w = v;
    w.client = flipped;
    try testing.expectError(error.BadRecordMac, replay(testing.allocator, w));
}
