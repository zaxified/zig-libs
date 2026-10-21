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

/// The recorded server's private keys, parsed once (an RSA key's CRT
/// set-up costs more than a handshake).
const Keys = struct {
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    p384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,
    ed: std.crypto.sign.Ed25519.SecretKey,
    rsa: *rsa.SecretKey,

    fn init(gpa: std.mem.Allocator) !Keys {
        const rsa_key = try gpa.create(rsa.SecretKey);
        errdefer gpa.destroy(rsa_key);
        try rsa.SecretKey.fromDer(rsa_key, &certs.rsa2048_pkcs1);
        return .{
            .p256 = try .fromBytes(certs.p256_scalar),
            .p384 = try .fromBytes(certs.p384_scalar),
            .ed = try .fromBytes(certs.ed25519_secret),
            .rsa = rsa_key,
        };
    }

    fn deinit(k: *Keys, gpa: std.mem.Allocator) void {
        gpa.destroy(k.rsa);
    }
};

fn replay(gpa: std.mem.Allocator, v: vectors.Case) !void {
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    return replayWith(gpa, v, &keys);
}

fn replayWith(gpa: std.mem.Allocator, v: vectors.Case, keys: *const Keys) !void {
    var chain: [1][]const u8 = undefined;
    var ck: server_mod.CertifiedKey = switch (v.cert) {
        .p256 => blk: {
            chain[0] = &certs.p256_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p256 = &keys.p256 } };
        },
        .p384 => blk: {
            chain[0] = &certs.p384_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p384 = &keys.p384 } };
        },
        .ed25519 => blk: {
            chain[0] = &certs.ed25519_cert;
            break :blk .{ .chain = &chain, .key = .{ .ed25519 = &keys.ed } };
        },
        .rsa2048 => blk: {
            chain[0] = &certs.rsa2048_cert;
            break :blk .{ .chain = &chain, .key = .{ .rsa = keys.rsa } };
        },
    };
    if (v.staple) {
        ck.ocsp_response = &vectors.ocsp_response;
        ck.sct_list = &vectors.sct_list;
    }
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

// Server-side handshakes per second, measured by replaying recorded
// sessions (the server's work only: key exchange, CertificateVerify,
// key schedule, records, the client's Finished checked; no client). Off by
// default; opt in with `TLSSERVER_BENCH` (`1` = every case, a case name =
// that one), in an optimized build:
//
//   TLSSERVER_BENCH=1 <test binary built -OReleaseFast>
test "bench: replayed handshakes per second (opt-in via TLSSERVER_BENCH)" {
    const only = std.testing.environ.getPosix("TLSSERVER_BENCH") orelse return error.SkipZigTest;
    const names = [_][]const u8{ "p256-aes256-x25519", "p256-default", "p256-p384group", "p384", "ed25519", "rsa2048-pss", "resume" };
    // An arena kept across replays: after the first one no replay asks the
    // kernel for memory.
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var keys: Keys = try .init(std.heap.page_allocator);
    defer keys.deinit(std.heap.page_allocator);
    for (names) |name| {
        // A case name runs that case alone (for a profile).
        if (!std.mem.eql(u8, only, "1") and !std.mem.eql(u8, only, name)) continue;
        const v = for (vectors.cases) |c| {
            if (std.mem.eql(u8, c.name, name)) break c;
        } else return error.NoSuchCase;
        try replayWith(gpa, v, &keys); // warm-up, and still byte-exact
        var best: f64 = 0;
        for (0..5) |_| {
            const t0 = nowNs();
            var n: usize = 0;
            while (nowNs() - t0 < 400_000_000) : (n += 1) {
                try replayWith(gpa, v, &keys);
                _ = arena.reset(.retain_capacity);
            }
            const rate = @as(f64, @floatFromInt(n)) * 1e9 / @as(f64, @floatFromInt(nowNs() - t0));
            best = @max(best, rate);
        }
        std.debug.print("bench {s:<20} {d:>8.0} handshakes/s (best of 5)\n", .{ name, best });
    }
}

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
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
