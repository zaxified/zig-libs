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
const outbound = @import("outbound.zig");
const server_mod = @import("server.zig");
const Connection = @import("connection.zig").Connection;
const Sink = @import("test_sink.zig").Sink;
const certs = @import("test_certs.zig");
const keys_mod = @import("keys.zig");
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
    /// The interop program's P-521 and ML-DSA-65 keys (`key_vectors`).
    p521: *keys_mod.CertKeyPair,
    mldsa65: *keys_mod.CertKeyPair,

    fn init(gpa: std.mem.Allocator) !Keys {
        const rsa_key = try gpa.create(rsa.SecretKey);
        errdefer gpa.destroy(rsa_key);
        try rsa.SecretKey.fromDer(rsa_key, &certs.rsa2048_pkcs1);
        const p521 = try loadVector(gpa, "p521-pkcs8");
        errdefer freeVector(gpa, p521);
        const mldsa65 = try loadVector(gpa, "mldsa65-both");
        return .{
            .p256 = try .fromBytes(certs.p256_scalar),
            .p384 = try .fromBytes(certs.p384_scalar),
            .ed = try .fromBytes(certs.ed25519_secret),
            .rsa = rsa_key,
            .p521 = p521,
            .mldsa65 = mldsa65,
        };
    }

    fn loadVector(gpa: std.mem.Allocator, comptime name: []const u8) !*keys_mod.CertKeyPair {
        const v = @import("root.zig").testKeyVector(name);
        const pair = try gpa.create(keys_mod.CertKeyPair);
        errdefer gpa.destroy(pair);
        try pair.fromPem(gpa, v.cert_pem, v.key_pem);
        return pair;
    }

    fn freeVector(gpa: std.mem.Allocator, pair: *keys_mod.CertKeyPair) void {
        pair.deinit(gpa);
        gpa.destroy(pair);
    }

    fn deinit(k: *Keys, gpa: std.mem.Allocator) void {
        gpa.destroy(k.rsa);
        freeVector(gpa, k.p521);
        freeVector(gpa, k.mldsa65);
    }
};

/// How the application side talks to the `Connection`: `read`/`writeAll`,
/// or the zero-copy `reader()`/`writer()` streams. Both must put the same
/// octets on the wire.
const Path = enum { calls, streams };

fn replay(gpa: std.mem.Allocator, v: vectors.Case, path: Path) !void {
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    return replayWith(gpa, v, &keys, path);
}

/// The next application data through `path` (null after close_notify).
fn nextData(c: *Connection, path: Path) !?[]const u8 {
    switch (path) {
        .calls => return c.read(),
        .streams => {
            const r = c.reader();
            const d = r.peekGreedy(1) catch |err| return switch (err) {
                error.EndOfStream => null,
                error.ReadFailed => c.err.?,
            };
            r.toss(d.len);
            return d;
        },
    }
}

/// A `Connection` set up as the recorded server, its input the client's
/// recorded octets, its output a `Sink`. On the heap: the configuration
/// points into it.
const Harness = struct {
    gpa: std.mem.Allocator,
    chain: [1][]const u8,
    ck: server_mod.CertifiedKey,
    compressed: [1]server_mod.CertifiedKey.CompressedCertificate,
    suites: [8]record.CipherSuite,
    csprng: std.Random.DefaultCsprng,
    ring: tlsresume.stek.DefaultRing,
    stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing),
    tickets: server_mod.Tickets,
    verifier: clientauth.X509Verifier,
    client_auth: server_mod.ClientAuth,
    /// The replay register of the `early_data` cases (`strikes` is the
    /// caller's when given: a second replay of a case is a replay).
    own_strikes: tlsresume.replay.StrikeRegister,
    early: server_mod.EarlyData,
    cfg: server_mod.Config,
    in_buf: []u8,
    reader: std.Io.Reader,
    out: []u8,
    sink: Sink,
    joiner: []u8,
    peer: []u8,
    conn: Connection,

    fn create(gpa: std.mem.Allocator, v: vectors.Case, keys: *const Keys) !*Harness {
        return createWith(gpa, v, keys, null);
    }

    fn createWith(gpa: std.mem.Allocator, v: vectors.Case, keys: *const Keys, strikes: ?*tlsresume.replay.StrikeRegister) !*Harness {
        const h = try gpa.create(Harness);
        errdefer gpa.destroy(h);
        h.gpa = gpa;
        h.ck = switch (v.cert) {
            .p256 => blk: {
                h.chain[0] = &certs.p256_cert;
                break :blk .{ .chain = &h.chain, .key = .{ .ecdsa_p256 = &keys.p256 } };
            },
            .p384 => blk: {
                h.chain[0] = &certs.p384_cert;
                break :blk .{ .chain = &h.chain, .key = .{ .ecdsa_p384 = &keys.p384 } };
            },
            .ed25519 => blk: {
                h.chain[0] = &certs.ed25519_cert;
                break :blk .{ .chain = &h.chain, .key = .{ .ed25519 = &keys.ed } };
            },
            .rsa2048 => blk: {
                h.chain[0] = &certs.rsa2048_cert;
                break :blk .{ .chain = &h.chain, .key = .{ .rsa = keys.rsa } };
            },
            .p521 => keys.p521.certifiedKey(),
            .mldsa65 => keys.mldsa65.certifiedKey(),
        };
        if (v.staple) {
            h.ck.ocsp_response = &vectors.ocsp_response;
            h.ck.sct_list = &vectors.sct_list;
        }
        if (v.compressed) |c| {
            h.compressed = .{.{ .algorithm = c.algorithm, .uncompressed_len = c.uncompressed_len, .data = c.data }};
            h.ck.compressed_certificates = &h.compressed;
        }
        for (v.suites, 0..) |s, i| h.suites[i] = @fromBackingInt(s);
        h.csprng = .init(@splat(v.seed));
        h.ring = .init();
        h.ring.rotate(1, &vectors.stek_key, @divFloor(vectors.clock_ms, 1000));
        h.stek = .{ .ring = &h.ring };
        h.tickets = .{ .ticketer = h.stek.ticketer(), .clock = .{ .now_ms = clock } };
        h.verifier = .{ .gpa = gpa, .anchors = &.{&client_certs.ca_cert} };
        h.client_auth = .{ .verifier = h.verifier.verifier(), .mandatory = v.client_auth == .mandatory, .clock = .{ .now_ms = clock } };
        h.own_strikes = .init(gpa, 4, 3600 * 1000);
        h.early = .{ .max_size = vectors.max_early_data, .replay = server_mod.strikeRegisterGuard(strikes orelse &h.own_strikes) };
        h.cfg = .{
            .certificate = .{ .fixed = &h.ck },
            .cipher_suites = h.suites[0..v.suites.len],
            .groups = v.groups,
            .alpn_protocols = v.alpn,
            .random = h.csprng.random(),
            .tickets = if (v.tickets) &h.tickets else null,
            .client_auth = if (v.client_auth != .off) &h.client_auth else null,
            .early_data = if (v.early_data) &h.early else null,
        };
        // The reader holds the whole recording in a buffer big enough for a
        // record (Connection's requirement).
        h.in_buf = try gpa.alloc(u8, @max(v.client.len, record.max_record_len));
        errdefer gpa.free(h.in_buf);
        @memcpy(h.in_buf[0..v.client.len], v.client);
        h.reader = .fixed(h.in_buf[0..v.client.len]);
        h.reader.buffer = h.in_buf;
        // Room for a full record besides the first flight.
        h.out = try gpa.alloc(u8, server_mod.minOutputLen(&h.cfg, &h.ck) + server_mod.full_record_output_len);
        errdefer gpa.free(h.out);
        h.sink = .init(gpa, h.out);
        h.joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
        errdefer gpa.free(h.joiner);
        h.peer = try gpa.alloc(u8, server_mod.peerBufferLen(h.client_auth.max_leaf_len));
        h.conn = .init(&h.cfg, &h.reader, &h.sink.writer, h.joiner);
        h.conn.server.setPeerBuffer(h.peer);
        return h;
    }

    fn destroy(h: *Harness) void {
        const gpa = h.gpa;
        h.conn.deinit();
        h.own_strikes.deinit();
        h.sink.deinit();
        gpa.free(h.joiner);
        gpa.free(h.peer);
        gpa.free(h.out);
        gpa.free(h.in_buf);
        gpa.destroy(h);
    }
};

fn replayWith(gpa: std.mem.Allocator, v: vectors.Case, keys: *const Keys, path: Path) !void {
    const h: *Harness = try .create(gpa, v, keys);
    defer h.destroy();
    const c = &h.conn;
    const written = &h.sink;
    try c.handshake();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    while (!std.mem.endsWith(u8, got.items, "ping\n")) {
        const d = (try nextData(c, path)) orelse return error.ClosedBeforePing;
        try got.appendSlice(gpa, d);
    }
    // The client's KeyUpdate (no reply due; s_client's comes with
    // "again\n") arrived before the server's close_notify in the
    // recording; reading it after makes the same octets out.
    const asked = c.server.client_application_secret;
    if (v.key_update) try c.keyUpdate(.update_requested);
    switch (path) {
        .calls => try c.writeAll("pong\n"),
        // Sealed by `close`, in one record before the close_notify — the
        // octets `writeAll` sends.
        .streams => c.writer().writeAll("pong\n") catch return c.err.?,
    }
    try c.close();
    var after: std.ArrayList(u8) = .empty;
    defer after.deinit(gpa);
    while (try nextData(c, path)) |d| try after.appendSlice(gpa, d);
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
    try testing.expectEqual(v.early_accepted, c.server.earlyDataAccepted());
    if (v.exported) |want| {
        var km: [vectors.exporter_len]u8 = undefined;
        try c.server.exportKeyingMaterial(&km, vectors.exporter_label, "");
        try testing.expectEqualSlices(u8, &want, &km);
    }
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
        replay(testing.allocator, v, .calls) catch |err| {
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
        try replayWith(gpa, v, &keys, .calls); // warm-up, and still byte-exact
        var best: f64 = 0;
        for (0..5) |_| {
            const t0 = nowNs();
            var n: usize = 0;
            while (nowNs() - t0 < 400_000_000) : (n += 1) {
                try replayWith(gpa, v, &keys, .calls);
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

test "the same sessions replay byte-exact through reader() and writer()" {
    for (vectors.cases) |v| {
        replay(testing.allocator, v, .streams) catch |err| {
            std.debug.print("case {s}: {t}\n", .{ v.name, err });
            return err;
        };
    }
}

test "0-RTT replayed: the second time the ticket's early data is refused, and the recording's Finished fails" {
    const v = try caseNamed("early");
    try testing.expect(v.early_accepted);
    var keys: Keys = try .init(testing.allocator);
    defer keys.deinit(testing.allocator);
    var strikes: tlsresume.replay.StrikeRegister = .init(testing.allocator, 4, 3600 * 1000);
    defer strikes.deinit();
    {
        const h: *Harness = try .createWith(testing.allocator, v, &keys, &strikes);
        defer h.destroy();
        try h.conn.handshake();
        try testing.expect(h.conn.server.inEarlyData());
        try testing.expectEqualStrings("ping\n", (try h.conn.read()).?);
    }
    {
        // A server that now takes more than the ticket promised holds the
        // client to the ticket's max_early_data_size (RFC 8446 §4.2.10).
        const h: *Harness = try .create(testing.allocator, v, &keys);
        defer h.destroy();
        h.early.max_size = 1 << 20;
        try h.conn.handshake();
        try testing.expectEqualStrings("ping\n", (try h.conn.read()).?);
        try testing.expectEqual(vectors.max_early_data - 5, h.conn.server.early_left);
    }
    const h: *Harness = try .createWith(testing.allocator, v, &keys, &strikes);
    defer h.destroy();
    // Same seed, same handshake keys: the early records are skipped (they
    // do not open under the handshake key), the Finished opens but was
    // computed over an EncryptedExtensions with early_data and an
    // EndOfEarlyData this server never saw.
    try testing.expectError(error.DecryptError, h.conn.handshake());
    try testing.expectEqual(server_mod.EarlyDataReason.replayed, h.conn.server.earlyDataReason());
    try testing.expect(!h.conn.server.isConnected());
}

fn caseNamed(name: []const u8) !vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return error.NoSuchCase;
}

test "writer(): records follow the data — a short write topped up, full records, a splat" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const v = try caseNamed("p256-aes256-x25519"); // no tickets: nothing sealed after the handshake
    try testing.expect(!v.tickets);
    const h: *Harness = try .create(gpa, v, &keys);
    defer h.destroy();
    const c = &h.conn;
    try c.handshake();
    const from = h.sink.written().len;
    var rx: record.Protection = undefined;
    try rx.init(c.server.suite, c.server.server_application_secret[0..48]);

    // An h2-style frame: a 9-octet header, then a payload too long for the
    // record's rest, then padding as a splat.
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    const w = c.writer();
    try w.writeAll("123456789");
    try want.appendSlice(gpa, "123456789");
    var payload: [40_000]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @truncate(i *% 7 +% 1);
    try w.writeAll(&payload);
    try want.appendSlice(gpa, &payload);
    try w.splatByteAll('z', 20_000);
    try want.appendNTimes(gpa, 'z', 20_000);
    try w.flush();

    const sent = try gpa.dupe(u8, h.sink.written()[from..]);
    defer gpa.free(sent);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var lens: std.ArrayList(usize) = .empty;
    defer lens.deinit(gpa);
    var at: usize = 0;
    while (at < sent.len) {
        const hd = record.parseHeader(sent[at..][0..5]);
        const opened = try rx.open(sent[at..][0 .. 5 + hd.length]);
        try testing.expectEqual(record.ContentType.application_data, opened.content_type);
        try got.appendSlice(gpa, opened.content);
        try lens.append(gpa, opened.content.len);
        at += 5 + hd.length;
    }
    try testing.expectEqualSlices(u8, want.items, got.items);
    // 60,009 octets: three full records and the rest — the 9-octet header
    // did not go out alone.
    try testing.expectEqualSlices(usize, &.{ 16384, 16384, 16384, 60_009 - 3 * 16384 }, lens.items);

    // Octets kept across a record are refused, not copied.
    try w.writeAll("ab");
    try testing.expectError(error.WriteFailed, w.rebase(1, w.buffer.len));
    try testing.expectEqual(error.RecordBoundary, c.err.?);
}

/// Opens every record of `sent` with `rx`, collecting each one's content.
fn openAll(gpa: std.mem.Allocator, rx: *record.Protection, sent: []u8, contents: *std.ArrayList([]u8)) !void {
    var at: usize = 0;
    while (at < sent.len) {
        const hd = record.parseHeader(sent[at..][0..5]);
        const opened = try rx.open(sent[at..][0 .. 5 + hd.length]);
        try contents.append(gpa, opened.content);
        at += 5 + hd.length;
    }
}

test "writer(): octets written before a read are sealed first and keep their place" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const h: *Harness = try .create(gpa, try caseNamed("p256-aes256-x25519"), &keys);
    defer h.destroy();
    const c = &h.conn;
    try c.handshake();
    const from = h.sink.written().len;
    var rx: record.Protection = undefined;
    try rx.init(c.server.suite, c.server.server_application_secret[0..48]);

    const w = c.writer();
    try w.writeAll("a");
    // The ping is already in the input: this read queues "a" and sends
    // nothing, and the next write must not land on the sealed record.
    try testing.expectEqualStrings("ping\n", (try nextData(c, .streams)).?);
    try w.writeAll("b");
    try w.flush();

    const sent = try gpa.dupe(u8, h.sink.written()[from..]);
    defer gpa.free(sent);
    var contents: std.ArrayList([]u8) = .empty;
    defer contents.deinit(gpa);
    try openAll(gpa, &rx, sent, &contents);
    try testing.expectEqual(@as(usize, 2), contents.items.len);
    try testing.expectEqualStrings("a", contents.items[0]);
    try testing.expectEqualStrings("b", contents.items[1]);
}

test "writeSlot: no slot while a KeyUpdate is due, even where a short record would fit" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const h: *Harness = try .create(gpa, try caseNamed("p256-aes256-x25519"), &keys);
    defer h.destroy();
    const c = &h.conn;
    try c.handshake();
    const s = &c.server;
    // Pretend output is pending until 25 octets are left above the alert
    // reserve: a 3-octet record fits (22 of overhead), the KeyUpdate (27)
    // does not.
    s.out.len = s.out.buf.len - outbound.alert_reserve - 25;
    try s.keyUpdate(.update_not_requested);
    try testing.expect(s.tx_update != null);
    try testing.expectEqual(@as(usize, 0), (try s.writeSlot()).len);
    s.out.len = 0;
    try testing.expect((try s.writeSlot()).len != 0);
    try testing.expect(s.tx_update == null);
}

test "writer(): drain takes the last slice `splat` times — none at 0" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const h: *Harness = try .create(gpa, try caseNamed("p256-aes256-x25519"), &keys);
    defer h.destroy();
    const c = &h.conn;
    try c.handshake();
    const w = c.writer();
    try testing.expectEqual(@as(usize, 2), try w.vtable.drain(w, &.{ "ab", "cd" }, 0));
    try testing.expectEqual(@as(usize, 3), try w.vtable.drain(w, &.{ "x", "yz" }, 1));
    try testing.expectEqual(@as(usize, 3), try w.vtable.drain(w, &.{"q"}, 3));
    try testing.expectEqualStrings("abxyzqqq", w.buffered());
}

test "writeAll into an output that never takes a record is OutputFull, not a loop" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const h: *Harness = try .create(gpa, try caseNamed("p256-aes256-x25519"), &keys);
    defer h.destroy();
    const c = &h.conn;
    try c.handshake();
    // As if the writer's buffer were below `minOutputLen`: room for the
    // alert reserve and a few octets, never a record.
    const full = c.server.out.buf;
    c.server.out.buf = full[0 .. outbound.alert_reserve + 10];
    try testing.expectError(error.OutputFull, c.writeAll("x"));
    c.server.out.buf = full;
    c.deinit();
    // After deinit no alias is left to write into.
    try testing.expectEqual(@as(usize, 0), c.writer().buffer.len);
    try testing.expectEqual(@as(usize, 0), c.reader().buffer.len);
}

test "reader(): more contiguous octets than one record holds is RecordBoundary" {
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    const h: *Harness = try .create(gpa, try caseNamed("p256-aes256-x25519"), &keys);
    defer h.destroy();
    const c = &h.conn;
    // "ping\n" came in one record of five octets: six are not there.
    const r = c.reader();
    try testing.expectError(error.ReadFailed, r.peek(6));
    try testing.expectEqual(error.RecordBoundary, c.err.?);
    try testing.expectEqualStrings("ping\n", r.buffered());
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
    try testing.expectError(error.BadRecordMac, replay(testing.allocator, w, .calls));
}

// ── dead-stack probe of a whole handshake (`burn.handshake_burn`) ───────

const sp = @import("testkit").stackprobe;
/// Past the deepest burn under a handshake (`tls13`'s hybrid kex, 160 KiB)
/// and the frames above it. One call per measurement: a second
/// `handshake` on a connected `Connection` does nothing.
const PHs = sp.Probe(.{ .window = 320 * 1024, .repeats = 1 });

test "STACKPROBE: no secret residue after a recorded handshake (full, hybrid, HRR, resumed, mTLS, RSA)" {
    try sp.skipUnlessOptimized();
    const gpa = testing.allocator;
    var keys: Keys = try .init(gpa);
    defer keys.deinit(gpa);
    inline for (.{ "p256-aes256-x25519", "go-no-hybrid", "p256-default", "hrr-p256", "resume", "mtls-p256", "rsa2048-pss", "p384", "ed25519" }) |name| {
        const h: *Harness = try .create(gpa, try caseNamed(name), &keys);
        defer h.destroy();
        const s = &h.conn.server;
        // The client's Certificate and CertificateVerify are checked in
        // unburned steps (public data: its chain, its signature, the
        // transcript hash), whose verifier frames reach far below the
        // burns: needles only there.
        const expect: sp.Expect = if (comptime std.mem.startsWith(u8, name, "mtls")) .{ .residue = false } else .{};
        _ = try PHs.run(name, Connection.handshake, .{&h.conn}, &[_][]const u8{
            &keys.p256.bytes,             &keys.p384.bytes,             &keys.ed.bytes,
            &s.client_application_secret, &s.server_application_secret, &s.exporter_master_secret,
        }, expect);
        try testing.expect(s.isConnected());
    }
}
