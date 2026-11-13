// SPDX-License-Identifier: MIT

//! TLS 1.2 session resumption (RFC 5077 tickets, RFC 5246 §7.3 abbreviated
//! handshake), against a synthetic resuming server.
//!
//! The server side of a resumption needs no certificate and no signature:
//! ServerHello (echoing the client's session_id), an optional
//! NewSessionTicket, ChangeCipherSpec, and a Finished keyed from the master
//! secret the cache entry holds. So these tests prime a `SessionCache` entry
//! by hand (the master secret, the ticket, a chain), compute the server's
//! flight with the PRF from `std.crypto.tls`, and check the client's output
//! (its ClientHello, its Finished) against the same computation. The full
//! handshake that creates such an entry, and a real server's behaviour, are
//! `tools/interop.zig`'s cases against Go's crypto/tls (`resume-12*`).
//!
//! Go's behaviour these follow (handshake_client.go, go1.26: loadSession,
//! processServerHello, readSessionTicket, saveSessionTicket) is summarised in
//! SPEC.md's Backlog entry for this feature.

const std = @import("std");
const testing = std.testing;
const Client = @import("Client.zig");
const hello = @import("hello.zig");

const tls = std.crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;

const host = "srv.test";
const suite_ecdhe_rsa_aes128gcm: u16 = 0xc02f;
const master: [48]u8 = blk: {
    var m: [48]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    break :blk m;
};
const server_random: [32]u8 = @splat(0x55);

fn entropy() [Client.Options.entropy_len]u8 {
    var e: [Client.Options.entropy_len]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    return e;
}

fn clientRandom() [32]u8 {
    return entropy()[0..32].*;
}

fn sessionId() [32]u8 {
    return entropy()[32..64].*;
}

// ── cache priming ──────────────────────────────────────────────────────────

const Prime = struct {
    ticket: []const u8 = "OLD-TICKET",
    suite: u16 = suite_ecdhe_rsa_aes128gcm,
    ems: bool = true,
    not_after_s: i64 = std.math.maxInt(i64),
    tls12: bool = true,
};

fn prime(cache: *Client.SessionCache, p: Prime) *Client.ClientSession {
    const e = cache.reserve(host).?;
    e.wipe();
    e.verification = .no_verification;
    e.leaf_not_after_s = p.not_after_s;
    _ = e.setChain(&.{ "leaf-der", "inter-der" });
    if (p.tls12) {
        @memcpy(e.resumption_secret[0..48], &master);
        @memcpy(e.ticket_buf[0..p.ticket.len], p.ticket);
        e.ticket_len = @intCast(p.ticket.len);
        e.ticket_lifetime_s = 3600;
        e.version12 = true;
        e.suite12 = p.suite;
        e.ems12 = p.ems;
        e.group12 = 0x0017;
        e.usable = true;
    }
    return e;
}

// ── running the client ─────────────────────────────────────────────────────

var in_buf: [Client.min_buffer_len]u8 = undefined;
var read_buf: [Client.min_buffer_len]u8 = undefined;
var write_buf: [Client.min_buffer_len]u8 = undefined;
var out_buf: [Client.min_buffer_len]u8 = undefined;
var sink: Client = undefined;
var info_storage: [16 * 1024]u8 = undefined;
var info: Client.ConnectionInfo = undefined;

const Cfg = struct {
    min_version: tls.ProtocolVersion = .tls_1_2,
    now_s: i64 = 0,
    ems: bool = true,
    cache: ?*Client.SessionCache,
};

const Result = struct {
    err: ?anyerror,
    /// What the client wrote.
    out: []const u8,
};

fn run(server: []const u8, cfg: Cfg) Result {
    @memcpy(in_buf[0..server.len], server);
    var reader = Reader.fixed(&in_buf);
    reader.end = server.len;
    var fw = Writer.fixed(&out_buf);
    info = .init(&info_storage);
    const e = entropy();
    const opts: Client.Options = .{
        .host = .{ .explicit = host },
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &e,
        .realtime_now = .{ .nanoseconds = cfg.now_s * std.time.ns_per_s },
        .connection_info = &info,
        .min_version = cfg.min_version,
        .extended_master_secret = cfg.ems,
        .session_cache = cfg.cache,
    };
    var err: ?anyerror = null;
    Client.initInto(&sink, &reader, &fw, opts) catch |x| {
        err = x;
    };
    return .{ .err = err, .out = fw.buffered() };
}

/// The ClientHello handshake message `run` writes first (record header
/// stripped), copied into `buf`, for a cache primed with `p` (null: no cache).
fn clientHello(buf: *[2048]u8, p: ?Prime, cfg_in: Cfg) ![]const u8 {
    var storage: [2]Client.ClientSession = undefined;
    var cache: Client.SessionCache = .init(&storage, null);
    defer cache.deinit();
    var cfg = cfg_in;
    if (p) |pp| {
        _ = prime(&cache, pp);
        cfg.cache = &cache;
    }
    const r = run("", cfg);
    try testing.expectEqual(error.TlsConnectionTruncated, r.err.?);
    try testing.expectEqual(@as(u8, 22), r.out[0]);
    const len = std.mem.readInt(u16, r.out[3..5], .big);
    @memcpy(buf[0..len], r.out[5..][0..len]);
    return buf[0..len];
}

/// The body of extension `t` in the ClientHello message `m`, or null.
fn findExt(m: []const u8, t: u16) ?[]const u8 {
    var i: usize = 4 + 2 + 32 + 1 + 32;
    i += 2 + std.mem.readInt(u16, m[i..][0..2], .big); // cipher suites
    i += 2; // compression
    const end = i + 2 + std.mem.readInt(u16, m[i..][0..2], .big);
    i += 2;
    while (i < end) {
        const len = std.mem.readInt(u16, m[i + 2 ..][0..2], .big);
        if (std.mem.readInt(u16, m[i..][0..2], .big) == t) return m[i + 4 ..][0..len];
        i += 4 + len;
    }
    return null;
}

// ── the synthetic server ───────────────────────────────────────────────────

const Srv = struct {
    /// Echo the client's session_id (resume) or answer with another.
    echo: bool = true,
    suite: u16 = suite_ecdhe_rsa_aes128gcm,
    ems: bool = true,
    /// The SessionTicket extension in the ServerHello.
    ticket_ext: bool = true,
    /// A NewSessionTicket after the ServerHello: null none, "" a withdrawal.
    ticket: ?[]const u8 = "NEW-TICKET",
    /// Send the ChangeCipherSpec + Finished at all.
    finish: bool = true,
    tamper_finished: bool = false,
    /// A NewSessionTicket as the very first message after the ServerHello
    /// even though the extension was not announced.
    unannounced_ticket: bool = false,
};

fn prf(label: []const u8, seed: []const []const u8, comptime n: usize) [n]u8 {
    var parts: [4][]const u8 = undefined;
    parts[0] = label;
    for (seed, 1..) |s, i| parts[i] = s;
    return tls.hmacExpandLabel(HmacSha256, &master, parts[0 .. 1 + seed.len], n);
}

fn putHs(w: *Writer, typ: tls.HandshakeType, body: []const u8) []const u8 {
    const start = w.end;
    w.writeByte(@backingInt(typ)) catch unreachable;
    w.writeInt(u24, @intCast(body.len), .big) catch unreachable;
    w.writeAll(body) catch unreachable;
    return w.buffer[start..w.end];
}

fn putPlainRecord(w: *Writer, ct: tls.ContentType, body: []const u8) void {
    w.writeByte(@backingInt(ct)) catch unreachable;
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.writeInt(u16, @intCast(body.len), .big) catch unreachable;
    w.writeAll(body) catch unreachable;
}

/// Everything the server sends, given the ClientHello message it saw. The
/// returned slice is in `buf`; `th` is left with the transcript through the
/// server's Finished (what the client's own Finished is computed over).
fn buildServer(buf: []u8, ch: []const u8, s: Srv, th: *Sha256) []const u8 {
    var w = Writer.fixed(buf);
    var scratch: [512]u8 = undefined;
    var sw = Writer.fixed(&scratch);
    th.* = Sha256.init(.{});
    th.update(ch);

    // ServerHello
    var body: [256]u8 = undefined;
    var bw = Writer.fixed(&body);
    bw.writeAll(&.{ 3, 3 }) catch unreachable;
    bw.writeAll(&server_random) catch unreachable;
    bw.writeByte(32) catch unreachable;
    const sid: [32]u8 = if (s.echo) sessionId() else @splat(0xee);
    bw.writeAll(&sid) catch unreachable;
    bw.writeInt(u16, s.suite, .big) catch unreachable;
    bw.writeByte(0) catch unreachable;
    var exts: [32]u8 = undefined;
    var ew = Writer.fixed(&exts);
    if (s.ems) ew.writeAll(&.{ 0, 23, 0, 0 }) catch unreachable;
    if (s.ticket_ext) ew.writeAll(&.{ 0, 35, 0, 0 }) catch unreachable;
    bw.writeInt(u16, @intCast(ew.end), .big) catch unreachable;
    bw.writeAll(ew.buffered()) catch unreachable;
    const sh = putHs(&sw, .server_hello, bw.buffered());
    th.update(sh);
    putPlainRecord(&w, .handshake, sh);

    var nst_buf: [128]u8 = undefined;
    if (s.ticket) |t| if (s.ticket_ext or s.unannounced_ticket) {
        var nw = Writer.fixed(&nst_buf);
        nw.writeInt(u32, 7200, .big) catch unreachable;
        nw.writeInt(u16, @intCast(t.len), .big) catch unreachable;
        nw.writeAll(t) catch unreachable;
        var sw2 = Writer.fixed(scratch[sw.end..]);
        const m = putHs(&sw2, .new_session_ticket, nw.buffered());
        th.update(m);
        putPlainRecord(&w, .handshake, m);
    };
    if (!s.finish) return w.buffered();

    putPlainRecord(&w, .change_cipher_spec, &.{1});
    // Finished, AES-128-GCM under the server write key.
    const hash = th.peek();
    const kb = prf("key expansion", &.{ &server_random, &clientRandom() }, 48);
    var verify = prf("server finished", &.{&hash}, 12);
    if (s.tamper_finished) verify[3] ^= 1;
    var fin: [16]u8 = undefined;
    fin[0] = 20;
    std.mem.writeInt(u24, fin[1..4], 12, .big);
    @memcpy(fin[4..], &verify);
    const explicit: [8]u8 = @splat(0);
    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..4], kb[36..40]); // server_write_IV
    @memcpy(nonce[4..], &explicit);
    const ad = explicit ++ [_]u8{ 22, 3, 3 } ++ [_]u8{ 0, 16 };
    var rec: [8 + 16 + 16]u8 = undefined;
    @memcpy(rec[0..8], &explicit);
    Aead.encrypt(rec[8..24], rec[24..40], &fin, &ad, nonce, kb[16..32].*);
    putPlainRecord(&w, .handshake, &rec);
    // The client's Finished covers the server's, as the server sent it.
    var fin_true: [16]u8 = fin;
    @memcpy(fin_true[4..], &prf("server finished", &.{&hash}, 12));
    th.update(&fin_true);
    return w.buffered();
}

/// Check the client's output after its ClientHello: ChangeCipherSpec, then
/// the Finished record under the client write key, verify_data as the PRF
/// over the transcript `th`.
fn expectClientFinished(out: []const u8, ch_len: usize, th: *Sha256) !void {
    const rest = out[5 + ch_len ..];
    try testing.expectEqualSlices(u8, &.{ 20, 3, 3, 0, 1, 1 }, rest[0..6]);
    const rec = rest[6..];
    try testing.expectEqual(@as(usize, 5 + 8 + 16 + 16), rec.len);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 40 }, rec[0..5]);
    const kb = prf("key expansion", &.{ &server_random, &clientRandom() }, 48);
    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..4], kb[32..36]); // client_write_IV
    @memcpy(nonce[4..], rec[5..13]);
    const seq0: [8]u8 = @splat(0);
    const ad = seq0 ++ [_]u8{ 22, 3, 3 } ++ [_]u8{ 0, 16 };
    var pt: [16]u8 = undefined;
    try Aead.decrypt(&pt, rec[13..29], rec[29..45].*, &ad, nonce, kb[0..16].*);
    try testing.expectEqual(@as(u8, 20), pt[0]);
    const hash = th.peek();
    const want = prf("client finished", &.{&hash}, 12);
    try testing.expectEqualSlices(u8, &want, pt[4..16]);
}

var srv_buf: [2048]u8 = undefined;

fn newCache(storage: []Client.ClientSession) Client.SessionCache {
    return .init(storage, null);
}

// ── tests ──────────────────────────────────────────────────────────────────

fn expectDropped(cache: *Client.SessionCache) !void {
    try testing.expect(cache.find(host) == null);
}

test "offer: the cached ticket goes out in the SessionTicket extension; the random session_id is the marker" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    try testing.expectEqualStrings("OLD-TICKET", findExt(ch, hello.ext_session_ticket).?);
    try testing.expectEqualSlices(u8, &sessionId(), ch[4 + 2 + 32 + 1 ..][0..32]);
    try testing.expect(findExt(ch, hello.ext_extended_master_secret) != null);
}

test "offer: no cache, TLS 1.3 only: no extension; a cache without a TLS 1.2 session: an empty one (Go: 'I accept tickets')" {
    var buf: [2048]u8 = undefined;
    try testing.expect(findExt(try clientHello(&buf, null, .{ .cache = null }), hello.ext_session_ticket) == null);
    try testing.expect(findExt(try clientHello(&buf, .{}, .{ .cache = null, .min_version = .tls_1_3 }), hello.ext_session_ticket) == null);
    const ch = try clientHello(&buf, .{ .tls12 = false }, .{ .cache = null });
    try testing.expectEqual(@as(usize, 0), findExt(ch, hello.ext_session_ticket).?.len);
}

test "offer: a session whose suite is no longer offered is not offered, and stays cached; one past its leaf's notAfter is deleted" {
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{ .suite = 0x1234 });
    var r = run("", .{ .cache = &cache });
    try testing.expectEqual(error.TlsConnectionTruncated, r.err.?);
    try testing.expectEqual(@as(usize, 0), findExt(r.out[5..], hello.ext_session_ticket).?.len);
    // Not offered, so not the thing that failed: still there.
    try testing.expect(cache.find(host) != null);

    _ = prime(&cache, .{ .not_after_s = 100 });
    r = run("", .{ .cache = &cache, .now_s = 200 });
    try testing.expectEqual(@as(usize, 0), findExt(r.out[5..], hello.ext_session_ticket).?.len);
    try expectDropped(&cache);
}

test "resume: abbreviated handshake -- server Finished first, ours verified against the PRF; did_resume; the new ticket replaces the old" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    const e = prime(&cache, .{});
    const gen = e.generation;
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{}, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expect(r.err == null);
    try expectClientFinished(r.out, ch.len, &th);
    try testing.expect(sink.did_resume);
    try testing.expect(info.did_resume);
    try testing.expectEqual(tls.ProtocolVersion.tls_1_2, info.version);
    try testing.expectEqual(@as(u16, suite_ecdhe_rsa_aes128gcm), @backingInt(info.cipher_suite));
    try testing.expect(info.extended_master_secret);
    try testing.expectEqual(@as(usize, 2), info.peerCertificates().len);
    try testing.expectEqualStrings("leaf-der", info.peerCertificates()[0]);
    // The entry: new ticket and lifetime hint, same master secret, same generation.
    try testing.expectEqualStrings("NEW-TICKET", e.ticket());
    try testing.expectEqual(@as(u32, 7200), e.ticket_lifetime_s);
    try testing.expectEqual(gen, e.generation);
    try testing.expect(e.usable and e.version12);
    try testing.expectEqualSlices(u8, &master, e.resumption_secret[0..48]);
    try testing.expectEqual(@as(u8, 2), e.chain_count);
    // The application stream is keyed: a second resumption from the new ticket offers it.
    const ch2 = try clientHello(&buf, .{ .ticket = "NEW-TICKET" }, .{ .cache = null });
    try testing.expectEqualStrings("NEW-TICKET", findExt(ch2, hello.ext_session_ticket).?);
}

test "resume: a server that sends no new ticket leaves the entry as it was" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    const e = prime(&cache, .{});
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{ .ticket_ext = false, .ticket = null }, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expect(r.err == null);
    try expectClientFinished(r.out, ch.len, &th);
    try testing.expect(sink.did_resume);
    try testing.expectEqualStrings("OLD-TICKET", e.ticket());
}

test "resume: a zero-length NewSessionTicket (RFC 5077 §3.3 withdrawal) drops the cache entry" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{ .ticket = "" }, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expect(r.err == null);
    try testing.expect(sink.did_resume);
    try expectDropped(&cache);
}

test "decline: a server that does not echo the session_id gets a full handshake; a failure then drops the stale ticket (Go: Put(key, nil))" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    var th: Sha256 = undefined;
    // The ServerHello only: the client now waits for a Certificate that never comes.
    const server = buildServer(&srv_buf, ch, .{ .echo = false, .ticket_ext = false, .ticket = null, .finish = false }, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expectEqual(error.TlsConnectionTruncated, r.err.?);
    // Nothing but the ClientHello was written: no Finished of a resumption.
    try testing.expectEqual(5 + ch.len, r.out.len);
    try expectDropped(&cache);
}

test "mismatches abort and drop the entry: suite, and the extended master secret either way (RFC 7627 §5.3)" {
    var buf: [2048]u8 = undefined;
    const Case = struct { p: Prime, s: Srv };
    const cases = [_]Case{
        .{ .p = .{}, .s = .{ .suite = 0xc030 } }, // another suite the client offers
        .{ .p = .{}, .s = .{ .ems = false } }, // the session had EMS, the server's answer has none
        .{ .p = .{ .ems = false }, .s = .{ .ems = true } }, // and the other way round
    };
    for (cases) |c| {
        const ch = try clientHello(&buf, c.p, .{ .cache = null });
        var storage: [2]Client.ClientSession = undefined;
        var cache = newCache(&storage);
        defer cache.deinit();
        _ = prime(&cache, c.p);
        var th: Sha256 = undefined;
        const server = buildServer(&srv_buf, ch, c.s, &th);
        const r = run(server, .{ .cache = &cache });
        try testing.expectEqual(error.TlsIllegalParameter, r.err.?);
        try expectDropped(&cache);
    }
}

test "an echoed session_id with no session offered is illegal_parameter (Go: the TLS 1.3 compatibility id echoed in 1.2)" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{ .tls12 = false }, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{ .tls12 = false });
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{ .ticket = null }, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expectEqual(error.TlsIllegalParameter, r.err.?);
}

test "a ticket nobody asked for: ServerHello extension without our offer is illegal_parameter; a NewSessionTicket without the extension, unexpected_message" {
    var buf: [2048]u8 = undefined;
    // No cache: the extension was not offered.
    const ch = try clientHello(&buf, null, .{ .cache = null });
    var th: Sha256 = undefined;
    var server = buildServer(&srv_buf, ch, .{ .echo = false, .finish = false }, &th);
    try testing.expectEqual(error.TlsIllegalParameter, run(server, .{ .cache = null }).err.?);

    const ch2 = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    server = buildServer(&srv_buf, ch2, .{ .ticket_ext = false, .unannounced_ticket = true }, &th);
    try testing.expectEqual(error.TlsUnexpectedMessage, run(server, .{ .cache = &cache }).err.?);
    try expectDropped(&cache);
}

test "an announced ticket must precede the ChangeCipherSpec (RFC 5077 §3.3; Go reads it first)" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{ .ticket = null }, &th);
    try testing.expectEqual(error.TlsUnexpectedMessage, run(server, .{ .cache = &cache }).err.?);
    try expectDropped(&cache);
}

test "a wrong server Finished is decrypt_error and drops the entry; nothing of ours is sent" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    var th: Sha256 = undefined;
    const server = buildServer(&srv_buf, ch, .{ .tamper_finished = true }, &th);
    const r = run(server, .{ .cache = &cache });
    try testing.expectEqual(error.TlsDecryptError, r.err.?);
    try testing.expectEqual(5 + ch.len, r.out.len);
    try expectDropped(&cache);
}

test "a NewSessionTicket that is malformed is decode_error" {
    var buf: [2048]u8 = undefined;
    const ch = try clientHello(&buf, .{}, .{ .cache = null });
    var storage: [2]Client.ClientSession = undefined;
    var cache = newCache(&storage);
    defer cache.deinit();
    _ = prime(&cache, .{});
    var th: Sha256 = undefined;
    // The ServerHello, then a NewSessionTicket whose length field overruns its body.
    const sh_only = buildServer(&srv_buf, ch, .{ .ticket = null, .finish = false }, &th);
    const bad = [_]u8{ 22, 3, 3, 0, 11, 4, 0, 0, 7, 0, 0, 0, 1, 0, 9, 'x' };
    @memcpy(srv_buf[sh_only.len..][0..bad.len], &bad);
    try testing.expectEqual(error.TlsDecodeError, run(srv_buf[0 .. sh_only.len + bad.len], .{ .cache = &cache }).err.?);
}
