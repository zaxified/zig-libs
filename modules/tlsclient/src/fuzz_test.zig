// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for tlsclient (added 2026-10-10).
//!
//! Two harnesses, both generic over their source of choices (`S`):
//! - `tlsclient-flight` (here): `Client.initInto` reads a malicious server's
//!   first flight. The templates are GENUINE: a complete TLS 1.3 flight
//!   (x25519 / AES-128-GCM-SHA256: ServerHello, ChangeCipherSpec, then
//!   EncryptedExtensions, Certificate, CertificateVerify and Finished under
//!   the real handshake keys, signed with the `client-p256` throwaway key)
//!   that the client ACCEPTS undamaged, and a plaintext TLS 1.2 flight
//!   (ServerHello, Certificate, ServerKeyExchange with a real signature,
//!   ServerHelloDone) that the client takes up to the point of sending its
//!   own Finished. The driver damages 0-3 octets (half of them in the first
//!   96 bytes: the hello's structure), maybe truncates. Oracle: a flight that
//!   differs from the genuine 1.3 one anywhere but a record's ignored
//!   legacy_version octets is REFUSED; a TLS 1.2 flight never completes
//!   (the server's Finished is never sent).
//! - `tlsclient-chain` (verify.zig): a server's Certificate chain through the
//!   well-formedness guard and `verifyAgainstBundle`.
//!
//! Driver: `TLSCLIENT_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const Client = @import("Client.zig");
pub const fuzz_driver = testkit.fuzz.driver;

const tls = std.crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(HmacSha256);
const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// `frame` into `buf` with 0-3 octets damaged (half of them within the first
/// 96 octets, where the structure is) and maybe truncated. The driver's `Rng`
/// only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 96) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── the genuine server flights ──────────────────────────────────────────────

const server_cert_der = derFromPem(@embedFile("testdata/client-p256.pem"));
const server_key_der = @embedFile("testdata/client-p256.key.der");

fn derFromPem(comptime pem: []const u8) []const u8 {
    const S = struct {
        const der = blk: {
            @setEvalBranchQuota(1_000_000);
            const begin = std.mem.indexOf(u8, pem, "-----\n").? + 6;
            const end = std.mem.indexOf(u8, pem, "\n-----END").?;
            var clean: [end - begin]u8 = undefined;
            var len: usize = 0;
            for (pem[begin..end]) |ch| if (ch != '\n') {
                clean[len] = ch;
                len += 1;
            };
            const b64 = clean[0..len];
            var out: [std.base64.standard.Decoder.calcSizeForSlice(b64) catch unreachable]u8 = undefined;
            std.base64.standard.Decoder.decode(&out, b64) catch unreachable;
            break :blk out;
        };
    };
    return &S.der;
}

const Templates = struct {
    entropy: [Client.Options.entropy_len]u8 = undefined,
    /// The ClientHello's length on the wire (what the client writes first).
    hello_len: usize = 0,
    f13: [4096]u8 = undefined,
    f13_len: usize = 0,
    /// Offset of every record header in `f13`.
    f13_records: [12]usize = undefined,
    f13_nrecords: usize = 0,
    f12: [4096]u8 = undefined,
    f12_len: usize = 0,
};
var tm: Templates = .{};
var tm_ready = false;

var in_buf: [Client.min_buffer_len]u8 = undefined;
var read_buf: [Client.min_buffer_len]u8 = undefined;
var write_buf: [Client.min_buffer_len]u8 = undefined;
var out_buf: [8192]u8 = undefined;
var sink: Client = undefined;

const Outcome = struct {
    /// `initInto`'s error, if any.
    init_err: ?anyerror = null,
    /// After an established session: the application octets read up to the
    /// server's close_notify, and the read's error (if it did not get there).
    app_octets: u64 = 0,
    read_err: ?anyerror = null,
    /// Octets the client wrote.
    written: u64 = 0,
};

/// `Client.initInto` over `input` with the fixed entropy; on success the
/// application stream is read to its end (`close_notify`).
fn runClient(input: []const u8, out_copy: ?*Writer) Outcome {
    @memcpy(in_buf[0..input.len], input);
    var reader = Reader.fixed(&in_buf);
    reader.end = input.len;
    var dw: Writer.Discarding = .init(&out_buf);
    var fw = Writer.fixed(&out_buf);
    const w: *Writer = if (out_copy != null) &fw else &dw.writer;
    const opts: Client.Options = .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &tm.entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    };
    var o: Outcome = .{};
    if (Client.initInto(&sink, &reader, w, opts)) |_| {
        if (sink.reader.discardRemaining()) |n| o.app_octets = n else |e| o.read_err = e;
    } else |e| o.init_err = e;
    o.written = if (out_copy != null) fw.end else dw.fullCount();
    if (out_copy) |c| c.* = fw;
    return o;
}

fn hsMsg(buf: []u8, typ: tls.HandshakeType, body: []const u8) []const u8 {
    buf[0] = @intFromEnum(typ);
    std.mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
    @memcpy(buf[4..][0..body.len], body);
    return buf[0 .. 4 + body.len];
}

fn putRecord(w: *Writer, ct: tls.ContentType, body: []const u8) void {
    tm.f13_records[tm.f13_nrecords] = w.end;
    tm.f13_nrecords += 1;
    w.writeByte(@intFromEnum(ct)) catch unreachable;
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.writeInt(u16, @intCast(body.len), .big) catch unreachable;
    w.writeAll(body) catch unreachable;
}

fn putEncrypted(w: *Writer, key: [16]u8, iv: [12]u8, seq: u64, ct: tls.ContentType, msg: []const u8) void {
    var inner: [2048]u8 = undefined;
    @memcpy(inner[0..msg.len], msg);
    inner[msg.len] = @intFromEnum(ct);
    const n = msg.len + 1;
    var rec: [2048 + 16]u8 = undefined;
    var header: [5]u8 = .{ @intFromEnum(tls.ContentType.application_data), 3, 3, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(n + 16), .big);
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (nonce[4..], seq_be) |*b, s| b.* ^= s;
    Aead.encrypt(rec[0..n], rec[n..][0..16], inner[0..n], &header, nonce, key);
    putRecord(w, .application_data, rec[0 .. n + 16]);
}

fn ensureTemplates() !void {
    if (tm_ready) return;
    tm = .{};
    for (&tm.entropy, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);

    // The ClientHello this entropy produces: an empty server.
    var hello_copy: Writer = undefined;
    const e = runClient("", &hello_copy);
    try testing.expectEqual(@as(?anyerror, error.TlsConnectionTruncated), e.init_err);
    const client_hello = hello_copy.buffered();
    tm.hello_len = client_hello.len;
    const session_echo = tm.entropy[32..64];
    const client_rand = tm.entropy[0..32];
    const client_x25519 = try X25519.KeyPair.generateDeterministic(tm.entropy[208..240].*);
    const srv_sk: [32]u8 = [_]u8{0x5c} ** 32;
    const srv_pub = try X25519.recoverPublicKey(srv_sk);
    const server_rand: [32]u8 = [_]u8{0x77} ** 32;

    // ── TLS 1.3 ─────────────────────────────────────────────────────────────
    var sh: [128]u8 = undefined;
    var shw = Writer.fixed(&sh);
    shw.writeByte(@intFromEnum(tls.HandshakeType.server_hello)) catch unreachable;
    shw.writeInt(u24, 0, .big) catch unreachable; // patched
    shw.writeInt(u16, 0x0303, .big) catch unreachable;
    shw.writeAll(&server_rand) catch unreachable;
    shw.writeByte(32) catch unreachable;
    shw.writeAll(session_echo) catch unreachable;
    shw.writeInt(u16, @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256), .big) catch unreachable;
    shw.writeByte(0) catch unreachable;
    shw.writeInt(u16, 6 + 4 + 4 + 32, .big) catch unreachable;
    shw.writeInt(u16, @intFromEnum(tls.ExtensionType.supported_versions), .big) catch unreachable;
    shw.writeInt(u16, 2, .big) catch unreachable;
    shw.writeInt(u16, 0x0304, .big) catch unreachable;
    shw.writeInt(u16, @intFromEnum(tls.ExtensionType.key_share), .big) catch unreachable;
    shw.writeInt(u16, 4 + 32, .big) catch unreachable;
    shw.writeInt(u16, @intFromEnum(tls.NamedGroup.x25519), .big) catch unreachable;
    shw.writeInt(u16, 32, .big) catch unreachable;
    shw.writeAll(&srv_pub) catch unreachable;
    std.mem.writeInt(u24, sh[1..4], @intCast(shw.end - 4), .big);
    const server_hello = sh[0..shw.end];

    var th = Sha256.init(.{});
    th.update(client_hello[tls.record_header_len..]);
    th.update(server_hello);
    const hello_hash = th.peek();
    const shared = try X25519.scalarmult(srv_sk, client_x25519.public_key);
    const zeroes = [1]u8{0} ** 32;
    const early = Hkdf.extract(&[1]u8{0}, &zeroes);
    const empty = tls.emptyHash(Sha256);
    const hs_derived = tls.hkdfExpandLabel(Hkdf, early, "derived", &empty, 32);
    const hs = Hkdf.extract(&hs_derived, &shared);
    const s_ts = tls.hkdfExpandLabel(Hkdf, hs, "s hs traffic", &hello_hash, 32);
    const key = tls.hkdfExpandLabel(Hkdf, s_ts, "key", "", 16);
    const iv = tls.hkdfExpandLabel(Hkdf, s_ts, "iv", "", 12);

    var w13 = Writer.fixed(&tm.f13);
    putRecord(&w13, .handshake, server_hello);
    putRecord(&w13, .change_cipher_spec, &.{1});
    var buf: [2048]u8 = undefined;
    var body: [2048]u8 = undefined;
    const ee = hsMsg(&buf, .encrypted_extensions, &.{ 0, 0 });
    th.update(ee);
    putEncrypted(&w13, key, iv, 0, .handshake, ee);

    const der = server_cert_der;
    body[0] = 0;
    std.mem.writeInt(u24, body[1..4], @intCast(3 + der.len + 2), .big);
    std.mem.writeInt(u24, body[4..7], @intCast(der.len), .big);
    @memcpy(body[7..][0..der.len], der);
    std.mem.writeInt(u16, body[7 + der.len ..][0..2], 0, .big);
    const cert = hsMsg(&buf, .certificate, body[0 .. 7 + der.len + 2]);
    th.update(cert);
    putEncrypted(&w13, key, iv, 1, .handshake, cert);

    const kp = try Es256.KeyPair.fromSecretKey(try Es256.SecretKey.fromBytes(server_key_der[7..39].*));
    const signed = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";
    var cv_msg: [signed.len + 32]u8 = undefined;
    cv_msg[0..signed.len].* = signed.*;
    cv_msg[signed.len..].* = th.peek();
    var sig_der: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(&cv_msg, null)).toDer(&sig_der);
    std.mem.writeInt(u16, body[0..2], @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big);
    std.mem.writeInt(u16, body[2..4], @intCast(sig.len), .big);
    @memcpy(body[4..][0..sig.len], sig);
    const cv = hsMsg(&buf, .certificate_verify, body[0 .. 4 + sig.len]);
    th.update(cv);
    putEncrypted(&w13, key, iv, 2, .handshake, cv);

    const fin_key = tls.hkdfExpandLabel(Hkdf, s_ts, "finished", "", HmacSha256.key_length);
    const verify_data = tls.hmac(HmacSha256, &th.peek(), fin_key);
    const fin = hsMsg(&buf, .finished, &verify_data);
    putEncrypted(&w13, key, iv, 3, .handshake, fin);
    th.update(fin);

    // The application stream: "ping", a KeyUpdate (nothing requested), "pong"
    // under the next key, close_notify.
    const ap_derived = tls.hkdfExpandLabel(Hkdf, hs, "derived", &empty, 32);
    const master = Hkdf.extract(&ap_derived, &zeroes);
    const s_ap = tls.hkdfExpandLabel(Hkdf, master, "s ap traffic", &th.peek(), 32);
    const akey = tls.hkdfExpandLabel(Hkdf, s_ap, "key", "", 16);
    const aiv = tls.hkdfExpandLabel(Hkdf, s_ap, "iv", "", 12);
    putEncrypted(&w13, akey, aiv, 0, .application_data, "ping");
    const ku = hsMsg(&buf, .key_update, &.{0});
    putEncrypted(&w13, akey, aiv, 1, .handshake, ku);
    const s_ap2 = tls.hkdfExpandLabel(Hkdf, s_ap, "traffic upd", "", 32);
    putEncrypted(&w13, tls.hkdfExpandLabel(Hkdf, s_ap2, "key", "", 16), tls.hkdfExpandLabel(Hkdf, s_ap2, "iv", "", 12), 0, .application_data, "pong");
    putEncrypted(&w13, tls.hkdfExpandLabel(Hkdf, s_ap2, "key", "", 16), tls.hkdfExpandLabel(Hkdf, s_ap2, "iv", "", 12), 1, .alert, &.{ 1, 0 });
    tm.f13_len = w13.end;

    // ── TLS 1.2 (plaintext until the server's Finished, which never comes) ──
    var w12 = Writer.fixed(&tm.f12);
    var m12: [1024]u8 = undefined;
    var bw = Writer.fixed(&body);
    bw.writeInt(u16, 0x0303, .big) catch unreachable;
    bw.writeAll(&server_rand) catch unreachable;
    bw.writeByte(0) catch unreachable; // no session id
    bw.writeInt(u16, @intFromEnum(tls.CipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256), .big) catch unreachable;
    bw.writeByte(0) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .server_hello, body[0..bw.end]));

    bw = Writer.fixed(&body);
    bw.writeInt(u24, @intCast(3 + der.len), .big) catch unreachable;
    bw.writeInt(u24, @intCast(der.len), .big) catch unreachable;
    bw.writeAll(der) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .certificate, body[0..bw.end]));

    var params: [3 + 1 + 32]u8 = undefined;
    params[0] = 3;
    std.mem.writeInt(u16, params[1..3], @intFromEnum(tls.NamedGroup.x25519), .big);
    params[3] = 32;
    params[4..][0..32].* = srv_pub;
    var to_sign: [32 + 32 + params.len]u8 = undefined;
    to_sign[0..32].* = client_rand.*;
    to_sign[32..64].* = server_rand;
    to_sign[64..].* = params;
    const sig12 = (try kp.sign(&to_sign, null)).toDer(&sig_der);
    bw = Writer.fixed(&body);
    bw.writeAll(&params) catch unreachable;
    bw.writeInt(u16, @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big) catch unreachable;
    bw.writeInt(u16, @intCast(sig12.len), .big) catch unreachable;
    bw.writeAll(sig12) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .server_key_exchange, body[0..bw.end]));
    putPlain(&w12, hsMsg(&m12, .server_hello_done, ""));
    tm.f12_len = w12.end;
    tm_ready = true;
}

fn putPlain(w: *Writer, msg: []const u8) void {
    w.writeByte(@intFromEnum(tls.ContentType.handshake)) catch unreachable;
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.writeInt(u16, @intCast(msg.len), .big) catch unreachable;
    w.writeAll(msg) catch unreachable;
}

const FlightMark = Marker(enum {
    genuine_accepted,
    tls13_refused_mac,
    tls13_refused_hello,
    app_refused,
    tls12_took_flight,
    tls12_refused,
    alert,
    truncated,
    decode,
    raw,
});

/// True when `got` differs from the genuine TLS 1.3 flight only in the
/// ignored legacy_version octets of the two cleartext records' headers.
fn sameButVersions(got: []const u8) bool {
    if (got.len != tm.f13_len) return false;
    for (got, tm.f13[0..tm.f13_len], 0..) |a, b, i| {
        if (a == b) continue;
        var ignored = false;
        // Only the two cleartext records: an encrypted record's header is AAD.
        for (tm.f13_records[0..2]) |r| {
            if (i == r + 1 or i == r + 2) ignored = true;
        }
        if (!ignored) return false;
    }
    return true;
}

pub fn fuzzFlight(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try ensureTemplates();
    var buf: [6000]u8 = undefined;
    var kind: enum { f13, f12, alert, raw } = .raw;
    var n: usize = 0;
    if (S != fuzz_driver.Rng) {
        n = src.slice(&buf);
    } else switch (src.valueRangeAtMost(u8, 0, 9)) {
        0...4 => {
            kind = .f13;
            n = damage(src, &buf, tm.f13[0..tm.f13_len]);
        },
        5...7 => {
            kind = .f12;
            n = damage(src, &buf, tm.f12[0..tm.f12_len]);
        },
        8 => {
            kind = .alert;
            const rec = [_]u8{ 0x15, 3, 3, 0, 2, src.value(u8), src.value(u8) };
            n = damage(src, &buf, &rec);
        },
        else => n = src.slice(&buf),
    }
    const o = runClient(buf[0..n], null);
    const err: ?anyerror = if (o.init_err) |e| e else o.read_err;
    const same = kind == .f13 and sameButVersions(buf[0..n]);
    if (err == null) {
        // Established and read to a clean close_notify: only the genuine flight.
        if (!same or o.app_octets != 8) {
            std.debug.print("tlsclient-flight: a flight that is not the genuine one was ACCEPTED (kind {t}, {d} application octets)\n", .{ kind, o.app_octets });
            return error.DamagedFlightAccepted;
        }
        FlightMark.mark(.genuine_accepted);
        return;
    }
    if (same) {
        std.debug.print("tlsclient-flight: the genuine flight was refused: {t}\n", .{err.?});
        return error.GenuineFlightRefused;
    }
    if (o.read_err != null) FlightMark.mark(.app_refused);
    if (o.init_err) |e| switch (e) {
        error.TlsBadRecordMac => FlightMark.mark(.tls13_refused_mac),
        error.TlsAlert => FlightMark.mark(.alert),
        error.TlsConnectionTruncated => FlightMark.mark(.truncated),
        error.TlsDecodeError => FlightMark.mark(.decode),
        else => if (kind == .f13) FlightMark.mark(.tls13_refused_hello),
    };
    switch (kind) {
        .f12 => if (o.written > tm.hello_len) FlightMark.mark(.tls12_took_flight) else FlightMark.mark(.tls12_refused),
        .raw => FlightMark.mark(.raw),
        else => {},
    }
}

fn fuzzFlightSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzFlight(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: a server's first flight, damaged, never panics and is never accepted" {
    try testing.fuzz({}, fuzzFlightSmith, .{});
}

test "fuzz driver: TLSCLIENT_FUZZ (flight)" {
    try fuzz_driver.run(fuzzFlight, .{ .prefix = "TLSCLIENT_FUZZ", .name = "tlsclient-flight", .scale = 10 });
}

test "fuzz harness: flight, 400 seeds, reaches every outcome" {
    try FlightMark.reach(fuzzFlight, "tlsclient-flight", 400);
}

test "the genuine flights: TLS 1.3 is accepted and read to close_notify, TLS 1.2 is taken up to the server's Finished" {
    try ensureTemplates();
    const o13 = runClient(tm.f13[0..tm.f13_len], null);
    try testing.expectEqual(@as(?anyerror, null), o13.init_err);
    try testing.expectEqual(@as(?anyerror, null), o13.read_err);
    try testing.expectEqual(@as(u64, 8), o13.app_octets); // "ping" + "pong", across a KeyUpdate
    const o12 = runClient(tm.f12[0..tm.f12_len], null);
    try testing.expectEqual(@as(?anyerror, error.TlsConnectionTruncated), o12.init_err);
    try testing.expect(o12.written > tm.hello_len);
}
