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
//!   own Finished, and (2026-10-13) the TLS 1.3 flight after a cookie
//!   HelloRetryRequest. The driver damages 0-3 octets (half of them in the first
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
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
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
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
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
            const begin = std.mem.find(u8, pem, "-----\n").? + 6;
            const end = std.mem.find(u8, pem, "\n-----END").?;
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
    /// The same flight after a cookie HelloRetryRequest (added 2026-10-13):
    /// HRR record first, transcript message_hash(CH1) ‖ HRR ‖ CH2 ‖ ….
    f13h: [6144]u8 = undefined,
    f13h_len: usize = 0,
    f13h_records: [12]usize = undefined,
    f13h_nrecords: usize = 0,
    /// The genuine flight's server application key and IV (for crafted
    /// application records in the regression tests).
    akey: [16]u8 = undefined,
    aiv: [12]u8 = undefined,
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
var info_storage: [16 * 1024]u8 = undefined;
var info: Client.ConnectionInfo = undefined;

fn selectNone(_: ?*anyopaque, _: *const Client.CertificateRequestInfo) ?Client.ClientAuth {
    return null;
}

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
    return runClientHook(input, out_copy, null);
}

/// `runClient`, with `hook` run on the established `sink` before the read.
fn runClientHook(input: []const u8, out_copy: ?*Writer, hook: ?*const fn () void) Outcome {
    @memcpy(in_buf[0..input.len], input);
    var reader = Reader.fixed(&in_buf);
    reader.end = input.len;
    var dw: Writer.Discarding = .init(&out_buf);
    var fw = Writer.fixed(&out_buf);
    const w: *Writer = if (out_copy != null) &fw else &dw.writer;
    // The session view and a client-certificate selector are on (2026-10-13)
    // so the OCSP/SCT, chain-copy and CertificateRequest parsers see the
    // damaged flights too.
    info = .init(&info_storage);
    const opts: Client.Options = .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &tm.entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .connection_info = &info,
        .client_auth_select = .{ .select = selectNone },
    };
    var o: Outcome = .{};
    if (Client.initInto(&sink, &reader, w, opts)) |_| {
        if (hook) |h| h();
        if (sink.reader.discardRemaining()) |n| o.app_octets = n else |e| o.read_err = e;
    } else |e| o.init_err = e;
    o.written = if (out_copy != null) fw.end else dw.fullCount();
    if (out_copy) |c| c.* = fw;
    return o;
}

fn hsMsg(buf: []u8, typ: tls.HandshakeType, body: []const u8) []const u8 {
    buf[0] = @backingInt(typ);
    std.mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
    @memcpy(buf[4..][0..body.len], body);
    return buf[0 .. 4 + body.len];
}

/// Where `putRecord` notes record offsets (the template being built).
var cur_records: *[12]usize = &tm.f13_records;
var cur_nrecords: *usize = &tm.f13_nrecords;

fn putRecord(w: *Writer, ct: tls.ContentType, body: []const u8) void {
    cur_records[cur_nrecords.*] = w.end;
    cur_nrecords.* += 1;
    w.writeByte(@backingInt(ct)) catch unreachable;
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.writeInt(u16, @intCast(body.len), .big) catch unreachable;
    w.writeAll(body) catch unreachable;
}

fn putEncrypted(w: *Writer, key: [16]u8, iv: [12]u8, seq: u64, ct: tls.ContentType, msg: []const u8) void {
    var inner: [2048]u8 = undefined;
    @memcpy(inner[0..msg.len], msg);
    inner[msg.len] = @backingInt(ct);
    const n = msg.len + 1;
    var rec: [2048 + 16]u8 = undefined;
    var header: [5]u8 = .{ @backingInt(tls.ContentType.application_data), 3, 3, 0, 0 };
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
    const client_x25519 = X25519.KeyPair.generateDeterministic(tm.entropy[208..240].*);
    const srv_sk: [32]u8 = @as([32]u8, @splat(0x5c));
    const srv_pub = X25519.recoverPublicKey(srv_sk);
    const server_rand: [32]u8 = @as([32]u8, @splat(0x77));

    // ── TLS 1.3 ─────────────────────────────────────────────────────────────
    var sh: [128]u8 = undefined;
    var shw = Writer.fixed(&sh);
    shw.writeByte(@backingInt(tls.HandshakeType.server_hello)) catch unreachable;
    shw.writeInt(u24, 0, .big) catch unreachable; // patched
    shw.writeInt(u16, 0x0303, .big) catch unreachable;
    shw.writeAll(&server_rand) catch unreachable;
    shw.writeByte(32) catch unreachable;
    shw.writeAll(session_echo) catch unreachable;
    shw.writeInt(u16, @backingInt(tls.CipherSuite.AES_128_GCM_SHA256), .big) catch unreachable;
    shw.writeByte(0) catch unreachable;
    shw.writeInt(u16, 6 + 4 + 4 + 32, .big) catch unreachable;
    shw.writeInt(u16, @backingInt(tls.ExtensionType.supported_versions), .big) catch unreachable;
    shw.writeInt(u16, 2, .big) catch unreachable;
    shw.writeInt(u16, 0x0304, .big) catch unreachable;
    shw.writeInt(u16, @backingInt(tls.ExtensionType.key_share), .big) catch unreachable;
    shw.writeInt(u16, 4 + 32, .big) catch unreachable;
    shw.writeInt(u16, @backingInt(tls.NamedGroup.x25519), .big) catch unreachable;
    shw.writeInt(u16, 32, .big) catch unreachable;
    shw.writeAll(&srv_pub) catch unreachable;
    std.mem.writeInt(u24, sh[1..4], @intCast(shw.end - 4), .big);
    const server_hello = sh[0..shw.end];

    cur_records = &tm.f13_records;
    cur_nrecords = &tm.f13_nrecords;
    var th0 = Sha256.init(.{});
    th0.update(client_hello[tls.record_header_len..]);
    tm.f13_len = try buildFlight13(&tm.f13, "", th0, server_hello, srv_sk, client_x25519.public_key);

    // The same after a cookie HRR: the client's two hellos, then the flight
    // over message_hash(CH1) ‖ HRR ‖ CH2.
    {
        var hrr_buf: [256]u8 = undefined;
        var hw = Writer.fixed(&hrr_buf);
        const cookie = "fuzz-cookie-0123";
        hw.writeAll(&.{ 22, 3, 3 }) catch unreachable;
        hw.writeInt(u16, 0, .big) catch unreachable; // patched
        hw.writeByte(@backingInt(tls.HandshakeType.server_hello)) catch unreachable;
        hw.writeInt(u24, 0, .big) catch unreachable; // patched
        hw.writeInt(u16, 0x0303, .big) catch unreachable;
        hw.writeAll(&tls.hello_retry_request_sequence) catch unreachable;
        hw.writeByte(32) catch unreachable;
        hw.writeAll(session_echo) catch unreachable;
        hw.writeInt(u16, @backingInt(tls.CipherSuite.AES_128_GCM_SHA256), .big) catch unreachable;
        hw.writeByte(0) catch unreachable;
        hw.writeInt(u16, 6 + 4 + 2 + cookie.len, .big) catch unreachable;
        hw.writeAll(&.{ 0, 43, 0, 2, 3, 4 }) catch unreachable; // supported_versions: 1.3
        hw.writeInt(u16, @backingInt(tls.ExtensionType.cookie), .big) catch unreachable;
        hw.writeInt(u16, 2 + cookie.len, .big) catch unreachable;
        hw.writeInt(u16, cookie.len, .big) catch unreachable;
        hw.writeAll(cookie) catch unreachable;
        std.mem.writeInt(u16, hrr_buf[3..5], @intCast(hw.end - 5), .big);
        std.mem.writeInt(u24, hrr_buf[6..9], @intCast(hw.end - 9), .big);
        const hrr_record = hrr_buf[0..hw.end];
        var two: Writer = undefined;
        const e2 = runClient(hrr_record, &two);
        try testing.expectEqual(@as(?anyerror, error.TlsConnectionTruncated), e2.init_err);
        const ch2 = two.buffered()[tm.hello_len + tls.record_header_len ..];
        var h1: [32]u8 = undefined;
        Sha256.hash(client_hello[tls.record_header_len..], &h1, .{});
        var thh = Sha256.init(.{});
        thh.update(&.{ @backingInt(tls.HandshakeType.message_hash), 0, 0, 32 });
        thh.update(&h1);
        thh.update(hrr_record[tls.record_header_len..]);
        thh.update(ch2);
        cur_records = &tm.f13h_records;
        cur_nrecords = &tm.f13h_nrecords;
        tm.f13h_records[0] = 0;
        tm.f13h_nrecords = 1;
        tm.f13h_len = try buildFlight13(&tm.f13h, hrr_record, thh, server_hello, srv_sk, client_x25519.public_key);
        cur_records = &tm.f13_records;
        cur_nrecords = &tm.f13_nrecords;
    }

    // ── TLS 1.2 (plaintext until the server's Finished, which never comes) ──
    var body: [2048]u8 = undefined;
    const der = server_cert_der;
    const kp = try Es256.KeyPair.fromSecretKey(try Es256.SecretKey.fromBytes(server_key_der[7..39].*));
    var sig_der: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    var w12 = Writer.fixed(&tm.f12);
    var m12: [1024]u8 = undefined;
    var bw = Writer.fixed(&body);
    bw.writeInt(u16, 0x0303, .big) catch unreachable;
    bw.writeAll(&server_rand) catch unreachable;
    bw.writeByte(0) catch unreachable; // no session id
    // The certificate's key is P-256, so the suite is ECDHE_ECDSA (RFC 8422
    // §5.3; the client checks the pairing since 2026-10-13 -- std accepted
    // ECDHE_RSA here).
    bw.writeInt(u16, @backingInt(tls.CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), .big) catch unreachable;
    bw.writeByte(0) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .server_hello, body[0..bw.end]));

    bw = Writer.fixed(&body);
    bw.writeInt(u24, @intCast(3 + der.len), .big) catch unreachable;
    bw.writeInt(u24, @intCast(der.len), .big) catch unreachable;
    bw.writeAll(der) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .certificate, body[0..bw.end]));

    var params: [3 + 1 + 32]u8 = undefined;
    params[0] = 3;
    std.mem.writeInt(u16, params[1..3], @backingInt(tls.NamedGroup.x25519), .big);
    params[3] = 32;
    params[4..][0..32].* = srv_pub;
    var to_sign: [32 + 32 + params.len]u8 = undefined;
    to_sign[0..32].* = client_rand.*;
    to_sign[32..64].* = server_rand;
    to_sign[64..].* = params;
    const sig12 = (try kp.sign(&to_sign, null)).toDer(&sig_der);
    bw = Writer.fixed(&body);
    bw.writeAll(&params) catch unreachable;
    bw.writeInt(u16, @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big) catch unreachable;
    bw.writeInt(u16, @intCast(sig12.len), .big) catch unreachable;
    bw.writeAll(sig12) catch unreachable;
    putPlain(&w12, hsMsg(&m12, .server_key_exchange, body[0..bw.end]));
    putPlain(&w12, hsMsg(&m12, .server_hello_done, ""));
    tm.f12_len = w12.end;
    tm_ready = true;
}

/// The TLS 1.3 server flight after `prefix` (records already sent) over the
/// transcript `th0` (everything before the ServerHello): ServerHello, CCS,
/// EncryptedExtensions, Certificate, CertificateVerify, Finished, then the
/// application stream. Returns its length in `out`.
fn buildFlight13(out: []u8, prefix: []const u8, th0: Sha256, server_hello: []const u8, srv_sk: [32]u8, client_x25519_pub: [32]u8) !usize {
    var th = th0;
    th.update(server_hello);
    const hello_hash = th.peek();
    const shared = try X25519.scalarmult(srv_sk, client_x25519_pub);
    const zeroes = @as([32]u8, @splat(0));
    const early = Hkdf.extract(&[1]u8{0}, &zeroes);
    const empty = tls.emptyHash(Sha256);
    const hs_derived = tls.hkdfExpandLabel(Hkdf, early, "derived", &empty, 32);
    const hs = Hkdf.extract(&hs_derived, &shared);
    const s_ts = tls.hkdfExpandLabel(Hkdf, hs, "s hs traffic", &hello_hash, 32);
    const key = tls.hkdfExpandLabel(Hkdf, s_ts, "key", "", 16);
    const iv = tls.hkdfExpandLabel(Hkdf, s_ts, "iv", "", 12);

    var w13 = Writer.fixed(out);
    w13.writeAll(prefix) catch unreachable;
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
    const signed = strRepeat(" ", 64) ++ "TLS 1.3, server CertificateVerify\x00";
    var cv_msg: [signed.len + 32]u8 = undefined;
    cv_msg[0..signed.len].* = signed.*;
    cv_msg[signed.len..].* = th.peek();
    var sig_der: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(&cv_msg, null)).toDer(&sig_der);
    std.mem.writeInt(u16, body[0..2], @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big);
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
    if (prefix.len == 0) { // the plain flight's keys, not the HRR variant's
        tm.akey = akey;
        tm.aiv = aiv;
    }
    putEncrypted(&w13, akey, aiv, 0, .application_data, "ping");
    const ku = hsMsg(&buf, .key_update, &.{0});
    putEncrypted(&w13, akey, aiv, 1, .handshake, ku);
    const s_ap2 = tls.hkdfExpandLabel(Hkdf, s_ap, "traffic upd", "", 32);
    putEncrypted(&w13, tls.hkdfExpandLabel(Hkdf, s_ap2, "key", "", 16), tls.hkdfExpandLabel(Hkdf, s_ap2, "iv", "", 12), 0, .application_data, "pong");
    putEncrypted(&w13, tls.hkdfExpandLabel(Hkdf, s_ap2, "key", "", 16), tls.hkdfExpandLabel(Hkdf, s_ap2, "iv", "", 12), 1, .alert, &.{ 1, 0 });
    return w13.end;
}

fn putPlain(w: *Writer, msg: []const u8) void {
    w.writeByte(@backingInt(tls.ContentType.handshake)) catch unreachable;
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.writeInt(u16, @intCast(msg.len), .big) catch unreachable;
    w.writeAll(msg) catch unreachable;
}

const FlightMark = Marker(enum {
    genuine_accepted,
    hrr_genuine_accepted,
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

/// True when `got` differs from a genuine TLS 1.3 flight only in the
/// ignored legacy_version octets of its cleartext records' headers (the
/// first `clear` records: ServerHello and CCS, with an HRR before them).
fn sameButVersions(got: []const u8, want: []const u8, records: []const usize, clear: usize) bool {
    if (got.len != want.len) return false;
    for (got, want, 0..) |a, b, i| {
        if (a == b) continue;
        var ignored = false;
        // Only cleartext records: an encrypted record's header is AAD.
        for (records[0..clear]) |r| {
            if (i == r + 1 or i == r + 2) ignored = true;
        }
        if (!ignored) return false;
    }
    return true;
}

pub fn fuzzFlight(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try ensureTemplates();
    var buf: [6144]u8 = undefined;
    var kind: enum { f13, f13h, f12, alert, raw } = .raw;
    var n: usize = 0;
    if (S != fuzz_driver.Rng) {
        n = src.slice(&buf);
    } else switch (src.valueRangeAtMost(u8, 0, 11)) {
        0...4 => {
            kind = .f13;
            n = damage(src, &buf, tm.f13[0..tm.f13_len]);
        },
        10, 11 => {
            kind = .f13h;
            n = damage(src, &buf, tm.f13h[0..tm.f13h_len]);
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
    const same = switch (kind) {
        .f13 => sameButVersions(buf[0..n], tm.f13[0..tm.f13_len], &tm.f13_records, 2),
        .f13h => sameButVersions(buf[0..n], tm.f13h[0..tm.f13h_len], &tm.f13h_records, 3),
        else => false,
    };
    if (err == null) {
        // Established and read to a clean close_notify: only the genuine flight.
        if (!same or o.app_octets != 8) {
            std.debug.print("tlsclient-flight: a flight that is not the genuine one was ACCEPTED (kind {t}, {d} application octets)\n", .{ kind, o.app_octets });
            return error.DamagedFlightAccepted;
        }
        if (kind == .f13h) FlightMark.mark(.hrr_genuine_accepted) else FlightMark.mark(.genuine_accepted);
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
        else => if (kind == .f13 or kind == .f13h) FlightMark.mark(.tls13_refused_hello),
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
    // The same flight after a cookie HelloRetryRequest.
    const o13h = runClient(tm.f13h[0..tm.f13h_len], null);
    try testing.expectEqual(@as(?anyerror, null), o13h.init_err);
    try testing.expectEqual(@as(u64, 8), o13h.app_octets);
    try testing.expect(sink.hello_retry_request);
    const o12 = runClient(tm.f12[0..tm.f12_len], null);
    try testing.expectEqual(@as(?anyerror, error.TlsConnectionTruncated), o12.init_err);
    try testing.expect(o12.written > tm.hello_len);
}

test "a short or all-zero application record ends the read with an error, not an underflow (std bugs, TLSCLIENT_FUZZ 2026-10-13)" {
    try ensureTemplates();
    // The genuine handshake, up to its first application record (index 6:
    // SH, CCS, EE, Certificate, CertificateVerify, Finished).
    const hs_end = tm.f13_records[6];
    var input: [4096]u8 = undefined;
    @memcpy(input[0..hs_end], tm.f13[0..hs_end]);
    // A record shorter than the AEAD tag.
    const short = [_]u8{ 23, 3, 3, 0, 5, 1, 2, 3, 4, 5 };
    @memcpy(input[hs_end..][0..short.len], &short);
    const o1 = runClient(input[0 .. hs_end + short.len], null);
    try testing.expectEqual(@as(?anyerror, null), o1.init_err);
    // The Reader reports ReadFailed; the cause is kept in `read_err`.
    try testing.expectEqual(@as(?anyerror, error.ReadFailed), o1.read_err);
    try testing.expectEqual(@as(?Client.ReadError, error.TlsBadLength), sink.read_err);
    // A record whose plaintext is all zeros: authentic, but no content type.
    var w = Writer.fixed(input[hs_end..]);
    var rec_store: [12]usize = undefined;
    var nrec: usize = 0;
    cur_records = &rec_store;
    cur_nrecords = &nrec;
    defer {
        cur_records = &tm.f13_records;
        cur_nrecords = &tm.f13_nrecords;
    }
    var zeros: [8]u8 = @splat(0);
    putEncryptedRaw(&w, tm.akey, tm.aiv, 0, &zeros);
    const o2 = runClient(input[0 .. hs_end + w.end], null);
    try testing.expectEqual(@as(?anyerror, null), o2.init_err);
    try testing.expectEqual(@as(?anyerror, error.ReadFailed), o2.read_err);
    try testing.expectEqual(@as(?Client.ReadError, error.TlsUnexpectedMessage), sink.read_err);
}

/// The inner plaintext of a crafted post-handshake record: `msg` then the
/// handshake content type; returns the client's read error after it.
fn postHandshakeRecordError(msg: []const u8) !?Client.ReadError {
    try ensureTemplates();
    const hs_end = tm.f13_records[6];
    var input: [4096]u8 = undefined;
    @memcpy(input[0..hs_end], tm.f13[0..hs_end]);
    var inner: [64]u8 = undefined;
    @memcpy(inner[0..msg.len], msg);
    inner[msg.len] = @backingInt(tls.ContentType.handshake);
    var w = Writer.fixed(input[hs_end..]);
    var rec_store: [12]usize = undefined;
    var nrec: usize = 0;
    cur_records = &rec_store;
    cur_nrecords = &nrec;
    defer {
        cur_records = &tm.f13_records;
        cur_nrecords = &tm.f13_nrecords;
    }
    putEncryptedRaw(&w, tm.akey, tm.aiv, 0, inner[0 .. msg.len + 1]);
    const o = runClient(input[0 .. hs_end + w.end], null);
    try testing.expectEqual(@as(?anyerror, null), o.init_err);
    try testing.expectEqual(@as(?anyerror, error.ReadFailed), o.read_err);
    return sink.read_err;
}

test "a KeyUpdate with an empty or oversized body is a decode_error before any key is switched (std 0.17 check, ours missed it)" {
    // Negative control (fix reverted): body-less KeyUpdate read handshake[0]
    // out of bounds -- a panic in safe builds, UB in ReleaseFast.
    try testing.expectEqual(@as(?Client.ReadError, error.TlsDecodeError), try postHandshakeRecordError(&.{ 0x18, 0, 0, 0 }));
    try testing.expectEqual(@as(?Client.ReadError, error.TlsDecodeError), try postHandshakeRecordError(&.{ 0x18, 0, 0, 2, 0, 0 }));
    // Keys untouched: the failing record did not advance the read key.
    try testing.expectEqual(@as(u64, 1), sink.read_seq);
}

test "a handshake record shorter than a message header or empty is a decode_error, not an out-of-bounds read" {
    // Negative control (fix reverted): empty fragment indexed cleartext[0]
    // beyond the (zero-length) slice; 3 octets read cleartext[1..][0..3].
    try testing.expectEqual(@as(?Client.ReadError, error.TlsDecodeError), try postHandshakeRecordError(&.{}));
    try testing.expectEqual(@as(?Client.ReadError, error.TlsDecodeError), try postHandshakeRecordError(&.{ 0x18, 0, 0 }));
    // A second message with a truncated header after a valid KeyUpdate.
    try testing.expectEqual(@as(?Client.ReadError, error.TlsDecodeError), try postHandshakeRecordError(&.{ 0x18, 0, 0, 1, 0, 0x18, 0 }));
}

fn makeTls12() void {
    // The 1.3 session `sink` becomes a TLS 1.2 AES-128-GCM one with known keys.
    const Cipher = @FieldType(tls.ApplicationCipher, "AES_128_GCM_SHA256");
    sink.application_cipher = .{ .AES_128_GCM_SHA256 = @unionInit(Cipher, "tls_1_2", .{
        .client_write_MAC_key = @splat(0),
        .server_write_MAC_key = @splat(0),
        .client_write_key = @splat(0x11),
        .server_write_key = @splat(0x22),
        .client_write_IV = @splat(0x33),
        .server_write_IV = @splat(0x44),
        .client_salt = @splat(0),
    }) };
    sink.tls_version = .tls_1_2;
    sink.read_seq = 0;
}

test "a KeyUpdate on a TLS 1.2 connection is an unexpected_message, not a read of the inactive tls_1_3 union field" {
    // Negative control (fix reverted): `p.tls_1_3` while `tls_1_2` is active --
    // a panic in safe builds (and the decrypt of the cipher below would work).
    try ensureTemplates();
    const hs_end = tm.f13_records[6];
    var input: [4096]u8 = undefined;
    @memcpy(input[0..hs_end], tm.f13[0..hs_end]);
    // One TLS 1.2 AES-128-GCM handshake record: explicit nonce, ciphertext, tag.
    const key: [16]u8 = @splat(0x22);
    const explicit: [8]u8 = @splat(0x55);
    const plain = [_]u8{ 0x18, 0, 0, 1, 0 };
    var nonce: [12]u8 = undefined;
    nonce[0..4].* = @as([4]u8, @splat(0x44));
    nonce[4..].* = explicit;
    var ad: [13]u8 = undefined;
    std.mem.writeInt(u64, ad[0..8], 0, .big);
    ad[8..11].* = .{ @backingInt(tls.ContentType.handshake), 3, 3 };
    std.mem.writeInt(u16, ad[11..13], plain.len, .big);
    var ct: [plain.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aead.encrypt(&ct, &tag, &plain, &ad, nonce, key);
    var w = Writer.fixed(input[hs_end..]);
    var body: [8 + plain.len + 16]u8 = undefined;
    body[0..8].* = explicit;
    body[8..][0..plain.len].* = ct;
    body[8 + plain.len ..][0..16].* = tag;
    w.writeAll(&.{ @backingInt(tls.ContentType.handshake), 3, 3 }) catch unreachable;
    w.writeInt(u16, body.len, .big) catch unreachable;
    w.writeAll(&body) catch unreachable;
    const o = runClientHook(input[0 .. hs_end + w.end], null, makeTls12);
    try testing.expectEqual(@as(?anyerror, null), o.init_err);
    try testing.expectEqual(@as(?anyerror, error.ReadFailed), o.read_err);
    try testing.expectEqual(@as(?Client.ReadError, error.TlsUnexpectedMessage), sink.read_err);
    // Control: the same record is authentic -- a plain TLS 1.2 KeyUpdate dies on
    // the type, not on a MAC failure (read_seq advanced past it).
    try testing.expectEqual(@as(u64, 1), sink.read_seq);
}

var big_in: [2 * Client.min_buffer_len]u8 = undefined;
var big_inner: [1 << 14 | 1]u8 = undefined;
var big_rec: [(1 << 14 | 1) + 16]u8 = undefined;

test "a full record with the caller's plaintext still buffered is record_overflow, not a write past read_buffer (audit 2026-10-19)" {
    // `readIndirect` decrypts a record in place after the plaintext the caller
    // has not consumed yet. std asserted room for the whole ciphertext there:
    // a `peek` of more than one record's worth, on a `min_buffer_len` read
    // buffer, met by a legal 2^14-octet record panicked in safe builds and
    // wrote past the buffer in ReleaseFast. Negative control (fix reverted):
    // the assert in `rebase` fires on the peek below.
    try ensureTemplates();
    const hs_end = tm.f13_records[6];
    @memcpy(big_in[0..hs_end], tm.f13[0..hs_end]);
    var w = Writer.fixed(big_in[hs_end..]);
    var rec_store: [12]usize = undefined;
    var nrec: usize = 0;
    cur_records = &rec_store;
    cur_nrecords = &nrec;
    defer {
        cur_records = &tm.f13_records;
        cur_nrecords = &tm.f13_nrecords;
    }
    // Record 0: 300 octets the caller keeps buffered.
    const small: [300]u8 = @splat('a');
    putEncrypted(&w, tm.akey, tm.aiv, 0, .application_data, &small);
    // Record 1: a legal full record, 2^14 octets of data + the content type.
    @memset(big_inner[0 .. 1 << 14], 'b');
    big_inner[1 << 14] = @backingInt(tls.ContentType.application_data);
    var header: [5]u8 = .{ @backingInt(tls.ContentType.application_data), 3, 3, 0, 0 };
    std.mem.writeInt(u16, header[3..5], big_rec.len, .big);
    var nonce = tm.aiv;
    nonce[11] ^= 1; // sequence 1
    Aead.encrypt(big_rec[0..big_inner.len], big_rec[big_inner.len..][0..16], &big_inner, &header, nonce, tm.akey);
    putRecord(&w, .application_data, &big_rec);

    var reader = Reader.fixed(big_in[0 .. hs_end + w.end]);
    var dw: Writer.Discarding = .init(&out_buf);
    try Client.initInto(&sink, &reader, &dw.writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &tm.entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    });
    // Room after 300 buffered octets: min_buffer_len - 300 < 2^14 + 1.
    comptime std.debug.assert(Client.min_buffer_len - small.len < big_inner.len);
    try testing.expectError(error.ReadFailed, sink.reader.peek(small.len + 1));
    try testing.expectEqual(@as(?Client.ReadError, error.TlsRecordOverflow), sink.read_err);
    // Control: the same stream read without holding the first record back
    // delivers every octet (the full record itself is accepted).
    var reader2 = Reader.fixed(big_in[0 .. hs_end + w.end]);
    try Client.initInto(&sink, &reader2, &dw.writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &tm.entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .allow_truncation_attacks = true,
    });
    var got: usize = 0;
    while (sink.reader.peekGreedy(1)) |b| {
        got += b.len;
        sink.reader.toss(b.len);
    } else |e| {
        try testing.expectEqual(error.EndOfStream, e);
    }
    try testing.expectEqual(small.len + (1 << 14), got);
}

/// One TLS 1.3 record over the raw inner plaintext `inner` (content type and
/// padding included by the caller).
fn putEncryptedRaw(w: *Writer, key: [16]u8, iv: [12]u8, seq: u64, inner: []const u8) void {
    var rec: [2048 + 16]u8 = undefined;
    var header: [5]u8 = .{ @backingInt(tls.ContentType.application_data), 3, 3, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(inner.len + 16), .big);
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (nonce[4..], seq_be) |*b, sb| b.* ^= sb;
    Aead.encrypt(rec[0..inner.len], rec[inner.len..][0..16], inner, &header, nonce, key);
    putRecord(w, .application_data, rec[0 .. inner.len + 16]);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
