// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh tlsclient`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-tlsclient`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `kex` — `Client.initInto` reading a canned TLS 1.3 ServerHello
//!    (x25519, TLS_AES_128_GCM_SHA256; built as `stackprobe_test.zig` builds
//!    it). Tainted: the key-share secrets in `Options.entropy` (bytes
//!    64..240: ML-KEM-768, P-256, P-384, X25519 seeds; the client random and
//!    legacy session id in 0..64 go out in the clear and stay defined). The
//!    client generates every key share, runs the X25519 exchange and derives
//!    the handshake key schedule, then fails on the truncated input. The
//!    encrypted part of the flight is NOT measured: tainting the handshake
//!    keys taints the decrypted server messages (certificate, extensions),
//!    and the client parses those as any TLS client must -- hundreds of
//!    contexts that say nothing about secrets (measured 2026-10-10: 696).
//!  * `cv` — `Client.signCertificateVerify` (the module's TLS 1.3
//!    client-certificate addition) with the client private key tainted, for
//!    all three key types (P-256, P-384, Ed25519).
//!
//! The in-file pattern is this module's own files; std's X25519/ML-KEM/
//! P-256/P-384/AES-GCM/HKDF carry their own constant-time story and are
//! counted in the total only.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const Client = @import("Client.zig");

const tls = std.crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacT = std.crypto.auth.hmac.sha2.HmacSha256;
const K = std.crypto.kdf.hkdf.Hkdf(HmacT);
const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const Target = enum { kex, cv };
const Taint = enum { yes, no };

fn derive(comptime tag: []const u8, comptime len: usize) [len]u8 {
    var out: [(len + 63) / 64 * 64]u8 = undefined;
    var i: usize = 0;
    while (i * 64 < out.len) : (i += 1) {
        Sha512.hash(tag ++ &[_]u8{@intCast(i)}, out[i * 64 ..][0..64], .{});
    }
    return out[0..len].*;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

// ── the canned server flight (as `stackprobe_test.zig` builds it) ───────────

var entropy: [Client.Options.entropy_len]u8 = undefined;
var in_buf: [Client.min_buffer_len]u8 = undefined;
var in_len: usize = 0;
/// Where the ServerHello record ends inside the full flight.
var hello_len: usize = 0;
var out_buf: [8192]u8 = undefined;
var read_buf: [Client.min_buffer_len]u8 = undefined;
var write_buf: [Client.min_buffer_len]u8 = undefined;
var in_reader: Reader = undefined;
var out_writer: Writer = undefined;
var client: Client = undefined;

fn callInit() !void {
    in_reader = Reader.fixed(&in_buf);
    in_reader.end = in_len;
    out_writer = Writer.fixed(&out_buf);
    try Client.initInto(&client, &in_reader, &out_writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    });
}

fn putBytes(p: *usize, bytes: []const u8) void {
    @memcpy(in_buf[p.*..][0..bytes.len], bytes);
    p.* += bytes.len;
}

fn putInt(comptime T: type, p: *usize, v: T) void {
    std.mem.writeInt(T, in_buf[p.*..][0..@sizeOf(T)], v, .big);
    p.* += @sizeOf(T);
}

fn buildServerHello(share: []const u8) void {
    var p: usize = 5;
    in_buf[0..3].* = .{ 0x16, 3, 3 };
    in_buf[p] = 2; // server_hello
    p += 4;
    putInt(u16, &p, 0x0303);
    putBytes(&p, &derive("tls-server-random", 32));
    in_buf[p] = 32;
    p += 1;
    putBytes(&p, entropy[32..64]); // legacy_session_id echo
    putInt(u16, &p, @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256));
    in_buf[p] = 0;
    p += 1;
    putInt(u16, &p, @intCast(6 + 4 + 4 + share.len));
    putInt(u16, &p, @intFromEnum(tls.ExtensionType.supported_versions));
    putInt(u16, &p, 2);
    putInt(u16, &p, 0x0304);
    putInt(u16, &p, @intFromEnum(tls.ExtensionType.key_share));
    putInt(u16, &p, @intCast(4 + share.len));
    putInt(u16, &p, @intFromEnum(tls.NamedGroup.x25519));
    putInt(u16, &p, @intCast(share.len));
    putBytes(&p, share);
    std.mem.writeInt(u24, in_buf[6..9], @intCast(p - 9), .big);
    std.mem.writeInt(u16, in_buf[3..5], @intCast(p - 5), .big);
    in_len = p;
}

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

fn hsMsg(buf: []u8, typ: tls.HandshakeType, body: []const u8) []const u8 {
    buf[0] = @intFromEnum(typ);
    std.mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
    @memcpy(buf[4..][0..body.len], body);
    return buf[0 .. 4 + body.len];
}

fn appendRecord(key: [Aead.key_length]u8, iv: [Aead.nonce_length]u8, seq: u64, msg: []const u8) void {
    var pt: [2048]u8 = undefined;
    @memcpy(pt[0..msg.len], msg);
    pt[msg.len] = @intFromEnum(tls.ContentType.handshake);
    const inner = pt[0 .. msg.len + 1];
    const rec = in_buf[in_len..];
    rec[0..3].* = .{ @intFromEnum(tls.ContentType.application_data), 3, 3 };
    std.mem.writeInt(u16, rec[3..5], @intCast(inner.len + Aead.tag_length), .big);
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (nonce[nonce.len - 8 ..], seq_be) |*b, s| b.* ^= s;
    Aead.encrypt(rec[5..][0..inner.len], rec[5 + inner.len ..][0..Aead.tag_length], inner, rec[0..5], nonce, key);
    in_len += 5 + inner.len + Aead.tag_length;
}

/// Builds the whole server flight in `in_buf` from an untainted pass.
fn buildFlight() !void {
    const srv_sk = derive("tls-server-x25519", 32);
    const srv_pub = try X25519.recoverPublicKey(srv_sk);
    const cli = try X25519.KeyPair.generateDeterministic(entropy[208..240].*);
    const shared = try X25519.scalarmult(srv_sk, cli.public_key);
    buildServerHello(&srv_pub);
    hello_len = in_len;

    // Capture the ClientHello: this run ends on the truncated input.
    if (callInit()) |_| return error.UnexpectedSuccess else |e| if (e != error.TlsConnectionTruncated) return e;
    var th = Sha256.init(.{});
    th.update(out_writer.buffered()[tls.record_header_len..]);
    th.update(in_buf[tls.record_header_len..in_len]);

    const dl = Sha256.digest_length;
    const zeroes = [1]u8{0} ** dl;
    const early = K.extract(&[1]u8{0}, &zeroes);
    const empty = tls.emptyHash(Sha256);
    const hs_derived = tls.hkdfExpandLabel(K, early, "derived", &empty, dl);
    const hs = K.extract(&hs_derived, &shared);
    const hello_hash = th.peek();
    const s_ts = tls.hkdfExpandLabel(K, hs, "s hs traffic", &hello_hash, dl);
    const key = tls.hkdfExpandLabel(K, s_ts, "key", "", Aead.key_length);
    const iv = tls.hkdfExpandLabel(K, s_ts, "iv", "", Aead.nonce_length);

    var buf: [2048]u8 = undefined;
    var body: [2048]u8 = undefined;
    putBytes(&in_len, &.{ @intFromEnum(tls.ContentType.change_cipher_spec), 3, 3, 0, 1, 1 });

    const ee = hsMsg(&buf, .encrypted_extensions, &.{ 0, 0 });
    th.update(ee);
    appendRecord(key, iv, 0, ee);

    const der = server_cert_der;
    body[0] = 0;
    std.mem.writeInt(u24, body[1..4], @intCast(3 + der.len + 2), .big);
    std.mem.writeInt(u24, body[4..7], @intCast(der.len), .big);
    @memcpy(body[7..][0..der.len], der);
    std.mem.writeInt(u16, body[7 + der.len ..][0..2], 0, .big);
    const cert = hsMsg(&buf, .certificate, body[0 .. 7 + der.len + 2]);
    th.update(cert);
    appendRecord(key, iv, 1, cert);

    const kp = try Es256.KeyPair.fromSecretKey(try Es256.SecretKey.fromBytes(server_key_der[7..39].*));
    const signed = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";
    var cv_msg: [signed.len + dl]u8 = undefined;
    cv_msg[0..signed.len].* = signed.*;
    cv_msg[signed.len..].* = th.peek();
    var sig_der: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(&cv_msg, null)).toDer(&sig_der);
    std.mem.writeInt(u16, body[0..2], @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big);
    std.mem.writeInt(u16, body[2..4], @intCast(sig.len), .big);
    @memcpy(body[4..][0..sig.len], sig);
    const cv = hsMsg(&buf, .certificate_verify, body[0 .. 4 + sig.len]);
    th.update(cv);
    appendRecord(key, iv, 2, cv);

    const fin_key = tls.hkdfExpandLabel(K, s_ts, "finished", "", HmacT.key_length);
    const verify_data = tls.hmac(HmacT, &th.peek(), fin_key);
    const fin = hsMsg(&buf, .finished, &verify_data);
    appendRecord(key, iv, 3, fin);

    // Reach: the untainted flight is accepted.
    try callInit();
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .kex => {
            entropy = derive("tls-kex-entropy", Client.Options.entropy_len);
            try buildFlight();
            // Measured: the ServerHello alone. Bytes 0..64 of the entropy are
            // the client random and the legacy session id, both sent in the
            // clear; 64..240 are the ML-KEM, P-256, P-384 and X25519 secrets.
            in_len = hello_len;
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(entropy[64..]);
            entropy = reloadVolatile(entropy.len, &entropy);
            if (callInit()) |_| return error.UnexpectedSuccess else |e| if (e != error.TlsConnectionTruncated) return e;
            // The key shares the client sent (derived from the secrets).
            std.debug.print("ctgrind_result={x}\n", .{out_writer.buffered()});
        },
        .cv => {
            const msg = " " ** 64 ++ "TLS 1.3, client CertificateVerify\x00" ++ derive("transcript", 32);
            const p256 = Client.ClientAuth.PrivateKey{ .ecdsa_secp256r1_sha256 = (try Es256.KeyPair.generateDeterministic(derive("p256", 32))).secret_key.bytes };
            const p384 = Client.ClientAuth.PrivateKey{ .ecdsa_secp384r1_sha384 = (try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generateDeterministic(derive("p384", 48))).secret_key.bytes };
            const ed = Client.ClientAuth.PrivateKey{ .ed25519 = derive("ed25519", 32) };
            for ([_]Client.ClientAuth.PrivateKey{ p256, p384, ed }) |k0| {
                var k = k0;
                if (taint == .yes) switch (k) {
                    inline else => |*raw| std.valgrind.memcheck.makeMemUndefined(raw),
                };
                var out: [160]u8 = undefined;
                const sig = try Client.signCertificateVerify(&out, &k, msg);
                std.debug.print("ctgrind_result={x}\n", .{sig});
            }
        },
    }
}
