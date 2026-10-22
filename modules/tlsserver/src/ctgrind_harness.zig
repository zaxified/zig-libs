// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh tlsserver`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-tlsserver`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `hs` — `Server.feed` on the plaintext ClientHello records of recorded
//!    sessions (`interop_vectors.zig`: P-256 over X25519, P-256 over
//!    X25519MLKEM768, P-384, Ed25519, a HelloRetryRequest), up to the
//!    server's first flight. Tainted: every octet `Config.random` draws (the
//!    server random, the ephemeral key-exchange secret, the signing nonce
//!    seed) and the certificate's private key. The server runs the key
//!    exchange, the handshake key schedule, CertificateVerify, its Finished
//!    and seals the flight. The client's encrypted flight is NOT measured:
//!    tainted handshake keys taint what the server decrypts (the client's
//!    Finished, certificate), and parsing that is public work on data the
//!    client sent.
//!  * `app` — `record.Protection` with the traffic secret tainted, per
//!    suite (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305): key and IV
//!    derivation, sealing records and opening them. Opening decrypts, so the
//!    content is tainted too; the RFC 8446 §5.4 padding scan and the AEAD
//!    tag verdict are counted there.
//!  * `ticket` — whole recorded sessions with the session-ticket key (STEK)
//!    tainted: issuing NewSessionTickets (`resume-new`) and resuming one
//!    (`resume`): sealing, then opening and parsing the ticket — whose
//!    content is the tainted plaintext after decryption.
//!
//!  * `ech` — the recorded Go ECH sessions (`go-ech`, `go-ech-hrr`) up to
//!    the first flight with the ECH private key tainted: the HPKE decap
//!    (`hpke`'s own story), the open of the inner hello and the accept
//!    confirmations. The decrypted inner hello is then tainted content:
//!    rebuilding and parsing it (`ech.reconstruct`, `hello.parseClientHello`)
//!    is public work on what the client encrypted, counted as such.
//!
//! The in-file pattern is this module's own files; `tls13`, `aesgcm`,
//! `tlsresume` and std's X25519/ML-KEM/P-256/P-384/Ed25519/HKDF carry their
//! own constant-time story and are counted in the total only.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const tlsresume = @import("tlsresume");
const server_mod = @import("server.zig");
const record = @import("record.zig");
const inbound = @import("inbound.zig");
const vectors = @import("interop_vectors.zig");
const certs = @import("test_certs.zig");

const Server = server_mod.Server;
const memcheck = std.valgrind.memcheck;

const Target = enum { hs, app, ticket, ech };
const Taint = enum { yes, no };

var taint_on = false;

/// `Config.random`: the recorded seed's CSPRNG, every octet it hands out
/// tainted when `taint_rng` is set.
const TaintRng = struct {
    csprng: std.Random.DefaultCsprng,
    taint: bool,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintRng = @ptrCast(@alignCast(ptr));
        self.csprng.fill(buf);
        if (self.taint) memcheck.makeMemUndefined(buf);
    }

    fn random(self: *TaintRng) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

var p256_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var p384_key: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey = undefined;
var ed_key: std.crypto.sign.Ed25519.SecretKey = undefined;
var stek_key: [32]u8 = vectors.stek_key;
var ech_key: [32]u8 = vectors.ech_key;
var ech_config: [128]u8 = undefined;
var ech_buf: [server_mod.ech.bufferLen(8192)]u8 = undefined;

fn clock(_: ?*anyopaque) i64 {
    return vectors.clock_ms;
}

fn caseNamed(name: []const u8) !vectors.Case {
    for (vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, name)) return c;
    }
    return error.NoSuchCase;
}

/// Where the client's plaintext records (ClientHellos, the compatibility
/// ChangeCipherSpec) end in a recording.
fn plaintextPrefix(client: []const u8) usize {
    var at: usize = 0;
    while (at + record.header_len <= client.len) {
        const t = client[at];
        if (t != 0x16 and t != 0x14) break;
        at += record.header_len + std.mem.readInt(u16, client[at + 3 ..][0..2], .big);
    }
    return @min(at, client.len);
}

var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
var out_buf: [64 * 1024]u8 = undefined;
var in_buf: [16 * 1024]u8 = undefined;
var peer: [server_mod.peerBufferLen(4096)]u8 = undefined;

/// Drives a server over `client` (fed whole), printing what it sends.
fn run(v: vectors.Case, client_len: usize, rng_taint: bool, key_taint: bool, stek_taint: bool, ech_taint: bool) !void {
    var chain: [1][]const u8 = undefined;
    var ck: server_mod.CertifiedKey = switch (v.cert) {
        .p256 => blk: {
            chain[0] = &certs.p256_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p256 = &p256_key } };
        },
        .p384 => blk: {
            chain[0] = &certs.p384_cert;
            break :blk .{ .chain = &chain, .key = .{ .ecdsa_p384 = &p384_key } };
        },
        .ed25519 => blk: {
            chain[0] = &certs.ed25519_cert;
            break :blk .{ .chain = &chain, .key = .{ .ed25519 = &ed_key } };
        },
        else => return error.UnsupportedCase,
    };
    _ = &ck;
    p256_key = try .fromBytes(certs.p256_scalar);
    p384_key = try .fromBytes(certs.p384_scalar);
    ed_key = try .fromBytes(certs.ed25519_secret);
    if (key_taint) {
        memcheck.makeMemUndefined(&p256_key.bytes);
        memcheck.makeMemUndefined(&p384_key.bytes);
        memcheck.makeMemUndefined(&ed_key.bytes);
    }

    var suites: [8]record.CipherSuite = undefined;
    for (v.suites, 0..) |s, i| suites[i] = @fromBackingInt(s);
    var rng: TaintRng = .{ .csprng = .init(@splat(v.seed)), .taint = rng_taint };

    stek_key = vectors.stek_key;
    if (stek_taint) memcheck.makeMemUndefined(&stek_key);
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(1, &stek_key, @divFloor(vectors.clock_ms, 1000));
    const stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing) = .{ .ring = &ring };
    const tickets: server_mod.Tickets = .{ .ticketer = stek.ticketer(), .clock = .{ .now_ms = clock } };

    ech_key = vectors.ech_key;
    const ech_public = std.crypto.dh.X25519.recoverPublicKey(ech_key);
    if (ech_taint) memcheck.makeMemUndefined(&ech_key);
    const ech_keys = [_]server_mod.ech.Key{.{ .config = try server_mod.ech.makeConfig(&ech_config, 7, &ech_public, "public.example", 0), .private_key = &ech_key }};
    const ech_cfg: server_mod.ech.Ech = .{ .keys = &ech_keys };
    const cfg: server_mod.Config = .{
        .certificate = .{ .fixed = &ck },
        .cipher_suites = suites[0..v.suites.len],
        .groups = v.groups,
        .alpn_protocols = v.alpn,
        .random = rng.random(),
        .tickets = if (v.tickets) &tickets else null,
        .ech = if (v.ech) &ech_cfg else null,
    };
    var s: Server = .init(&cfg, &joiner, &out_buf);
    defer s.deinit();
    s.setPeerBuffer(&peer);
    s.setEchBuffer(&ech_buf);

    @memcpy(in_buf[0..client_len], v.client[0..client_len]);
    var at: usize = 0;
    while (at < client_len) {
        const r = try s.feed(in_buf[at..client_len]);
        at += r.consumed;
        const sent = s.pendingOutput();
        std.debug.print("ctgrind_result={x}\n", .{sent});
        s.discardOutput(sent.len);
        if (r.event == .need_more) break;
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;
    taint_on = taint == .yes;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .hs => for ([_][]const u8{ "p256-aes256-x25519", "p256-default", "p384", "ed25519", "hrr-p256" }) |name| {
            const v = try caseNamed(name);
            try run(v, plaintextPrefix(v.client), taint_on, taint_on, false, false);
        },
        .app => for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
            var secret: [48]u8 = undefined;
            std.crypto.hash.sha2.Sha384.hash("tlsserver ctgrind traffic secret", &secret, .{});
            const len = suite.hashLen().?;
            if (taint_on) memcheck.makeMemUndefined(secret[0..len]);
            var tx: record.Protection = undefined;
            var rx: record.Protection = undefined;
            try tx.init(suite, secret[0..len]);
            try rx.init(suite, secret[0..len]);
            var buf: [record.header_len + 64 + 1 + 16 + record.tag_len]u8 = undefined;
            for ([_]usize{ 0, 16 }) |pad| {
                const msg = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
                @memcpy(buf[record.header_len..][0..msg.len], msg);
                const rec = try tx.seal(&buf, msg.len, .application_data, pad);
                std.debug.print("ctgrind_result={x}\n", .{rec});
                const opened = try rx.open(rec);
                std.debug.print("ctgrind_result={x}\n", .{opened.content});
            }
            tx.wipe();
            rx.wipe();
        },
        .ticket => for ([_][]const u8{ "resume-new", "resume" }) |name| {
            const v = try caseNamed(name);
            try run(v, v.client.len, false, false, taint_on, false);
        },
        .ech => for ([_][]const u8{ "go-ech", "go-ech-hrr" }) |name| {
            const v = try caseNamed(name);
            try run(v, plaintextPrefix(v.client), false, false, false, taint_on);
        },
    }
}
