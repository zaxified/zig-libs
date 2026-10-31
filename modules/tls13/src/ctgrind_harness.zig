// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time
//! contract". Run it through `../../../scripts/checks/ctgrind.sh tls13`, which
//! builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-tls13`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What is tainted (and what is not)
//!
//!  * `ks` — the WHOLE RFC 8446 §7.1 schedule, SHA-256 and SHA-384, over a
//!    tainted PSK and a tainted (EC)DHE shared secret: early secret, binder
//!    key, PSK binder, handshake secret, both handshake traffic secrets,
//!    master secret, application traffic secrets, exporter (and
//!    `exportKeyingMaterial`), resumption master secret and PSK, traffic
//!    update, finished key, traffic key/iv. Transcript hashes are public.
//!  * `<group>_shared` — `kex.sharedSecret` from a tainted PRIVATE key
//!    (`KeyPair.secret`'s group prefix; for the ML-KEM groups the 64-byte
//!    keygen seed, which `sharedSecret` re-expands). The peer share is the
//!    server's real answer, i.e. public wire data.
//!  * `<group>_server` — `kex.serverExchange` with a TAINTED random source:
//!    the bytes it draws ARE the server's ephemeral private scalar (curves) or
//!    the ML-KEM encapsulation randomness `m` (ML-KEM groups). The client's
//!    share is public.
//!  * `sign_<scheme>` — `certverify.sign` with the signing key tainted: the
//!    ECDSA scalar (P-256, P-384, P-521), the Ed25519 seed, the RSA-PSS
//!    CRT private fields (p, q, dP, dQ, qInv and their Montgomery
//!    parameters, as `rsa`'s own harness taints them). Signing randomness
//!    (the PSS salt) is public. ML-DSA is not a row: its signer is std's.
//!
//! Groups: x25519, p256 (secp256r1), p384 (secp384r1), x25519mlkem768,
//! p256mlkem768 (SecP256r1MLKEM768), p384mlkem1024 (SecP384r1MLKEM1024),
//! mlkem1024.
//!
//! ## The two traps (see `hpke`'s and `ct25519`'s harnesses)
//!
//! 1. Without `-fvalgrind` the taint call is a silent no-op; the driver builds
//!    both ways and prints the no-op row on purpose.
//! 2. An optimizer could keep a defined copy from before `makeMemUndefined`;
//!    every tainted value passes `reloadVolatile` once before the call.
//!
//! ## The propagation witness
//!
//! Every target prints its result as hex (`ctgrind_result={x}`); the hex
//! formatter is not constant-time, so a non-zero total next to a small
//! in-file count means "no branch found", not "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const tls13 = @import("root.zig");

const kex = tls13.kex;
const ks = tls13.keyschedule;
const cv = tls13.certverify;
const kat = tls13.certverify_kat_vectors;

const Taint = enum { yes, no };

fn taintBytes(taint: bool, bytes: []u8) void {
    if (taint) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// One real load through a volatile pointer, byte by byte, of the whole value.
fn reloadStruct(comptime T: type, s: *const T) T {
    var out: T = undefined;
    for (std.mem.asBytes(&out), std.mem.asBytes(s)) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

fn publicBytes(comptime n: usize, label: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var ctr: u32 = 0;
    var off: usize = 0;
    while (off < n) : (ctr += 1) {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(label);
        h.update(std.mem.asBytes(&ctr));
        var blk: [32]u8 = undefined;
        h.final(&blk);
        const k = @min(32, n - off);
        @memcpy(out[off..][0..k], blk[0..k]);
        off += k;
    }
    return out;
}

/// A deterministic ChaCha random source whose output may be marked secret
/// (undefined to memcheck) as it is drawn — used for `serverExchange`, whose
/// draws ARE the ephemeral private key.
const Rng = struct {
    chacha: std.Random.ChaCha,
    taint: bool,

    fn init(seed_label: []const u8, taint: bool) Rng {
        return .{ .chacha = std.Random.ChaCha.init(publicBytes(32, seed_label)), .taint = taint };
    }

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *Rng = @ptrCast(@alignCast(ptr));
        self.chacha.fill(buf);
        if (self.taint) std.valgrind.memcheck.makeMemUndefined(buf);
    }

    fn random(self: *Rng) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

// ── key schedule ────────────────────────────────────────────────────────

fn keySchedule(comptime Hash: type, taint: bool) void {
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.Hmac(Hash));
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const S = ks.tls13;
    const L = Hkdf.prk_length;

    var psk = publicBytes(L, "ctgrind-tls13-ks-psk");
    var dhe = publicBytes(L + 16, "ctgrind-tls13-ks-dhe");
    taintBytes(taint, &psk);
    taintBytes(taint, &dhe);
    const psk_r = reloadStruct([L]u8, &psk);
    const dhe_r = reloadStruct([L + 16]u8, &dhe);

    const empty = ks.emptyTranscriptHash(Hash);
    const th_sh = publicBytes(L, "ctgrind-tls13-ks-th-sh");
    const th_sf = publicBytes(L, "ctgrind-tls13-ks-th-sf");
    const th_cf = publicBytes(L, "ctgrind-tls13-ks-th-cf");

    var early: [L]u8 = undefined;
    S.earlySecret(Hkdf, &early, &psk_r);
    var binder_key: [L]u8 = undefined;
    S.binderKey(Hkdf, &binder_key, &early, empty);
    var res_binder_key: [L]u8 = undefined;
    S.resumptionBinderKey(Hkdf, &res_binder_key, &early, empty);
    var binder: [Hmac.mac_length]u8 = undefined;
    S.pskBinder(Hkdf, Hmac, &binder, &binder_key, &th_sh);

    var hs: [L]u8 = undefined;
    S.deriveHandshakeSecret(Hkdf, &hs, &early, empty, &dhe_r);
    var c_hs: [L]u8 = undefined;
    var s_hs: [L]u8 = undefined;
    S.deriveHandshakeTrafficSecrets(Hkdf, &c_hs, &s_hs, &hs, &th_sh);
    var fin_key: [Hmac.mac_length]u8 = undefined;
    S.deriveFinishedKey(Hkdf, Hmac.mac_length, &fin_key, &s_hs);
    var verify: [Hmac.mac_length]u8 = undefined;
    S.computeFinishedVerifyData(Hmac, &verify, &fin_key, &th_sf);
    var hs_key: [16]u8 = undefined;
    var hs_iv: [12]u8 = undefined;
    S.deriveTrafficKeyIv(Hkdf, 16, 12, &hs_key, &hs_iv, &c_hs);

    var master: [L]u8 = undefined;
    S.deriveMasterSecret(Hkdf, &master, &hs, empty);
    var c_ap: [L]u8 = undefined;
    var s_ap: [L]u8 = undefined;
    var exp: [L]u8 = undefined;
    S.deriveApplicationSecrets(Hkdf, &c_ap, &s_ap, &exp, &master, &th_sf);
    var c_ap2: [L]u8 = undefined;
    var s_ap2: [L]u8 = undefined;
    S.deriveApplicationTrafficSecrets(Hkdf, &c_ap2, &s_ap2, &master, &th_sf);
    var exp2: [L]u8 = undefined;
    S.deriveExporterMasterSecret(Hkdf, &exp2, &master, &th_sf);
    var exported: [40]u8 = undefined;
    S.exportKeyingMaterial(Hash, Hkdf, &exported, &exp, "EXPORTER-ctgrind", "context") catch unreachable;
    var next: [L]u8 = undefined;
    S.nextApplicationTrafficSecret(Hkdf, &next, &c_ap);
    var ap_key: [16]u8 = undefined;
    var ap_iv: [12]u8 = undefined;
    S.deriveTrafficKeyIv(Hkdf, 16, 12, &ap_key, &ap_iv, &next);

    var res_master: [L]u8 = undefined;
    S.deriveResumptionMasterSecret(Hkdf, &res_master, &master, &th_cf);
    var res_psk: [L]u8 = undefined;
    S.deriveResumptionPsk(Hkdf, &res_psk, &res_master, &.{ 0, 0 });

    // Propagation witness: one value per stage of the schedule.
    std.debug.print("ctgrind_result={x}\n", .{binder});
    std.debug.print("ctgrind_result={x}\n", .{verify});
    std.debug.print("ctgrind_result={x}{x}\n", .{ hs_key, hs_iv });
    std.debug.print("ctgrind_result={x}{x}\n", .{ ap_key, ap_iv });
    std.debug.print("ctgrind_result={x}\n", .{exported});
    std.debug.print("ctgrind_result={x}\n", .{res_psk});
    std.debug.print("ctgrind_result={x}\n", .{res_binder_key});
    std.debug.print("ctgrind_result={x}\n", .{s_ap ++ s_ap2 ++ exp2});
}

// ── key exchange ────────────────────────────────────────────────────────

/// `sharedSecret` from a tainted private key: the client generates its share
/// (public randomness), a real server answers it, then the client's secret is
/// tainted and `sharedSecret` runs on the server's share.
fn kexShared(group: u16, taint: bool) !void {
    var crng = Rng.init("ctgrind-tls13-kex-client", false);
    var srng = Rng.init("ctgrind-tls13-kex-server", false);
    var kp: kex.KeyPair = undefined;
    try kex.generate(group, crng.random(), &kp);
    var sx: kex.ServerExchange = undefined;
    try kex.serverExchange(group, kp.public[0..kp.public_len], srng.random(), &sx);

    const n = kex.scalarLen(group);
    taintBytes(taint, kp.secret[0..n]);
    const secret = reloadStruct([kex.secret_len]u8, &kp.secret);

    var out: kex.SharedSecret = undefined;
    try kex.sharedSecret(group, secret[0..n], sx.public[0..sx.public_len], &out);
    std.debug.print("ctgrind_result={x}\n", .{out.slice()});
}

/// `serverExchange` with a tainted random source (the ephemeral private key).
fn kexServer(group: u16, taint: bool) !void {
    var crng = Rng.init("ctgrind-tls13-kex-client", false);
    var srng = Rng.init("ctgrind-tls13-kex-server", taint);
    var kp: kex.KeyPair = undefined;
    try kex.generate(group, crng.random(), &kp);
    var sx: kex.ServerExchange = undefined;
    try kex.serverExchange(group, kp.public[0..kp.public_len], srng.random(), &sx);
    std.debug.print("ctgrind_result={x}\n", .{sx.shared.slice()});
    std.debug.print("ctgrind_result={x}\n", .{sx.public[0..@min(sx.public_len, 64)]});
}

// ── CertificateVerify ───────────────────────────────────────────────────

fn signEcdsa(comptime field: []const u8, scheme: cv.SignatureScheme, sk_bytes: anytype, th: []const u8, taint: bool) !void {
    const Sk = std.meta.Child(@FieldType(cv.SecretKey, field));
    var sk = try Sk.fromBytes(sk_bytes);
    taintBytes(taint, &sk.bytes);
    const skr = reloadStruct(Sk, &sk);
    var out: [cv.max_signature_len]u8 = undefined;
    const secret = @unionInit(cv.SecretKey, field, &skr);
    const sig = try cv.sign(scheme, secret, .server, th, null, &out);
    std.debug.print("ctgrind_result={x}\n", .{sig});
    // Taint-arrival witness. p384 and p521 declassify the signature they
    // return, so without this a zero row would not show the key was ever
    // tainted. Hex of the (still tainted) key copy is not constant-time.
    std.debug.print("ctgrind_key={x}\n", .{skr.bytes[0..8]});
}

fn signEd25519(taint: bool) !void {
    var sk = try std.crypto.sign.Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes);
    // The seed only: the second half is the (public) key.
    taintBytes(taint, sk.bytes[0..32]);
    const skr = reloadStruct(@TypeOf(sk), &sk);
    var out: [cv.max_signature_len]u8 = undefined;
    const sig = try cv.sign(.ed25519, .{ .ed25519 = &skr }, .client, &kat.ed25519_client.transcript_hash, null, &out);
    std.debug.print("ctgrind_result={x}\n", .{sig});
}

fn signRsa(taint: bool) !void {
    const rsa_t = std.meta.Child(@FieldType(cv.SecretKey, "rsa"));
    var sk: rsa_t = undefined;
    try kat.rsa_pss_sha256_server.secretKey(&sk);
    // Exactly the fields the CRT private operation reads, as `rsa`'s harness.
    taintBytes(taint, std.mem.asBytes(&sk.p));
    taintBytes(taint, std.mem.asBytes(&sk.q));
    taintBytes(taint, std.mem.asBytes(&sk.dp));
    taintBytes(taint, std.mem.asBytes(&sk.dq));
    taintBytes(taint, std.mem.asBytes(&sk.qinv));
    inline for (.{ &sk.p_mont, &sk.q_mont }) |mp| {
        taintBytes(taint, std.mem.asBytes(&mp.m));
        taintBytes(taint, std.mem.asBytes(&mp.n0inv));
        taintBytes(taint, std.mem.asBytes(&mp.r2));
        taintBytes(taint, std.mem.asBytes(&mp.one_mont));
    }
    const skr = reloadStruct(rsa_t, &sk);
    var rng = Rng.init("ctgrind-tls13-pss-salt", false);
    var out: [cv.max_signature_len]u8 = undefined;
    const sig = try cv.sign(.rsa_pss_rsae_sha256, .{ .rsa = &skr }, .server, &kat.rsa_pss_sha256_server.transcript_hash, rng.random(), &out);
    std.debug.print("ctgrind_result={x}\n", .{sig});
}

const Target = enum {
    ks256,
    ks384,
    x25519_shared,
    x25519_server,
    p256_shared,
    p256_server,
    p384_shared,
    p384_server,
    x25519mlkem768_shared,
    x25519mlkem768_server,
    p256mlkem768_shared,
    p256mlkem768_server,
    p384mlkem1024_shared,
    p384mlkem1024_server,
    mlkem1024_shared,
    mlkem1024_server,
    sign_p256,
    sign_p384,
    sign_p521,
    sign_ed25519,
    sign_rsa,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = (std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint) == .yes;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .ks256 => keySchedule(std.crypto.hash.sha2.Sha256, taint),
        .ks384 => keySchedule(std.crypto.hash.sha2.Sha384, taint),
        .x25519_shared => try kexShared(kex.x25519_group, taint),
        .x25519_server => try kexServer(kex.x25519_group, taint),
        .p256_shared => try kexShared(kex.secp256r1_group, taint),
        .p256_server => try kexServer(kex.secp256r1_group, taint),
        .p384_shared => try kexShared(kex.secp384r1_group, taint),
        .p384_server => try kexServer(kex.secp384r1_group, taint),
        .x25519mlkem768_shared => try kexShared(kex.x25519_mlkem768_group, taint),
        .x25519mlkem768_server => try kexServer(kex.x25519_mlkem768_group, taint),
        .p256mlkem768_shared => try kexShared(kex.secp256r1_mlkem768_group, taint),
        .p256mlkem768_server => try kexServer(kex.secp256r1_mlkem768_group, taint),
        .p384mlkem1024_shared => try kexShared(kex.secp384r1_mlkem1024_group, taint),
        .p384mlkem1024_server => try kexServer(kex.secp384r1_mlkem1024_group, taint),
        .mlkem1024_shared => try kexShared(kex.mlkem1024_group, taint),
        .mlkem1024_server => try kexServer(kex.mlkem1024_group, taint),
        .sign_p256 => try signEcdsa("ecdsa_p256", .ecdsa_secp256r1_sha256, kat.ecdsa_p256_server.secret_key_bytes, &kat.ecdsa_p256_server.transcript_hash, taint),
        .sign_p384 => try signEcdsa("ecdsa_p384", .ecdsa_secp384r1_sha384, kat.ecdsa_p384_server.secret_key_bytes, &kat.ecdsa_p384_server.transcript_hash, taint),
        .sign_p521 => try signEcdsa("ecdsa_p521", .ecdsa_secp521r1_sha512, kat.ecdsa_p521_server.secret_key_bytes, &kat.ecdsa_p521_server.transcript_hash, taint),
        .sign_ed25519 => try signEd25519(taint),
        .sign_rsa => try signRsa(taint),
    }
}
