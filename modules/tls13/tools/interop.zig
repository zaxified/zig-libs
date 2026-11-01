// SPDX-License-Identifier: MIT

//! Live differential oracle: `tls13` against OpenSSL 3.5's libcrypto (the
//! reference named by the maturity card; system `libcrypto.so.3`, path below or
//! `LIBCRYPTO_SO`, no headers needed).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-tls13` runs it;
//! `zig build check-interop` compiles it. It needs `zig` on PATH (it builds the
//! C side, `tools/c_oracle/oracle.c`, with `zig cc`) and OpenSSL 3.5. Run from
//! the repository root.
//!
//!     zig build interop-tls13                          # seed 0x71541305, ~300 cases
//!     zig build interop-tls13 -- --seed 7 --cases 900  # another draw, 3x the rows
//!     zig build interop-tls13 -- --write               # also rewrite src/openssl_oracle_vectors.zig
//!
//! Three parts, every row one case, all of them judged by OpenSSL:
//!   1. Key schedule (RFC 8446 section 7, SHA-256 and SHA-384): random PSK or
//!      none, (EC)DHE secret and transcript hashes -> every secret of section
//!      7.1 (early, both binder keys, the PSK binder, client early traffic and
//!      early exporter, handshake, both handshake traffic, master, both
//!      application traffic, exporter master, resumption master and the PSK it
//!      stands for), the finished keys and a Finished verify_data, the traffic
//!      keys and IVs of section 7.3 for both AEAD key lengths, the KeyUpdate
//!      secrets and one TLS-Exporter output, byte for byte. The C side computes
//!      the schedule twice (EVP_KDF "HKDF" with the HkdfLabel built there, and
//!      libssl's own EVP_KDF "TLS13-KDF") and the two are a row of their own.
//!   2. Key exchange, every group of `kex`: x25519, secp256r1, secp384r1,
//!      secp521r1, mlkem512, mlkem768, mlkem1024 and the three hybrids, the hybrids as OpenSSL's NATIVE
//!      X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 keys (not
//!      composed from parts). OpenSSL client <-> our server and our client <->
//!      OpenSSL server, the shared secrets equal; then malformed peers (short,
//!      long and empty shares, off-curve and mis-tagged points, an all-zero
//!      X25519 element, a non-canonical ML-KEM key, a flipped ML-KEM ciphertext)
//!      given to both, the two verdicts recorded. A verdict where we refuse and
//!      OpenSSL accepts is allowed only with an RFC sentence in `stricter`.
//!   3. CertificateVerify, every scheme `certverify` has (ECDSA P-256/384/521,
//!      RSA-PSS-RSAE SHA-256/384/512, Ed25519, ML-DSA-44/65/87; OpenSSL 3.5 has
//!      all ten): we sign and OpenSSL verifies over the RFC 8446 section 4.4.3
//!      content (the C side builds it itself, server and client context
//!      strings), OpenSSL signs and we verify, a flipped bit and the wrong
//!      context string are refused by both.
//!
//! OpenSSL's randomness (keygen, encapsulation, ECDSA nonces, PSS salts) is
//! replaced by a seeded generator (`RAND_set_rand_method`), so a run is a pure
//! function of `--seed`, `--cases` and the OpenSSL build: `--write` freezes a
//! bounded subset (well under 300 KiB) of the OpenSSL-produced values into
//! `src/openssl_oracle_vectors.zig`, which `src/openssl_oracle_test.zig` replays
//! hermetically inside `test-tls13`. Exit 0 only when every row agrees; the last
//! line is `cases=N agree=N`.

const std = @import("std");
const bench = @import("testkit").bench;
const tls13 = @import("tls13");
const rsa = @import("rsa");
const p521 = @import("p521");

const kex = tls13.kex;
const cv = tls13.certverify;
const kv = tls13.certverify_kat_vectors;
const keyschedule = tls13.keyschedule;
const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;
const mldsa = std.crypto.sign.mldsa;

const prog = "interop-tls13";
const work_dir = ".zig-cache/interop-tls13";
const c_source = "modules/tls13/tools/c_oracle/oracle.c";
const vectors_path = "modules/tls13/src/openssl_oracle_vectors.zig";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const default_seed: u64 = 0x71541305;
const default_cases: usize = 300;
const vectors_budget: usize = 300 * 1024;

// ---- the peer ----

const Oracle = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    rbuf: [1 << 16]u8 = undefined,
    wbuf: [1 << 16]u8 = undefined,
    r: std.Io.File.Reader = undefined,
    w: std.Io.File.Writer = undefined,

    fn start(o: *Oracle) void {
        o.r = o.child.stdout.?.readerStreaming(o.io, &o.rbuf);
        o.w = o.child.stdin.?.writerStreaming(o.io, &o.wbuf);
    }

    fn stop(o: *Oracle) void {
        o.child.stdin.?.close(o.io);
        o.child.stdin = null;
        _ = o.child.wait(o.io) catch {};
    }

    /// One request, one reply: the text after `OK`, or null for `ERR` (the
    /// peer refused). A dead peer or a malformed reply is an error.
    fn ask(o: *Oracle, line: []const u8) !?[]const u8 {
        try o.w.interface.writeAll(line);
        try o.w.interface.writeByte('\n');
        try o.w.interface.flush();
        const reply = (try o.r.interface.takeDelimiter('\n')) orelse {
            std.debug.print(prog ++ ": the C side ended while answering `{s}`\n", .{line[0..@min(line.len, 40)]});
            return error.PeerGone;
        };
        if (std.mem.eql(u8, reply, "ERR")) return null;
        if (!std.mem.startsWith(u8, reply, "OK")) return error.BadReply;
        return try o.arena.dupe(u8, std.mem.trimStart(u8, reply[2..], " "));
    }
};

fn hx(arena: std.mem.Allocator, b: []const u8) ![]const u8 {
    if (b.len == 0) return "-";
    return arena.print("{x}", .{b});
}

fn unhex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 1 and s[0] == '-') return arena.alloc(u8, 0);
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

// ---- what is frozen ----

const Fz = struct {
    ks: std.ArrayList(KsRow) = .empty,
    kex_server: std.ArrayList(KexServerRow) = .empty,
    kex_client: std.ArrayList(KexClientRow) = .empty,
    neg: std.ArrayList(NegRow) = .empty,
    sig: std.ArrayList(SigRow) = .empty,
};

const KsRow = struct {
    sha384: bool,
    psk: ?[]const u8,
    dhe: ?[]const u8,
    th: [4][]const u8,
    nonce: []const u8,
    label: []const u8,
    ctx: []const u8,
    exp_len: usize,
    key_len: usize,
    fields: []const []const u8,
};
const KexServerRow = struct { group: u16, secret: []const u8, cshare: []const u8, sshare: []const u8, ss: []const u8 };
const KexClientRow = struct { group: u16, seed: u64, cshare: []const u8, ss: []const u8 };
const NegRow = struct { group: u16, client_dir: bool, kind: []const u8, secret: []const u8, share: []const u8, ours: bool, ossl: bool };
const SigRow = struct { scheme: u16, pk: []const u8, pk2: []const u8, client: bool, th: []const u8, sig: []const u8 };

const Run = struct {
    arena: std.mem.Allocator,
    o: *Oracle,
    prng: std.Random.DefaultPrng,
    csprng: std.Random.DefaultCsprng,
    cases: usize = 0,
    agree: usize = 0,
    fz: Fz = .{},

    fn rnd(r: *Run) std.Random {
        return r.prng.random();
    }

    fn row(r: *Run, ok: bool, comptime fmt: []const u8, args: anytype) void {
        r.cases += 1;
        if (ok) {
            r.agree += 1;
            return;
        }
        std.debug.print("DISAGREE " ++ fmt ++ "\n", args);
    }

    fn randBytes(r: *Run, n: usize) ![]u8 {
        const b = try r.arena.alloc(u8, n);
        r.rnd().bytes(b);
        return b;
    }

    fn reqf(r: *Run, comptime fmt: []const u8, args: anytype) !?[]const u8 {
        return r.o.ask(try r.arena.print(fmt, args));
    }
};

// ---- part 1: the key schedule ----

const ks_names = [_][]const u8{
    "early",        "ext_binder_key", "res_binder_key", "psk_binder",    "c_e_traffic",  "e_exp_master", "handshake",
    "c_hs_traffic", "s_hs_traffic",   "master",         "c_ap_traffic",  "s_ap_traffic", "exp_master",   "res_master",
    "res_psk",      "c_finished_key", "s_finished_key", "s_verify_data", "c_hs_key",     "c_hs_iv",      "s_hs_key",
    "s_hs_iv",      "c_ap_key",       "c_ap_iv",        "s_ap_key",      "s_ap_iv",      "c_ap_next",    "s_ap_next",
    "exported",
};

const KsIn = struct {
    sha384: bool,
    psk: ?[]const u8,
    dhe: ?[]const u8,
    th: [4][]const u8,
    nonce: []const u8,
    label: []const u8,
    ctx: []const u8,
    exp_len: usize,
    key_len: usize,
};

/// Our side of the schedule, the fields in the C side's order.
fn ksOurs(comptime Hash: type, comptime Hkdf: type, comptime Hmac: type, arena: std.mem.Allocator, in: KsIn) ![]const []u8 {
    const L = Hkdf.prk_length;
    const S = keyschedule.tls13;
    const empty = keyschedule.emptyTranscriptHash(Hash);
    const zeros: [L]u8 = @splat(0);
    var f: std.ArrayList([]u8) = .empty;

    var early: [L]u8 = undefined;
    const psk: []const u8 = in.psk orelse &zeros;
    S.earlySecret(Hkdf, &early, psk);
    try f.append(arena, try arena.dupe(u8, &early));
    var ext: [L]u8 = undefined;
    S.binderKey(Hkdf, &ext, &early, empty);
    try f.append(arena, try arena.dupe(u8, &ext));
    var resb: [L]u8 = undefined;
    S.resumptionBinderKey(Hkdf, &resb, &early, empty);
    try f.append(arena, try arena.dupe(u8, &resb));
    var binder: [L]u8 = undefined;
    S.pskBinder(Hkdf, Hmac, &binder, &ext, in.th[0]);
    try f.append(arena, try arena.dupe(u8, &binder));
    var ce: [L]u8 = undefined;
    S.deriveSecret(Hkdf, &ce, &early, "c e traffic", in.th[0]);
    try f.append(arena, try arena.dupe(u8, &ce));
    var ee: [L]u8 = undefined;
    S.deriveSecret(Hkdf, &ee, &early, "e exp master", in.th[0]);
    try f.append(arena, try arena.dupe(u8, &ee));

    var hs: [L]u8 = undefined;
    S.deriveHandshakeSecret(Hkdf, &hs, &early, empty, in.dhe);
    try f.append(arena, try arena.dupe(u8, &hs));
    var c_hs: [L]u8 = undefined;
    var s_hs: [L]u8 = undefined;
    S.deriveHandshakeTrafficSecrets(Hkdf, &c_hs, &s_hs, &hs, in.th[1]);
    try f.append(arena, try arena.dupe(u8, &c_hs));
    try f.append(arena, try arena.dupe(u8, &s_hs));
    var ms: [L]u8 = undefined;
    S.deriveMasterSecret(Hkdf, &ms, &hs, empty);
    try f.append(arena, try arena.dupe(u8, &ms));
    var c_ap: [L]u8 = undefined;
    var s_ap: [L]u8 = undefined;
    var exp: [L]u8 = undefined;
    S.deriveApplicationSecrets(Hkdf, &c_ap, &s_ap, &exp, &ms, in.th[2]);
    try f.append(arena, try arena.dupe(u8, &c_ap));
    try f.append(arena, try arena.dupe(u8, &s_ap));
    try f.append(arena, try arena.dupe(u8, &exp));
    var res: [L]u8 = undefined;
    S.deriveResumptionMasterSecret(Hkdf, &res, &ms, in.th[3]);
    try f.append(arena, try arena.dupe(u8, &res));
    var rpsk: [L]u8 = undefined;
    S.deriveResumptionPsk(Hkdf, &rpsk, &res, in.nonce);
    try f.append(arena, try arena.dupe(u8, &rpsk));

    var fc: [L]u8 = undefined;
    var fs: [L]u8 = undefined;
    S.deriveFinishedKey(Hkdf, L, &fc, &c_hs);
    S.deriveFinishedKey(Hkdf, L, &fs, &s_hs);
    try f.append(arena, try arena.dupe(u8, &fc));
    try f.append(arena, try arena.dupe(u8, &fs));
    var vd: [L]u8 = undefined;
    keyschedule.computeFinishedVerifyData(Hmac, &vd, &fs, in.th[2]);
    try f.append(arena, try arena.dupe(u8, &vd));

    const traffic = [_]*const [L]u8{ &c_hs, &s_hs, &c_ap, &s_ap };
    for (traffic) |t| {
        switch (in.key_len) {
            inline 16, 32 => |kl| {
                var key: [kl]u8 = undefined;
                var iv: [12]u8 = undefined;
                S.deriveTrafficKeyIv(Hkdf, kl, 12, &key, &iv, t);
                try f.append(arena, try arena.dupe(u8, &key));
                try f.append(arena, try arena.dupe(u8, &iv));
            },
            else => unreachable,
        }
    }
    var n1: [L]u8 = undefined;
    var n2: [L]u8 = undefined;
    S.nextApplicationTrafficSecret(Hkdf, &n1, &c_ap);
    S.nextApplicationTrafficSecret(Hkdf, &n2, &s_ap);
    try f.append(arena, try arena.dupe(u8, &n1));
    try f.append(arena, try arena.dupe(u8, &n2));
    const exported = try arena.alloc(u8, in.exp_len);
    try S.exportKeyingMaterial(Hash, Hkdf, exported, &exp, in.label, in.ctx);
    try f.append(arena, exported);
    return f.items;
}

fn ksCase(r: *Run, i: usize) !void {
    const sha384 = i % 2 == 1;
    const L: usize = if (sha384) 48 else 32;
    const rn = r.rnd();
    const has_psk = rn.boolean();
    const has_dhe = !has_psk or rn.boolean();
    const dhe_lens = [_]usize{ 32, 48, 64, 80 };
    var label_buf: [32]u8 = undefined;
    const label_n = rn.intRangeAtMost(usize, 1, 12);
    @memcpy(label_buf[0..13], "EXPERIMENTAL ");
    for (label_buf[13..][0..label_n]) |*c| c.* = rn.intRangeAtMost(u8, 'a', 'z');
    const in: KsIn = .{
        .sha384 = sha384,
        .psk = if (has_psk) try r.randBytes(L) else null,
        .dhe = if (has_dhe) try r.randBytes(dhe_lens[rn.uintLessThan(usize, dhe_lens.len)]) else null,
        .th = .{ try r.randBytes(L), try r.randBytes(L), try r.randBytes(L), try r.randBytes(L) },
        .nonce = try r.randBytes(rn.uintAtMost(usize, 8)),
        .label = try r.arena.dupe(u8, label_buf[0 .. 13 + label_n]),
        .ctx = try r.randBytes(rn.uintAtMost(usize, 40)),
        .exp_len = rn.intRangeAtMost(usize, 1, 80),
        .key_len = if (rn.boolean()) 16 else 32,
    };
    const ours = if (sha384)
        try ksOurs(std.crypto.hash.sha2.Sha384, std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384), std.crypto.auth.hmac.sha2.HmacSha384, r.arena, in)
    else
        try ksOurs(std.crypto.hash.sha2.Sha256, std.crypto.kdf.hkdf.HkdfSha256, std.crypto.auth.hmac.sha2.HmacSha256, r.arena, in);

    const reply = try r.reqf("KS {s} {d} {s} {d} {s} {s} {s} {s} {s} {s} {s} {s} {d} {d}", .{
        if (sha384) "384" else "256",
        @intFromBool(has_psk),
        try hx(r.arena, in.psk orelse ""),
        @intFromBool(has_dhe),
        try hx(r.arena, in.dhe orelse ""),
        try hx(r.arena, in.th[0]),
        try hx(r.arena, in.th[1]),
        try hx(r.arena, in.th[2]),
        try hx(r.arena, in.th[3]),
        try hx(r.arena, in.nonce),
        try hx(r.arena, in.label),
        try hx(r.arena, in.ctx),
        in.exp_len,
        in.key_len,
    }) orelse {
        r.row(false, "key schedule case {d}: OpenSSL refused the request", .{i});
        return;
    };
    var theirs: std.ArrayList([]u8) = .empty;
    var kdf_verdict: []const u8 = "?";
    var it = std.mem.tokenizeScalar(u8, reply, ' ');
    while (it.next()) |t| {
        if (std.mem.startsWith(u8, t, "tls13kdf=")) kdf_verdict = t["tls13kdf=".len..] else try theirs.append(r.arena, try unhex(r.arena, t));
    }
    var bad: ?usize = null;
    if (theirs.items.len != ks_names.len) {
        r.row(false, "key schedule case {d}: OpenSSL returned {d} fields, expected {d}", .{ i, theirs.items.len, ks_names.len });
        return;
    }
    for (ours, theirs.items, 0..) |a, b, k| {
        if (!std.mem.eql(u8, a, b)) {
            bad = k;
            break;
        }
    }
    if (bad) |k| {
        r.row(false, "key schedule case {d} ({s}): field {s} ours {x} OpenSSL {x}", .{ i, if (sha384) "SHA-384" else "SHA-256", ks_names[k], ours[k], theirs.items[k] });
    } else r.row(true, "", .{});
    r.row(std.mem.eql(u8, kdf_verdict, "ok"), "key schedule case {d}: OpenSSL's TLS13-KDF vs its HKDF: {s}", .{ i, kdf_verdict });

    if (i < 6) {
        const fields = try r.arena.alloc([]const u8, ours.len);
        for (ours, fields) |a, *d| d.* = try hx(r.arena, a);
        try r.fz.ks.append(r.arena, .{
            .sha384 = sha384,
            .psk = if (in.psk) |p| try hx(r.arena, p) else null,
            .dhe = if (in.dhe) |p| try hx(r.arena, p) else null,
            .th = .{ try hx(r.arena, in.th[0]), try hx(r.arena, in.th[1]), try hx(r.arena, in.th[2]), try hx(r.arena, in.th[3]) },
            .nonce = try hx(r.arena, in.nonce),
            .label = try hx(r.arena, in.label),
            .ctx = try hx(r.arena, in.ctx),
            .exp_len = in.exp_len,
            .key_len = in.key_len,
            .fields = fields,
        });
    }
}

// ---- part 2: the key exchange ----

const Group = struct { name: []const u8, id: u16 };
const groups = [_]Group{
    .{ .name = "x25519", .id = kex.x25519_group },
    .{ .name = "secp256r1", .id = kex.secp256r1_group },
    .{ .name = "secp384r1", .id = kex.secp384r1_group },
    .{ .name = "secp521r1", .id = kex.secp521r1_group },
    .{ .name = "x25519mlkem768", .id = kex.x25519_mlkem768_group },
    .{ .name = "secp256r1mlkem768", .id = kex.secp256r1_mlkem768_group },
    .{ .name = "secp384r1mlkem1024", .id = kex.secp384r1_mlkem1024_group },
    .{ .name = "mlkem1024", .id = kex.mlkem1024_group },
    .{ .name = "mlkem512", .id = kex.mlkem512_group },
    .{ .name = "mlkem768", .id = kex.mlkem768_group },
};

const Span = struct { off: usize, len: usize };
const Layout = struct { ec: ?Span = null, x: ?usize = null, ml: ?usize = null };

/// Where the elements sit in a share (draft-ietf-tls-ecdhe-mlkem layouts:
/// X25519MLKEM768 ML-KEM first, the NIST hybrids the ECDH element first).
fn layout(gid: u16, server_form: bool) Layout {
    return switch (gid) {
        kex.x25519_group => .{ .x = 0 },
        kex.secp256r1_group => .{ .ec = .{ .off = 0, .len = 65 } },
        kex.secp384r1_group => .{ .ec = .{ .off = 0, .len = 97 } },
        kex.secp521r1_group => .{ .ec = .{ .off = 0, .len = 133 } },
        kex.x25519_mlkem768_group => .{ .ml = 0, .x = if (server_form) 1088 else 1184 },
        kex.secp256r1_mlkem768_group => .{ .ec = .{ .off = 0, .len = 65 }, .ml = 65 },
        kex.secp384r1_mlkem1024_group => .{ .ec = .{ .off = 0, .len = 97 }, .ml = 97 },
        kex.mlkem1024_group, kex.mlkem512_group, kex.mlkem768_group => .{ .ml = 0 },
        else => unreachable,
    };
}

const Kind = enum { trunc1, extra1, empty, ec_offcurve, ec_badprefix, x_zero, ml_noncanon, ml_ct_flip };

fn mutate(arena: std.mem.Allocator, kind: Kind, gid: u16, server_form: bool, share: []const u8) !?[]u8 {
    const l = layout(gid, server_form);
    switch (kind) {
        .trunc1 => return try arena.dupe(u8, share[0 .. share.len - 1]),
        .extra1 => return try std.mem.concat(arena, u8, &.{ share, &.{0} }),
        .empty => return try arena.alloc(u8, 0),
        .ec_offcurve => {
            const ec = l.ec orelse return null;
            const m = try arena.dupe(u8, share);
            m[ec.off + ec.len - 1] ^= 1; // the low bit of Y
            return m;
        },
        .ec_badprefix => {
            const ec = l.ec orelse return null;
            const m = try arena.dupe(u8, share);
            m[ec.off] = 0x02; // a compressed-point tag on an uncompressed-length element
            return m;
        },
        .x_zero => {
            const x = l.x orelse return null;
            const m = try arena.dupe(u8, share);
            @memset(m[x..][0..32], 0);
            return m;
        },
        .ml_noncanon => {
            if (server_form) return null;
            const ml = l.ml orelse return null;
            const m = try arena.dupe(u8, share);
            m[ml] = 0xff; // coefficient 0 = 4095 >= q (FIPS 203 section 7.2)
            m[ml + 1] = 0xff;
            return m;
        },
        .ml_ct_flip => {
            if (!server_form) return null;
            const ml = l.ml orelse return null;
            const m = try arena.dupe(u8, share);
            m[ml + 10] ^= 1; // implicit rejection: both sides ACCEPT and derive an unrelated secret
            return m;
        },
    }
}

/// Rows where we refuse and OpenSSL accepts, each with the RFC sentence that
/// makes our refusal right. Empty: every verdict so far is the same.
fn stricter(kind: Kind, gid: u16) ?[]const u8 {
    _ = kind;
    _ = gid;
    return null;
}

fn kexGroup(r: *Run, g: Group, iters: usize) !void {
    const sl = kex.scalarLen(g.id);
    var kp0: kex.KeyPair = undefined;
    var sshare0: []const u8 = &.{};
    var cid0: []const u8 = "";
    for (0..iters) |it| {
        // OpenSSL as the server, our client.
        var kp: kex.KeyPair = undefined;
        try kex.generate(g.id, r.csprng.random(), &kp);
        const cshare = kp.public[0..kp.public_len];
        if (it == 0) kp0 = kp;
        const rep = try r.reqf("KEMS {s} {s}", .{ g.name, try hx(r.arena, cshare) }) orelse {
            r.row(false, "{s}: OpenSSL's server refuses our client share", .{g.name});
            continue;
        };
        var tk = std.mem.tokenizeScalar(u8, rep, ' ');
        const sshare = try unhex(r.arena, tk.next().?);
        const ss = try unhex(r.arena, tk.next().?);
        var ours: kex.SharedSecret = undefined;
        if (kex.sharedSecret(g.id, kp.secret[0..sl], sshare, &ours)) {
            r.row(std.mem.eql(u8, ours.slice(), ss), "{s}: our client's secret {x} differs from OpenSSL server's {x}", .{ g.name, ours.slice(), ss });
        } else |e| r.row(false, "{s}: our client refuses OpenSSL's server share ({t})", .{ g.name, e });
        if (it == 0) {
            sshare0 = sshare;
            try r.fz.kex_server.append(r.arena, .{ .group = g.id, .secret = try hx(r.arena, kp.secret[0..sl]), .cshare = try hx(r.arena, cshare), .sshare = try hx(r.arena, sshare), .ss = try hx(r.arena, ss) });
        }

        // OpenSSL as the client, our server.
        const gen = try r.reqf("KEMC_GEN {s}", .{g.name}) orelse {
            r.row(false, "{s}: OpenSSL could not generate a client key", .{g.name});
            continue;
        };
        var gt = std.mem.tokenizeScalar(u8, gen, ' ');
        const id = gt.next().?;
        const ocshare = try unhex(r.arena, gt.next().?);
        const row_seed = r.rnd().int(u64);
        var rp = std.Random.DefaultPrng.init(row_seed);
        var x: kex.ServerExchange = undefined;
        if (kex.serverExchange(g.id, ocshare, rp.random(), &x)) {
            const fin = try r.reqf("KEMC_FIN {s} {s}", .{ id, try hx(r.arena, x.public[0..x.public_len]) }) orelse {
                r.row(false, "{s}: OpenSSL's client refuses our server share", .{g.name});
                continue;
            };
            const oss = try unhex(r.arena, fin);
            r.row(std.mem.eql(u8, x.shared.slice(), oss), "{s}: our server's secret {x} differs from OpenSSL client's {x}", .{ g.name, x.shared.slice(), oss });
            if (it == 0) {
                cid0 = id;
                try r.fz.kex_client.append(r.arena, .{ .group = g.id, .seed = row_seed, .cshare = try hx(r.arena, ocshare), .ss = try hx(r.arena, oss) });
            }
        } else |e| r.row(false, "{s}: our server refuses OpenSSL's client share ({t})", .{ g.name, e });
    }

    // Malformed peers, both ways round.
    if (sshare0.len == 0 or cid0.len == 0) {
        r.row(false, "{s}: no valid share to derive the malformed ones from", .{g.name});
        return;
    }
    const server_share = sshare0; // a valid SERVER-form share (OpenSSL's)
    const client_share = kp0.public[0..kp0.public_len];
    var idx = [2]usize{ 0, 0 };
    for (std.enums.values(Kind)) |kind| {
        for ([_]bool{ false, true }) |client_dir| {
            // client_dir: OpenSSL's and our CLIENT are given a bad SERVER share; otherwise
            // OpenSSL's and our SERVER are given a bad CLIENT share.
            const base = if (client_dir) server_share else client_share;
            const m = (try mutate(r.arena, kind, g.id, client_dir, base)) orelse continue;
            var ours_ok: bool = undefined;
            var theirs_ok: bool = undefined;
            if (client_dir) {
                var ss: kex.SharedSecret = undefined;
                ours_ok = if (kex.sharedSecret(g.id, kp0.secret[0..sl], m, &ss)) true else |_| false;
                theirs_ok = (try r.reqf("KEMC_FIN {s} {s}", .{ cid0, try hx(r.arena, m) })) != null;
            } else {
                var rp = std.Random.DefaultPrng.init(1);
                var x: kex.ServerExchange = undefined;
                ours_ok = if (kex.serverExchange(g.id, m, rp.random(), &x)) true else |_| false;
                theirs_ok = (try r.reqf("KEMS {s} {s}", .{ g.name, try hx(r.arena, m) })) != null;
            }
            const stricter_ok = !ours_ok and theirs_ok and stricter(kind, g.id) != null;
            r.row(ours_ok == theirs_ok or stricter_ok, "{s} {s} {s}: ours {s}, OpenSSL {s}", .{
                g.name,
                if (client_dir) "bad server share to a client" else "bad client share to a server",
                @tagName(kind),
                if (ours_ok) "accepts" else "refuses",
                if (theirs_ok) "accepts" else "refuses",
            });
            const n = &idx[@intFromBool(client_dir)];
            try r.fz.neg.append(r.arena, .{
                .group = g.id,
                .client_dir = client_dir,
                .kind = @tagName(kind),
                .secret = if (client_dir) try hx(r.arena, kp0.secret[0..sl]) else "-",
                .share = try hx(r.arena, m),
                .ours = ours_ok,
                .ossl = theirs_ok,
            });
            n.* += 1;
        }
    }
}

// ---- part 3: CertificateVerify ----

const SigSet = struct {
    scheme: cv.SignatureScheme,
    id: u8,
    sk: cv.SecretKey,
    pk: cv.PublicKey,
    /// The public key as frozen: SEC1 point, Ed25519 key, ML-DSA key, or the RSA modulus.
    pk_bytes: []const u8,
    /// The RSA public exponent, empty otherwise.
    pk2_bytes: []const u8,
};

fn ecDer(arena: std.mem.Allocator, head: []const u8, scalar: []const u8, tail: []const u8) ![]const u8 {
    return std.mem.concat(arena, u8, &.{ head, scalar, tail });
}

fn sigKeys(r: *Run) ![]SigSet {
    const arena = r.arena;
    var sets: std.ArrayList(SigSet) = .empty;
    const rn = r.rnd();

    {
        const Kp = Ecdsa.EcdsaP256Sha256.KeyPair;
        var seed: [Kp.seed_length]u8 = undefined;
        rn.bytes(&seed);
        const kp = try arena.create(Kp);
        kp.* = try Kp.generateDeterministic(seed);
        const sb = kp.secret_key.toBytes();
        const pkb = kp.public_key.toUncompressedSec1();
        const der = try ecDer(arena, &.{ 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20 }, &sb, &.{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 });
        _ = try r.o.ask(try arena.print("KEY 0 ec {s}", .{try hx(arena, der)}));
        try sets.append(arena, .{ .scheme = .ecdsa_secp256r1_sha256, .id = 0, .sk = .{ .ecdsa_p256 = &kp.secret_key }, .pk = .{ .ecdsa_p256 = kp.public_key }, .pk_bytes = try arena.dupe(u8, &pkb), .pk2_bytes = "" });
    }
    {
        const Kp = Ecdsa.EcdsaP384Sha384.KeyPair;
        var seed: [Kp.seed_length]u8 = undefined;
        rn.bytes(&seed);
        const kp = try arena.create(Kp);
        kp.* = try Kp.generateDeterministic(seed);
        const sb = kp.secret_key.toBytes();
        const pkb = kp.public_key.toUncompressedSec1();
        const der = try ecDer(arena, &.{ 0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30 }, &sb, &.{ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 });
        _ = try r.o.ask(try arena.print("KEY 1 ec {s}", .{try hx(arena, der)}));
        try sets.append(arena, .{ .scheme = .ecdsa_secp384r1_sha384, .id = 1, .sk = .{ .ecdsa_p384 = &kp.secret_key }, .pk = .{ .ecdsa_p384 = kp.public_key }, .pk_bytes = try arena.dupe(u8, &pkb), .pk2_bytes = "" });
    }
    {
        const Kp = p521.EcdsaP521Sha512.KeyPair;
        var seed: [Kp.seed_length]u8 = undefined;
        rn.bytes(&seed);
        const kp = try arena.create(Kp);
        try Kp.generateDeterministicInto(kp, &seed);
        const sb = kp.secret_key.toBytes();
        const pkb = kp.public_key.toUncompressedSec1();
        const der = try ecDer(arena, &.{ 0x30, 0x50, 0x02, 0x01, 0x01, 0x04, 0x42 }, &sb, &.{ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 });
        _ = try r.o.ask(try arena.print("KEY 2 ec {s}", .{try hx(arena, der)}));
        try sets.append(arena, .{ .scheme = .ecdsa_secp521r1_sha512, .id = 2, .sk = .{ .ecdsa_p521 = &kp.secret_key }, .pk = .{ .ecdsa_p521 = kp.public_key }, .pk_bytes = try arena.dupe(u8, &pkb), .pk2_bytes = "" });
    }
    {
        var seed: [32]u8 = undefined;
        rn.bytes(&seed);
        const kp = try arena.create(Ed25519.KeyPair);
        kp.* = try Ed25519.KeyPair.generateDeterministic(seed);
        const edpk = kp.public_key.toBytes();
        _ = try r.o.ask(try arena.print("KEY 3 ed {s}", .{try hx(arena, &seed)}));
        try sets.append(arena, .{ .scheme = .ed25519, .id = 3, .sk = .{ .ed25519 = &kp.secret_key }, .pk = .{ .ed25519 = kp.public_key }, .pk_bytes = try arena.dupe(u8, &edpk), .pk2_bytes = "" });
    }
    {
        // One RSA-2048 key for the three PSS schemes: the fixture of certverify_kat_vectors.
        const f = kv.rsa_pss_sha256_server;
        const sk = try arena.create(rsa.SecretKey);
        try f.secretKey(sk);
        const pk = try f.publicKey();
        _ = try r.o.ask(try arena.print("KEY 4 rsa {s} {s} {s} {s} {s}", .{ try hx(arena, &f.n), try hx(arena, &f.e), try hx(arena, &f.d), try hx(arena, &f.p), try hx(arena, &f.q) }));
        for ([_]cv.SignatureScheme{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 }) |s|
            try sets.append(arena, .{ .scheme = s, .id = 4, .sk = .{ .rsa = sk }, .pk = .{ .rsa = pk }, .pk_bytes = try arena.dupe(u8, &f.n), .pk2_bytes = try arena.dupe(u8, &f.e) });
    }
    try mldsaSet(r, &sets, 5, "mldsa44", mldsa.MLDSA44);
    try mldsaSet(r, &sets, 6, "mldsa65", mldsa.MLDSA65);
    try mldsaSet(r, &sets, 7, "mldsa87", mldsa.MLDSA87);
    return sets.items;
}

fn mldsaSet(r: *Run, sets: *std.ArrayList(SigSet), id: u8, comptime tag: []const u8, comptime M: type) !void {
    const arena = r.arena;
    var seed: [32]u8 = undefined;
    r.rnd().bytes(&seed);
    const kp = try arena.create(M.KeyPair);
    kp.* = try M.KeyPair.generateDeterministic(seed);
    const pkb = try arena.dupe(u8, &kp.public_key.toBytes());
    _ = try r.o.ask(try arena.print("KEY {d} " ++ tag ++ " {s}", .{ id, try hx(arena, &seed) }));
    try sets.append(arena, .{
        .scheme = @field(cv.SignatureScheme, tag),
        .id = id,
        .sk = @unionInit(cv.SecretKey, tag, &kp.secret_key),
        .pk = @unionInit(cv.PublicKey, tag, pkb),
        .pk_bytes = pkb,
        .pk2_bytes = "",
    });
}

fn flipBit(r: *Run, sig: []const u8) ![]u8 {
    const b = try r.arena.dupe(u8, sig);
    b[r.rnd().uintLessThan(usize, b.len)] ^= @as(u8, 1) << r.rnd().int(u3);
    return b;
}

fn sigCase(r: *Run, s: SigSet, it: usize) !void {
    const arena = r.arena;
    const name = @tagName(s.scheme);
    const side: cv.Side = if (r.rnd().boolean()) .server else .client;
    const other: cv.Side = if (side == .server) .client else .server;
    const sc = if (side == .server) "s" else "c";
    const oc = if (side == .server) "c" else "s";
    const th = try r.randBytes(if (r.rnd().boolean()) 32 else 48);
    const buf = try arena.alloc(u8, cv.max_signature_len);
    const rand: ?std.Random = if (s.scheme == .ed25519) null else r.csprng.random();
    const sch = @backingInt(s.scheme);

    // We sign, OpenSSL verifies; one flipped bit; the other context string.
    const sig = cv.sign(s.scheme, s.sk, side, th, rand, buf) catch |e| {
        r.row(false, "{s}: we cannot sign ({t})", .{ name, e });
        return;
    };
    const v = try r.reqf("VERIFY {d} {x} {s} {s} {s}", .{ s.id, sch, sc, try hx(arena, th), try hx(arena, sig) });
    r.row(v != null and std.mem.eql(u8, v.?, "1"), "{s}: OpenSSL does not verify our signature", .{name});
    const bad = try flipBit(r, sig);
    const ours_bad = if (cv.verify(s.scheme, s.pk, side, th, bad)) false else |_| true;
    const v2 = try r.reqf("VERIFY {d} {x} {s} {s} {s}", .{ s.id, sch, sc, try hx(arena, th), try hx(arena, bad) });
    r.row(ours_bad and v2 != null and std.mem.eql(u8, v2.?, "0"), "{s}: flipped bit: we refuse {any}, OpenSSL refuses {any}", .{ name, ours_bad, v2 != null and std.mem.eql(u8, v2.?, "0") });
    const ours_wrong = if (cv.verify(s.scheme, s.pk, other, th, sig)) false else |_| true;
    const v3 = try r.reqf("VERIFY {d} {x} {s} {s} {s}", .{ s.id, sch, oc, try hx(arena, th), try hx(arena, sig) });
    r.row(ours_wrong and v3 != null and std.mem.eql(u8, v3.?, "0"), "{s}: wrong context string: we refuse {any}, OpenSSL refuses {any}", .{ name, ours_wrong, v3 != null and std.mem.eql(u8, v3.?, "0") });

    // OpenSSL signs, we verify; one flipped bit.
    const sg = try r.reqf("SIGN {d} {x} {s} {s}", .{ s.id, sch, sc, try hx(arena, th) }) orelse {
        r.row(false, "{s}: OpenSSL cannot sign", .{name});
        return;
    };
    const osig = try unhex(arena, sg);
    if (cv.verify(s.scheme, s.pk, side, th, osig)) {
        r.row(true, "", .{});
    } else |e| r.row(false, "{s}: we do not verify OpenSSL's signature ({t})", .{ name, e });
    const obad = try flipBit(r, osig);
    const ours_obad = if (cv.verify(s.scheme, s.pk, side, th, obad)) false else |_| true;
    const v4 = try r.reqf("VERIFY {d} {x} {s} {s} {s}", .{ s.id, sch, sc, try hx(arena, th), try hx(arena, obad) });
    r.row(ours_obad and v4 != null and std.mem.eql(u8, v4.?, "0"), "{s}: OpenSSL's signature with a flipped bit: we refuse {any}, OpenSSL refuses {any}", .{ name, ours_obad, v4 != null and std.mem.eql(u8, v4.?, "0") });

    if (it < 2) try r.fz.sig.append(arena, .{
        .scheme = sch,
        .pk = try hx(arena, s.pk_bytes),
        .pk2 = try hx(arena, s.pk2_bytes),
        .client = side == .client,
        .th = try hx(arena, th),
        .sig = try hx(arena, osig),
    });
}

// ---- the frozen file ----

fn lit(w: *std.Io.Writer, s: []const u8) !void {
    try w.print("\"{s}\"", .{s});
}

fn optLit(w: *std.Io.Writer, s: ?[]const u8) !void {
    if (s) |v| try lit(w, v) else try w.writeAll("null");
}

fn writeVectors(r: *Run, io: std.Io, version: []const u8, seed: u64, cases: usize) !void {
    var aw: std.Io.Writer.Allocating = .init(r.arena);
    const w = &aw.writer;
    try w.print(
        \\// SPDX-License-Identifier: MIT
        \\// GENERATED by `zig build interop-tls13 -- --write` (modules/tls13/tools/interop.zig)
        \\// against {s}, seed 0x{x}, --cases {d}. Do not edit: re-take it.
        \\
        \\//! OpenSSL's side of the live oracle, frozen: key-schedule secrets, shared
        \\//! secrets and shares, malformed-peer verdicts and CertificateVerify signatures
        \\//! it produced, replayed by `openssl_oracle_test.zig`. All binary values are hex
        \\//! ("-" is empty); public material and test keys only.
        \\
        \\pub const openssl_version = "{s}";
        \\
        \\pub const Ks = struct {{
        \\    sha384: bool,
        \\    psk: ?[]const u8,
        \\    dhe: ?[]const u8,
        \\    th: [4][]const u8,
        \\    nonce: []const u8,
        \\    label: []const u8,
        \\    ctx: []const u8,
        \\    exp_len: usize,
        \\    key_len: usize,
        \\    /// In the order of `ks_names`.
        \\    fields: [{d}][]const u8,
        \\}};
        \\/// OpenSSL as the server; our client's secret key and share.
        \\pub const KexServer = struct {{ group: u16, secret: []const u8, cshare: []const u8, sshare: []const u8, ss: []const u8 }};
        \\/// OpenSSL as the client; our server draws from `std.Random.DefaultPrng.init(seed)`.
        \\pub const KexClient = struct {{ group: u16, seed: u64, cshare: []const u8, ss: []const u8 }};
        \\/// A malformed peer share given to both; `secret` is our client's key for `client_dir`.
        \\pub const Neg = struct {{ group: u16, client_dir: bool, kind: []const u8, secret: []const u8, share: []const u8, ours: bool, ossl: bool }};
        \\/// A signature OpenSSL made over the RFC 8446 section 4.4.3 content.
        \\pub const Sig = struct {{ scheme: u16, pk: []const u8, pk2: []const u8, client: bool, th: []const u8, sig: []const u8 }};
        \\
        \\pub const ks_names = [_][]const u8{{
    , .{ version, seed, cases, version, ks_names.len });
    for (ks_names) |n| try w.print(" \"{s}\",", .{n});
    try w.writeAll(" };\n\npub const ks = [_]Ks{\n");
    for (r.fz.ks.items) |k| {
        try w.print("    .{{ .sha384 = {any}, .psk = ", .{k.sha384});
        try optLit(w, k.psk);
        try w.writeAll(", .dhe = ");
        try optLit(w, k.dhe);
        try w.writeAll(", .th = .{");
        for (k.th) |t| {
            try w.writeAll(" ");
            try lit(w, t);
            try w.writeAll(",");
        }
        try w.writeAll(" }, .nonce = ");
        try lit(w, k.nonce);
        try w.writeAll(", .label = ");
        try lit(w, k.label);
        try w.writeAll(", .ctx = ");
        try lit(w, k.ctx);
        try w.print(", .exp_len = {d}, .key_len = {d}, .fields = .{{\n", .{ k.exp_len, k.key_len });
        for (k.fields) |f| {
            try w.writeAll("        ");
            try lit(w, f);
            try w.writeAll(",\n");
        }
        try w.writeAll("    } },\n");
    }
    try w.writeAll("};\n\npub const kex_server = [_]KexServer{\n");
    for (r.fz.kex_server.items) |k| {
        try w.print("    .{{ .group = 0x{x:0>4}, .secret = ", .{k.group});
        try lit(w, k.secret);
        try w.writeAll(", .cshare = ");
        try lit(w, k.cshare);
        try w.writeAll(", .sshare = ");
        try lit(w, k.sshare);
        try w.writeAll(", .ss = ");
        try lit(w, k.ss);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n\npub const kex_client = [_]KexClient{\n");
    for (r.fz.kex_client.items) |k| {
        try w.print("    .{{ .group = 0x{x:0>4}, .seed = {d}, .cshare = ", .{ k.group, k.seed });
        try lit(w, k.cshare);
        try w.writeAll(", .ss = ");
        try lit(w, k.ss);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n\npub const neg = [_]Neg{\n");
    for (r.fz.neg.items) |k| {
        try w.print("    .{{ .group = 0x{x:0>4}, .client_dir = {any}, .kind = \"{s}\", .secret = ", .{ k.group, k.client_dir, k.kind });
        try lit(w, k.secret);
        try w.writeAll(", .share = ");
        try lit(w, k.share);
        try w.print(", .ours = {any}, .ossl = {any} }},\n", .{ k.ours, k.ossl });
    }
    try w.writeAll("};\n\npub const sigs = [_]Sig{\n");
    for (r.fz.sig.items) |k| {
        try w.print("    .{{ .scheme = 0x{x:0>4}, .pk = ", .{k.scheme});
        try lit(w, k.pk);
        try w.writeAll(", .pk2 = ");
        try lit(w, k.pk2);
        try w.print(", .client = {any}, .th = ", .{k.client});
        try lit(w, k.th);
        try w.writeAll(", .sig = ");
        try lit(w, k.sig);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    const data = aw.written();
    if (data.len > vectors_budget) {
        std.debug.print(prog ++ ": the frozen file would be {d} bytes, over the {d} budget\n", .{ data.len, vectors_budget });
        return error.TooBig;
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = vectors_path, .data = data });
    try fmtFrozen(r.arena, io, vectors_path);
    std.debug.print(prog ++ ": wrote {s} ({d} bytes; {d} key-schedule, {d}+{d} key-exchange, {d} malformed-peer, {d} signature rows)\n", .{ vectors_path, data.len, r.fz.ks.items.len, r.fz.kex_server.items.len, r.fz.kex_client.items.len, r.fz.neg.items.len, r.fz.sig.items.len });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    var seed: u64 = default_seed;
    var cases: usize = default_cases;
    var write = false;
    const args = try init.minimal.args.toSlice(arena);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--write")) {
            write = true;
        } else if (std.mem.eql(u8, a, "--seed") and i + 1 < args.len) {
            i += 1;
            seed = try std.fmt.parseInt(u64, args[i], 0);
        } else if (std.mem.eql(u8, a, "--cases") and i + 1 < args.len) {
            i += 1;
            cases = try std.fmt.parseInt(usize, args[i], 10);
        } else {
            std.debug.print("usage: zig build interop-tls13 [-- [--seed N] [--cases N] [--write]]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const crypto_so = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, prog, &.{ "zig", "cc" }, abs, c_source, &.{crypto_so});

    const o = try arena.create(Oracle);
    o.* = .{
        .arena = arena,
        .io = io,
        .child = std.process.spawn(io, .{ .argv = &.{exe}, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit }) catch |e| {
            std.debug.print(prog ++ ": could not start {s} ({t})\n", .{ exe, e });
            return 1;
        },
    };
    o.start();
    defer o.stop();

    const version = (try o.ask("VERSION")).?;
    _ = try o.ask(try arena.print("SEED {x}", .{seed}));
    std.debug.print(prog ++ ": {s}, seed 0x{x}, cases {d}\n", .{ version, seed, cases });

    const csprng_seed: [4]u64 = @splat(seed);
    var r: Run = .{ .arena = arena, .o = o, .prng = .init(seed), .csprng = .init(@bitCast(csprng_seed)) };

    // Proportions at the default of 300: 24 schedules (2 rows each), 6 exchanges per
    // direction and group, 3 signing rounds per scheme (5 rows each).
    const ks_n = @max(2, (cases * 24 / default_cases + 1) / 2 * 2);
    const kex_n = @max(1, cases * 6 / default_cases);
    const sig_n = @max(1, cases * 3 / default_cases);

    for (0..ks_n) |k| try ksCase(&r, k);
    const after_ks = r.cases;
    for (groups) |g| try kexGroup(&r, g, kex_n);
    const after_kex = r.cases;
    const sets = try sigKeys(&r);
    for (sets) |s| for (0..sig_n) |k| try sigCase(&r, s, k);

    if (write) try writeVectors(&r, io, version, seed, cases);

    std.debug.print(prog ++ ": key schedule {d} rows, key exchange {d} rows ({d} groups), CertificateVerify {d} rows ({d} schemes)\n", .{ after_ks, after_kex - after_ks, groups.len, r.cases - after_kex, sets.len });
    std.debug.print("cases={d} agree={d}\n", .{ r.cases, r.agree });
    return if (r.agree == r.cases) 0 else 1;
}

/// `zig fmt` the frozen file, so `--write` leaves it as `scripts/test.sh
/// checks-fast`'s fmt check wants it (the writer does not lay out empty
/// lists or long lines the way zig fmt does).
fn fmtFrozen(arena: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "zig", "fmt", path } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("zig fmt {s} failed:\n{s}\n", .{ path, res.stderr });
        return error.FmtFailed;
    }
}
