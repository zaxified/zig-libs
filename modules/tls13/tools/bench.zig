// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tls13` against OpenSSL 3.5's libcrypto (the
//! reference named by the maturity card), the program behind the
//! `**Performance:**` line of the card (CONVENTIONS.md §9, kept instrument
//! kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tls13` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds the C side, `tools/c_bench/foreign_bench.c`, with `zig cc -O3
//! -march=native`) and the system OpenSSL 3.5 (`libcrypto.so.3`, path below or
//! `LIBCRYPTO_SO`; no headers needed). Run from the repository root.
//!
//! `tls13` is a set of primitives, not a connection, so the comparison is per
//! primitive, against what a TLS stack calls in libcrypto -- public EVP APIs
//! only, no libssl:
//!   ks256, ks384    one full-handshake key schedule (RFC 8446 §7.1): early,
//!                   handshake and master secrets, client and server handshake
//!                   and application traffic secrets, the exporter master secret
//!                   and one 32-octet TLS-Exporter output. Ours: `keyschedule`;
//!                   OpenSSL: EVP_KDF "HKDF" (EXTRACT_ONLY / EXPAND_ONLY, the HkdfLabel built in C; "TLS13-KDF" works too, but its EXTRACT_ONLY `salt` is the PREVIOUS secret, Derive-Secret'd with the caller's label first -- see SPEC § Interop),
//!                   a fresh EVP_KDF_CTX per call.
//!   gen_<g>         the client's key generation and the encoding of its share
//!   srv_<g>         the server: parse the client's share, generate or
//!                   encapsulate, encode its share, derive the shared secret
//!   cli_<g>         the client: parse the server's share, derive or decapsulate
//!                   (ours: `kex.generate[Expanded]`, `kex.serverExchange`,
//!                   `kex.sharedSecret[Expanded]`; OpenSSL: EVP_PKEY keygen / fromdata /
//!                   derive / encapsulate / decapsulate, the hybrids composed
//!                   from their parts in the draft's layout)
//!   sign_<s>, verify_<s>   a CertificateVerify signature over the RFC 8446
//!                   §4.4.3 signed content (ours: `certverify.sign` / `verify`;
//!                   OpenSSL: EVP_DigestSign / EVP_DigestVerify, a fresh
//!                   EVP_MD_CTX per call as libssl does)
//! <g> is x25519, secp256r1, secp384r1, x25519mlkem768, secp256r1mlkem768,
//! secp384r1mlkem1024, mlkem1024; <s> is ecdsa_secp256r1_sha256,
//! ecdsa_secp384r1_sha384, rsa_pss_rsae_sha256 (RSA-2048) or ed25519. The count
//! is 1 per operation. Notes on what the rows contain: the ML-KEM groups use
//! `kex.generateExpanded` (`gen_*`: keygen also hands back the expanded
//! decapsulation key, as OpenSSL's keygen leaves it in the EVP_PKEY) and
//! `kex.sharedSecretExpanded` (`cli_*`: decapsulation only, no seed
//! re-expansion, as the OpenSSL client holds the expanded key). Nothing is
//! expanded outside a timed region: the one expansion is inside `gen_*`. Randomness: ours draws from a
//! ChaCha CSPRNG seeded once (also given to the ECDSA and RSA-PSS signers);
//! OpenSSL draws from its own DRBG.
//!
//! Before anything is timed, both sides must agree (the interop gate): for the
//! fixed inputs the key schedule's every secret and the exporter output are
//! identical; for every group the OpenSSL server accepts our client share and
//! we derive its secret, and our server accepts OpenSSL's client share and
//! OpenSSL derives ours; OpenSSL verifies each of our signatures and we verify
//! each of OpenSSL's, over the same signed content. The keys are the fixtures
//! of `certverify_kat_vectors`.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the spread
//! printed is (worst round − best round) / best round per side. Ratios are
//! ours/OpenSSL by user-mode cycles when both sides count them, else by wall
//! time. Arguments filter workloads by substring (no card line then).
//!
//! The fastest candidate of the field, aws-lc-rs 1.18.0 (rustls' provider, the
//! same pin as `modules/tlsserver/tools/rust_bench`), is the `alt` column:
//! `tools/rust_bench` (read its header) is built once with `cargo build
//! --release --locked --offline` into `.zig-cache/bench-tls13/target`, passes
//! the same interop gate (its secrets and signatures against ours, both ways;
//! files `aws_*` / `zigA_*`), and runs the same rows. Forced differences: the
//! key schedule's Extract is HMAC via `hmac::sign` and Expand a fresh
//! `hkdf::Prk` per call (aws-lc-rs hides the PRK bytes); there is no hybrid
//! group in aws-lc-rs, so the hybrids are composed from parts as for OpenSSL;
//! signing keys are parsed once and there is no per-call context object;
//! owned `Vec` results stay in the timing. `/fast` is ours over the faster of
//! OpenSSL and aws-lc-rs per row. No row is missing: aws-lc-rs does all 27.

const std = @import("std");
const bench = @import("testkit").bench;
const tls13 = @import("tls13");
const rsa = @import("rsa");

const kex = tls13.kex;
const cv = tls13.certverify;
const kv = tls13.certverify_kat_vectors;
const keyschedule = tls13.keyschedule;
const Work = bench.Work(Op);
const Ed25519 = std.crypto.sign.Ed25519;
const Ecdsa = std.crypto.sign.ecdsa;

const bench_name = "bench-tls13";
const work_dir = ".zig-cache/bench-tls13";
const cargo_manifest = "modules/tls13/tools/rust_bench/Cargo.toml";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const seed: u8 = 0x5e;

const Kind = enum { ks, gen, srv, cli, sign, verify };
const Op = struct { kind: Kind = .ks, idx: u8 = 0 };
const Ctx = struct { op: Op = .{} };

// ---- key schedule ----

const exporter_label = "EXPERIMENTAL bench";
const exporter_context = "bench-exporter-c";

fn Ks(comptime Hash: type, comptime Hkdf: type) type {
    return struct {
        const L = Hkdf.prk_length;
        const out_len = 8 * L + 32;
        var dhe: [L]u8 = undefined;
        var th_hs: [L]u8 = undefined;
        var th_ap: [L]u8 = undefined;
        /// early, hs, hs_c, hs_s, ms, ap_c, ap_s, exp (L each), then the 32-octet export.
        var out: [out_len]u8 = undefined;

        fn init() void {
            for (0..L) |j| {
                dhe[j] = @truncate(j * 3 + 1);
                th_hs[j] = @truncate(0x40 + j);
                th_ap[j] = @truncate(0x80 + j);
            }
        }

        fn run() void {
            const sched = keyschedule.tls13;
            const zeros: [L]u8 = @splat(0);
            const empty = keyschedule.emptyTranscriptHash(Hash);
            const early = out[0..L];
            const hs = out[L..][0..L];
            const ms = out[4 * L ..][0..L];
            const exp = out[7 * L ..][0..L];
            sched.earlySecret(Hkdf, early, &zeros);
            sched.deriveHandshakeSecret(Hkdf, hs, early, empty, &dhe);
            sched.deriveHandshakeTrafficSecrets(Hkdf, out[2 * L ..][0..L], out[3 * L ..][0..L], hs, &th_hs);
            sched.deriveMasterSecret(Hkdf, ms, hs, empty);
            sched.deriveApplicationSecrets(Hkdf, out[5 * L ..][0..L], out[6 * L ..][0..L], exp, ms, &th_ap);
            sched.exportKeyingMaterial(Hash, Hkdf, out[8 * L ..][0..32], exp, exporter_label, exporter_context) catch @panic("exportKeyingMaterial");
        }
    };
}

const Ks256 = Ks(std.crypto.hash.sha2.Sha256, std.crypto.kdf.hkdf.HkdfSha256);
const Ks384 = Ks(std.crypto.hash.sha2.Sha384, std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384));

// ---- key exchange ----

const Group = struct { name: []const u8, id: u16 };
/// The order and names are the C side's.
const groups = [_]Group{
    .{ .name = "x25519", .id = kex.x25519_group },
    .{ .name = "secp256r1", .id = kex.secp256r1_group },
    .{ .name = "secp384r1", .id = kex.secp384r1_group },
    .{ .name = "x25519mlkem768", .id = kex.x25519_mlkem768_group },
    .{ .name = "secp256r1mlkem768", .id = kex.secp256r1_mlkem768_group },
    .{ .name = "secp384r1mlkem1024", .id = kex.secp384r1_mlkem1024_group },
    .{ .name = "mlkem1024", .id = kex.mlkem1024_group },
};

var csprng: std.Random.DefaultCsprng = undefined;
/// Per group: the client's key pair and the server's answer to its share.
var client_kp: [groups.len]kex.KeyPair = undefined;
var server_x: [groups.len]kex.ServerExchange = undefined;
var scratch_kp: kex.KeyPair = undefined;
var client_exp: [groups.len]kex.Expanded = @splat(.none);
var scratch_exp: kex.Expanded = .none;
var scratch_x: kex.ServerExchange = undefined;
var scratch_ss: kex.SharedSecret = undefined;

fn kexSetup() !void {
    csprng = .init(@splat(seed));
    for (groups, 0..) |g, i| {
        try kex.generateExpanded(g.id, csprng.random(), &client_kp[i], &client_exp[i]);
        try kex.serverExchange(g.id, client_kp[i].public[0..client_kp[i].public_len], csprng.random(), &server_x[i]);
    }
}

// ---- CertificateVerify ----

const schemes = [_]cv.SignatureScheme{ .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256, .ed25519 };
const th256: [32]u8 = @splat(0x11);
const th384: [48]u8 = @splat(0x22);
/// The transcript hash signed under each scheme (the C side's `sch_th`).
const transcripts = [_][]const u8{ &th256, &th384, &th256, &th256 };

var p256_sk: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var p384_sk: Ecdsa.EcdsaP384Sha384.SecretKey = undefined;
var ed_kp: Ed25519.KeyPair = undefined;
/// The Ed25519 row signs through the prepared signer (public-key check once at
/// load, as aws-lc-rs/OpenSSL hold a loaded key); `certverify.sign` re-derives
/// the public key on every call and is the `.every_sign` configuration.
var ed_signer: cv.Ed25519Signer = undefined;
var rsa_sk: rsa.SecretKey = undefined;
var sign_keys: [schemes.len]cv.SecretKey = undefined;
var verify_keys: [schemes.len]cv.PublicKey = undefined;
var sigs: [schemes.len][cv.max_signature_len]u8 = undefined;
var sig_lens: [schemes.len]usize = undefined;
var scratch_sig: [cv.max_signature_len]u8 = undefined;

fn signRandom(i: usize) ?std.Random {
    return if (schemes[i] == .ed25519) null else csprng.random();
}

fn signSetup() !void {
    p256_sk = try kv.ecdsa_p256_server.secretKey();
    p384_sk = try kv.ecdsa_p384_server.secretKey();
    ed_kp = try kv.ed25519_client.keyPair();
    ed_signer = try cv.Ed25519Signer.init(&ed_kp.secret_key);
    try kv.rsa_pss_sha256_server.secretKey(&rsa_sk);
    sign_keys = .{ .{ .ecdsa_p256 = &p256_sk }, .{ .ecdsa_p384 = &p384_sk }, .{ .rsa = &rsa_sk }, .{ .ed25519 = &ed_kp.secret_key } };
    verify_keys = .{
        .{ .ecdsa_p256 = try kv.ecdsa_p256_server.publicKey() },
        .{ .ecdsa_p384 = try kv.ecdsa_p384_server.publicKey() },
        .{ .rsa = try kv.rsa_pss_sha256_server.publicKey() },
        .{ .ed25519 = ed_kp.public_key },
    };
    for (schemes, 0..) |s, i| {
        const sig = try cv.sign(s, sign_keys[i], .server, transcripts[i], signRandom(i), &sigs[i]);
        sig_lens[i] = sig.len;
        try cv.verify(s, verify_keys[i], .server, transcripts[i], sig);
    }
}

// ---- the timed operations ----

fn once(x: *Ctx) usize {
    const i: usize = x.op.idx;
    switch (x.op.kind) {
        .ks => if (i == 0) Ks256.run() else Ks384.run(),
        .gen => kex.generateExpanded(groups[i].id, csprng.random(), &scratch_kp, &scratch_exp) catch @panic("kex.generateExpanded"),
        .srv => kex.serverExchange(groups[i].id, client_kp[i].public[0..client_kp[i].public_len], csprng.random(), &scratch_x) catch @panic("kex.serverExchange"),
        .cli => kex.sharedSecretExpanded(groups[i].id, client_kp[i].secret[0..kex.scalarLen(groups[i].id)], &client_exp[i], server_x[i].public[0..server_x[i].public_len], &scratch_ss) catch @panic("kex.sharedSecretExpanded"),
        .sign => {
            const sig = (if (schemes[i] == .ed25519)
                ed_signer.sign(.server, transcripts[i], null, &scratch_sig)
            else
                cv.sign(schemes[i], sign_keys[i], .server, transcripts[i], signRandom(i), &scratch_sig)) catch @panic("certverify.sign");
            std.mem.doNotOptimizeAway(sig.len);
        },
        .verify => cv.verify(schemes[i], verify_keys[i], .server, transcripts[i], sigs[i][0..sig_lens[i]]) catch @panic("certverify.verify"),
    }
    return 1;
}

// ---- interop ----

fn put(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime fmt: []const u8, args: anytype, data: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = try arena.print(fmt, args), .data = data });
}

fn get(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return dir.readFileAlloc(io, try arena.print(fmt, args), arena, .limited(1 << 16));
}

fn fail(comptime fmt: []const u8, args: anytype) error{InteropFailed} {
    std.debug.print(bench_name ++ ": FAILED -- " ++ fmt ++ "\n", args);
    return error.InteropFailed;
}

/// Everything the foreign sides need from us for their half of the check.
fn writeOurs(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator) !void {
    Ks256.init();
    Ks384.init();
    Ks256.run();
    Ks384.run();
    try put(dir, io, arena, "zig_ks256.bin", .{}, &Ks256.out);
    try put(dir, io, arena, "zig_ks384.bin", .{}, &Ks384.out);
    for (groups, 0..) |g, i|
        try put(dir, io, arena, "zig_{s}.cshare", .{g.name}, client_kp[i].public[0..client_kp[i].public_len]);
    // The signing keys for OpenSSL: SEC1 ECPrivateKey (RFC 5915: version 1,
    // the scalar, the curve's OID) for the curves, the seed for Ed25519, the
    // RSA components big-endian (OpenSSL derives the CRT values).
    try put(dir, io, arena, "ec256.der", .{}, &(.{ 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ kv.ecdsa_p256_server.secret_key_bytes ++ .{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }));
    try put(dir, io, arena, "ec384.der", .{}, &(.{ 0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30 } ++ kv.ecdsa_p384_server.secret_key_bytes ++ .{ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }));
    try put(dir, io, arena, "ed25519.seed", .{}, &kv.ed25519_client.seed);
    const r = kv.rsa_pss_sha256_server;
    try put(dir, io, arena, "rsa_n.bin", .{}, &r.n);
    try put(dir, io, arena, "rsa_e.bin", .{}, &r.e);
    try put(dir, io, arena, "rsa_d.bin", .{}, &r.d);
    try put(dir, io, arena, "rsa_p.bin", .{}, &r.p);
    try put(dir, io, arena, "rsa_q.bin", .{}, &r.q);
    // aws-lc-rs takes the RSA key as PKCS#1 DER (it validates the CRT values).
    const der_buf = try arena.alloc(u8, 4096);
    try put(dir, io, arena, "rsa_pkcs1.der", .{}, try rsa_sk.toPkcs1Der(der_buf));
    for (schemes, 0..) |s, i|
        try put(dir, io, arena, "zig_sig_{s}.sig", .{@tagName(s)}, sigs[i][0..sig_lens[i]]);
}

const Who = struct { label: []const u8, theirs: []const u8, ours: []const u8 };
const ossl: Who = .{ .label = "OpenSSL", .theirs = "ossl", .ours = "zig" };
const aws: Who = .{ .label = "aws-lc-rs", .theirs = "aws", .ours = "zigA" };

/// Our half two of the key exchange (OpenSSL served our client share), and
/// our server's answer to OpenSSL's client share, for `interop2`.
/// `who` names the foreign side and the files: OpenSSL's are `ossl_*` and ours
/// for it `zig_*`; aws-lc-rs's are `aws_*` and ours for it `zigA_*`.
fn checkKex(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime who: Who) !void {
    for (groups, 0..) |g, i| {
        const theirs_share = try get(dir, io, arena, who.theirs ++ "_{s}.sshare", .{g.name});
        const theirs_ss = try get(dir, io, arena, who.theirs ++ "_{s}.sss", .{g.name});
        var ss: kex.SharedSecret = undefined;
        kex.sharedSecret(g.id, client_kp[i].secret[0..kex.scalarLen(g.id)], theirs_share, &ss) catch |e|
            return fail("{s}: our client rejects {s}'s server share ({t})", .{ g.name, who.label, e });
        if (!std.mem.eql(u8, ss.slice(), theirs_ss)) return fail("{s}: our client's shared secret differs from {s}'s server's", .{ g.name, who.label });
        const their_client = try get(dir, io, arena, who.theirs ++ "_{s}.cshare", .{g.name});
        var x: kex.ServerExchange = undefined;
        kex.serverExchange(g.id, their_client, csprng.random(), &x) catch |e|
            return fail("{s}: our server rejects {s}'s client share ({t})", .{ g.name, who.label, e });
        try put(dir, io, arena, who.ours ++ "_{s}.sshare", .{g.name}, x.public[0..x.public_len]);
        try put(dir, io, arena, who.ours ++ "_{s}.sss", .{g.name}, x.shared.slice());
    }
}

fn checkSigs(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime who: Who) !void {
    for (schemes, 0..) |s, i| {
        const sig = try get(dir, io, arena, who.theirs ++ "_sig_{s}.sig", .{@tagName(s)});
        cv.verify(s, verify_keys[i], .server, transcripts[i], sig) catch |e|
            return fail("{s}: we do not verify {s}'s signature ({t})", .{ @tagName(s), who.label, e });
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    try kexSetup();
    try signSetup();
    try writeOurs(dir, io, arena);

    const crypto_so = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/tls13/tools/c_bench/foreign_bench.c", &.{crypto_so});
    // OpenSSL checks the key schedule, serves our client shares and verifies
    // our signatures; we then check its half, and it checks ours.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    try checkKex(dir, io, arena, ossl);
    try checkSigs(dir, io, arena, ossl);
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop2");
    std.debug.print("{s}: interop OK with OpenSSL (key schedule SHA-256 and SHA-384 identical; {d} groups agree both ways; {d} signature schemes verify both ways)\n", .{ bench_name, groups.len, schemes.len });

    // aws-lc-rs: built once, offline, then the same gate.
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const cargo = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (cargo.term != .exited or cargo.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, cargo.stderr });
        return 1;
    }
    const rust_exe = try arena.print("{s}/release/rust_bench", .{target});
    try bench.foreignOnce(arena, io, bench_name, rust_exe, abs, "interop");
    try checkKex(dir, io, arena, aws);
    try checkSigs(dir, io, arena, aws);
    try bench.foreignOnce(arena, io, bench_name, rust_exe, abs, "interop2");
    std.debug.print("{s}: interop OK with aws-lc-rs (same checks)\n", .{bench_name});

    var ws: std.ArrayList(Work) = .empty;
    try ws.append(arena, .{ .name = "ks256", .op = .{ .kind = .ks, .idx = 0 }, .ref = "ks256", .alt = "ks256", .alt_exe = 1 });
    try ws.append(arena, .{ .name = "ks384", .op = .{ .kind = .ks, .idx = 1 }, .ref = "ks384", .alt = "ks384", .alt_exe = 1 });
    inline for (.{ .gen, .srv, .cli }) |k| {
        for (groups, 0..) |g, i| {
            const n = try arena.print("{s}_{s}", .{ @tagName(k), g.name });
            try ws.append(arena, .{ .name = n, .op = .{ .kind = k, .idx = @intCast(i) }, .ref = n, .alt = n, .alt_exe = 1 });
        }
    }
    inline for (.{ .sign, .verify }) |k| {
        for (schemes, 0..) |s, i| {
            const n = try arena.print("{s}_{s}", .{ @tagName(k), @tagName(s) });
            try ws.append(arena, .{ .name = n, .op = .{ .kind = k, .idx = @intCast(i) }, .ref = n, .alt = n, .alt_exe = 1 });
        }
    }

    var ctx: Ctx = .{};
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ exe, rust_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\ncandidate: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3}); worst ours/min(OpenSSL, aws-lc-rs) = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> libcrypto (key schedule, 7 key-exchange groups, 4 CertificateVerify schemes) · fastest {d:.2}× worst vs the faster of OpenSSL and aws-lc-rs 1.18.0 (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
