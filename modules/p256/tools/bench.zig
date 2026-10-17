// SPDX-License-Identifier: MIT

//! Comparative benchmark: `p256` against OpenSSL's P-256 (EVP over the x86-64
//! nistz256 assembly; the reference), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-p256` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, or `LIBCRYPTO_SO`; no headers
//! needed). Run from the repository root.
//!
//! Workloads, one operation each over a 32-byte message (OpenSSL side:
//! `SHA256` + `EVP_PKEY_sign`/`_verify` on contexts set up once):
//!   sign        `EcdsaP256Sha256.KeyPair.sign(msg, null)` (std-shaped API,
//!               RFC 6979 deterministic nonce) vs OpenSSL sign (random nonce)
//!   sign_raw    `ecdsaSignDeterministic` (raw-bytes API) vs the same
//!   verify      `ecdsaVerify` (SEC1 key + r||s, the fast verifier jwt uses)
//!               vs OpenSSL verify
//!   verify_std  `EcdsaP256Sha256.Signature.verify` (the std-shaped verifier)
//!               vs the same OpenSSL verify
//!   ecdh        `P256.mul(peer, d)` + affine x vs `EVP_PKEY_derive` (peer
//!               set once)
//!   keygen      `EcdsaP256Sha256.KeyPair.generate` vs `EVP_PKEY_keygen` (+ free)
//! Inputs are written into `.zig-cache/bench-p256/` from fixed seeds.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them, else by
//! wall time. Before timing anything OpenSSL must verify our signature and we
//! must verify OpenSSL's. Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const p256 = @import("p256");
const Ecdsa = p256.EcdsaP256Sha256;

const bench_name = "bench-p256";
const work_dir = ".zig-cache/bench-p256";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";

const Op = enum { sign, sign_raw, verify, verify_std, ecdh, keygen };

const Ctx = struct {
    io: std.Io,
    kp: Ecdsa.KeyPair,
    sk: [32]u8,
    pub_sec1: [65]u8,
    peer: p256.P256,
    msg: [32]u8,
    sig: [64]u8,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    switch (x.op) {
        .sign => {
            const s = Ecdsa.KeyPair.sign(&x.kp, &x.msg, null) catch unreachable;
            std.mem.doNotOptimizeAway(&s);
            return 64;
        },
        .sign_raw => {
            const s = p256.sign.ecdsaSignDeterministic(&x.sk, &x.msg) catch unreachable;
            std.mem.doNotOptimizeAway(&s);
            return 64;
        },
        .verify => {
            if (!p256.sign.ecdsaVerify(&x.pub_sec1, &x.msg, x.sig)) unreachable;
            return 1;
        },
        .verify_std => {
            Ecdsa.Signature.fromBytes(x.sig).verify(&x.msg, x.kp.public_key) catch unreachable;
            return 1;
        },
        .ecdh => {
            const q = x.peer.mul(x.sk, .big) catch unreachable;
            const shared = q.affineCoordinates().x.toBytes(.big);
            std.mem.doNotOptimizeAway(&shared);
            return 32;
        },
        .keygen => {
            const kp = Ecdsa.KeyPair.generate(x.io);
            std.mem.doNotOptimizeAway(&kp);
            return 65;
        },
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

    var prng = std.Random.DefaultPrng.init(0x9256_be7c);
    const r = prng.random();
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    r.bytes(&seed);
    var ctx: Ctx = undefined;
    ctx.io = io;
    ctx.kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    ctx.sk = ctx.kp.secret_key.toBytes();
    ctx.pub_sec1 = ctx.kp.public_key.toUncompressedSec1();
    r.bytes(&seed);
    const peer_kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    ctx.peer = try p256.P256.fromSec1(&peer_kp.public_key.toUncompressedSec1());
    r.bytes(&ctx.msg);
    ctx.sig = (try Ecdsa.KeyPair.sign(&ctx.kp, &ctx.msg, null)).toBytes();
    var der_buf: [p256.sign.der_max_len]u8 = undefined;
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &ctx.msg });
    try dir.writeFile(io, .{ .sub_path = "ours_pub.bin", .data = &ctx.pub_sec1 });
    try dir.writeFile(io, .{ .sub_path = "ours_sig.der", .data = p256.sign.rawToDer(ctx.sig, &der_buf) });

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/p256/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: OpenSSL verified ours inside `interop`; now ours
    // verifies OpenSSL's.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    const their_pub = try dir.readFileAlloc(io, "ossl_pub.bin", arena, .limited(4096));
    const their_der = try dir.readFileAlloc(io, "ossl_sig.der", arena, .limited(4096));
    const their_sig = p256.sign.derToRaw(their_der) orelse {
        std.debug.print("bench-p256: FAILED -- OpenSSL's DER signature does not parse\n", .{});
        return 1;
    };
    if (!p256.sign.ecdsaVerify(their_pub, &ctx.msg, their_sig)) {
        std.debug.print("bench-p256: FAILED -- OpenSSL's signature does not verify here\n", .{});
        return 1;
    }

    const ws = [_]Work{
        .{ .name = "sign", .op = .sign, .ref = "ossl.sign" },
        .{ .name = "sign_raw", .op = .sign_raw, .ref = "ossl.sign" },
        .{ .name = "verify", .op = .verify, .ref = "ossl.verify" },
        .{ .name = "verify_std", .op = .verify_std, .ref = "ossl.verify" },
        .{ .name = "ecdh", .op = .ecdh, .ref = "ossl.ecdh" },
        .{ .name = "keygen", .op = .keygen, .ref = "ossl.keygen" },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
