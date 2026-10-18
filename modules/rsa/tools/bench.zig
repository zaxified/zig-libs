// SPDX-License-Identifier: MIT

//! Comparative benchmark: `rsa` against OpenSSL's RSA (EVP; the reference),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-rsa` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, or `LIBCRYPTO_SO`; no headers
//! needed). Run from the repository root. OpenSSL generates the 2048-, 3072-
//! and 4096-bit keys (once per run) into `.zig-cache/bench-rsa/`; both sides
//! load the same keys.
//!
//! Workloads, per key size, one operation each on a warm key (built once:
//! the key-construction cost is a separate matter, see SPEC "Performance"):
//!   sign_<b>    `signPkcs1v15(Sha256)` -- this module's default, base
//!               blinding OFF -- vs OpenSSL PKCS#1 v1.5 sign (blinding ON)
//!   signbl_<b>  `signPkcs1v15Blinded(.csprng)` vs the same OpenSSL sign
//!   verify_<b>  `verifyPkcs1v15(Sha256)` vs OpenSSL verify
//!   dec_<b>     `decryptOaep(Sha256)` (blinding OFF) vs OpenSSL OAEP decrypt
//!   decbl_<b>   `decryptOaepBlinded(.csprng)` vs the same OpenSSL decrypt
//!   signca_<b>, decca_<b>  the same with `.cached` blinding (one
//!               `BlindingCache`, the scheme OpenSSL itself runs)
//! The message is 32 bytes (OpenSSL side: `SHA256` + `EVP_PKEY_sign/verify`).
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them, else by
//! wall time. Before timing anything OpenSSL's signature must equal ours byte
//! for byte (PKCS#1 v1.5 is deterministic) and OpenSSL must decrypt our OAEP
//! ciphertext to the message. Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const rsa = @import("rsa");
const Sha256 = std.crypto.hash.sha2.Sha256;

const bench_name = "bench-rsa";
const work_dir = ".zig-cache/bench-rsa";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const sizes = [_]usize{ 2048, 3072, 4096 };

const Kind = enum { sign, signbl, signca, verify, dec, decbl, decca };
const Op = struct { kind: Kind, size: usize };

const Key = struct {
    sk: *rsa.SecretKey,
    pk: rsa.PublicKey,
    sig: []u8,
    ct: []u8,
};

const Ctx = struct {
    keys: [sizes.len]Key,
    msg: [32]u8,
    out: [512]u8,
    rng: std.Random,
    cache: rsa.BlindingCache,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    const k = &x.keys[std.mem.indexOfScalar(usize, &sizes, x.op.size).?];
    switch (x.op.kind) {
        .sign => return (rsa.signPkcs1v15(k.sk, Sha256, &x.msg, &x.out) catch unreachable).len,
        .signbl => return (rsa.signPkcs1v15Blinded(k.sk, Sha256, .{ .csprng = x.rng }, &x.msg, &x.out) catch unreachable).len,
        .signca => return (rsa.signPkcs1v15Blinded(k.sk, Sha256, .{ .cached = &x.cache }, &x.msg, &x.out) catch unreachable).len,
        .verify => {
            rsa.verifyPkcs1v15(k.pk, Sha256, &x.msg, k.sig) catch unreachable;
            return 1;
        },
        .dec => return (rsa.decryptOaep(k.sk, Sha256, k.ct, "", &x.out) catch unreachable).len,
        .decbl => return (rsa.decryptOaepBlinded(k.sk, Sha256, .{ .csprng = x.rng }, k.ct, "", &x.out) catch unreachable).len,
        .decca => return (rsa.decryptOaepBlinded(k.sk, Sha256, .{ .cached = &x.cache }, k.ct, "", &x.out) catch unreachable).len,
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

    var prng = std.Random.DefaultPrng.init(0x45a_be7c);
    var csprng = std.Random.DefaultCsprng.init(@splat(0x5a));
    var ctx: Ctx = undefined;
    ctx.rng = csprng.random();
    ctx.cache = rsa.BlindingCache.init(ctx.rng);
    defer ctx.cache.deinit();
    prng.random().bytes(&ctx.msg);
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &ctx.msg });

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/rsa/tools/c_bench/foreign_bench.c", &.{so});
    std.debug.print("bench-rsa: OpenSSL generating the keys ...\n", .{});
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "keygen");

    for (sizes, 0..) |bits, i| {
        const k = &ctx.keys[i];
        const sk_der = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "sk_{d}.der", .{bits}), arena, .limited(1 << 16));
        const pk_der = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "pk_{d}.der", .{bits}), arena, .limited(1 << 16));
        k.sk = try arena.create(rsa.SecretKey);
        try rsa.SecretKey.fromDer(k.sk, sk_der);
        k.pk = try rsa.PublicKey.fromDer(pk_der);
        k.sig = try arena.dupe(u8, try rsa.signPkcs1v15(k.sk, Sha256, &ctx.msg, &ctx.out));
        k.ct = try arena.dupe(u8, try rsa.encryptOaep(k.pk, Sha256, ctx.rng, &ctx.msg, "", &ctx.out));
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "ct_{d}.bin", .{bits}), .data = k.ct });
    }

    // Interop before timing: OpenSSL decrypts our OAEP ciphertexts (checked in
    // `interop`); its PKCS#1 v1.5 signatures must equal ours byte for byte.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    for (sizes, 0..) |bits, i| {
        const theirs = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "sig_{d}.bin", .{bits}), arena, .limited(4096));
        if (!std.mem.eql(u8, theirs, ctx.keys[i].sig)) {
            std.debug.print("bench-rsa: FAILED -- OpenSSL's {d}-bit signature differs from ours\n", .{bits});
            return 1;
        }
    }

    var ws: std.ArrayList(Work) = .empty;
    for (sizes) |bits| for (std.enums.values(Kind)) |kind| {
        const theirs: []const u8 = switch (kind) {
            .sign, .signbl, .signca => "sign",
            .verify => "verify",
            .dec, .decbl, .decca => "dec",
        };
        try ws.append(arena, .{
            .name = try std.fmt.allocPrint(arena, "{s}_{d}", .{ @tagName(kind), bits }),
            .op = .{ .kind = kind, .size = bits },
            .ref = try std.fmt.allocPrint(arena, "ossl.{s}_{d}", .{ theirs, bits }),
        });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
