// SPDX-License-Identifier: MIT

//! Comparative benchmark: `aescbc` against Go's `crypto/cipher` CBC (the
//! card's reference) and OpenSSL's EVP AES-256-CBC (the fastest candidate),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-aescbc` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` (1.26,
//! stdlib only, built with `GOTOOLCHAIN=local GOPROXY=off` from
//! `tools/go_bench`), `zig` on PATH (it builds `tools/c_bench/foreign_bench.c`
//! with `zig cc -O3 -march=native`) and the system OpenSSL 3
//! (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no headers needed). Run
//! from the repository root.
//!
//! Workloads, AES-256, key schedule set up once unless named: `enc_N` /
//! `dec_N` -- one N-byte message per op, IV set per op (ours: `Encryptor` /
//! `Decryptor` `setIv` + `update`; Go: `NewCBCEncrypter`/`Decrypter` over one
//! `cipher.Block` + `CryptBlocks`; OpenSSL: `EVP_*Init_ex` with only the IV +
//! `Update`); `oneshot_dec_1024` -- key AND IV per op (ours: `decrypt`, burn
//! included; Go: `aes.NewCipher` + decrypter; OpenSSL: `EVP_DecryptInit_ex`
//! with key and IV); `pkcs7_dec_1024` -- decrypt + PKCS#7 removal of a
//! 1008-byte message (ours: `update` + `unpadPkcs7`; Go: the loop a Go user
//! writes, crypto/cipher has none; OpenSSL: padding on, `Update` + `Final`);
//! `stream_enc_1008` -- the encrypting side of that (ours: `StreamEncryptor`
//! `update` + `finish`; Go: padding by hand + `CryptBlocks`);
//! `cts_enc_1000` / `cts_dec_1000` -- ciphertext stealing, CS3, key and IV
//! per op (ours: `encryptCts`/`decryptCts`; OpenSSL: `AES-256-CBC-CTS`,
//! `EVP_CipherInit_ex2` with key and IV -- Go has no CTS, so these two rows' `ref` column is
//! OpenSSL and the card's Go ratio leaves them out).
//! Inputs are written into `.zig-cache/bench-aescbc/` from fixed seeds.
//!
//! Method (`testkit.bench`, shared by every crypto module's bench):
//! each side doubles its batch until it takes over 100 ms and keeps the best
//! of five; per workload the sides alternate for `BENCH_ROUNDS` (default 3)
//! rounds, each keeping its best. Ratios are ours/theirs by user-mode cycles
//! when all sides count them, else by wall time. Before timing anything, Go's
//! and OpenSSL's CBC of the 16 KiB message, OpenSSL's PKCS#7-padded
//! ciphertext (one-shot and streamed) and OpenSSL's CTS in all three variants
//! over eight lengths must equal ours byte for byte.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const aescbc = @import("aescbc");
const Aes256 = std.crypto.core.aes.Aes256;

const bench_name = "bench-aescbc";
const work_dir = ".zig-cache/bench-aescbc";
const go_dir = "modules/aescbc/tools/go_bench";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const len = 16384;

/// The OpenSSL-only rows first: the driver keeps the last `ref` banner it saw.
const Op = enum { cts_enc_1000, cts_dec_1000, enc_16384, dec_16384, enc_64, dec_64, oneshot_dec_1024, pkcs7_dec_1024, stream_enc_1008 };
/// Workloads Go's crypto/cipher has no counterpart for: timed against OpenSSL
/// alone, which is then their `ref` column.
const openssl_only = [_]Op{ .cts_enc_1000, .cts_dec_1000 };

const Ctx = struct {
    enc: aescbc.Encryptor(Aes256),
    dec: aescbc.Decryptor(Aes256),
    key: [32]u8,
    iv: [16]u8,
    msg: *[len]u8,
    ct: *[len]u8,
    pad: [1024]u8,
    cts: [1000]u8,
    stream: aescbc.StreamEncryptor(Aes256, .pkcs7),
    out: *[len]u8,
    op: Op = undefined,
};

fn encN(x: *Ctx, n: usize) usize {
    x.enc.setIv(x.iv);
    return x.enc.update(x.msg[0..n], x.out[0..n]) catch unreachable;
}

fn decN(x: *Ctx, n: usize) usize {
    x.dec.setIv(x.iv);
    return x.dec.update(x.ct[0..n], x.out[0..n]) catch unreachable;
}

fn once(x: *Ctx) usize {
    const r = switch (x.op) {
        .enc_16384 => encN(x, len),
        .dec_16384 => decN(x, len),
        .enc_64 => encN(x, 64),
        .dec_64 => decN(x, 64),
        .oneshot_dec_1024 => aescbc.decrypt(Aes256, &x.key, x.iv, x.ct[0..1024], x.out) catch unreachable,
        .stream_enc_1008 => blk: {
            x.stream.setIv(x.iv);
            const a = x.stream.update(x.msg[0..1008], x.out) catch unreachable;
            break :blk a + (x.stream.finish(x.out[a..]) catch unreachable);
        },
        .cts_enc_1000 => aescbc.encryptCts(Aes256, .cs3, &x.key, x.iv, x.msg[0..1000], x.out) catch unreachable,
        .cts_dec_1000 => aescbc.decryptCts(Aes256, .cs3, &x.key, x.iv, &x.cts, x.out) catch unreachable,
        .pkcs7_dec_1024 => blk: {
            x.dec.setIv(x.iv);
            _ = x.dec.update(&x.pad, x.out[0..1024]) catch unreachable;
            break :blk aescbc.unpadPkcs7(x.out[0..1024]) catch 0;
        },
    };
    std.mem.doNotOptimizeAway(x.out);
    return r;
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

    var prng = std.Random.DefaultPrng.init(0xae5_cbc_b3c4);
    const r = prng.random();
    var ctx: Ctx = undefined;
    r.bytes(&ctx.key);
    r.bytes(&ctx.iv);
    ctx.msg = try arena.create([len]u8);
    ctx.ct = try arena.create([len]u8);
    ctx.out = try arena.create([len]u8);
    r.bytes(ctx.msg);
    _ = try aescbc.encrypt(Aes256, &ctx.key, ctx.iv, ctx.msg, ctx.ct);
    var padded: [1024]u8 = undefined;
    _ = try aescbc.padPkcs7(ctx.msg[0..1008], &padded);
    _ = try aescbc.encrypt(Aes256, &ctx.key, ctx.iv, &padded, &ctx.pad);
    _ = try aescbc.encryptCts(Aes256, .cs3, &ctx.key, ctx.iv, ctx.msg[0..1000], &ctx.cts);
    ctx.stream.initInto(&ctx.key, ctx.iv);
    ctx.enc.initInto(&ctx.key, ctx.iv);
    ctx.dec.initInto(&ctx.key, ctx.iv);
    try dir.writeFile(io, .{ .sub_path = "key32.bin", .data = &ctx.key });
    try dir.writeFile(io, .{ .sub_path = "iv.bin", .data = &ctx.iv });
    try dir.writeFile(io, .{ .sub_path = "msg16384.bin", .data = ctx.msg });
    try dir.writeFile(io, .{ .sub_path = "ct16384.bin", .data = ctx.ct });
    try dir.writeFile(io, .{ .sub_path = "pad1024.bin", .data = &ctx.pad });
    try dir.writeFile(io, .{ .sub_path = "cts1000.bin", .data = &ctx.cts });

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const c_exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/aescbc/tools/c_bench/foreign_bench.c", &.{so});
    const go_exe = try buildGo(arena, io, init.environ_map, abs) orelse return 1;

    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, c_exe, abs, "interop");
    try bench.foreignOnce(arena, io, bench_name, go_exe, abs, "interop");
    const checks = [_]struct { []const u8, []const u8 }{ .{ "ossl_cbc.bin", ctx.ct }, .{ "go_cbc.bin", ctx.ct }, .{ "ossl_pkcs7.bin", &ctx.pad } };
    for (checks) |c| {
        const theirs = try dir.readFileAlloc(io, c[0], arena, .limited(1 << 20));
        if (!std.mem.eql(u8, theirs, c[1])) {
            std.debug.print("{s}: FAILED -- {s} differs from ours\n", .{ bench_name, c[0] });
            return 1;
        }
    }
    // CTS, every variant and a spread of tail lengths, against OpenSSL's
    // AES-256-CBC-CTS: the differential oracle for encryptCts (decryptCts is
    // checked to invert each).
    for ([_]aescbc.CtsVariant{ .cs1, .cs2, .cs3 }) |v| for ([_]usize{ 16, 17, 31, 32, 47, 48, 1000, 1024 }) |n| {
        const name = try arena.print("ossl_cts_{s}_{d}.bin", .{ switch (v) {
            .cs1 => "CS1",
            .cs2 => "CS2",
            .cs3 => "CS3",
        }, n });
        const theirs = try dir.readFileAlloc(io, name, arena, .limited(1 << 20));
        _ = try aescbc.encryptCts(Aes256, v, &ctx.key, ctx.iv, ctx.msg[0..n], ctx.out);
        var back: [1024]u8 = undefined;
        _ = try aescbc.decryptCts(Aes256, v, &ctx.key, ctx.iv, theirs, &back);
        if (!std.mem.eql(u8, theirs, ctx.out[0..n]) or !std.mem.eql(u8, back[0..n], ctx.msg[0..n])) {
            std.debug.print("{s}: FAILED -- CTS {s} differs from OpenSSL's\n", .{ bench_name, name });
            return 1;
        }
    };
    // Our streaming PKCS#7 encrypt equals OpenSSL's padded ciphertext.
    ctx.op = .stream_enc_1008;
    if (once(&ctx) != 1024 or !std.mem.eql(u8, ctx.out[0..1024], &ctx.pad)) {
        std.debug.print("{s}: FAILED -- streaming PKCS#7 encrypt\n", .{bench_name});
        return 1;
    }
    // Our stateful decrypt of OpenSSL's padded ciphertext gives back the message.
    ctx.op = .pkcs7_dec_1024;
    if (once(&ctx) != 1008 or !std.mem.eql(u8, ctx.out[0..1008], ctx.msg[0..1008])) {
        std.debug.print("{s}: FAILED -- PKCS#7 round trip\n", .{bench_name});
        return 1;
    }

    var ws: std.ArrayList(Work) = .empty;
    inline for (@typeInfo(Op).@"enum".field_names, @typeInfo(Op).@"enum".field_values) |f_name, f_value| {
        const op: Op = @fromBackingInt(@intCast(f_value));
        if (std.mem.findScalar(Op, &openssl_only, op) != null)
            try ws.append(arena, .{ .name = f_name, .op = op, .ref = f_name, .ref_exe = 1, .fast_only = true })
        else
            try ws.append(arena, .{ .name = f_name, .op = op, .ref = f_name, .alt = f_name, .ref_exe = 0, .alt_exe = 1 });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ go_exe, c_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nfastest candidate: {s}\nworst ours/Go = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{
        std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0,
    });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto/cipher · fastest {d:.2}× OpenSSL <version> (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}

/// The Go side, built from `tools/go_bench` with the local toolchain and no
/// network (stdlib only). Null after printing why.
fn buildGo(arena: std.mem.Allocator, io: std.Io, environ: anytype, abs: []const u8) !?[]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return null;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, build.stderr });
        return null;
    }
    return exe;
}
