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
//! Method (shared driver at the bottom, as in every crypto module's bench):
//! each side doubles its batch until it takes over 100 ms and keeps the best
//! of five; per workload the sides alternate for `BENCH_ROUNDS` (default 3)
//! rounds, each keeping its best. Ratios are ours/theirs by user-mode cycles
//! when all sides count them, else by wall time. Before timing anything, Go's
//! and OpenSSL's CBC of the 16 KiB message, OpenSSL's PKCS#7-padded
//! ciphertext (one-shot and streamed) and OpenSSL's CTS in all three variants
//! over eight lengths must equal ours byte for byte.

const std = @import("std");
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
    const c_exe = try buildForeign(arena, io, abs, "modules/aescbc/tools/c_bench/foreign_bench.c", &.{so});
    const go_exe = try buildGo(arena, io, init.environ_map, abs) orelse return 1;

    // Interop before timing.
    try foreignOnce(arena, io, c_exe, abs, "interop");
    try foreignOnce(arena, io, go_exe, abs, "interop");
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
        const name = try std.fmt.allocPrint(arena, "ossl_cts_{s}_{d}.bin", .{ switch (v) {
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
    inline for (@typeInfo(Op).@"enum".fields) |f| {
        const op: Op = @enumFromInt(f.value);
        if (std.mem.indexOfScalar(Op, &openssl_only, op) != null)
            try ws.append(arena, .{ .name = f.name, .op = op, .ref = f.name, .ref_exe = 1 })
        else
            try ws.append(arena, .{ .name = f.name, .op = op, .ref = f.name, .alt = f.name, .ref_exe = 0, .alt_exe = 1 });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{ go_exe, c_exe }, abs, &ctx, ws.items, filters, rounds, w);
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
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
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

// ---- comparison driver (the same in every crypto module's tools/bench.zig) ----

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`).
const Cycles = struct {
    fd: ?i32,

    fn open() Cycles {
        if (@import("builtin").os.tag != .linux) return .{ .fd = null };
        const linux = std.os.linux;
        var attr: linux.perf_event_attr = .{
            .type = .HARDWARE,
            .config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES),
            .flags = .{ .exclude_kernel = true, .exclude_hv = true },
        };
        const rc = linux.perf_event_open(&attr, 0, -1, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return .{ .fd = null };
        return .{ .fd = @intCast(rc) };
    }

    fn read(c: Cycles) u64 {
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

fn timeIt(io: std.Io, cyc: Cycles, x: *Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = once(x);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = @as(f64, @floatFromInt(best_cycles)) / nf, .count = count };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`, which
/// prints `name \t ns/op \t cycles/op \t count` and its banner on stderr.
fn foreign(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8, banner: *[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    banner.* = res.stderr;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const cycles = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .cycles = cycles, .count = count };
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index the foreign programs.
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0 };

const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",
};

fn drive(io: std.Io, arena: std.mem.Allocator, exes: []const []const u8, abs: []const u8, ctx: *Ctx, ws: []const Work, filters: []const [:0]const u8, rounds: usize, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    var metric_cycles = true;
    var mismatch = false;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, x.name, f) != null;
            if (!hit) continue;
        }
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        // The sides alternate, `rounds` times, each keeping its best: timed one
        // after the other they would see different loads of a shared machine.
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, exes[x.ref_exe], abs, x.ref, &s.banner));
            ours.add(timeIt(io, cyc, ctx));
            if (x.alt) |a| alt.add(try foreign(arena, io, exes[x.alt_exe], abs, a, &s.alt_banner));
        }
        const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (x.alt == null or alt.best_cyc > 0);
        metric_cycles = metric_cycles and by_cyc;
        const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
        s.worst_ref = @max(s.worst_ref, r_ref);
        s.best_ref = @min(s.best_ref, r_ref);
        var r_fast: f64 = r_ref;
        if (x.alt != null) {
            r_fast = ours.best(by_cyc) / @min(ref.best(by_cyc), alt.best(by_cyc));
            s.worst_fast = @max(s.worst_fast orelse 0, r_fast);
        }
        const spr_alt = if (x.alt != null) alt.spread(by_cyc) else 0;
        s.max_spread = @max(s.max_spread, @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)));
        const same = ours.count == ref.count and (x.alt == null or ours.count == alt.count);
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,        ours.best_ns, ref.best_ns,               if (x.alt != null) alt.best_ns else 0,
            r_ref,         r_fast,       100 * ours.spread(by_cyc), 100 * ref.spread(by_cyc),
            100 * spr_alt, ours.count,
            if (same) "" else " ≠",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (metric_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{bench_name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` with `zig cc -O3 -march=native`
/// against `libs` (shared objects named by path, so no headers are needed).
fn buildForeign(arena: std.mem.Allocator, io: std.Io, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, cc.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
fn foreignOnce(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}
