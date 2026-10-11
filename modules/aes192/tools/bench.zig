// SPDX-License-Identifier: MIT

//! Comparative benchmark: `aes192` against OpenSSL's EVP AES-192 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-aes192` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads, over one 16 KiB message under a key set up once unless named:
//! `ecb_enc_16384` / `ecb_dec_16384` -- independent blocks (ours:
//! `encryptWide`/`decryptWide` at std's `optimal_parallel_blocks`, theirs: EVP
//! AES-192-ECB); `cbc_enc_16384` -- chained blocks, i.e. the latency of one
//! block (ours: `encrypt` on the XOR of the previous output, theirs: EVP
//! AES-192-CBC with the IV set per op); `ctr_16384` -- counter mode (ours:
//! `std.crypto.core.modes.ctr` over `Aes192EncryptCtx`, as `ssh`'s aes192-ctr
//! does; theirs: EVP AES-192-CTR, IV set per op); `key_enc` / `key_dec` -- one
//! key schedule per op (ours: `Aes192EncryptCtx.init` / `Aes192DecryptCtx.init`,
//! burn included; theirs: `EVP_*Init_ex` with only the key on a context that
//! already holds the cipher). Inputs are written into `.zig-cache/bench-aes192/`
//! from fixed seeds.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! ECB, CBC and CTR outputs of the 16 KiB message must equal ours byte for
//! byte. Arguments filter workloads by substring (no card line then).

const std = @import("std");
const aes192 = @import("aes192");

const bench_name = "bench-aes192";
const work_dir = ".zig-cache/bench-aes192";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const len = 16384;
const wide = aes192.Block.parallel.optimal_parallel_blocks;

const Op = enum { ecb_enc, ecb_dec, cbc_enc, ctr, key_enc, key_dec };

const Ctx = struct {
    enc: aes192.Aes192EncryptCtx,
    dec: aes192.Aes192DecryptCtx,
    key: [24]u8,
    iv: [16]u8,
    msg: *[len]u8,
    out: *[len]u8,
    op: Op = undefined,
};

fn ecbEnc(c: aes192.Aes192EncryptCtx, out: *[len]u8, msg: *const [len]u8) void {
    var i: usize = 0;
    while (i < len) : (i += 16 * wide) c.encryptWide(wide, out[i..][0 .. 16 * wide], msg[i..][0 .. 16 * wide]);
}

fn ecbDec(c: aes192.Aes192DecryptCtx, out: *[len]u8, msg: *const [len]u8) void {
    var i: usize = 0;
    while (i < len) : (i += 16 * wide) c.decryptWide(wide, out[i..][0 .. 16 * wide], msg[i..][0 .. 16 * wide]);
}

fn cbcEnc(c: aes192.Aes192EncryptCtx, out: *[len]u8, msg: *const [len]u8, iv: [16]u8) void {
    var prev = iv;
    var i: usize = 0;
    while (i < len) : (i += 16) {
        var x: [16]u8 = undefined;
        for (&x, prev, msg[i..][0..16]) |*d, p, m| d.* = p ^ m;
        c.encrypt(out[i..][0..16], &x);
        prev = out[i..][0..16].*;
    }
}

fn once(x: *Ctx) usize {
    switch (x.op) {
        .ecb_enc => ecbEnc(x.enc, x.out, x.msg),
        .ecb_dec => ecbDec(x.dec, x.out, x.msg),
        .cbc_enc => cbcEnc(x.enc, x.out, x.msg, x.iv),
        .ctr => std.crypto.core.modes.ctr(aes192.Aes192EncryptCtx, x.enc, x.out, x.msg, x.iv, .big),
        .key_enc => {
            const c = aes192.Aes192EncryptCtx.init(x.key);
            std.mem.doNotOptimizeAway(&c);
            return 0;
        },
        .key_dec => {
            const c = aes192.Aes192DecryptCtx.init(x.key);
            std.mem.doNotOptimizeAway(&c);
            return 0;
        },
    }
    std.mem.doNotOptimizeAway(x.out);
    return len;
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

    var prng = std.Random.DefaultPrng.init(0xae5_192_b3c4);
    const r = prng.random();
    var ctx: Ctx = undefined;
    r.bytes(&ctx.key);
    r.bytes(&ctx.iv);
    ctx.msg = try arena.create([len]u8);
    ctx.out = try arena.create([len]u8);
    r.bytes(ctx.msg);
    ctx.enc = .init(ctx.key);
    ctx.dec = .init(ctx.key);
    try dir.writeFile(io, .{ .sub_path = "key24.bin", .data = &ctx.key });
    try dir.writeFile(io, .{ .sub_path = "iv.bin", .data = &ctx.iv });
    try dir.writeFile(io, .{ .sub_path = "msg16384.bin", .data = ctx.msg });

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try buildForeign(arena, io, abs, "modules/aes192/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: ECB both ways, CBC, CTR.
    try foreignOnce(arena, io, exe, abs, "interop");
    const checks = [_]struct { file: []const u8, op: Op }{ .{ .file = "ossl_ecb.bin", .op = .ecb_enc }, .{ .file = "ossl_cbc.bin", .op = .cbc_enc }, .{ .file = "ossl_ctr.bin", .op = .ctr } };
    for (checks) |c| {
        const theirs = try dir.readFileAlloc(io, c.file, arena, .limited(1 << 20));
        ctx.op = c.op;
        _ = once(&ctx);
        if (!std.mem.eql(u8, theirs, ctx.out)) {
            std.debug.print("bench-aes192: FAILED -- OpenSSL's {s} differs from ours\n", .{c.file});
            return 1;
        }
        if (c.op == .ecb_enc) {
            const back = try arena.create([len]u8);
            ecbDec(ctx.dec, back, ctx.out);
            if (!std.mem.eql(u8, back, ctx.msg)) {
                std.debug.print("bench-aes192: FAILED -- ECB decrypt does not invert encrypt\n", .{});
                return 1;
            }
        }
    }

    var ws: std.ArrayList(Work) = .empty;
    for ([_]struct { []const u8, Op }{
        .{ "ecb_enc_16384", .ecb_enc }, .{ "ecb_dec_16384", .ecb_dec }, .{ "cbc_enc_16384", .cbc_enc },
        .{ "ctr_16384", .ctr },         .{ "key_enc", .key_enc },       .{ "key_dec", .key_dec },
    }) |w| try ws.append(arena, .{ .name = w[0], .op = w[1], .ref = w[0] });

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{exe}, abs, &ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP AES-192 · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
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
