// SPDX-License-Identifier: MIT

//! Comparative benchmark: `decimal` against libmpdec 4.0.1 (the C engine of
//! Python's `decimal`, BSD-2) as the reference and rust_decimal 1.42.1 (Rust,
//! MIT) as the fastest candidate for the fixed `Decimal` -- the program behind
//! the `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-decimal` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Run from the repository
//! root. It needs, in `.zig-cache/bench-decimal/`:
//!
//!   * a static libmpdec built from the mpdecimal-4.0.1 tarball (steps and the
//!     sha256 in `tools/mpdec_bench/README.md`; not built here, the tree is
//!     looked for under `src/mpdecimal-4.0.1/libmpdec/`),
//!   * `cc` (the C driver `tools/mpdec_bench/driver.c` is compiled HERE, once,
//!     `-O2 -g -std=gnu11`, against that libmpdec.a), and
//!   * `cargo` with the crates in the local registry (`tools/rust_bench`,
//!     pinned `=1.42.1`, `Cargo.lock` committed; built here `--locked
//!     --offline` into `.zig-cache/bench-decimal/target`).
//!
//! Each foreign side times itself exactly as this side does (double the batch
//! until it takes over 100 ms, best of five; ns per op, one op = the whole
//! workload) and prints `name \t ns \t count`. All three read the files this
//! program writes (seeded): money.txt (100 000 amounts like `-12345.67`),
//! rate.txt (100 000 rates with 7 fractional digits), big28.txt (2000) and
//! big200.txt (500 numbers of 28 / 200 digits, point in the middle).
//!
//!   parse_money   100k money strings -> Decimal   | mpd_qset_string (prec 38) | Decimal::from_str
//!   addsub_chain  1000 chains of 100 alternating add/sub of money values
//!   mul12         rate * rate (14 places) rounded to 12, half away from zero
//!   mul2          money * rate rounded to 2 places, half even
//!   divround12    money / money rounded to 12 places, half even (divRound |
//!                 mpd_qdiv prec 38 + quantize | `/` + round_dp_with_strategy)
//!   tostr_money   toString of the 100k money values (mpd: mpd_to_sci_size)
//!   tostr_q12     toString of the 100k 12-place quotients
//!   add28 mul28 div28 sqrt28 add200 mul200 div200 sqrt200
//!                 BigDecimal at 28 / 200 digits (2000 / 500 pairs per op) vs
//!                 mpd at the same precision (div / sqrt at prec P half-even;
//!                 add / mul at prec 2P+8, i.e. exact, as BigDecimal is exact).
//!                 mpd-only: rust_decimal has no big type.
//!
//! The count: the sum over all results of FNV-1a-64 of the canonical text of
//! the result (plain notation, trailing fractional zeros and a dangling dot
//! stripped, "-0" -> "0"), computed untimed by each side. Before anything is
//! timed (1) the first 1000 canonical results of every workload must be
//! BYTE-IDENTICAL on all sides and (2) the counts must agree. Ratios are
//! ours/theirs by wall time (the foreign sides count no cycles); the sides
//! alternate for BENCH_ROUNDS (default 3) rounds, each keeping its best.
//! Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const dec = @import("decimal");
const Decimal = dec.Decimal;
const BigDecimal = dec.BigDecimal;
const Work = bench.Work(Op);

const bench_name = "bench-decimal";
const work_dir = ".zig-cache/bench-decimal";
const mpd_lib_dir = work_dir ++ "/src/mpdecimal-4.0.1/libmpdec";
const driver_src = "modules/decimal/tools/mpdec_bench/driver.c";
const cargo_manifest = "modules/decimal/tools/rust_bench/Cargo.toml";
const gpa = std.heap.smp_allocator;

/// Our side's BigDecimal heap in the timed loops: a bump allocator rewound at
/// the start of every batch. libmpdec's driver reuses one result `mpd_t` and
/// never mallocs per operation; this is the Zig counterpart of that reuse, so
/// the big rows compare the arithmetic, not a general-purpose malloc/free
/// (about 20 ns per result with smp_allocator, half of a 28-digit add).
var op_buf: [64 << 20]u8 = undefined;
var op_fba: std.heap.FixedBufferAllocator = .init(&op_buf);

const n_dec = 100_000;
const chain_len = 100;

const Kind = enum {
    parse_money,
    addsub_chain,
    mul12,
    mul2,
    divround12,
    tostr_money,
    tostr_q12,
    add28,
    mul28,
    div28,
    sqrt28,
    add200,
    mul200,
    div200,
    sqrt200,
};
const kinds = std.enums.values(Kind);
const Op = struct { kind: Kind };

fn isBig(k: Kind) bool {
    return @backingInt(k) >= @backingInt(Kind.add28);
}
fn bigIdx(comptime k: Kind) usize {
    return if (comptime std.mem.endsWith(u8, @tagName(k), "28")) 0 else 1;
}
fn bigPrec(comptime k: Kind) u32 {
    return if (bigIdx(k) == 0) 28 else 200;
}
fn bigPairs(t: usize) usize {
    return if (t == 0) 2000 else 500;
}

const Ctx = struct {
    op: Op = undefined,
    money_s: []const []const u8,
    money: []Decimal,
    rate: []Decimal,
    quo: []Decimal,
    big: [2][]BigDecimal,
    counts: [kinds.len]u64 = @splat(0),
};

// ── the operations ───────────────────────────────────────────────────────────

fn mixD(d: Decimal) u64 {
    return @truncate(@as(u128, @bitCast(d.raw)));
}

inline fn opDec(comptime k: Kind, x: *const Ctx, i: usize) Decimal {
    const n = x.money.len;
    switch (k) {
        .parse_money => return Decimal.parse(x.money_s[i]) catch @panic("parse failed"),
        .addsub_chain => {
            var acc = Decimal.zero;
            for (0..chain_len) |j| {
                const m = x.money[i * chain_len + j];
                acc = (if (j & 1 == 1) acc.sub(m) else acc.add(m)) catch @panic("overflow");
            }
            return acc;
        },
        .mul12 => return x.rate[i].mul(x.rate[(i + 1) % n]) catch @panic("overflow"),
        .mul2 => {
            const p = x.money[i].mul(x.rate[i]) catch @panic("overflow");
            return p.rescale(2, .half_even) catch @panic("overflow");
        },
        .divround12 => return x.money[i].divRound(x.money[(i + 1) % n], 12, .half_even) catch @panic("div failed"),
        else => unreachable,
    }
}

inline fn opBig(comptime k: Kind, x: *const Ctx, i: usize) BigDecimal {
    const ally = op_fba.allocator();
    const a = x.big[comptime bigIdx(k)];
    const lhs = a[i];
    const rhs = a[(i + 1) % a.len];
    const tag = comptime @tagName(k);
    if (comptime std.mem.startsWith(u8, tag, "add")) return BigDecimal.add(ally, lhs, rhs) catch @panic("add failed");
    if (comptime std.mem.startsWith(u8, tag, "mul")) return BigDecimal.mul(ally, lhs, rhs) catch @panic("mul failed");
    if (comptime std.mem.startsWith(u8, tag, "div")) {
        const r = BigDecimal.divPrec(ally, lhs, rhs, comptime bigPrec(k), .half_even) catch @panic("div failed");
        return r.value;
    }
    return BigDecimal.sqrt(ally, lhs, comptime bigPrec(k), .half_even) catch @panic("sqrt failed");
}

fn run(x: *const Ctx, k: Kind) u64 {
    var s: u64 = 0;
    switch (k) {
        inline .parse_money, .mul12, .mul2, .divround12 => |kk| for (0..n_dec) |i| {
            s +%= mixD(opDec(kk, x, i));
        },
        .addsub_chain => for (0..n_dec / chain_len) |i| {
            s +%= mixD(opDec(.addsub_chain, x, i));
        },
        .tostr_money, .tostr_q12 => for (if (k == .tostr_money) x.money else x.quo) |d| {
            var buf: [Decimal.str_buf_len]u8 = undefined;
            const t = d.toString(&buf);
            s +%= t.len + t[t.len - 1];
        },
        inline else => |kk| for (0..bigPairs(bigIdx(kk))) |i| {
            if (i == 0) op_fba.reset();
            var r = opBig(kk, x, i);
            s +%= r.coeff.len() +% r.coeff.limbs[0];
            r.deinit();
        },
    }
    return s;
}

fn once(x: *Ctx) u64 {
    const k = x.op.kind;
    std.mem.doNotOptimizeAway(run(x, k));
    return x.counts[@backingInt(k)];
}

// ── the untimed check: canonical text, hash, sample ──────────────────────────

fn resultCount(k: Kind) usize {
    return switch (k) {
        .addsub_chain => n_dec / chain_len,
        .add28, .mul28, .div28, .sqrt28 => bigPairs(0),
        .add200, .mul200, .div200, .sqrt200 => bigPairs(1),
        else => n_dec,
    };
}

fn fnv1a(s: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (s) |c| {
        h ^= c;
        h *%= 0x100000001b3;
    }
    return h;
}

/// Trailing fractional zeros and a dangling dot stripped; "-0" -> "0".
fn canon(s: []const u8) []const u8 {
    var t = s;
    if (std.mem.findScalar(u8, t, '.') != null) {
        t = std.mem.trimEnd(u8, t, "0");
        t = std.mem.trimEnd(u8, t, ".");
    }
    if (std.mem.eql(u8, t, "-0")) return "0";
    return t;
}

fn textOf(x: *const Ctx, comptime k: Kind, i: usize, out: *std.ArrayList(u8)) !void {
    var b: [Decimal.str_buf_len]u8 = undefined;
    switch (k) {
        .tostr_money => try out.appendSlice(gpa, x.money[i].toString(&b)),
        .tostr_q12 => try out.appendSlice(gpa, x.quo[i].toString(&b)),
        .parse_money, .addsub_chain, .mul12, .mul2, .divround12 => try out.appendSlice(gpa, opDec(k, x, i).toString(&b)),
        else => {
            op_fba.reset();
            var r = opBig(k, x, i);
            defer r.deinit();
            const s = try r.toStringAlloc(gpa);
            defer gpa.free(s);
            try out.appendSlice(gpa, s);
        },
    }
}

fn checkKind(x: *const Ctx, k: Kind, sample: *std.ArrayList(u8)) !u64 {
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(gpa);
    var sum: u64 = 0;
    switch (k) {
        inline else => |kk| for (0..resultCount(kk)) |i| {
            tmp.clearRetainingCapacity();
            try textOf(x, kk, i, &tmp);
            const c = canon(tmp.items);
            sum +%= fnv1a(c);
            if (i < 1000) {
                try sample.appendSlice(gpa, c);
                try sample.append(gpa, '\n');
            }
        },
    }
    return sum;
}

// ── the inputs ───────────────────────────────────────────────────────────────

fn genMoney(r: std.Random, w: *std.Io.Writer) !void {
    if (r.uintLessThan(u8, 100) < 30) try w.writeByte('-');
    const digits = r.intRangeAtMost(u8, 1, 5);
    var lo: u32 = 1;
    for (1..digits) |_| lo *= 10;
    try w.print("{d}", .{r.intRangeAtMost(u32, lo, lo * 10 - 1)});
    const f = r.uintLessThan(u8, 100);
    if (f < 85) {
        try w.print(".{d:0>2}", .{r.uintLessThan(u8, 100)});
    } else if (f < 92) {
        try w.print(".{d}", .{r.uintLessThan(u8, 10)});
    }
}

fn genRate(r: std.Random, w: *std.Io.Writer) !void {
    if (r.uintLessThan(u8, 100) < 25) try w.writeByte('-');
    const d = r.intRangeAtMost(u8, 0, 3);
    var hi: u32 = 1;
    for (0..d) |_| hi *= 10;
    const ip: u32 = if (d == 0) 0 else r.uintLessThan(u32, hi);
    try w.print("{d}.{d:0>7}", .{ ip, r.uintLessThan(u32, 10_000_000) });
}

fn genBig(r: std.Random, w: *std.Io.Writer, p: usize) !void {
    const int_digits = p - p / 2;
    for (0..p) |i| {
        if (i == int_digits) try w.writeByte('.');
        const d: u8 = if (i == 0) r.intRangeAtMost(u8, 1, 9) else r.uintLessThan(u8, 10);
        try w.writeByte('0' + d);
    }
}

fn genFile(arena: std.mem.Allocator, r: std.Random, n: usize, comptime gen: anytype, args: anytype) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    for (0..n) |_| {
        try @call(.auto, gen, .{ r, &out.writer } ++ args);
        try out.writer.writeByte('\n');
    }
    return out.written();
}

fn splitLines(arena: std.mem.Allocator, text: []const u8) ![]const []const u8 {
    var v: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |l| try v.append(arena, l);
    return v.items;
}

fn parseAll(arena: std.mem.Allocator, lines: []const []const u8) ![]Decimal {
    const v = try arena.alloc(Decimal, lines.len);
    for (lines, v) |l, *d| d.* = try Decimal.parse(l);
    return v;
}

fn parseBig(arena: std.mem.Allocator, lines: []const []const u8) ![]BigDecimal {
    const v = try arena.alloc(BigDecimal, lines.len);
    for (lines, v) |l, *d| d.* = try BigDecimal.parse(gpa, l);
    return v;
}

// ── main ─────────────────────────────────────────────────────────────────────

const Foreign = struct { name: []const u8, hash: u64 };

fn runCheck(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8) !std.ArrayList(Foreign) {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "check" } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} check failed:\n{s}\n", .{ bench_name, exe, res.stderr });
        return error.ForeignFailed;
    }
    var v: std.ArrayList(Foreign) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        _ = f.next(); // "count"
        const name = f.next().?;
        try v.append(arena, .{ .name = name, .hash = try std.fmt.parseInt(u64, f.next().?, 10) });
    }
    return v;
}

fn runCmd(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8, env: ?*const std.process.Environ.Map, what: []const u8) !void {
    const res = std.process.run(arena, io, .{ .argv = argv, .environ_map = env }) catch |e| {
        std.debug.print("{s}: could not run {s} ({t}) -- the benchmark needs it\n", .{ bench_name, argv[0], e });
        return error.BuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed:\n{s}\n", .{ bench_name, what, res.stderr });
        return error.BuildFailed;
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

    var prng = std.Random.DefaultPrng.init(0xdec1_3a1);
    const r = prng.random();
    const money_t = try genFile(arena, r, n_dec, genMoney, .{});
    const rate_t = try genFile(arena, r, n_dec, genRate, .{});
    const big28_t = try genFile(arena, r, 2000, genBig, .{@as(usize, 28)});
    const big200_t = try genFile(arena, r, 500, genBig, .{@as(usize, 200)});
    try dir.writeFile(io, .{ .sub_path = "money.txt", .data = money_t });
    try dir.writeFile(io, .{ .sub_path = "rate.txt", .data = rate_t });
    try dir.writeFile(io, .{ .sub_path = "big28.txt", .data = big28_t });
    try dir.writeFile(io, .{ .sub_path = "big200.txt", .data = big200_t });

    const money_s = try splitLines(arena, money_t);
    const money = try parseAll(arena, money_s);
    const quo = try arena.alloc(Decimal, money.len);
    for (quo, 0..) |*q, i| q.* = try money[i].divRound(money[(i + 1) % money.len], 12, .half_even);
    var ctx: Ctx = .{
        .money_s = money_s,
        .money = money,
        .rate = try parseAll(arena, try splitLines(arena, rate_t)),
        .quo = quo,
        .big = .{ try parseBig(arena, try splitLines(arena, big28_t)), try parseBig(arena, try splitLines(arena, big200_t)) },
    };

    // Our own results first: counts and the first 1000 canonical results.
    var samples: [kinds.len]std.ArrayList(u8) = @splat(.empty);
    for (kinds) |k| ctx.counts[@backingInt(k)] = try checkKind(&ctx, k, &samples[@backingInt(k)]);

    // The foreign sides, built once.
    const mpd_exe = try arena.print("{s}/mpdec_bench", .{abs});
    std.debug.print("{s}: building the C side (cc, {s}) ...\n", .{ bench_name, driver_src });
    runCmd(arena, io, &.{ "cc", "-O2", "-g", "-std=gnu11", "-I", mpd_lib_dir, driver_src, mpd_lib_dir ++ "/libmpdec.a", "-lm", "-o", mpd_exe }, null, "cc (is libmpdec built? see modules/decimal/tools/mpdec_bench/README.md)") catch return 1;
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    runCmd(arena, io, &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest }, &env, "cargo build") catch return 1;
    const rust_exe = try arena.print("{s}/release/rust_bench", .{target});

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    // Pre-check: the first 1000 results byte-identical, the counts equal.
    const sides = [_]struct { tag: []const u8, label: []const u8, exe: []const u8 }{
        .{ .tag = "mpd", .label = "libmpdec", .exe = mpd_exe },
        .{ .tag = "rust", .label = "rust_decimal", .exe = rust_exe },
    };
    var bad = false;
    for (sides) |sd| {
        const theirs = try runCheck(arena, io, sd.exe, abs);
        for (theirs.items) |t| {
            const k = std.meta.stringToEnum(Kind, t.name).?;
            const ours = samples[@backingInt(k)].items;
            const file = try dir.readFileAlloc(io, try arena.print("sample_{s}_{s}.txt", .{ sd.tag, t.name }), arena, .limited(1 << 24));
            const same_sample = std.mem.eql(u8, ours, file);
            const same_count = ctx.counts[@backingInt(k)] == t.hash;
            if (!same_sample or !same_count) bad = true;
            try w.print("pre-check: {s:<12} {s:<13} first 1000 {s}, count {s}\n", .{ sd.label, t.name, if (same_sample) "identical" else "DIFFER", if (same_count) "equal" else "DIFFERENT" });
            if (!same_sample) {
                var a = std.mem.splitScalar(u8, ours, '\n');
                var b = std.mem.splitScalar(u8, file, '\n');
                var line: usize = 0;
                while (true) : (line += 1) {
                    const la = a.next();
                    const lb = b.next();
                    if (la == null and lb == null) break;
                    if (!std.mem.eql(u8, la orelse "", lb orelse "")) {
                        try w.print("    first difference at result {d}: ours {s} | {s} {s}\n", .{ line, la orelse "(end)", sd.label, lb orelse "(end)" });
                        break;
                    }
                }
            }
        }
    }
    try w.flush();
    if (bad) {
        try w.writeAll(bench_name ++ ": FAILED -- the sides disagree before timing; see above\n");
        try w.flush();
        return 1;
    }

    var ws: std.ArrayList(Work) = .empty;
    for (kinds) |k| try ws.append(arena, .{
        .name = @tagName(k),
        .op = .{ .kind = k },
        .ref = @tagName(k),
        .alt = if (isBig(k)) null else @tagName(k),
        .alt_exe = 1,
    });

    const s = bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ mpd_exe, rust_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("reference: {s}\ncandidate: {s}\nworst ours/libmpdec = {d:.3} (best {d:.3})", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref });
    if (s.worst_fast) |wf| try w.print("; worst ours/min(libmpdec, rust_decimal) = {d:.3}", .{wf});
    try w.writeByte('\n');
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libmpdec 4.0.1 · fastest {d:.2}× worst vs the faster of libmpdec 4.0.1 and rust_decimal 1.42.1 (Decimal workloads only; measured 2026-10-20)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
