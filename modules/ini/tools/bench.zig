// SPDX-License-Identifier: MIT

//! Comparative benchmark: `ini` against go-ini (gopkg.in/ini.v1 v1.67.3, the
//! reference: the fullest feature set, `tools/go_bench`), the Rust `configparser`
//! crate 3.3.0 and the two pull parsers `ini_core` 0.2.0 (Rust, `tools/rust_bench`)
//! and inih (C, `tools/c_bench.c`). The program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-ini` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26, cargo and
//! `zig cc`, and the pinned sources in the module caches, fetched once with:
//!     go mod download gopkg.in/ini.v1@v1.67.3 github.com/benhoyt/inih@r62
//!     cargo fetch --manifest-path modules/ini/tools/rust_bench/Cargo.toml
//! Run from the repository root. CPU-bound on texts this driver writes into
//! `.zig-cache/bench-ini/` (the other sides read the same files); no file I/O
//! is timed.
//!
//! The texts: `small.ini` (5 sections of 6 keys, a small config) and `large.ini`
//! (200 sections of 30 keys, ~200 KiB), `key = value`, a `#` comment before every
//! fifth key, a blank line between sections, no quotes, `;`, `:` or backslashes.
//! `probes.txt` is 64 existing (section, key) pairs of `large.ini`.
//!
//! Every side is set to the same reading: `=` only, no inline comments, no
//! continuation lines, keys case-sensitive, no quote handling. go-ini: BlockMode
//! off (its locks would be pure overhead), `Value()` for the raw value; ours has
//! no locks. One op:
//!   parse_small, parse_large  text to a document with lookups ready, then the
//!       values of 16 probes (`parse_small`: every 2nd key). Count = their total
//!       length. Ours `parse` (a copy of every name and value, in one arena,
//!       plus the index); go-ini `Empty` + `Append` (also a copy, maps);
//!       configparser `read` (its API returns a clone of the whole map too:
//!       that is the call a user has).
//!   get_hit   64 lookups of existing keys in `large.ini`, total value length.
//!       Ours `get`; go-ini `Section(s).GetKey(k)` + `Value`; configparser `get`
//!       (returns a fresh String).
//!   get_miss  the same 64 with a key that is absent. Count = misses.
//!   write     the document to text, sections in order, `key=value`, count = the
//!       `=` bytes. Ours `Document.write` (proves each line reads back); go-ini
//!       `WriteTo` (PrettyFormat off); configparser `pretty_writes` (hash order).
//!   edit      `large.ini` loaded, 16 keys changed, written back. Ours `Editor`,
//!       keeping comments and layout byte for byte; go-ini Load + `SetValue` +
//!       `WriteTo`, normalising them. No configparser row: it loses comments.
//!   scan_*    a pass over `large.ini` without building anything, total length of
//!       section names, keys and values. The reference has no streaming reader,
//!       so these rows count for `fastest` only. Ours `Scanner`; `ini_core`
//!       with `auto_trim`; inih `ini_parse_string_length` with the section
//!       handler on and multi-line and inline comments compiled out.
//! `-Djcc-safe` (`BENCH_JCC_SAFE`) builds the Rust and C sides with the Intel
//! JCC-erratum padding too; Go's assembler pads by default.
//! The counts must agree or the run fails. Ratios are ours/theirs by wall time;
//! the verdict is the WORST ratio. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const ini = @import("ini");

const ref_short = "go-ini";
const ref_card = "go-ini v1.67.3";
const bench_name = "bench-ini";
const work_dir = ".zig-cache/bench-ini";
const go_dir = "modules/ini/tools/go_bench";
const rust_manifest = "modules/ini/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/ini/tools/rust_bench/target/release/ini_rust_bench";
const inih_version = "v0.0.0-20250911204704-26254ee9de76"; // tag r62
const n_sections = 200;
const n_keys = 30;
const n_probes = 64;
const n_parse_probes = 16;

const Op = enum { parse_small, parse_large, get_hit, get_miss, write, edit, scan };

const Probe = struct { section: []const u8, key: []const u8, miss: []const u8 };

const Ctx = struct {
    op: Op = .parse_small,
    small: []const u8 = "",
    large: []const u8 = "",
    probes: []const Probe = &.{},
    small_probes: []const Probe = &.{},
    doc: *const ini.Document = undefined,
    out: []u8 = &.{},
    opts: ini.Options = .{ .global_entries = false },
};

const gpa = std.heap.smp_allocator;

fn parseProbes(text: []const u8, opts: ini.Options, probes: []const Probe) u64 {
    var doc = ini.parse(gpa, text, opts) catch @panic("bench-ini: parse");
    defer doc.deinit();
    var t: u64 = 0;
    for (probes) |p| t += (doc.get(p.section, p.key) orelse @panic("bench-ini: probe")).len;
    return t;
}

fn countEq(s: []const u8) u64 {
    return std.mem.count(u8, s, "=");
}

fn once(c: *Ctx) u64 {
    switch (c.op) {
        .parse_small => return parseProbes(c.small, c.opts, c.small_probes),
        .parse_large => return parseProbes(c.large, c.opts, c.probes[0..n_parse_probes]),
        .get_hit => {
            var t: u64 = 0;
            for (c.probes) |p| t += (c.doc.get(p.section, p.key) orelse @panic("bench-ini: hit")).len;
            return t;
        },
        .get_miss => {
            var t: u64 = 0;
            for (c.probes) |p| {
                if (c.doc.get(p.section, p.miss) == null) t += 1;
            }
            return t;
        },
        .write => {
            var w: std.Io.Writer = .fixed(c.out);
            c.doc.write(gpa, &w, .{ .options = c.opts, .separator = "=" }) catch @panic("bench-ini: write");
            return countEq(w.buffered());
        },
        .edit => {
            var ed = ini.Editor.init(gpa, c.large, c.opts) catch @panic("bench-ini: editor");
            defer ed.deinit();
            for (c.probes[0..n_parse_probes]) |p| ed.set(p.section, p.key, "edited value") catch @panic("bench-ini: set");
            var w: std.Io.Writer = .fixed(c.out);
            ed.write(&w) catch @panic("bench-ini: editor write");
            return countEq(w.buffered());
        },
        .scan => {
            var t: u64 = 0;
            var sc = ini.Scanner.init(c.large, c.opts);
            while (sc.next()) |ev| switch (ev) {
                .section => |h| t += h.name.len,
                .entry => |e| t += e.key.len + e.value.len,
                else => {},
            };
            return t;
        },
    }
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn word(r: std.Random, w: *std.Io.Writer, min: usize, max: usize) !void {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-./ ";
    const n = r.intRangeAtMost(usize, min, max);
    for (0..n) |i| {
        // No blank at either end: the value must read back as written.
        const top = if (i == 0 or i + 1 == n) alphabet.len - 1 else alphabet.len;
        try w.writeByte(alphabet[r.uintLessThan(usize, top)]);
    }
}

fn makeText(arena: std.mem.Allocator, r: std.Random, sections: usize, keys: usize, probe_every: usize, probes: *std.ArrayList(Probe)) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    for (0..sections) |s| {
        if (s != 0) try w.writeByte('\n');
        try w.print("[section_{d:0>4}]\n", .{s});
        for (0..keys) |k| {
            if (k % 5 == 0) {
                try w.writeAll("# a comment about the next key: ");
                try word(r, w, 8, 40);
                try w.writeByte('\n');
            }
            try w.print("key_{d:0>4}_name = ", .{k});
            try word(r, w, 4, 48);
            try w.writeByte('\n');
            if (probe_every != 0 and (s * keys + k) % probe_every == 0) {
                try probes.append(arena, .{
                    .section = try std.fmt.allocPrint(arena, "section_{d:0>4}", .{s}),
                    .key = try std.fmt.allocPrint(arena, "key_{d:0>4}_name", .{k}),
                    .miss = try std.fmt.allocPrint(arena, "key_{d:0>4}_absent", .{k}),
                });
            }
        }
    }
    return out.written();
}

fn writeProbes(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, probes: []const Probe) !void {
    var out: std.Io.Writer.Allocating = .init(arena);
    for (probes) |p| try out.writer.print("{s}\t{s}\t{s}\n", .{ p.section, p.key, p.miss });
    try dir.writeFile(io, .{ .sub_path = name, .data = out.written() });
}

fn shuffled(arena: std.mem.Allocator, r: std.Random, all: []const Probe, n: usize) ![]const Probe {
    const copy = try arena.dupe(Probe, all);
    r.shuffle(Probe, copy);
    return copy[0..n];
}

fn rustBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, jcc_safe: bool) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    var env = try environ.clone(arena);
    if (jcc_safe) try env.put("RUSTFLAGS", "-C target-cpu=native -C llvm-args=-x86-branches-within-32B-boundaries") else try env.put("RUSTFLAGS", "-C target-cpu=native");
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t})\n", .{ bench_name, e });
        return error.RustBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.RustBuildFailed;
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var prng = std.Random.DefaultPrng.init(0x1a1_2026_1102);
    const r = prng.random();
    var small_all: std.ArrayList(Probe) = .empty;
    var large_all: std.ArrayList(Probe) = .empty;
    const small = try makeText(arena, r, 5, 6, 2, &small_all);
    const large = try makeText(arena, r, n_sections, n_keys, 7, &large_all);
    const probes = try shuffled(arena, r, large_all.items, n_probes);
    try dir.writeFile(io, .{ .sub_path = "small.ini", .data = small });
    try dir.writeFile(io, .{ .sub_path = "large.ini", .data = large });
    try writeProbes(arena, io, dir, "probes.txt", probes);
    try writeProbes(arena, io, dir, "small_probes.txt", small_all.items);
    std.debug.print("{s}: small.ini {d} bytes, large.ini {d} bytes\n", .{ bench_name, small.len, large.len });

    var ctx: Ctx = .{ .small = small, .large = large, .probes = probes, .small_probes = small_all.items };
    var doc = try ini.parse(gpa, large, ctx.opts);
    defer doc.deinit();
    ctx.doc = &doc;
    ctx.out = try arena.alloc(u8, large.len * 2);

    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const jcc_safe = init.environ_map.get("BENCH_JCC_SAFE") != null;
    try rustBuild(arena, io, init.environ_map, jcc_safe);
    const rust_abs = try cwd.realPathFileAlloc(io, rust_exe, arena);
    const home = init.environ_map.get("HOME") orelse return error.NoHome;
    const inih_dir = try std.fmt.allocPrint(arena, "{s}/go/pkg/mod/github.com/benhoyt/inih@{s}", .{ home, inih_version });
    const c_exe = try bench.buildForeign(arena, io, bench_name, &.{
        "zig",                                                                    "cc",
        "-DINI_ALLOW_MULTILINE=0",                                                "-DINI_ALLOW_INLINE_COMMENTS=0",
        "-DINI_CALL_HANDLER_ON_NEW_SECTION=1",                                    "-DINI_MAX_LINE=1024",
        if (jcc_safe) "-mbranches-within-32B-boundaries" else "-DNO_JCC_PADDING", try std.fmt.allocPrint(arena, "-I{s}", .{inih_dir}),
    }, abs, "modules/ini/tools/c_bench.c", &.{try std.fmt.allocPrint(arena, "{s}/ini.c", .{inih_dir})});

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "parse_small", .op = .parse_small, .ref = "parse_small", .alt = "parse_small", .alt_exe = 1, .wall_only = true },
        .{ .name = "parse_large", .op = .parse_large, .ref = "parse_large", .alt = "parse_large", .alt_exe = 1, .wall_only = true },
        .{ .name = "get_hit", .op = .get_hit, .ref = "get_hit", .alt = "get_hit", .alt_exe = 1, .wall_only = true },
        .{ .name = "get_miss", .op = .get_miss, .ref = "get_miss", .alt = "get_miss", .alt_exe = 1, .wall_only = true },
        .{ .name = "write", .op = .write, .ref = "write", .alt = "write", .alt_exe = 1, .wall_only = true },
        .{ .name = "edit", .op = .edit, .ref = "edit", .wall_only = true },
        .{ .name = "scan_ini_core", .op = .scan, .ref = "scan_ini_core", .ref_exe = 1, .fast_only = true, .wall_only = true },
        .{ .name = "scan_inih", .op = .scan, .ref = "scan_inih", .ref_exe = 2, .fast_only = true, .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ go_exe, rust_abs, c_exe },
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2}); worst ours/fastest = {?d:.2}\n", .{ ref_short, s.worst_ref, s.best_ref, s.worst_fast });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {?d:.2}× (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card, s.worst_fast });
    try w.flush();
    return 0;
}
