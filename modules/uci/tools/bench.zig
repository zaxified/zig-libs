// SPDX-License-Identifier: MIT

//! Comparative benchmark: `uci`'s file layer against libuci (OpenWrt's uci,
//! LGPL-2.1, built from a source copy; its source is not read, only run) and
//! github.com/digineo/go-uci (MIT, pinned in `tools/go_bench/go.mod`), the
//! program behind the `**Performance:**` line of the maturity card.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-uci` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 with
//! go-uci in the module cache (`GOPROXY=off`) and a C compiler for libuci:
//! set `LIBUCI_SRC` to a directory holding a built-from-source copy of the
//! OpenWrt uci tree (`uci.h`, `libuci.c`, `file.c`, `util.c`, `delta.c`,
//! `parse.c`, a `uci_config.h`). Run from the repository root.
//!
//! libuci measured fastest on every row, so it is the card's FASTEST and the
//! other measured implementation, go-uci, is the REFERENCE (two different
//! implementations; `ref_exe` is go-uci, `alt_exe` libuci). Export has no
//! reference (go-uci's writer is private): those rows are `fast_only`, counted
//! against libuci only. One op, in-process on every side, files in the page cache:
//!   parse_small   load a ~1 KB `network`-shaped config (6 sections) from a
//!                 file and drop it. Ours `Store.load` (stat, open, read,
//!                 parse) + `Package.deinit`; libuci `uci_load` + `uci_unload`;
//!                 go-uci `LoadConfig(name, true)` (ReadFile + parse; the old
//!                 tree is garbage).
//!   parse_large   the same for 600 sections of 6 options and one 3-entry list.
//!   parse_quoted  300 sections whose values are quoted: an apostrophe inside
//!                 double quotes (go-uci cannot read the `'it'\''s'` splice), a double quote with escapes, a two-line
//!                 value with a `#` in it, a bare word; same ops.
//!   parse_multiline  the same shape but option `c` spans two lines: go-uci
//!                 cannot read a multi-line value ("unterminated quoted
//!                 string", measured), so this row is `fast_only`, against
//!                 libuci alone.
//!   export_small  serialize the loaded package to memory. Ours `serialize`
//!   export_large  (into a fresh buffer, freed); libuci `uci_export` to an
//!                 `open_memstream`. libuci also prints a trailing blank line.
//! Count (checked equal on every side): the number of sections, taken once
//! outside the timed loop; it does not compare the output bytes (the
//! differential tests do). NOT like for like: libuci's model is a linked list
//! of malloc'd elements with a per-package arena of its own contexts, ours is
//! one arena of slices; go-uci's `LoadConfig` also builds a lexer token stream.
//! Not measured here: commit (fsync-bound, disk-dependent) and staged overlay.
//! Ratios are ours/theirs by wall time; the verdict is the WORST ratio.

const std = @import("std");
const bench = @import("testkit").bench;
const uci = @import("uci");

const bench_name = "bench-uci";
const work_dir = ".zig-cache/bench-uci";
const go_dir = "modules/uci/tools/go_bench";
const small_sections = 6;
const large_sections = 600;

const Op = enum { parse_small, parse_large, parse_quoted, parse_multiline, export_small, export_large };

const Ctx = struct {
    op: Op = .parse_small,
    io: std.Io,
    conf: std.Io.Dir,
    small: uci.Package,
    large: uci.Package,
};

const quoted_sections = 300;

const gpa = std.heap.smp_allocator; // global-alloc-ok: a bench program, not library code

fn once(c: *Ctx) u64 {
    const store: uci.Store = .{ .io = c.io, .conf = c.conf };
    switch (c.op) {
        .parse_small, .parse_large, .parse_quoted, .parse_multiline => {
            var p = store.load(gpa, switch (c.op) {
                .parse_small => "small",
                .parse_large => "large",
                .parse_quoted => "quoted",
                else => "multiline",
            }, null) catch @panic("bench-uci: load");
            defer p.deinit(gpa);
            return p.sections.len;
        },
        .export_small, .export_large => {
            const p = if (c.op == .export_small) &c.small else &c.large;
            const out = uci.serialize(gpa, p) catch @panic("bench-uci: serialize");
            defer gpa.free(out);
            std.mem.doNotOptimizeAway(out.len);
            return p.sections.len;
        },
    }
}

fn makeQuoted(arena: std.mem.Allocator, r: std.Random, n: usize, multiline: bool) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (0..n) |i| {
        try buf.print(arena, "config iface 's{d}'\n", .{i});
        try buf.print(arena, "\toption a \"it's {x}\"\n", .{r.int(u32)});
        try buf.print(arena, "\toption b \"say \\\"hi\\\" {x} \\\\ done\"\n", .{r.int(u32)});
        if (multiline) {
            try buf.print(arena, "\toption c 'line one {x}\nline two # not a comment'\n", .{r.int(u32)});
        } else try buf.print(arena, "\toption c 'line one {x} # not a comment'\n", .{r.int(u32)});
        try buf.print(arena, "\toption d bare{x}\n", .{r.int(u32)});
        try buf.append(arena, '\n');
    }
    return buf.items;
}

fn makeText(arena: std.mem.Allocator, r: std.Random, n: usize) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    // No `package` line: go-uci refuses one ("imports/exports not yet supported").
    for (0..n) |i| {
        try buf.print(arena, "config iface 's{d}'\n", .{i});
        for (0..6) |k| try buf.print(arena, "\toption k{d} 'v{x}{x}'\n", .{ k, r.int(u32), r.int(u16) });
        for (0..3) |_| try buf.print(arena, "\tlist dns '10.{d}.{d}.{d}'\n", .{ r.int(u8), r.int(u8), r.int(u8) });
        try buf.append(arena, '\n');
    }
    return buf.items;
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

    var prng = std.Random.DefaultPrng.init(0x0c1_2026_1104);
    const r = prng.random();
    const small = try makeText(arena, r, small_sections);
    const large = try makeText(arena, r, large_sections);
    try dir.writeFile(io, .{ .sub_path = "small", .data = small });
    try dir.writeFile(io, .{ .sub_path = "large", .data = large });
    const quoted = try makeQuoted(arena, r, quoted_sections, false);
    try dir.writeFile(io, .{ .sub_path = "quoted", .data = quoted });
    const multiline = try makeQuoted(arena, r, quoted_sections, true);
    try dir.writeFile(io, .{ .sub_path = "multiline", .data = multiline });
    std.debug.print("{s}: small {d} bytes, large {d} bytes\n", .{ bench_name, small.len, large.len });

    var ctx: Ctx = .{
        .io = io,
        .conf = dir,
        .small = try uci.parse(gpa, small),
        .large = try uci.parse(gpa, large),
    };

    const src = init.environ_map.get("LIBUCI_SRC") orelse {
        std.debug.print("{s}: set LIBUCI_SRC to a built-from-source copy of the OpenWrt uci tree\n", .{bench_name});
        return 2;
    };
    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const c_exe = try bench.buildForeign(arena, io, bench_name, &.{
        "zig",                           "cc",
        "-std=gnu99",                    try std.fmt.allocPrint(arena, "-I{s}", .{src}),
        "-DUCI_PREFIX=\"/nonexistent\"", "-D_GNU_SOURCE",
    }, abs, "modules/uci/tools/c_bench.c", &.{
        try std.fmt.allocPrint(arena, "{s}/libuci.c", .{src}),
        try std.fmt.allocPrint(arena, "{s}/file.c", .{src}),
        try std.fmt.allocPrint(arena, "{s}/util.c", .{src}),
        try std.fmt.allocPrint(arena, "{s}/delta.c", .{src}),
        try std.fmt.allocPrint(arena, "{s}/parse.c", .{src}),
    });

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "parse_small", .op = .parse_small, .ref = "parse_small", .ref_exe = 1, .alt = "parse_small", .alt_exe = 0, .wall_only = true },
        .{ .name = "parse_large", .op = .parse_large, .ref = "parse_large", .ref_exe = 1, .alt = "parse_large", .alt_exe = 0, .wall_only = true },
        .{ .name = "parse_quoted", .op = .parse_quoted, .ref = "parse_quoted", .ref_exe = 1, .alt = "parse_quoted", .alt_exe = 0, .wall_only = true },
        .{ .name = "parse_multiline", .op = .parse_multiline, .ref = "parse_multiline", .ref_exe = 0, .fast_only = true, .wall_only = true },
        .{ .name = "export_small", .op = .export_small, .ref = "export_small", .ref_exe = 0, .fast_only = true, .wall_only = true },
        .{ .name = "export_large", .op = .export_large, .ref = "export_large", .ref_exe = 0, .fast_only = true, .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ c_exe, go_exe },
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/go-uci (the reference) = {d:.2} (best {d:.2}); worst ours/libuci (the fastest, every row) = {?d:.2}\n", .{ s.worst_ref, s.best_ref, s.worst_fast });
    try w.flush();
    return 0;
}
