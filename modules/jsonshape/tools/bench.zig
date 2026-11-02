// SPDX-License-Identifier: MIT

//! Comparative benchmark: `jsonshape`'s RFC 9535 engine against theory/jsonpath
//! v0.12.2 (Go, the reference: RFC 9535 complete, located results, a function
//! registry, `tools/go_bench`), serde_json_path 0.7.2 (Rust, `tools/rust_bench`),
//! ohler55/ojg v1.28.9 `jp` (Go) and jsonpath-rust 1.0.12 (Rust). The program
//! behind the `**Performance:**` line of the maturity card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-jsonshape` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26, cargo, and
//! the pinned sources in the module caches, fetched once with:
//!     go mod download github.com/theory/jsonpath@v0.12.2 github.com/ohler55/ojg@v1.28.9
//!     cargo fetch --manifest-path modules/jsonshape/tools/rust_bench/Cargo.toml
//! Run from the repository root. CPU-bound on `doc.json` and `paths.txt`, which
//! this driver writes into `.zig-cache/bench-jsonshape/` and the other sides
//! read; no file I/O is timed.
//!
//! The document: 2000 store items, 238,641 bytes. Every side evaluates over its
//! own language's usual parsed tree: ours `std.json.Value` (array-hash objects),
//! Go `any` from `encoding/json` (maps), Rust `serde_json::Value` (BTreeMap).
//!
//! Three kinds of row, so path parsing, evaluation and document parsing are never
//! mixed:
//!   eval_*     one evaluation of an already compiled path over the already
//!       parsed document; count = nodes selected. Ours `query`; theory `Select`;
//!       serde_json_path `query`; ojg `Expr.Get`; jsonpath-rust
//!       `js_path_process` (it has no entry without paths, so it builds them).
//!   located_*  the same with each node's Normalized Path as text; count = total
//!       length of those texts. Ours `queryLocated`; theory `SelectLocated` +
//!       `String`; serde_json_path `query_located` + `to_string`. ojg has no such
//!       API. jsonpath-rust's path text has a different form, so no row.
//!   compile_*  text to a compiled path; count = text length. Ours `compile`
//!       (including the one regex compile of `compile_regex`, which the others
//!       do at evaluation, so that row is not like with like); theory `Parse`; serde_json_path
//!       `JsonPath::parse`; ojg `ParseString`; jsonpath-rust `parse_json_path`.
//!   doc_parse  info, not in the verdict: the cost of the JSON parser, which
//!       here is `std.json`, not this module; count = document length.
//!
//! `/ojg` and `/jpr` rows count for `fastest` only. Ratios are ours/theirs by wall
//! time (Go has no cycle counter here); the verdict is the WORST ratio. The counts
//! must agree or the run fails. Arguments filter workloads.
//! `-Djcc-safe` (`BENCH_JCC_SAFE`) builds the Rust side with the Intel JCC-erratum
//! padding too; Go's assembler pads by default.

const std = @import("std");
const bench = @import("testkit").bench;
const js = @import("jsonshape");

const ref_short = "theory/jsonpath";
const ref_card = "theory/jsonpath v0.12.2";
const bench_name = "bench-jsonshape";
const work_dir = ".zig-cache/bench-jsonshape";
const go_dir = "modules/jsonshape/tools/go_bench";
const rust_manifest = "modules/jsonshape/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/jsonshape/tools/rust_bench/target/release/jsonshape_rust_bench";

const Kind = enum { eval, located, compile, doc };
const Item = struct { name: []const u8, kind: Kind, path: []const u8 = "", ojg: bool = true, jpr: bool = true };

// `ojg`/`jpr` false: that side has no such row (see tools/README.md).
const items = [_]Item{
    .{ .name = "eval_name", .kind = .eval, .path = "$.store.items[1000].meta.dims.w" },
    .{ .name = "eval_wild", .kind = .eval, .path = "$.store.items[*].price" },
    .{ .name = "eval_slice", .kind = .eval, .path = "$.store.items[10:1900:3].id" },
    .{ .name = "eval_desc", .kind = .eval, .path = "$..price" },
    .{ .name = "eval_desc_all", .kind = .eval, .path = "$..*" },
    .{ .name = "eval_filter", .kind = .eval, .path = "$.store.items[?(@.price < 50 && @.active == true)].id" },
    .{ .name = "eval_filter_len", .kind = .eval, .path = "$.store.items[?(length(@.tags) > 2)].name" },
    .{ .name = "eval_filter_sub", .kind = .eval, .path = "$.store.items[?@.meta.dims[?@ > 15]].id" },
    .{ .name = "eval_search", .kind = .eval, .path = "$.store.items[?search(@.name, '7.7')].id" },
    .{ .name = "eval_match", .kind = .eval, .path = "$.store.items[?match(@.meta.kind, 'k[0-3]')].id" },
    .{ .name = "located_wild", .kind = .located, .path = "$.store.items[*].meta.kind", .ojg = false, .jpr = false },
    .{ .name = "compile_simple", .kind = .compile, .path = "$.store.items[*].meta.dims.w" },
    .{ .name = "compile_filter", .kind = .compile, .path = "$.store.items[?(@.price < 50 && @.active == true || !@.tags)].meta['kind']" },
    .{ .name = "compile_regex", .kind = .compile, .path = "$.store.items[?search(@.name, '[a-z]+-[0-9]+')].id" },
    .{ .name = "doc_parse", .kind = .doc, .ojg = false, .jpr = false },
};

const Ctx = struct {
    op: usize = 0,
    root: std.json.Value = .null,
    doc: []const u8 = "",
    paths: []js.Path = &.{},
    scratch: *std.heap.ArenaAllocator,
};

const no_limit: js.QueryOptions = .{ .max_matches = std.math.maxInt(usize), .max_work = std.math.maxInt(usize) };

fn once(ctx: *Ctx) u64 {
    _ = ctx.scratch.reset(.retain_capacity);
    const a = ctx.scratch.allocator();
    const it = items[ctx.op];
    switch (it.kind) {
        .eval => {
            const got = js.query(a, ctx.root, ctx.paths[ctx.op], no_limit) catch @panic("bench-jsonshape: query");
            return got.len;
        },
        .located => {
            const got = js.queryLocated(a, ctx.root, ctx.paths[ctx.op], no_limit) catch @panic("bench-jsonshape: located");
            var total: u64 = 0;
            for (got) |g| total += g.path.len;
            return total;
        },
        .compile => {
            const p = js.compile(a, it.path, null) catch @panic("bench-jsonshape: compile");
            std.mem.doNotOptimizeAway(p.segs.ptr);
            return it.path.len;
        },
        .doc => {
            const root = js.parseDocument(a, ctx.doc, .{}) catch @panic("bench-jsonshape: parse");
            std.mem.doNotOptimizeAway(root.object.count());
            return ctx.doc.len;
        },
    }
}

fn makeDoc(a: std.mem.Allocator) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "{\"store\":{\"name\":\"bench\",\"items\":[");
    for (0..2000) |i| {
        if (i > 0) try out.append(a, ',');
        try out.print(a, "{{\"id\":{d},\"name\":\"item-{d}\",\"price\":{d}.{d},\"active\":{s},\"tags\":[", .{ i, i, (i * 37) % 100, i % 10, if (i % 3 == 0) "true" else "false" });
        for (0..i % 5) |t| {
            if (t > 0) try out.append(a, ',');
            try out.print(a, "\"t{d}\"", .{t});
        }
        try out.print(a, "],\"meta\":{{\"kind\":\"k{d}\",\"dims\":{{\"w\":{d},\"h\":{d}}}}}}}", .{ i % 7, i % 13, i % 17 });
    }
    try out.appendSlice(a, "]},\"version\":3}");
    return out.items;
}

fn rustBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, jcc_safe: bool) !void {
    var env = try environ.clone(arena);
    if (jcc_safe) try env.put("RUSTFLAGS", "-C llvm-args=-x86-branches-within-32B-boundaries");
    const res = try std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest },
        .environ_map = &env,
    });
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    const doc = try makeDoc(arena);
    try dir.writeFile(io, .{ .sub_path = "doc.json", .data = doc });
    var listing: std.ArrayList(u8) = .empty;
    for (items) |it| try listing.print(arena, "{s}\t{s}\n", .{ it.name, it.path });
    try dir.writeFile(io, .{ .sub_path = "paths.txt", .data = listing.items });
    std.debug.print("{s}: doc.json {d} bytes\n", .{ bench_name, doc.len });

    const paths = try arena.alloc(js.Path, items.len);
    for (items, paths) |it, *p| {
        if (it.kind == .eval or it.kind == .located) p.* = try js.compile(arena, it.path, null);
    }
    var scratch = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer scratch.deinit();
    var ctx: Ctx = .{ .root = try js.parseDocument(arena, doc, .{}), .doc = doc, .paths = paths, .scratch = &scratch };

    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    try rustBuild(arena, io, init.environ_map, init.environ_map.get("BENCH_JCC_SAFE") != null);
    const rust_abs = try cwd.realPathFileAlloc(io, rust_exe, arena);

    const W = bench.Work(usize);
    var ws: std.ArrayList(W) = .empty;
    for (items, 0..) |it, i| {
        try ws.append(arena, .{ .name = it.name, .op = i, .ref = it.name, .alt = it.name, .alt_exe = 1, .wall_only = true, .info = it.kind == .doc });
        if (it.ojg) {
            const n = try arena.print("ojg_{s}", .{it.name});
            try ws.append(arena, .{ .name = try arena.print("{s}/ojg", .{it.name}), .op = i, .ref = n, .fast_only = true, .wall_only = true });
        }
        if (it.jpr) {
            const n = try arena.print("jpr_{s}", .{it.name});
            try ws.append(arena, .{ .name = try arena.print("{s}/jpr", .{it.name}), .op = i, .ref = n, .ref_exe = 1, .fast_only = true, .wall_only = true });
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ go_exe, rust_abs },
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws.items, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2}); worst ours/fastest = {?d:.2}\n", .{ ref_short, s.worst_ref, s.best_ref, s.worst_fast });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {?d:.2}× (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card, s.worst_fast });
    try w.flush();
    return 0;
}
