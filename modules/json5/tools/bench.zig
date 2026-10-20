// SPDX-License-Identifier: MIT

//! Comparative benchmark: `json5` against json5/json5 2.2.3 (the `json5` npm
//! package, run under bun) -- the program behind the `**Performance:**` line of
//! the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-json5` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `bun` on PATH and
//! the package in bun's install cache (`bun add json5@2.2.3` once, anywhere;
//! same as `ref_oracle.js`; JSON5_REF overrides the path). Run from the
//! repository root.
//!
//! The reference side is `tools/bench_ref.js`, one bun process per workload and
//! round: it times itself exactly as this side does (double the batch until it
//! takes over 100 ms, best of five) and prints `name \t ns \t count`.
//!
//!   small_config  a ~1 KB JSON5 config (comments, unquoted keys, single quotes,
//!                 trailing commas, hex, multi-line strings), 1000 parses per op
//!   large_json    a ~1 MB plain JSON document (nested objects, arrays, strings,
//!                 numbers; generated deterministically), one parse per op
//!   large_json5   the same document as JSON5 (unquoted keys, single quotes,
//!                 `//` comments every few lines, trailing commas)
//!   large_json5_preprocess   ours only, INFO: `json5.preprocess` alone
//!
//! Ours is `json5.parseFromSlice(std.json.Value, ...)` (preprocess + std.json
//! into a Value, strings copied, freed after every parse) against
//! `JSON5.parse(text)`. Both sides read the same files, written here. The
//! result count is the number of object members + array elements in the parsed
//! tree: a parser that drops data cannot win. The sides alternate for
//! BENCH_ROUNDS (default 3) rounds, each keeping its best; ratios are
//! ours/reference by wall time; the verdict is the worst. Arguments filter
//! workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const json5 = @import("json5");

const bench_name = "bench-json5";
const work_dir = ".zig-cache/bench-json5";
const ref_script = "modules/json5/tools/bench_ref.js";
const ref_short = "ref";
const gpa = std.heap.smp_allocator;

const Kind = enum { parse, preprocess };
const Work = struct { name: []const u8, file: []const u8, kind: Kind, reps: usize, info: bool = false };
const works = [_]Work{
    .{ .name = "small_config", .file = "small_config.json5", .kind = .parse, .reps = 1000 },
    .{ .name = "large_json", .file = "large_json.json", .kind = .parse, .reps = 1 },
    .{ .name = "large_json5", .file = "large_json5.json5", .kind = .parse, .reps = 1 },
    .{ .name = "large_json5_preprocess", .file = "large_json5.json5", .kind = .preprocess, .reps = 1, .info = true },
};

const small_config =
    \\// service configuration -- ttydesk / bxp shape
    \\{
    \\  name: 'edge-gateway',
    \\  "version": 3, // trailing comment
    \\  /* block comment
    \\     over two lines */
    \\  enabled: true,
    \\  listen: { host: '0.0.0.0', port: 0x1F90, backlog: 128, },
    \\  limits: {
    \\    max_body: 0x100000,
    \\    timeout_ms: 2500,
    \\    ratio: .75,
    \\    offset: +5,
    \\    burst: 1e3,
    \\  },
    \\  banner: 'Welcome to the edge gateway.\n\
    \\Second line of the banner, continued \
    \\across source lines.',
    \\  routes: [
    \\    { path: '/health', handler: 'health', methods: ['GET', 'HEAD'], },
    \\    { path: '/api/v1/items', handler: 'items', methods: ['GET', 'POST'], auth: true, },
    \\    { path: '/api/v1/items/:id', handler: 'item', methods: ['GET', 'PUT', 'DELETE'], auth: true, },
    \\    { path: '/static', handler: 'files', methods: ['GET'], cache: 3600, },
    \\  ],
    \\  upstreams: [
    \\    // primary first
    \\    { name: 'primary', addr: '10.0.0.10:8080', weight: 10, tags: ['a', 'b', 'c'], },
    \\    { name: 'secondary', addr: '10.0.0.11:8080', weight: 5, tags: ['a'], },
    \\    { name: 'canary', addr: '10.0.0.12:8080', weight: 0x1, tags: [], },
    \\  ],
    \\  logging: { level: 'info', file: '/var/log/gateway.log', rotate: { size: 0xA00000, keep: 7, }, },
    \\  features: { http2: true, tls13: true, 'zero-rtt': false, experimental: null, },
    \\  colors: [0xFF0000, 0x00FF00, 0x0000FF, -0x10, 1.5e-3, -2.25],
    \\  'quoted key': "double 'quoted' value",
    \\}
    \\
;

// ── the large document, generated once as JSON and once as JSON5 ─────────────

const Emit = struct {
    w: *std.Io.Writer,
    json5: bool,
    prng: std.Random.DefaultPrng,
    counter: u32 = 0,
    lines: u32 = 0,

    const words = [_][]const u8{ "alpha", "beta gamma", "delta\\nepsilon", "caf\\u00e9 au lait", "tab\\there", "lorem ipsum dolor sit amet", "x", "snowman \\u2603", "path/to/some/file.txt", "The quick brown fox" };

    fn indent(e: *Emit, depth: usize) !void {
        for (0..depth) |_| try e.w.writeAll("  ");
    }

    fn key(e: *Emit, name: []const u8) !void {
        if (e.json5) try e.w.print("{s}: ", .{name}) else try e.w.print("\"{s}\": ", .{name});
    }

    fn str(e: *Emit, s: []const u8) !void {
        const q: u8 = if (e.json5) '\'' else '"';
        try e.w.print("{c}{s}{c}", .{ q, s, q });
    }

    fn word(e: *Emit) !void {
        const r = e.prng.random();
        try e.str(words[r.uintLessThan(usize, words.len)]);
    }

    fn num(e: *Emit) !void {
        const r = e.prng.random();
        switch (r.uintLessThan(u8, 8)) {
            0 => try e.w.print("{d}", .{r.intRangeAtMost(i32, -1_000_000, 1_000_000)}),
            1 => try e.w.print("{e}", .{@as(f64, @floatFromInt(r.intRangeAtMost(i32, 1, 999_999))) * 1e-9}),
            else => try e.w.print("{d:.3}", .{@as(f64, @floatFromInt(r.intRangeAtMost(i32, -1_000_000, 1_000_000))) / 1000.0}),
        }
    }

    /// A line break after a member; in JSON5 a `//` comment line before every
    /// fourth member.
    fn member(e: *Emit, depth: usize, name: []const u8) !void {
        e.lines += 1;
        if (e.json5 and e.lines % 4 == 0) {
            try e.indent(depth);
            try e.w.print("// note {d}\n", .{e.lines});
        }
        try e.indent(depth);
        try e.key(name);
    }

    fn comma(e: *Emit, last: bool) !void {
        if (!last or e.json5) try e.w.writeByte(',');
        try e.w.writeByte('\n');
    }

    fn record(e: *Emit, depth: usize) anyerror!void {
        const r = e.prng.random();
        const d = depth + 1;
        try e.w.writeAll("{\n");
        try e.member(d, "id");
        e.counter += 1;
        try e.w.print("{d}", .{e.counter});
        try e.comma(false);
        try e.member(d, "name");
        try e.word();
        try e.comma(false);
        try e.member(d, "active");
        try e.w.writeAll(if (r.boolean()) "true" else "false");
        try e.comma(false);
        try e.member(d, "score");
        try e.num();
        try e.comma(false);
        try e.member(d, "tags");
        try e.w.writeByte('[');
        const nt = r.intRangeAtMost(u8, 3, 6);
        for (0..nt) |i| {
            if (i != 0) try e.w.writeAll(", ");
            try e.word();
        }
        if (e.json5) try e.w.writeByte(',');
        try e.w.writeByte(']');
        try e.comma(false);
        try e.member(d, "values");
        try e.w.writeByte('[');
        const nv = r.intRangeAtMost(u8, 4, 10);
        for (0..nv) |i| {
            if (i != 0) try e.w.writeAll(", ");
            try e.num();
        }
        if (e.json5) try e.w.writeByte(',');
        try e.w.writeByte(']');
        try e.comma(false);
        try e.member(d, "note");
        if (r.uintLessThan(u8, 5) == 0) try e.w.writeAll("null") else try e.word();
        const has_meta = depth < 3;
        const has_children = depth < 2;
        try e.comma(!has_meta and !has_children);
        if (has_meta) {
            try e.member(d, "meta");
            try e.record(d);
            try e.comma(!has_children);
        }
        if (has_children) {
            try e.member(d, "children");
            try e.w.writeAll("[\n");
            const nc = r.intRangeAtMost(u8, 1, 2);
            for (0..nc) |i| {
                try e.indent(d + 1);
                try e.record(d + 1);
                try e.comma(i + 1 == nc);
            }
            try e.indent(d);
            try e.w.writeByte(']');
            try e.comma(true);
        }
        try e.indent(depth);
        try e.w.writeByte('}');
    }

    fn document(e: *Emit, records: ?usize, allocating: *std.Io.Writer.Allocating, min_len: usize) !usize {
        try e.w.writeAll("[\n");
        var n: usize = 0;
        while (if (records) |rc| n < rc else allocating.written().len < min_len) : (n += 1) {
            try e.w.writeAll("  ");
            try e.record(1);
            try e.comma(false);
        }
        // the last record carries a comma: JSON needs none after it
        if (!e.json5) {
            // rewrite the trailing ",\n" as "\n"
            allocating.writer.end -= 2;
            try e.w.writeByte('\n');
        }
        try e.w.writeAll("]\n");
        return n;
    }
};

fn generate(arena: std.mem.Allocator, as_json5: bool, records: ?usize) !struct { text: []const u8, records: usize } {
    var out: std.Io.Writer.Allocating = .init(arena);
    var e: Emit = .{ .w = &out.writer, .json5 = as_json5, .prng = .init(0x6a736f6e35) };
    const n = try e.document(records, &out, 1 << 20);
    return .{ .text = out.written(), .records = n };
}

// ── our side ─────────────────────────────────────────────────────────────────

fn countValue(v: std.json.Value) u64 {
    var n: u64 = 0;
    switch (v) {
        .array => |a| {
            n += a.items.len;
            for (a.items) |x| n += countValue(x);
        },
        .object => |o| {
            n += o.count();
            for (o.values()) |x| n += countValue(x);
        },
        else => {},
    }
    return n;
}

const Data = struct { texts: [works.len][]const u8 };

fn once(d: *const Data, wi: usize) u64 {
    const w = works[wi];
    const text = d.texts[wi];
    var sum: u64 = 0;
    for (0..w.reps) |_| switch (w.kind) {
        .parse => {
            const p = json5.parseFromSlice(std.json.Value, gpa, text, .{}) catch @panic("json5 parse failed");
            sum += countValue(p.value);
            p.deinit();
        },
        .preprocess => {
            const out = json5.preprocess(gpa, text) catch @panic("json5 preprocess failed");
            sum += out.len;
            gpa.free(out);
        },
    };
    return sum;
}

fn selected(name: []const u8, filters: []const [:0]const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |f| if (std.mem.find(u8, name, f) != null) return true;
    return false;
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

    const big_json = try generate(arena, false, null);
    const big_json5 = try generate(arena, true, big_json.records);
    try dir.writeFile(io, .{ .sub_path = "small_config.json5", .data = small_config });
    try dir.writeFile(io, .{ .sub_path = "large_json.json", .data = big_json.text });
    try dir.writeFile(io, .{ .sub_path = "large_json5.json5", .data = big_json5.text });
    var d: Data = undefined;
    d.texts = .{ small_config, big_json.text, big_json5.text, big_json5.text };

    // Our own sanity check before anything is timed: the JSON and JSON5 renderings
    // of the large document must parse to the same tree size.
    {
        const a = try json5.parseFromSlice(std.json.Value, gpa, big_json.text, .{});
        defer a.deinit();
        const b = try json5.parseFromSlice(std.json.Value, gpa, big_json5.text, .{});
        defer b.deinit();
        if (countValue(a.value) != countValue(b.value)) {
            std.debug.print("{s}: the JSON and JSON5 documents differ in size ({d} vs {d})\n", .{ bench_name, countValue(a.value), countValue(b.value) });
            return 1;
        }
    }

    const bun_ver = blk: {
        const r = std.process.run(arena, io, .{ .argv = &.{ "bun", "--version" } }) catch |e| {
            std.debug.print("{s}: could not run bun ({t}) -- the benchmark needs it\n", .{ bench_name, e });
            return 1;
        };
        break :blk std.mem.trim(u8, r.stdout, " \n");
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("document: {d} records, {d} bytes JSON, {d} bytes JSON5; small_config {d} bytes\n", .{ big_json.records, big_json.text.len, big_json5.text.len, small_config.len });
    try w.print("{s:<24} {s:>13} {s:>13} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "/ref", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var banner: []const u8 = "";
    for (works, 0..) |wk, wi| {
        if (!selected(wk.name, filters)) continue;
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        const has_ref = wk.kind == .parse;
        for (0..rounds) |_| {
            if (has_ref) ref.add(try bench.foreignArgv(arena, io, bench_name, &.{ "bun", ref_script, abs, wk.name }, wk.name, &banner));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        max_spread = @max(max_spread, ours.spread(false));
        if (!has_ref) {
            try w.print("{s:<24} {d:>13.0} {s:>13} {s:>8} {d:>6.1}% {s:>7}  {d}  (info only: no reference counterpart)\n", .{ wk.name, ours.best_ns, "-", "-", 100 * ours.spread(false), "-", ours.count });
            try w.flush();
            continue;
        }
        const ratio = ours.best_ns / ref.best_ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        max_spread = @max(max_spread, ref.spread(false));
        const same = ours.count == ref.count;
        mismatch = mismatch or !same;
        try w.print("{s:<24} {d:>13.0} {d:>13.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ wk.name, ours.best_ns, ref.best_ns, ratio, 100 * ours.spread(false), 100 * ref.spread(false), ours.count, if (same) "" else " ≠ ref (ref count printed below)" });
        if (!same) try w.print("  ref count {d}\n", .{ref.count});
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (banner.len > 0) try w.print("reference: {s}\n", .{std.mem.trim(u8, banner, " \n")});
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× json5/json5 2.2.3 (bun {s}) · fastest ? (measured <today>)\n", .{ best, worst, bun_ver });
    try w.flush();
    return 0;
}
