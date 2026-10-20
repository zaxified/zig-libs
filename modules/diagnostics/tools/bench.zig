// SPDX-License-Identifier: MIT

//! Comparative benchmark: `diagnostics` (the `snippet` style) against
//! codespan-reporting 0.13.1 (Rust, Apache-2.0; the layout code is ported from
//! it) as the reference and annotate-snippets 0.12.17 (Rust, MIT OR Apache-2.0)
//! as the second candidate for the `fastest` column -- the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-diagnostics` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cargo` and the
//! crates in the local registry (`cargo fetch` once; pinned by
//! `tools/codespan_bench/Cargo.toml`/`Cargo.lock`). The Rust side is built here,
//! offline and `--locked`, into `.zig-cache/bench-diagnostics/target`. Run from
//! the repository root.
//!
//! The corpus is generated here (deterministic) and written, with the spans of
//! every workload, to `.zig-cache/bench-diagnostics/`; the Rust side reads the
//! same files (`tools/codespan_bench/src/main.rs`) and times itself exactly as
//! this side does (double the batch until it takes over 100 ms, best of five).
//!
//!   many_single  10 000 diagnostics, one primary label each on random lines of
//!                a 1 MB, ~20 000-line source
//!   many_multi   2 000 diagnostics, 3 labels each: the primary, a secondary on
//!                the same line, a secondary on another line (1-40 lines away)
//!   multiline    1 000 diagnostics with a primary span over 5 lines
//!   long_line    200 diagnostics on a 100 KB single-line source, no term_width
//!   long_line_tw INFO: the same with term_width 120, against annotate-snippets
//!                only (codespan has no such option)
//!
//! Ours is `renderOne` into a reused in-memory writer, `.style = .snippet`,
//! `.chars = .ascii`, `.column = .char`, `Source.line_starts` from
//! `Source.indexLines` built once (codespan's `SimpleFile` precomputes them
//! too); codespan is `term::emit_to_io_write` into a reused `Vec<u8>`; annotate
//! gets one `Snippet` of the source lines a diagnostic is on (so it does not
//! scan 1 MB per diagnostic) and returns a `String` per diagnostic, which is
//! only measured.
//!
//! Before anything is timed: (1) our output for the first 20 diagnostics of
//! many_single and many_multi must be BYTE-IDENTICAL to codespan's; (2) the
//! count of every workload -- diagnostics rendered plus '^' in the output -- must
//! agree between ours, codespan and annotate-snippets (the full output cannot
//! be compared: annotate-snippets draws another layout). The sides alternate for
//! BENCH_ROUNDS (default 3) rounds, each keeping its best; the Rust side has no
//! cycle counter, so ratios are ours/theirs by wall time. Arguments filter
//! workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const diagnostics = @import("diagnostics");
const Work = bench.Work(Op);

const bench_name = "bench-diagnostics";
const work_dir = ".zig-cache/bench-diagnostics";
const cargo_manifest = "modules/diagnostics/tools/codespan_bench/Cargo.toml";
const file_name = "f.txt";
const header = "bad value";
const primary_msg = "unexpected token";
const secondary_msg = "related here";
const gpa = std.heap.smp_allocator;

const Span = struct { start: usize, end: usize };
const Kind = enum { many_single, many_multi, multiline, long_line, long_line_tw };
const kinds = std.enums.values(Kind);
const Op = struct { kind: Kind };

const Prepared = struct {
    diags: []diagnostics.Diagnostic,
    spans: []const []const Span,
    /// The number of '^' in the output, counted on the first render.
    carets: ?u64 = null,
};

const Ctx = struct {
    prepared: [kinds.len]Prepared,
    sources: [2][1]diagnostics.Source,
    out: std.Io.Writer.Allocating,
    op: Op = undefined,
};

fn sourceOf(k: Kind) usize {
    return switch (k) {
        .long_line, .long_line_tw => 1,
        else => 0,
    };
}

fn renderAll(x: *Ctx, k: Kind, limit: usize) void {
    const p = &x.prepared[@backingInt(k)];
    const opts: diagnostics.RenderOptions = .{
        .style = .snippet,
        .sources = &x.sources[sourceOf(k)],
        .chars = .ascii,
        .column = .char,
        .term_width = if (k == .long_line_tw) 120 else null,
    };
    x.out.clearRetainingCapacity();
    for (p.diags[0..@min(limit, p.diags.len)]) |d| diagnostics.renderOne(&x.out.writer, d, opts) catch @panic("render failed");
}

fn once(x: *Ctx) usize {
    const k = x.op.kind;
    renderAll(x, k, std.math.maxInt(usize));
    const p = &x.prepared[@backingInt(k)];
    if (p.carets == null) p.carets = std.mem.count(u8, x.out.written(), "^");
    return p.diags.len + p.carets.?;
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn randomLine(r: std.Random, out: *std.ArrayList(u8), len: usize) !void {
    for (0..len) |i| {
        const edge = i == 0 or i + 1 == len;
        const c: u8 = if (!edge and r.uintLessThan(u8, 6) == 0) ' ' else 'a' + r.uintLessThan(u8, 26);
        try out.append(gpa, c);
    }
}

fn lineLen(text: []const u8, starts: []const u32, l: usize) usize {
    const end: usize = if (l + 1 < starts.len) starts[l + 1] - 1 else text.len;
    return end - starts[l];
}

fn lineOf(starts: []const u32, off: usize) usize {
    var lo: usize = 0;
    var hi: usize = starts.len; // first start > off
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (starts[mid] <= off) lo = mid + 1 else hi = mid;
    }
    return lo - 1;
}

fn spanOnLine(r: std.Random, starts: []const u32, text: []const u8, l: usize, lo_col: usize, hi_col: usize) Span {
    // A span of 1..12 bytes starting at a column in [lo_col, hi_col), inside the line.
    const len = lineLen(text, starts, l);
    const hi = @min(hi_col, len);
    const col = lo_col + r.uintLessThan(usize, hi - lo_col);
    const w = r.intRangeAtMost(usize, 1, @min(12, len - col));
    return .{ .start = starts[l] + col, .end = starts[l] + col + w };
}

const Gen = struct {
    big: []const u8,
    big_starts: []const u32,
    long: []const u8,
    long_starts: []const u32,
    specs: [kinds.len][]const []const Span,
};

fn generate() !Gen {
    var prng = std.Random.DefaultPrng.init(0xd1a9_05c0);
    const r = prng.random();

    var big: std.ArrayList(u8) = .empty;
    while (big.items.len < 1 << 20) {
        try randomLine(r, &big, r.intRangeAtMost(usize, 25, 85));
        try big.append(gpa, '\n');
    }
    var long: std.ArrayList(u8) = .empty;
    try randomLine(r, &long, 100_000);
    const bs = try diagnostics.Source.indexLines(gpa, big.items);
    const ls = try diagnostics.Source.indexLines(gpa, long.items);
    const nl = bs.len - 1; // the line after the last '\n' is empty

    var g: Gen = .{ .big = big.items, .big_starts = bs, .long = long.items, .long_starts = ls, .specs = undefined };

    const single = try gpa.alloc([]const Span, 10_000);
    for (single) |*d| {
        const l = r.uintLessThan(usize, nl);
        const s = try gpa.alloc(Span, 1);
        s[0] = spanOnLine(r, bs, big.items, l, 0, lineLen(big.items, bs, l));
        d.* = s;
    }
    const multi = try gpa.alloc([]const Span, 2_000);
    for (multi) |*d| {
        const l = r.uintLessThan(usize, nl);
        const len = lineLen(big.items, bs, l);
        const half = len / 2;
        const dist = r.intRangeAtMost(usize, 1, 40);
        const l2 = if (l + dist < nl) l + dist else l - dist;
        const s = try gpa.alloc(Span, 3);
        s[0] = spanOnLine(r, bs, big.items, l, 0, half - 12);
        s[1] = spanOnLine(r, bs, big.items, l, half + 1, len);
        s[2] = spanOnLine(r, bs, big.items, l2, 0, lineLen(big.items, bs, l2));
        d.* = s;
    }
    const ml = try gpa.alloc([]const Span, 1_000);
    for (ml) |*d| {
        const l = r.uintLessThan(usize, nl - 5);
        const len = lineLen(big.items, bs, l);
        const l4 = l + 4;
        const s = try gpa.alloc(Span, 1);
        s[0] = .{
            .start = bs[l] + r.uintLessThan(usize, len),
            .end = bs[l4] + r.intRangeAtMost(usize, 1, lineLen(big.items, bs, l4)),
        };
        d.* = s;
    }
    const ll = try gpa.alloc([]const Span, 200);
    for (ll) |*d| {
        const s = try gpa.alloc(Span, 1);
        s[0] = spanOnLine(r, ls, long.items, 0, 0, long.items.len);
        d.* = s;
    }
    g.specs = .{ single, multi, ml, ll, ll };
    return g;
}

fn writeSpec(io: std.Io, dir: std.Io.Dir, name: []const u8, spec: []const []const Span) !void {
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    for (spec) |d| {
        for (d, 0..) |s, i| try buf.writer.print("{s}{d} {d}", .{ if (i == 0) "" else " ", s.start, s.end });
        try buf.writer.writeByte('\n');
    }
    try dir.writeFile(io, .{ .sub_path = name, .data = buf.written() });
}

// ── our side ─────────────────────────────────────────────────────────────────

fn prepare(arena: std.mem.Allocator, starts: []const u32, spec: []const []const Span) ![]diagnostics.Diagnostic {
    const out = try arena.alloc(diagnostics.Diagnostic, spec.len);
    for (spec, out) |d, *o| {
        const p = d[0];
        const l0 = lineOf(starts, p.start);
        const l1 = lineOf(starts, p.end);
        const labels = try arena.alloc(diagnostics.Label, d.len - 1);
        for (d[1..], labels) |s, *lab| {
            const a = lineOf(starts, s.start);
            const b = lineOf(starts, s.end);
            lab.* = .{
                .line = @intCast(a + 1),
                .col = @intCast(s.start - starts[a] + 1),
                .end_line = @intCast(b + 1),
                .end_col = @intCast(s.end - starts[b] + 1),
                .message = secondary_msg,
            };
        }
        o.* = .{
            .path = "",
            .file = file_name,
            .line = @intCast(l0 + 1),
            .col = @intCast(p.start - starts[l0] + 1),
            .end_line = @intCast(l1 + 1),
            .end_col = @intCast(p.end - starts[l1] + 1),
            .severity = .@"error",
            .code = "",
            .message = header,
            .span_message = primary_msg,
            .labels = if (labels.len > 0) labels else null,
        };
    }
    return out;
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

    const g = try generate();
    try dir.writeFile(io, .{ .sub_path = "big.txt", .data = g.big });
    try dir.writeFile(io, .{ .sub_path = "long.txt", .data = g.long });
    try writeSpec(io, dir, "single.spec", g.specs[0]);
    try writeSpec(io, dir, "multi.spec", g.specs[1]);
    try writeSpec(io, dir, "multiline.spec", g.specs[2]);
    try writeSpec(io, dir, "long.spec", g.specs[3]);

    var ctx: Ctx = .{
        .prepared = undefined,
        .sources = .{
            .{.{ .file = file_name, .text = g.big, .line_starts = g.big_starts }},
            .{.{ .file = file_name, .text = g.long, .line_starts = g.long_starts }},
        },
        .out = .init(gpa),
    };
    for (kinds) |k| {
        const si = sourceOf(k);
        const starts = if (si == 0) g.big_starts else g.long_starts;
        const spec = g.specs[@backingInt(k)];
        ctx.prepared[@backingInt(k)] = .{ .diags = try prepare(arena, starts, spec), .spans = spec };
    }

    // The Rust side, built once, offline.
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const built = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (built.term != .exited or built.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, built.stderr });
        return 1;
    }
    const exe = try arena.print("{s}/release/codespan_bench", .{target});

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    // Pre-check 1: byte-identical output on a sample.
    const chk = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "check" } });
    if (chk.term != .exited or chk.term.exited != 0) {
        std.debug.print("{s}: the Rust check failed:\n{s}\n", .{ bench_name, chk.stderr });
        return 1;
    }
    for ([_]Kind{ .many_single, .many_multi }) |k| {
        renderAll(&ctx, k, 20);
        const theirs = try dir.readFileAlloc(io, try arena.print("sample_cs_{t}.txt", .{k}), arena, .limited(1 << 24));
        const mine = ctx.out.written();
        if (!std.mem.eql(u8, mine, theirs)) {
            const at = std.mem.findDiff(u8, mine, theirs) orelse @min(mine.len, theirs.len);
            std.debug.print("{s}: FAILED -- {t}: our output differs from codespan's at byte {d} (ours {d} bytes, theirs {d})\n", .{ bench_name, k, at, mine.len, theirs.len });
            try dir.writeFile(io, .{ .sub_path = try arena.print("sample_ours_{t}.txt", .{k}), .data = mine });
            return 1;
        }
        try w.print("pre-check: {t}: first 20 diagnostics byte-identical to codespan-reporting ({d} bytes)\n", .{ k, mine.len });
    }

    // Pre-check 2: the count of every workload agrees on all three sides.
    var lines = std.mem.tokenizeScalar(u8, chk.stdout, '\n');
    var bad = false;
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        _ = f.next(); // "count"
        const name = f.next().?;
        const cs = try std.fmt.parseInt(u64, f.next().?, 10);
        const an = try std.fmt.parseInt(u64, f.next().?, 10);
        const k = std.meta.stringToEnum(Kind, name).?;
        ctx.op = .{ .kind = k };
        const mine = once(&ctx);
        const ok = mine == cs and mine == an;
        if (!ok) bad = true;
        try w.print("pre-check: count {s:<13} ours {d:>8}  codespan {d:>8}  annotate {d:>8}{s}\n", .{ name, mine, cs, an, if (ok) "" else "  MISMATCH" });
    }
    try w.flush();
    if (bad) {
        try w.writeAll(bench_name ++ ": FAILED -- the counts differ before timing; see above\n");
        try w.flush();
        return 1;
    }

    var ws: std.ArrayList(Work) = .empty;
    for ([_]Kind{ .many_single, .many_multi, .multiline, .long_line }) |k| {
        try ws.append(arena, .{
            .name = @tagName(k),
            .op = .{ .kind = k },
            .ref = try arena.print("cs_{t}", .{k}),
            .alt = try arena.print("as_{t}", .{k}),
        });
    }
    try ws.append(arena, .{ .name = "long_line_tw", .op = .{ .kind = .long_line_tw }, .ref = "as_long_line_tw", .info = true });

    const s = bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("reference: {s}\nworst ours/codespan = {d:.3} (best {d:.3})", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (s.worst_fast) |wf| try w.print("; worst ours/min(codespan, annotate) = {d:.3}", .{wf});
    try w.writeByte('\n');
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× codespan-reporting 0.13.1 · fastest {d:.2}× worst vs the faster of codespan-reporting 0.13.1 and annotate-snippets 0.12.17 (measured 2026-10-20)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
