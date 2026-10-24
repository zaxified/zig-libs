// SPDX-License-Identifier: MIT

//! Comparative benchmark: `staticfiles` against Go 1.26.0 `net/http`
//! `FileServer(http.Dir)` (the reference), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-staticfiles` runs it
//! (always ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (stdlib only, `GOPROXY=off`). Run from the repository root.
//!
//! Both sides serve the SAME file tree (written under
//! `.zig-cache/bench-staticfiles/root`: a 1 KiB index page, a 4 KiB png, a
//! 20 KiB css, a 200 KiB js, a 100 KiB jpg in a subdirectory with its own
//! index, a tiny file three directories deep). Each workload is a set of
//! requests, request bytes in, response bytes out, with no sockets: ours
//! `http.Server.serveStream` over `staticfiles.httpHandler` (no compression, no
//! directory listing), Go's `http.ReadRequest` + `FileServer.ServeHTTP` into a
//! buffer. Both open, stat, read and close the real files on every request,
//! so the HTTP stacks and the kernel are in the number on both sides (as in
//! router's `serve`).
//!   small  GET / (index.html), /logo.png, /a/b/c/d.txt
//!   large  GET /app.js (200 KiB), /img/photo.jpg (100 KiB)
//!   cond   GET /app.css with a future If-Modified-Since (304);
//!          GET /app.js with Range: bytes=1000-1999 (206)
//!   miss   GET /missing.txt (404); GET /img (301 to /img/)
//! Result count = sum of the status codes + the body bytes of every 200 / 206
//! (404 / 301 bodies differ in text between the two and are not counted).
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/Go by wall time; the verdict is the WORST
//! ratio. Arguments filter workloads.
//!
//! "Fastest in the field": `tools/rust_fast_bench` (tower-http 0.7.1 `ServeDir`
//! driven as a tower `Service` in-process on a tokio current-thread runtime,
//! over the same request bytes and file tree) is timed the same way. It is not
//! like-for-like work (the Rust request side is httparse + `http::Request`;
//! ServeDir is async and its file IO goes through tokio's blocking pool, which
//! is its real cost and is left in; default configuration; the source header
//! says where). Its directory redirect is a 307 where ours is a 301 and counts
//! as one; any other status that differs from ours shows up as a count
//! mismatch. `BENCH_FAST=0` skips it (needs cargo and the
//! pinned crates in ~/.cargo/registry). The card's fastest figure is ours /
//! the cheaper of {Go, tower-http} per row, worst over the rows.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const staticfiles = @import("staticfiles");

const bench_name = "bench-staticfiles";
const work_dir = ".zig-cache/bench-staticfiles";
const go_dir = "modules/staticfiles/tools/go_bench";
const ref_short = "Go";
const ref_card = "Go 1.26.8 net/http FileServer"; // GOTOOLCHAIN=local: the host's go

const fast_rs_manifest = "modules/staticfiles/tools/rust_fast_bench/Cargo.toml";
const fast_rs_exe = "modules/staticfiles/tools/rust_fast_bench/target/release/staticfiles_fast_bench";
const fast_name = "tower-http";
const fast_card = "tower-http 0.7.1 ServeDir";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "small", "large", "cond", "miss" };

const Req = struct { path: []const u8, extra: []const u8 = "" };
const sets = [names.len][]const Req{
    &.{ .{ .path = "/" }, .{ .path = "/logo.png" }, .{ .path = "/a/b/c/d.txt" } },
    &.{ .{ .path = "/app.js" }, .{ .path = "/img/photo.jpg" } },
    &.{
        .{ .path = "/app.css", .extra = "If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT\r\n" },
        .{ .path = "/app.js", .extra = "Range: bytes=1000-1999\r\n" },
    },
    &.{ .{ .path = "/missing.txt" }, .{ .path = "/img" } },
};

const Data = struct {
    handler: staticfiles.Handler,
    wires: [names.len][3][]const u8,
    out: []u8,
};

fn once(d: *const Data, w: usize) u64 {
    var sum: u64 = 0;
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    for (d.wires[w][0..sets[w].len]) |wire| {
        var in: std.Io.Reader = .fixed(wire);
        var out: std.Io.Writer = .fixed(d.out);
        http.Server.serveStream(.{
            .handler = staticfiles.httpHandler,
            .context = @constCast(&d.handler),
            .server_name = null,
        }, &in, &out, .{
            .head = &head_buf,
            .request_body = &request_body_buf,
            .response_body = &response_body_buf,
            .chunk = &chunk_buf,
        });
        const resp = out.buffered();
        const status = std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
        sum += status;
        if (status == 200 or status == 206) {
            const he = std.mem.find(u8, resp, "\r\n\r\n") orelse resp.len - 4;
            sum += resp.len - (he + 4);
        }
    }
    return sum;
}

fn writeFile(io: std.Io, dir: std.Io.Dir, path: []const u8, size: usize, fill: u8) !void {
    if (std.fs.path.dirname(path)) |p| try dir.createDirPath(io, p);
    const data = try std.heap.smp_allocator.alloc(u8, size);
    defer std.heap.smp_allocator.free(data);
    for (data, 0..) |*b, i| b.* = if (i % 64 == 63) '\n' else fill + @as(u8, @intCast(i % 20));
    try dir.writeFile(io, .{ .sub_path = path, .data = data });
}

var io_global: std.Io = undefined;

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    io_global = io;
    try dir.createDirPath(io, "root");
    const root = try dir.openDir(io, "root", .{});
    try writeFile(io, root, "index.html", 1024, 'a');
    try writeFile(io, root, "logo.png", 4096, 'b');
    try writeFile(io, root, "app.css", 20 * 1024, 'c');
    try writeFile(io, root, "app.js", 200 * 1024, 'd');
    try writeFile(io, root, "img/photo.jpg", 100 * 1024, 'e');
    try writeFile(io, root, "img/index.html", 512, 'f');
    try writeFile(io, root, "a/b/c/d.txt", 300, 'g');
    var d: Data = undefined;
    d.handler = staticfiles.Handler.init(io, root, .{});
    d.out = try arena.alloc(u8, 512 * 1024);
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        for (sets[wi], 0..) |q, i| {
            const wire = try arena.print("GET {s} HTTP/1.1\r\nHost: t\r\n{s}Connection: close\r\n\r\n", .{ q.path, q.extra });
            d.wires[wi][i] = wire;
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(wire);
        }
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.wire", .{name}), .data = all.written() });
    }
    return d;
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

    var d: Data = try setup(arena, io, dir);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    if (use_fast) try rustBuild(arena, io);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    if (use_fast) try w.print("{s:<22} {s:>11} {s:>9}  vs cheapest (who)\n", .{ "", fast_name ++ " ns", "ours/best" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var worst_fast_row: []const u8 = "";
    var worst_fast_who: []const u8 = "";
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var fast: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) fast.add(try fastRun(arena, io, abs, name));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name): the cost of the HTTP stacks both sides
        // carry is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        const in_net = std.mem.startsWith(u8, name, if (@hasDecl(@This(), "net_prefix")) @field(@This(), "net_prefix") else "");
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (in_net and base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        if (use_fast) {
            // no shared HTTP-stack baseline here: gross times, the cheaper of
            // the reference and the contender is the yardstick
            var fastest_t = go.best_ns;
            var fastest_who: []const u8 = ref_short;
            try w.print("{s:<22} {d:>11.0}", .{ "", fast.best_ns });
            max_spread = @max(max_spread, fast.spread(false));
            if (fast.count != ours.count) {
                mismatch = true;
                try w.print(" ({s}: {d} != ours {d})", .{ fast_name, fast.count, ours.count });
            }
            if (fast.best_ns < fastest_t) {
                fastest_t = fast.best_ns;
                fastest_who = fast_card;
            }
            const ratio_fast = ours.best_ns / fastest_t;
            if (!info and ratio_fast > worst_fast) {
                worst_fast = ratio_fast;
                worst_fast_row = name;
                worst_fast_who = fastest_who;
            }
            try w.print(" {d:>9.3}  ({s})\n", .{ ratio_fast, fastest_who });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst vs fastest = {d:.2} (row {s}, {s})\n", .{ worst_fast, worst_fast_row, worst_fast_who });
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_fast_who })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

// ---- the "fastest in the field" side ----

/// `cargo build --release --offline` of tools/rust_fast_bench.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", fast_rs_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

/// `<exe> <work dir> <workload> <contender>` prints `name \t ns/op \t count`.
fn fastRun(arena: std.mem.Allocator, io: std.Io, abs: []const u8, name: []const u8) !bench.Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ fast_rs_exe, abs, name, fast_name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed on {s}:\n{s}\n", .{ bench_name, fast_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
