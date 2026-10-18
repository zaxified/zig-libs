// SPDX-License-Identifier: MIT

//! Comparative benchmark: `http` (the HTTP/1.1 server codec) against Go 1.26.0
//! `net/http` (the reference), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-http` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 (stdlib
//! only, `GOPROXY=off`). Run from the repository root.
//!
//! What it measures: a connection's worth of keep-alive requests, bytes in and
//! bytes out, no sockets. Ours `http.Server.serveStream` over a handler; Go's
//! `bufio.Reader` + `http.ReadRequest` in a loop + a handler writing the status
//! line, headers and body into a per-request buffer (the real Go server adds
//! the Date header, `Content-Length` bookkeeping and a socket write on top, so
//! the Go side is the lighter one here -- the ratio errs against us). One op =
//! 16 requests on one stream, the last `Connection: close`. Workloads, each
//! with the same handler on both sides:
//!   get      browser-like GET (10 headers, ~600 B head): read User-Agent, set
//!            3 headers, 200-byte JSON body
//!   post     POST with a 1 KiB `Content-Length` body, read to the end, "ok"
//!   chunked  POST with a chunked body (3 x 500 B), read to the end, "ok"
//!   large    GET answered with 64 KiB (`Content-Length` set, 16 x 4 KiB writes)
//!   headers  GET with 40 request headers (a proxied request): look one up
//! Result count = per request 200 + request-body bytes read + response-body
//! bytes written + the length of the header looked up, accumulated by the
//! handlers themselves; before any timing each side checks that one op gave
//! exactly 16 `HTTP/1.1 200` responses. Each side times the same way (double
//! the batch until it takes over 100 ms, best of five); the sides alternate for
//! BENCH_ROUNDS (default 3) rounds, each keeping its best. Ratios are ours/Go
//! by wall time; the verdict is the WORST ratio. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");

const bench_name = "bench-http";
const work_dir = ".zig-cache/bench-http";
const go_dir = "modules/http/tools/go_bench";
const ref_short = "Go";
const ref_card = "Go 1.26.0 net/http";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "get", "post", "chunked", "large", "headers" };
const n_req = 16;

const Data = struct {
    wires: [names.len][]u8,
    out: []u8,
};

var total: u64 = 0;
const json_body = "{\"id\":42,\"name\":\"example\",\"tags\":[\"a\",\"b\",\"c\"],\"active\":true,\"score\":3.14159,\"description\":\"A short JSON document returned by the benchmark handler so that the response has a body of a realistic size.\",\"n\":1}                    ";
const block = @as([4096]u8, @splat('x'));

fn hGet(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const ua: []const u8 = req.header("User-Agent") orelse "";
    total += ua.len;
    try rw.setHeader("Content-Type", "application/json");
    try rw.setHeader("X-Request-Cost", "12");
    try rw.setHeader("Cache-Control", "no-store");
    try rw.writeAll(json_body[0..200]);
    total += 200 + 200;
}

fn hPost(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    total += req.reader().discardRemaining() catch 0;
    try rw.writeAll("ok");
    total += 200 + 2;
}

fn hLarge(_: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    try rw.setHeader("Content-Length", "65536");
    for (0..16) |_| try rw.writeAll(&block);
    total += 200 + 65536;
}

fn hHeaders(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const tid: []const u8 = req.header("X-Trace-Id") orelse "";
    total += tid.len;
    try rw.writeAll("ok");
    total += 200 + 2;
}

fn once(d: *const Data, w: usize) u64 {
    total = 0;
    var head_buf: [8192]u8 = undefined;
    var request_body_buf: [4096]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    var in: std.Io.Reader = .fixed(d.wires[w]);
    var out: std.Io.Writer = .fixed(d.out);
    http.Server.serveStream(.{
        .handler = switch (w) {
            0 => hGet,
            1, 2 => hPost,
            3 => hLarge,
            else => hHeaders,
        },
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return total;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.out = try arena.alloc(u8, 16 * (65536 + 1024));
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        const w = &all.writer;
        for (0..n_req) |i| {
            const conn: []const u8 = if (i == n_req - 1) "close" else "keep-alive";
            switch (wi) {
                0 => try w.print(
                    "GET /api/items/{d}?expand=owner&fields=id,name HTTP/1.1\r\n" ++
                        "Host: api.example.com\r\n" ++
                        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n" ++
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" ++
                        "Accept-Language: cs,en-US;q=0.9,en;q=0.8\r\n" ++
                        "Accept-Encoding: gzip, deflate, br\r\n" ++
                        "Cookie: sid=3f9a8c1d2b7e4a6f90c1d2e3f4a5b6c7; theme=dark; lang=cs; consent=yes\r\n" ++
                        "Referer: https://api.example.com/dashboard\r\n" ++
                        "Cache-Control: max-age=0\r\n" ++
                        "Upgrade-Insecure-Requests: 1\r\n" ++
                        "Connection: {s}\r\n\r\n",
                    .{ i, conn },
                ),
                1 => {
                    try w.print("POST /api/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: {s}\r\n\r\n", .{conn});
                    try w.splatByteAll('{', 1024);
                },
                2 => {
                    try w.print("POST /api/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: {s}\r\n\r\n", .{conn});
                    for (0..3) |_| {
                        try w.writeAll("1f4\r\n");
                        try w.splatByteAll('{', 500);
                        try w.writeAll("\r\n");
                    }
                    try w.writeAll("0\r\n\r\n");
                },
                3 => try w.print("GET /big HTTP/1.1\r\nHost: api.example.com\r\nConnection: {s}\r\n\r\n", .{conn}),
                else => {
                    try w.print("GET /proxy/{d} HTTP/1.1\r\nHost: api.example.com\r\n", .{i});
                    for (0..38) |h| try w.print("X-Header-{d:0>2}: value-{d:0>2}-abcdefghijklmnop\r\n", .{ h, h });
                    try w.print("X-Trace-Id: abcdef0123456789\r\nConnection: {s}\r\n\r\n", .{conn});
                },
            }
        }
        d.wires[wi] = try arena.dupe(u8, all.written());
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.wire", .{name}), .data = d.wires[wi] });
    }
    // Each workload must give exactly 16 responses on our side too.
    for (names, 0..) |_, wi| {
        var in: std.Io.Reader = .fixed(d.wires[wi]);
        var out: std.Io.Writer = .fixed(d.out);
        var hb: [8192]u8 = undefined;
        var rb: [4096]u8 = undefined;
        var sb: [8192]u8 = undefined;
        var cb: [512]u8 = undefined;
        http.Server.serveStream(.{ .handler = switch (wi) {
            0 => hGet,
            1, 2 => hPost,
            3 => hLarge,
            else => hHeaders,
        }, .server_name = null }, &in, &out, .{ .head = &hb, .request_body = &rb, .response_body = &sb, .chunk = &cb });
        const n = std.mem.count(u8, out.buffered(), "HTTP/1.1 200 ");
        if (n != n_req) {
            std.debug.print("{s}: workload {s}: expected {d} responses, got {d}\n", .{ bench_name, names[wi], n_req, n });
            return error.BadWorkload;
        }
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
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
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
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}
