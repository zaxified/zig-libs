// SPDX-License-Identifier: MIT

//! Comparative benchmark: `aaa-gate` against labstack/echo v5.4.0
//! `middleware.KeyAuth` (Go, MIT; the reference), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-aaa-gate` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! github.com/labstack/echo/v5 v5.4.0 + golang.org/x/time v0.15.0 in the module
//! cache (pinned by `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`,
//! `GOTOOLCHAIN=local`). Run from the repository root.
//!
//! LAYER. Neither side has an entry point that covers credential EXTRACTION
//! (header lookup, prefix cut, query scan) together with the decision outside
//! a request: ours is `middlewareRun` (`verify`/`verifyApiKey` take an already
//! extracted value), echo's KeyAuth is a middleware that needs an
//! `echo.Context`. So the layer is "the request is parsed, the router runs the
//! middleware chain and the response is rendered": 64 PRE-PARSED requests to
//! one route "/" per op, parsed once outside the timed region (ours
//! `h1.RequestHead.parse` into a hand-built `http.Server.Request`, then
//! `Router.dispatch` + `Gate.middleware()` with a fresh `ResponseWriter` over a
//! fixed buffer + `end()`; echo's `http.ReadRequest` into a slice, then
//! `Echo.ServeHTTP` (`KeyAuthWithConfig` + a route) with a ResponseWriter that
//! renders status line, headers and body into a buffer). No sockets, and no
//! head parsing in either number. The router and the response writer are still
//! in it on both sides, so each workload is measured twice, with the middleware
//! and without it (`_plain`: the same requests, the same route, no middleware;
//! INFO only), and the verdict is the "net" ratio per row: (with - plain) per
//! side, i.e. the cost of the gate itself including its 401 answer. Gross
//! (router + writer included) is printed beside.
//!
//! Same policy on both sides, 3 configured keys (26 bytes each, the same strings
//! as tokens and as API keys), no audit hook (echo has none):
//!   bearer_ok          `Authorization: Bearer <valid>` (the three in rotation)
//!   bearer_denied      `Authorization: Bearer <26 bytes on no list>` -> 401
//!   api_key_header_ok  `X-Api-Key: <valid>`   (ours `.api_key`, echo
//!                      `header:X-Api-Key`)
//!   api_key_query_ok   `GET /?api_key=<valid>` (ours `api_key_query_param`,
//!                      echo `query:api_key`)
//!   no_credential      no credential at all, bearer policy -> 401
//!   basic_ok           HTTP Basic, a valid user:password (echo `BasicAuthWithConfig`)
//!   basic_denied       same, a wrong password -> 401
//!
//! THE COMPARE (owner decision 2026-10-17: like for like). echo leaves the
//! comparison to the caller's `Validator`; the verdict one gives aaa-gate's
//! guarantee — SHA-256 digests only, the presented value hashed and compared
//! against every digest without early exit (no length or content leak). Each
//! row also prints `<row>_raw`: echo with its documented "SECURE" raw-key
//! validator (`ConstantTimeCompare`, first match returns; leaks the length and
//! keeps the secrets) — information only, not in the verdict. On a CPU without
//! SHA-NI the hash is most of either side's gate cost.
//! The 401 answers differ the same way: ours `Unauthorized\n` text/plain plus a
//! `WWW-Authenticate: Bearer` challenge, echo's default error handler (a JSON
//! `{"message":"Unauthorized"}` via `encoding/json`, no challenge for KeyAuth).
//! Result count = sum of status codes, so a policy that diverges shows up as
//! a count mismatch before any timing is read.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/echo by wall time; the verdict is the WORST
//! net ratio over the five rows. Arguments filter rows.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const aaa = @import("aaa-gate");

const bench_name = "bench-aaa-gate";
const work_dir = ".zig-cache/bench-aaa-gate";
const go_dir = "modules/aaa-gate/tools/go_bench";
const ref_short = "echo";
const ref_card = "labstack/echo v5.4.0";

const names = [_][]const u8{ "bearer_ok", "bearer_denied", "api_key_header_ok", "api_key_query_ok", "no_credential", "basic_ok", "basic_denied" };
const n_req = 64;

const keys = [_][]const u8{
    "tok-alpha-0123456789abcdef",
    "tok-bravo-0123456789abcdef",
    "tok-charlie-0123456789abcd",
};

/// Which gate (router) a row goes through; the same split as the Go `lookup`.
const Which = enum { bearer, api_header, api_query, basic };
const which = [_]Which{ .bearer, .bearer, .api_header, .api_query, .bearer, .basic, .basic };
/// Expected status per row (a hard check on top of the count comparison).
const expect_status = [_]u16{ 200, 401, 200, 200, 401, 200, 401 };

const Data = struct {
    plain: *router.Router,
    gated: [4]*router.Router,
    pre: [names.len][]Pre,
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

var gates: [4]aaa.Gate = undefined;

fn once(d: *const Data, w: usize, plain: bool) u64 {
    const r = if (plain) d.plain else d.gated[@backingInt(which[w])];
    var sum: u64 = 0;
    var out_buf: [1024]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    for (d.pre[w]) |*p| {
        var out: std.Io.Writer = .fixed(&out_buf);
        var rw: http.Server.ResponseWriter = .init(&out, &response_body_buf, &chunk_buf, .{});
        r.dispatch(&p.req, &rw) catch unreachable;
        rw.end() catch unreachable;
        sum += rw.status;
    }
    return sum;
}

/// One request parsed ONCE, outside the timed region (the head parser of the
/// server, as the router's own tests build a request by hand).
const Pre = struct {
    in: std.Io.Reader,
    head_buf: [512]u8,
    head: http.h1.RequestHead,
    body_scratch: [64]u8,
    body: http.Server.RequestBody,
    req: http.Server.Request,

    fn build(p: *Pre, wire: []const u8) !void {
        p.in = .fixed(wire);
        p.head = try http.h1.RequestHead.parse(try http.h1.readHead(&p.in, &p.head_buf));
        p.body = .init(&p.head, &p.in, &p.body_scratch);
        const q = std.mem.indexOfScalar(u8, p.head.target, '?');
        p.req = .{
            .method = .get,
            .target = p.head.target,
            .path = if (q) |i| p.head.target[0..i] else p.head.target,
            .query = if (q) |i| p.head.target[i + 1 ..] else "",
            .head = p.head,
            .body = &p.body,
            .context = null,
        };
    }
};

fn newRouter(arena: std.mem.Allocator) !*router.Router {
    const r = try arena.create(router.Router);
    r.* = router.Router.init(std.heap.smp_allocator);
    return r;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.plain = try newRouter(arena);
    try d.plain.get("/", hOk);
    const gpa = std.heap.smp_allocator;
    gates[0] = try aaa.Gate.init(gpa, .{ .token = keys[0], .extra_tokens = keys[1..] });
    gates[1] = try aaa.Gate.init(gpa, .{ .auth_mode = .api_key, .api_key = keys[0], .extra_api_keys = keys[1..] });
    gates[2] = try aaa.Gate.init(gpa, .{ .auth_mode = .api_key, .api_key = keys[0], .extra_api_keys = keys[1..], .api_key_query_param = "api_key" });
    gates[3] = try aaa.Gate.init(gpa, .{ .auth_mode = .basic, .basic_users = &.{
        .{ .user = "user-0", .password = keys[0] },
        .{ .user = "user-1", .password = keys[1] },
        .{ .user = "user-2", .password = keys[2] },
    } });
    for (&d.gated, 0..) |*slot, i| {
        slot.* = try newRouter(arena);
        try slot.*.use(gates[i].middleware());
        try slot.*.get("/", hOk);
    }
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        d.pre[wi] = try arena.alloc(Pre, n_req);
        for (0..n_req) |i| {
            const valid = keys[i % keys.len];
            const wire = if (std.mem.eql(u8, name, "bearer_ok"))
                try std.fmt.allocPrint(arena, "GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{valid})
            else if (std.mem.eql(u8, name, "bearer_denied"))
                try std.fmt.allocPrint(arena, "GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer tok-wrong-{d:0>16}\r\nConnection: close\r\n\r\n", .{i})
            else if (std.mem.eql(u8, name, "api_key_header_ok"))
                try std.fmt.allocPrint(arena, "GET / HTTP/1.1\r\nHost: t\r\nX-Api-Key: {s}\r\nConnection: close\r\n\r\n", .{valid})
            else if (std.mem.eql(u8, name, "api_key_query_ok"))
                try std.fmt.allocPrint(arena, "GET /?api_key={s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{valid})
            else if (std.mem.startsWith(u8, name, "basic_")) blk: {
                const pw = if (std.mem.eql(u8, name, "basic_ok")) valid else "wrong-password-000000000";
                const cred = try std.fmt.allocPrint(arena, "user-{d}:{s}", .{ i % keys.len, pw });
                const enc = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(cred.len));
                _ = std.base64.standard.Encoder.encode(enc, cred);
                break :blk try std.fmt.allocPrint(arena, "GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {s}\r\nConnection: close\r\n\r\n", .{enc});
            } else // no_credential
                try std.fmt.allocPrint(arena, "GET / HTTP/1.1\r\nHost: t\r\nAccept: */*\r\nConnection: close\r\n\r\n", .{});
            try d.pre[wi][i].build(wire);
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(wire);
        }
        const bytes = all.written();
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.wire", .{name}), .data = bytes });
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}_plain.wire", .{name}), .data = bytes });
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}_raw.wire", .{name}), .data = bytes });
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

    // Hard check before any timing: every row answers its expected status on
    // our side (the Go side is compared by count below).
    for (0..names.len) |wi| {
        const sum = once(&d, wi, false);
        if (sum != @as(u64, expect_status[wi]) * n_req) {
            std.debug.print("{s}: row {s}: our statuses sum to {d}, expected {d} x {d}\n", .{ bench_name, names[wi], sum, expect_status[wi], n_req });
            return 1;
        }
    }

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
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        const plain_name = try std.fmt.allocPrint(arena, "{s}_plain", .{name});
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var ours_p: bench.Side = .{};
        var go_p: bench.Side = .{};
        var go_raw: bench.Side = .{};
        const raw_name = try std.fmt.allocPrint(arena, "{s}_raw", .{name});
        for (0..rounds) |_| {
            go_p.add(try bench.foreign(arena, io, bench_name, exe, abs, plain_name, null));
            ours_p.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi, true }, true));
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            go_raw.add(try bench.foreign(arena, io, bench_name, exe, abs, raw_name, null));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi, false }, true));
        }
        const rows = [2]struct { []const u8, bench.Side, bench.Side }{ .{ plain_name, ours_p, go_p }, .{ name, ours, go } };
        for (rows, 0..) |row, k| {
            const gross = row[1].best_ns / row[2].best_ns;
            var net: f64 = std.math.nan(f64);
            if (k == 1 and go.best_ns > go_p.best_ns) net = (ours.best_ns - ours_p.best_ns) / (go.best_ns - go_p.best_ns);
            max_spread = @max(max_spread, @max(row[1].spread(false), row[2].spread(false)));
            const same = row[1].count == row[2].count;
            mismatch = mismatch or !same;
            if (k == 1) {
                const ratio = if (std.math.isNan(net)) gross else net;
                worst = @max(worst, ratio);
                best = @min(best, ratio);
            }
            try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ row[0], row[1].best_ns, row[2].best_ns, gross, net, 100 * row[1].spread(false), 100 * row[2].spread(false), row[1].count, if (!same) " ≠ " ++ ref_short else if (k == 0) "  (info only, not in the verdict)" else "" });
        }
        {
            const net_raw = if (go_raw.best_ns > go_p.best_ns) (ours.best_ns - ours_p.best_ns) / (go_raw.best_ns - go_p.best_ns) else std.math.nan(f64);
            try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}  (echo raw-key validator, info only)\n", .{ raw_name, ours.best_ns, go_raw.best_ns, ours.best_ns / go_raw.best_ns, net_raw, 100 * ours.spread(false), 100 * go_raw.spread(false), go_raw.count });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time (verdict = net of each row's _plain twin; gross where net is undefined); largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured 2026-10-17)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}
