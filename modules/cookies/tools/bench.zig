// SPDX-License-Identifier: MIT

//! Comparative benchmark: `cookies` against Go's `net/http` cookie code (go
//! 1.26.0; the reference), the program behind the `**Performance:**` line of
//! the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-cookies` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 (stdlib
//! only, `GOPROXY=off`). Run from the repository root.
//!
//! Workloads -- what an HTTP server does with cookies; one op = every header
//! (parse_*) or every cookie spec (build) once:
//!   parse_find   pick the session cookie out of a `Cookie` request header
//!                (6 headers, 1..9 cookies, one of them a 330-byte token);
//!                ours `cookies.find`, Go `Request.Cookie("sid")`
//!   parse_all    walk every pair of the same headers; ours `cookies.parse`
//!                iterator, Go `http.ParseCookie`
//!   build        render a `Set-Cookie` value (8 specs: session, CSRF, prefs,
//!                `__Host-` ...); ours `SetCookie.bufPrint` into a stack
//!                buffer, Go `Cookie.String()`. Max-Age only: Go formats an
//!                Expires time itself, ours takes ready text, which would not
//!                be the same work. Attribute ORDER differs; the byte sum of
//!                the output does not.
//! Both sides validate (Go drops invalid cookies, ours rejects them); the
//! inputs are valid for both. Each side times the same way (double the batch
//! until it takes over 100 ms, best of five); per workload the sides alternate
//! for BENCH_ROUNDS (default 3) rounds, each keeping its best. The result
//! count must agree or the run fails. Ratios are ours/Go by wall time; the
//! verdict is the WORST ratio. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const cookies = @import("cookies");

const bench_name = "bench-cookies";
const work_dir = ".zig-cache/bench-cookies";
const go_dir = "modules/cookies/tools/go_bench";
const ref_short = "Go";
const ref_card = "Go 1.26.0 net/http";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "parse_find", "parse_all", "build" };

const Spec = struct {
    name: []const u8,
    value: []const u8,
    path: []const u8 = "",
    domain: []const u8 = "",
    max_age: i64 = 0,
    secure: bool = false,
    http_only: bool = false,
    same_site: u8 = 0, // 0 none set, 1 lax, 2 strict, 3 None
};

const sid = "3f9a8c1d2b7e4a6f90c1d2e3f4a5b6c7d8e9f00112233445566778899aabbccd";
const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDAsInNjb3BlIjoicmVhZCB3cml0ZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSJ9.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmUtc2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU";

const headers = [_][]const u8{
    "sid=" ++ sid,
    "theme=dark; sid=" ++ sid ++ "; lang=cs",
    "_ga=GA1.2.1234567890.1700000000; _gid=GA1.2.987654321.1700000001; sid=" ++ sid ++ "; csrf=Zm9vYmFyYmF6; theme=dark; lang=cs-CZ; consent=yes; tz=Europe/Prague; cart=7",
    "access=" ++ jwt ++ "; sid=" ++ sid,
    "a=1; b=2; c=3; d=4",
    "tracking=abcdefghijklmnopqrstuvwxyz0123456789; other=value; last=1",
};

const specs = [_]Spec{
    .{ .name = "sid", .value = sid, .path = "/", .max_age = 3600, .secure = true, .http_only = true, .same_site = 1 },
    .{ .name = "csrf", .value = "Zm9vYmFyYmF6", .path = "/", .secure = true, .same_site = 2 },
    .{ .name = "theme", .value = "dark", .path = "/", .domain = "example.com", .max_age = 31536000 },
    .{ .name = "__Host-sid", .value = sid, .path = "/", .secure = true, .http_only = true, .same_site = 2 },
    .{ .name = "lang", .value = "cs" },
    .{ .name = "cart", .value = "7", .path = "/shop", .max_age = 86400, .http_only = true, .same_site = 1 },
    .{ .name = "xsite", .value = "1", .path = "/", .secure = true, .same_site = 3 },
    .{ .name = "gone", .value = "deleted", .path = "/", .domain = "app.example.com", .max_age = 1 },
};

const Data = struct {};

fn sumBytes(s: []const u8) u64 {
    var t: u64 = 0;
    for (s) |c| t += c;
    return t;
}

fn once(_: *const Data, w: usize) u64 {
    var t: u64 = 0;
    switch (w) {
        0 => for (headers) |h| {
            if (cookies.find(h, "sid")) |v| t += sumBytes(v) + 1;
        },
        1 => for (headers) |h| {
            var it = cookies.parse(h);
            while (it.next()) |c| t += sumBytes(c.name) + sumBytes(c.value);
        },
        else => for (specs) |s| {
            var buf: [1024]u8 = undefined;
            const out = (cookies.SetCookie{
                .name = s.name,
                .value = s.value,
                .path = if (s.path.len != 0) s.path else null,
                .domain = if (s.domain.len != 0) s.domain else null,
                .max_age = if (s.max_age != 0) s.max_age else null,
                .secure = s.secure,
                .http_only = s.http_only,
                .same_site = switch (s.same_site) {
                    1 => .lax,
                    2 => .strict,
                    3 => .none,
                    else => null,
                },
            }).bufPrint(&buf) catch unreachable;
            t += sumBytes(out);
        },
    }
    return t;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var h: std.Io.Writer.Allocating = .init(arena);
    for (headers) |x| try h.writer.print("{s}\n", .{x});
    try dir.writeFile(io, .{ .sub_path = "headers.txt", .data = h.written() });
    var s: std.Io.Writer.Allocating = .init(arena);
    for (specs) |x| try s.writer.print("{s}\t{s}\t{s}\t{s}\t{d}\t{d}\t{d}\t{d}\n", .{ x.name, x.value, x.path, x.domain, x.max_age, @intFromBool(x.secure), @intFromBool(x.http_only), x.same_site });
    try dir.writeFile(io, .{ .sub_path = "specs.tsv", .data = s.written() });
    return .{};
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
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
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
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
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
