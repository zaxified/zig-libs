// SPDX-License-Identifier: MIT
//! Harness over route tables and requests: a random table of patterns
//! (static segments, `:p`/`{p}`, in-segment shapes, regexp constraints,
//! wildcards, trailing slashes), registered directly, through a group, an
//! inline group (`with`) and a mounted sub-router; then requests that fill a
//! registered pattern or are drawn at random, through `http.Server`'s
//! socket-free `serveStream`. Oracles:
//!
//!   - no crash, no hang, no leak; the status is one the router can answer
//!     (200 from a route, 301/308 redirect, 404, 405);
//!   - **reconstruction**: on a 200, the matched pattern with every capture
//!     replaced by its value is exactly the request path — the captures
//!     really are the path's pieces, the literals really were there (a
//!     re-parse of the pattern written here, sharing no code with the
//!     matcher);
//!   - no capture is empty but a wildcard's;
//!   - a constrained capture's value matches its regexp whole (checked
//!     with `regex` directly);
//!   - on a 405 `Allow` is present and does not name the request's method
//!     (nor HEAD's GET);
//!   - on a redirect, `Location` is the path with one trailing slash added
//!     or removed.
//!
//! Planted mutants (2026-10-07): the harness fails on a dropped literal
//! prefix check, a skipped constraint, a stale capture after backtracking,
//! an empty capture. It does not see a MISSED match (no completeness
//! reference: a literal search starting one byte early refuses `.b.c` for
//! `{p}.{q}`), nor a mount that stores the full pattern as the relative one
//! (no router here is mounted twice) — the unit tests and the chi oracle
//! kill both.
//!
//! Driver: `ROUTER_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). 400 seeds also run in every
//! ordinary test run.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const regex = @import("regex");
const router = @import("root.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

const Label = enum { routed, not_found, wrong_method, redirect, constrained, mounted, grouped };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn hit(comptime l: Label) void {
    fuzz_driver.hit(@tagName(l));
    reach[@intFromEnum(l)] += 1;
}

const words = [_][]const u8{ "a", "b", "v1", "x.y", "users" };

fn genSegment(comptime S: type, src: *S, out: *std.ArrayList(u8), a: std.mem.Allocator, d: usize, last: bool) !bool {
    const p = ([_][]const u8{ "p0", "p1", "p2", "p3" })[d];
    const q = ([_][]const u8{ "q0", "q1", "q2", "q3" })[d];
    switch (src.valueRangeAtMost(u8, 0, 11)) {
        0, 1, 2, 3 => try out.appendSlice(a, words[src.index(words.len)]),
        4 => try out.print(a, ":{s}", .{p}),
        5 => try out.print(a, "{{{s}}}", .{p}),
        6 => try out.print(a, "{{{s}}}.json", .{p}),
        7 => try out.print(a, "{{{s}}}.{{{s}}}", .{ p, q }),
        8 => try out.print(a, "v{{{s}}}", .{p}),
        9 => try out.print(a, "{{{s}:[0-9]+}}", .{p}),
        10 => try out.print(a, "{{{s}:[a-z]+}}-{{{s}}}", .{ p, q }),
        else => {
            if (!last) {
                try out.appendSlice(a, "a");
                return false;
            }
            try out.appendSlice(a, if (src.value(bool)) "*" else "*rest");
            return true;
        },
    }
    return false;
}

fn genPattern(comptime S: type, src: *S, a: std.mem.Allocator) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const depth = src.valueRangeAtMost(u8, 1, 3);
    for (0..depth) |d| {
        try out.append(a, '/');
        if (try genSegment(S, src, &out, a, d, d + 1 == depth)) return out.items;
    }
    if (src.valueRangeAtMost(u8, 0, 7) == 0) try out.append(a, '/');
    return out.items;
}

const values = [_][]const u8{ "1", "42", "ab", "x", "a.b", "a-b", "v2", "json", "z9" };
/// Segments that only an empty capture could match (`.json` for `{p}.json`,
/// `v` for `v{p}`, `-b` for `{p}-{q}`): the requests must reach that edge.
const edge_segments = [_][]const u8{ ".json", "v", "-b", "a-" }; // never `.`/`..`: dot segments are normalized away

/// A request path: a registered pattern with its captures filled, or random
/// segments.
fn genPath(comptime S: type, src: *S, a: std.mem.Allocator, patterns: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (patterns.len != 0 and src.value(bool)) {
        const pat = patterns[src.index(patterns.len)];
        var i: usize = 0;
        while (i < pat.len) : (i += 1) {
            const c = pat[i];
            if (c == '{') {
                i = closeOf(pat, i);
                try out.appendSlice(a, values[src.index(values.len)]);
            } else if ((c == ':' or c == '*') and (i == 0 or pat[i - 1] == '/')) {
                while (i + 1 < pat.len and pat[i + 1] != '/') i += 1;
                for (0..src.valueRangeAtMost(u8, if (c == '*') 0 else 1, 2)) |k| {
                    if (k != 0) try out.append(a, '/');
                    try out.appendSlice(a, values[src.index(values.len)]);
                }
            } else try out.append(a, c);
        }
        if (src.valueRangeAtMost(u8, 0, 5) == 0) try out.append(a, '/');
        return out.items;
    }
    for (0..src.valueRangeAtMost(u8, 1, 4)) |_| {
        try out.append(a, '/');
        const w = switch (src.valueRangeAtMost(u8, 0, 4)) {
            0, 1 => words[src.index(words.len)],
            2, 3 => values[src.index(values.len)],
            else => edge_segments[src.index(edge_segments.len)],
        };
        try out.appendSlice(a, w);
    }
    return out.items;
}

/// The `}` closing the `{` at `open` (braces nest, `\` escapes).
fn closeOf(pat: []const u8, open: usize) usize {
    var depth: usize = 0;
    var i = open;
    while (i < pat.len) : (i += 1) {
        switch (pat[i]) {
            '\\' => i += 1,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    unreachable;
}

const Ctx = router.Ctx;

fn echo(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll(ctx.matchedPattern().?);
    for (ctx.params.entries[0..ctx.params.len]) |e| {
        try ctx.res.writeAll("\x00");
        try ctx.res.writeAll(e.name);
        try ctx.res.writeAll("\x00");
        try ctx.res.writeAll(e.value);
    }
}

/// Rebuild the path from `pattern` and the captures `echo` wrote, by a
/// re-parse of the pattern grammar written here.
fn reconstruct(a: std.mem.Allocator, pattern: []const u8, caps: []const [2][]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        const c = pattern[i];
        if (c == '{') {
            const close = closeOf(pattern, i);
            const inner = pattern[i + 1 .. close];
            const name = inner[0 .. std.mem.indexOfScalar(u8, inner, ':') orelse inner.len];
            try out.appendSlice(a, try capValue(caps, name));
            i = close;
        } else if ((c == ':' or c == '*') and (i == 0 or pattern[i - 1] == '/')) {
            var end = i + 1;
            while (end < pattern.len and pattern[end] != '/') end += 1;
            const name = if (c == '*' and end == i + 1) "*" else pattern[i + 1 .. end];
            try out.appendSlice(a, try capValue(caps, name));
            i = end - 1;
        } else try out.append(a, c);
    }
    return out.items;
}

fn capValue(caps: []const [2][]const u8, name: []const u8) ![]const u8 {
    for (caps) |c| if (std.mem.eql(u8, c[0], name)) return c[1];
    return error.CaptureMissing;
}

/// Whether `name` is the pattern's trailing wildcard (`*` or `*name`).
fn isWildcardName(pattern: []const u8, name: []const u8) bool {
    const slash = std.mem.lastIndexOfScalar(u8, pattern, '/') orelse return false;
    const last = pattern[slash + 1 ..];
    if (last.len == 0 or last[0] != '*') return false;
    return if (last.len == 1) std.mem.eql(u8, name, "*") else std.mem.eql(u8, last[1..], name);
}

/// Every constraint of `pattern` holds for its capture.
fn checkConstraints(a: std.mem.Allocator, pattern: []const u8, caps: []const [2][]const u8) !void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, pattern, i, '{')) |open| {
        const close = closeOf(pattern, open);
        const inner = pattern[open + 1 .. close];
        i = close + 1;
        const colon = std.mem.indexOfScalar(u8, inner, ':') orelse continue;
        hit(.constrained);
        var re = try regex.Regex.compile(a, inner[colon + 1 ..]);
        defer re.deinit(a);
        if (!re.fullMatch(try capValue(caps, inner[0..colon]))) return error.ConstraintBypassed;
    }
}

const Response = struct { status: u16, body: []const u8, allow: ?[]const u8, location: ?[]const u8 };

fn serve(r: *router.Router, method: []const u8, path: []const u8, out_buf: []u8) !Response {
    var req_buf: [600]u8 = undefined;
    const wire = try std.fmt.bufPrint(&req_buf, "{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ method, path });
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const resp = out.buffered();
    if (resp.len < 12) return error.NoResponse;
    const head_end = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.NoResponse;
    return .{
        .status = try std.fmt.parseInt(u16, resp[9..12], 10),
        .body = resp[head_end + 4 ..],
        .allow = headerValue(resp[0..head_end], "Allow"),
        .location = headerValue(resp[0..head_end], "Location"),
    };
}

fn headerValue(head: []const u8, comptime name: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, head, "\r\n" ++ name ++ ": ") orelse return null;
    const start = i + name.len + 4;
    const end = std.mem.indexOfPos(u8, head, start, "\r\n") orelse head.len;
    return head[start..end];
}

const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE", "HEAD" };

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var r = router.Router.init(gpa);
    defer r.deinit();
    r.trailing_slash = if (src.value(bool)) .redirect else .strict;
    var sub = router.Router.init(gpa);
    defer sub.deinit();
    const g = try r.group("/g");
    const inline_g = try r.with(&.{});

    var patterns: std.ArrayList([]const u8) = .empty;
    for (0..src.valueRangeAtMost(u8, 1, 8)) |_| {
        const pat = try genPattern(S, src, a);
        const m: http.Method = switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => .get,
            1 => .post,
            2 => .put,
            else => .delete,
        };
        const where = src.valueRangeAtMost(u8, 0, 4);
        const ok = switch (where) {
            0 => g.add(m, pat, echo),
            1 => inline_g.add(m, pat, echo),
            2 => sub.add(m, pat, echo),
            else => r.add(m, pat, echo),
        };
        // A conflict with an earlier route is a registration error, fine.
        _ = ok catch continue;
        try patterns.append(a, switch (where) {
            0 => try std.mem.concat(a, u8, &.{ "/g", pat }),
            2 => try std.mem.concat(a, u8, &.{ "/m", pat }),
            else => pat,
        });
    }
    r.mount("/m", &sub) catch {};

    for (0..src.valueRangeAtMost(u8, 1, 6)) |_| {
        const path = try genPath(S, src, a, patterns.items);
        const method = methods[src.index(methods.len)];
        var out_buf: [4096]u8 = undefined;
        const resp = try serve(&r, method, path, &out_buf);
        switch (resp.status) {
            200 => {
                if (std.mem.eql(u8, method, "HEAD")) continue; // no body to read
                hit(.routed);
                if (std.mem.startsWith(u8, path, "/m/") or std.mem.eql(u8, path, "/m")) hit(.mounted);
                if (std.mem.startsWith(u8, path, "/g/")) hit(.grouped);
                var parts = std.mem.splitScalar(u8, resp.body, 0);
                const pattern = parts.next().?;
                var caps: std.ArrayList([2][]const u8) = .empty;
                while (parts.next()) |name| try caps.append(a, .{ name, parts.next() orelse return error.BadEcho });
                // No capture is ever empty but a wildcard's (README).
                for (caps.items) |c| if (c[1].len == 0 and !isWildcardName(pattern, c[0])) return error.EmptyCapture;
                const rebuilt = try reconstruct(a, pattern, caps.items);
                if (!std.mem.eql(u8, rebuilt, path)) {
                    std.debug.print("{s} {s} -> {s}, rebuilt {s}\n", .{ method, path, pattern, rebuilt });
                    return error.CapturesDoNotRebuildThePath;
                }
                try checkConstraints(a, pattern, caps.items);
            },
            404 => hit(.not_found),
            405 => {
                hit(.wrong_method);
                const allow = resp.allow orelse return error.MethodNotAllowedWithoutAllow;
                if (allow.len == 0) return error.EmptyAllow;
                var it = std.mem.splitSequence(u8, allow, ", ");
                while (it.next()) |m| if (std.mem.eql(u8, m, method)) return error.AllowNamesTheRefusedMethod;
            },
            301, 308 => {
                hit(.redirect);
                const loc = resp.location orelse return error.RedirectWithoutLocation;
                const toggled = if (path.len > 1 and path[path.len - 1] == '/')
                    std.mem.eql(u8, loc, path[0 .. path.len - 1])
                else
                    loc.len == path.len + 1 and std.mem.startsWith(u8, loc, path) and loc[path.len] == '/';
                if (!toggled) return error.RedirectIsNotTheSlashVariant;
            },
            else => {
                std.debug.print("{s} {s}: status {d}\n", .{ method, path, resp.status });
                return error.UnexpectedStatus;
            },
        }
    }
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor — so each seed is its own input
/// (a ranged draw first would collapse every seed to one, `check-fuzz-reach`).
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        comptime std.debug.assert(T == bool);
        return self.cur.byte() & 1 == 1;
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzOne(_: void, smith: *testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return harness(ScriptSource, &src, testing.allocator);
}

test "fuzz: route tables and requests never trap, captures rebuild the path" {
    try testing.fuzz({}, fuzzOne, .{});
}

test "fuzz driver: ROUTER_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "ROUTER_FUZZ", .name = "router" });
}

test "fuzz harness: 400 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("unreached: {t}\n", .{@as(Label, @enumFromInt(i))});
        return error.Unreached;
    };
}
