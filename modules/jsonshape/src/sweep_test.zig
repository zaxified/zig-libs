// SPDX-License-Identifier: MIT
//! No-panic sweep tests for jsonshape (wave GW). Findings JS-1 .. JS-3, see
//! ~/CML/20261029-panic-sweep/jsonshape-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const js = @import("root.zig");

// ── forked child (a hang or crash is observable, not fatal to the runner) ───

const Child = struct { died: bool };

fn runChild(comptime body: fn () void) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        body();
        linux.exit_group(0);
    }
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 10000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    return .{ .died = linux.W.IFSIGNALED(status) or linux.W.EXITSTATUS(status) != 0 };
}

fn shapeIn(arena: std.mem.Allocator, doc: []const u8, spec: js.ShapeSpec) !@import("dataset").Dataset {
    return js.shape(arena, doc, spec);
}

fn newArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(std.heap.page_allocator); // global-alloc-ok: test-only helper outside a test block; every caller deinits the arena
}

// ── JS-1: || / && chains must not recurse once per term ─────────────────────

const chain_terms = 50_000;

const ChainJob = struct {
    and_chain: bool,
    rows: usize = 0,
    err: ?anyerror = null,

    fn run(job: *ChainJob) void {
        var arena_state = newArena();
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const op: []const u8 = if (job.and_chain) "&&" else "||";
        const term: []const u8 = if (job.and_chain) "@.a==1" else "@.a==2";
        var path: std.ArrayList(u8) = .empty;
        path.appendSlice(a, "$[?") catch return;
        for (0..chain_terms) |i| {
            if (i != 0) path.appendSlice(a, op) catch return;
            path.appendSlice(a, term) catch return;
        }
        path.appendSlice(a, "]") catch return;
        const ds = shapeIn(a, "[{\"a\":1},{\"a\":2},{\"a\":3}]", .{ .path = path.items, .max_work = 100_000_000 }) catch |e| {
            job.err = e;
            return;
        };
        job.rows = ds.rows.len;
    }
};

test "filter: a 50k-term || or && chain is evaluated iteratively on a 1 MiB stack (sweep JS-1)" {
    for ([_]bool{ false, true }) |and_chain| {
        var job: ChainJob = .{ .and_chain = and_chain };
        const th = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, ChainJob.run, .{&job});
        th.join();
        try testing.expectEqual(@as(?anyerror, null), job.err);
        // || chain of `a==2`: only the second item; && chain of `a==1`: only the first.
        try testing.expectEqual(@as(usize, 1), job.rows);
    }
}

// ── JS-2: the work budget ───────────────────────────────────────────────────

/// Smallest `max_work` for which `shape` succeeds (found by search, so the test
/// counts at the boundary and never measures time).
fn minWork(doc: []const u8, path: []const u8) !usize {
    var w: usize = 0;
    while (w < 100_000) : (w += 1) {
        var arena_state = newArena();
        defer arena_state.deinit();
        _ = shapeIn(arena_state.allocator(), doc, .{ .path = path, .max_work = w }) catch |e| switch (e) {
            error.WorkLimit => continue,
            else => return e,
        };
        return w;
    }
    return error.NeverSucceeds;
}

test "work budget: exact step counts at the boundary (sweep JS-2)" {
    // $.a[*] on 3 elements. Path: root evalSegs 1 + selector 1 + `.a` evalSegs 1 +
    // selector 1 + 3 element evalSegs = 7; output: 3 items x (row + 2 cells) = 9.
    try testing.expectEqual(@as(usize, 16), try minWork("{\"a\":[1,2,3]}", "$.a[*]"));
    // One fewer is the distinct error, not TooManyMatches and not an empty answer.
    var arena_state = newArena();
    defer arena_state.deinit();
    try testing.expectError(error.WorkLimit, shapeIn(arena_state.allocator(), "{\"a\":[1,2,3]}", .{ .path = "$.a[*]", .max_work = 15 }));
}

test "work budget: every evaluation step kind is charged (sweep JS-2)" {
    // path: root evalSegs 1 + selector 1 + per item (evalExpr 1, `@` evalSegs 1, jsonEq 1 --
    // `compare` always computes equality first -- and the match's evalSegs 1) x 3 = 14;
    // output: 3 items x (row + 2 cells) = 9
    try testing.expectEqual(@as(usize, 23), try minWork("[1,2,3]", "$[?@>0]"));
    // only item 1 matches: 1 + 1 + 3 * (evalExpr + `@` + jsonEq) + 1 match = 12, + 1 item x 3 = 3
    try testing.expectEqual(@as(usize, 15), try minWork("[1,2,3]", "$[?@==1]"));
    // pure descent without any selector match: root evalSegs 1 + descendAll on 4 nodes x
    // (1 + 1 selector) = 9; no items, no cells
    try testing.expectEqual(@as(usize, 9), try minWork("{\"a\":[1,2]}", "$..zzz"));
}

fn docWith(a: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return std.mem.concat(a, u8, &.{try std.mem.print(try a.alloc(u8, 40_000), fmt, args)});
}

fn rep(a: std.mem.Allocator, c: u8, n: usize) ![]u8 {
    const b = try a.alloc(u8, n);
    @memset(b, c);
    return b;
}

test "work budget: iteration after the stop is cut, not walked uncharged (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const small = try docWith(a, "{{\"big\":[{s}],\"m\":[1,2,3]}}", .{"0,0,0,0,0"});
    const bigs = try rep(a, '0', 1);
    _ = bigs;
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"big\":[0");
    for (0..2000) |_| try b.appendSlice(a, ",0");
    try b.appendSlice(a, "],\"m\":[1,2,3]}");
    // the exists-query stops at the first element of `big`; the rest of `big` must cost nothing
    const p = "$.m[?$.big[*]]";
    try testing.expectEqual(try minWork(small, p), try minWork(b.items, p));
}

test "work budget: a filter walk stops at the first match of an existence test (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"big\":[0");
    for (0..2000) |_| try b.appendSlice(a, ",0");
    try b.appendSlice(a, "],\"m\":[1,2,3]}");
    const p = "$.m[?$.big[?@>=0]]";
    try testing.expectEqual(try minWork("{\"big\":[0,0,0],\"m\":[1,2,3]}", p), try minWork(b.items, p));
    // slice loop too
    const q = "$.m[?$.big[0:99999]]";
    try testing.expectEqual(try minWork("{\"big\":[0,0,0],\"m\":[1,2,3]}", q), try minWork(b.items, q));
}

test "path depth: a plain segment chain past the cap is DepthLimit (sweep JS-4)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const deep = try deepChainDoc(a, 100);
    var p: std.ArrayList(u8) = .empty;
    try p.append(a, '$');
    for (0..70) |_| try p.appendSlice(a, "[0]");
    try testing.expectError(error.DepthLimit, shapeIn(a, deep, .{ .path = p.items }));
    p.items.len = 1 + 3 * 30;
    _ = try shapeIn(a, deep, .{ .path = p.items });
}

test "work budget: every selector of a list is charged (sweep JS-2)" {
    const doc = "{\"x\":[1,2]}";
    // child list: 2 extra selectors = 2 extra steps
    try testing.expectEqual(@as(usize, 2), try minWork(doc, "$['a','b','c']") - try minWork(doc, "$['a']"));
    // descendant list: 2 extra selectors on each of the 4 visited nodes
    try testing.expectEqual(@as(usize, 8), try minWork(doc, "$..['a','b','c']") - try minWork(doc, "$..['a']"));
}

test "work budget: string compare, order, number parse and long names are charged by length (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const s64 = try rep(a, 'a', 64);
    const s6400 = try rep(a, 'a', 6400);
    const t64 = try rep(a, 'b', 64);
    const t6400 = try rep(a, 'b', 6400);
    const eq_small = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s64, s64 });
    const eq_big = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s6400, s6400 });
    // jsonEq on two equal strings: len/64 per evaluation, 2 items: 2 * (100 - 1)
    try testing.expectEqual(@as(usize, 2 * 99), try minWork(eq_big, "$.i[?$.s == $.t]") - try minWork(eq_small, "$.i[?$.s == $.t]"));
    const lt_small = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s64, t64 });
    const lt_big = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s6400, t6400 });
    // `<`: jsonEq (a's length) and jsonLt (min length), per item
    try testing.expectEqual(@as(usize, 2 * 2 * 99), try minWork(lt_big, "$.i[?$.s < $.t]") - try minWork(lt_small, "$.i[?$.s < $.t]"));
    // a number literal std.json keeps as text (does not fit i64) is parsed per evaluation
    const n64 = try rep(a, '9', 64);
    const n640 = try rep(a, '9', 640);
    const num_small = try docWith(a, "{{\"i\":[1,2],\"n\":{s}}}", .{n64});
    const num_big = try docWith(a, "{{\"i\":[1,2],\"n\":{s}}}", .{n640});
    try testing.expectEqual(@as(usize, 2 * 9), try minWork(num_big, "$.i[?$.n == 1]") - try minWork(num_small, "$.i[?$.n == 1]"));
    // hashing a long name selector
    const k64 = try rep(a, 'k', 64);
    const k6400 = try rep(a, 'k', 6400);
    const pk_small = try std.mem.print(try a.alloc(u8, 100), "$['{s}']", .{k64});
    const pk_big = try std.mem.print(try a.alloc(u8, 6500), "$['{s}']", .{k6400});
    try testing.expectEqual(@as(usize, 99), try minWork("{\"x\":1}", pk_big) - try minWork("{\"x\":1}", pk_small));
}

test "work budget: every output row and cell is charged, text cells by length (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = "{\"d\":[{\"a\":1},{\"a\":2},{\"a\":3}]}";
    const two = [_]js.JsonCol{ .{ .name = "a", .key = "a" }, .{ .name = "b", .key = "b" } };
    const four = [_]js.JsonCol{ .{ .name = "a", .key = "a" }, .{ .name = "b", .key = "b" }, .{ .name = "c", .key = "c" }, .{ .name = "d", .key = "d" } };
    // legacy dot-path (ignores max_matches): 3 items x (row + columns)
    var w: usize = 0;
    inline for (.{ .{ &two, 9 }, .{ &four, 15 } }) |case| {
        w = 0;
        while (w < 1000) : (w += 1) {
            _ = js.shape(a, doc, .{ .path = "d", .columns = case[0], .max_work = w }) catch |e| switch (e) {
                error.WorkLimit => continue,
                else => return e,
            };
            break;
        }
        try testing.expectEqual(@as(usize, case[1]), w);
    }
    // text cell by length
    const s64 = try rep(a, 's', 64);
    const s6400 = try rep(a, 's', 6400);
    const col = [_]js.JsonCol{.{ .name = "s", .key = "s", .type = .text }};
    var wl: [2]usize = undefined;
    for ([_][]const u8{ s64, s6400 }, 0..) |str, i| {
        const d = try docWith(a, "{{\"d\":[{{\"s\":\"{s}\"}}]}}", .{str});
        w = 0;
        while (w < 1000) : (w += 1) {
            _ = js.shape(a, d, .{ .path = "d", .columns = &col, .max_work = w }) catch |e| switch (e) {
                error.WorkLimit => continue,
                else => return e,
            };
            break;
        }
        wl[i] = w;
    }
    try testing.expectEqual(@as(usize, 99), wl[1] - wl[0]);
    // a long column key is hashed per row
    const kcol = [_]js.JsonCol{.{ .name = "k", .key = try rep(a, 'k', 6400) }};
    w = 0;
    while (w < 1000) : (w += 1) {
        _ = js.shape(a, doc, .{ .path = "d", .columns = &kcol, .max_work = w }) catch |e| switch (e) {
            error.WorkLimit => continue,
            else => return e,
        };
        break;
    }
    try testing.expectEqual(@as(usize, 3 * 2 + 3 * 100), w); // 3 x (row + cell) + 3 x 6400/64
}

fn cellsBody() void {
    var arena_state = newArena();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    b.appendSlice(a, "{\"d\":[1") catch @panic("oom");
    for (0..100_000) |_| b.appendSlice(a, ",1") catch @panic("oom");
    b.appendSlice(a, "]}") catch @panic("oom");
    var cols: [2000]js.JsonCol = undefined;
    for (&cols) |*c| c.* = .{ .name = "c", .key = "c" };
    // legacy path => no max_matches; 100k x 2000 cells x 24 B would be ~4.8 GB
    const r = js.shape(a, b.items, .{ .path = "d", .columns = &cols });
    if (r) |_| @panic("expected WorkLimit") else |e| if (e != error.WorkLimit) @panic("wrong error");
}

test "work budget: rows x columns is refused before it is allocated (sweep JS-2)" {
    const c = try runChild(cellsBody);
    try testing.expect(!c.died);
}

test "path depth: a descent past the path-depth cap is DepthLimit, never a silent drop (sweep JS-4)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const deep = try deepChainDoc(a, 100); // within max_depth (512), past the path cap (64)
    try testing.expectError(error.DepthLimit, shapeIn(a, deep, .{ .path = "$..*" }));
    try testing.expectError(error.DepthLimit, shapeIn(a, deep, .{ .path = "$..x" }));
    const shallow = try deepChainDoc(a, 30);
    _ = try shapeIn(a, shallow, .{ .path = "$..*" });
    // a comparison of two deeply nested equal containers
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"i\":[1],\"a\":");
    try b.appendSlice(a, deep);
    try b.appendSlice(a, ",\"b\":");
    try b.appendSlice(a, deep);
    try b.appendSlice(a, "}");
    try testing.expectError(error.DepthLimit, shapeIn(a, b.items, .{ .path = "$.i[?$.a == $.b]" }));
}

test "work budget: length() charges the string length per evaluation (sweep JS-2)" {
    const short = "{\"s\":\"hello\",\"i\":[1,2]}";
    var long_buf: [600]u8 = undefined;
    const long = try std.mem.print(&long_buf, "{{\"s\":\"{s}\",\"i\":[1,2]}}", .{&@as([500]u8, @splat('x'))});
    const p = "$.i[?length($.s)>1]";
    const w_short = try minWork(short, p);
    const w_long = try minWork(long, p);
    // two items, each evaluating length($.s): (500 - 5) extra characters each
    try testing.expectEqual(@as(usize, 2 * (500 - 5)), w_long - w_short);
}

test "work budget: comparing equal containers charges every node (sweep JS-2)" {
    const small = "{\"b\":[1,2],\"i\":[[1,2]]}";
    const big = "{\"b\":[1,2,3,4,5,6,7,8,9,10],\"i\":[[1,2,3,4,5,6,7,8,9,10]]}";
    const p = "$.i[?@==$.b]";
    const d = try minWork(big, p) - try minWork(small, p);
    try testing.expect(d >= 8);
}

fn deepChainDoc(a: std.mem.Allocator, levels: usize) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    for (0..levels) |_| try b.append(a, '[');
    try b.append(a, '1');
    for (0..levels) |_| try b.append(a, ']');
    return b.items;
}

fn exponentialBody() void {
    var arena_state = newArena();
    const a = arena_state.allocator();
    const doc = deepChainDoc(a, 60) catch @panic("oom");
    const r = js.shape(a, doc, .{ .path = "$..*..*..*..*..*..*..*..*..*..x" });
    if (r) |_| @panic("expected WorkLimit") else |e| if (e != error.WorkLimit) @panic("wrong error");
}

fn quadraticBody() void {
    var arena_state = newArena();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    b.appendSlice(a, "{\"v\":[") catch @panic("oom");
    for (0..3000) |i| {
        if (i != 0) b.append(a, ',') catch @panic("oom");
        b.append(a, '1') catch @panic("oom");
    }
    b.appendSlice(a, "]}") catch @panic("oom");
    const r = js.shape(a, b.items, .{ .path = "$.v[?count($..*) > 0]" });
    if (r) |_| @panic("expected WorkLimit") else |e| if (e != error.WorkLimit) @panic("wrong error");
}

fn unionBody() void {
    var arena_state = newArena();
    const a = arena_state.allocator();
    const doc = deepChainDoc(a, 40) catch @panic("oom");
    var p: std.ArrayList(u8) = .empty;
    p.append(a, '$') catch @panic("oom");
    for (0..20) |_| p.appendSlice(a, "[0,0,0,0,0,0,0,0]") catch @panic("oom");
    p.appendSlice(a, ".x") catch @panic("oom");
    const r = js.shape(a, doc, .{ .path = p.items });
    if (r) |_| @panic("expected WorkLimit") else |e| if (e != error.WorkLimit) @panic("wrong error");
}

fn descentOnlyBody() void {
    var arena_state = newArena();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    b.appendSlice(a, "{\"v\":[") catch @panic("oom");
    for (0..3000) |i| {
        if (i != 0) b.append(a, ',') catch @panic("oom");
        b.append(a, '1') catch @panic("oom");
    }
    b.appendSlice(a, "]}") catch @panic("oom");
    // `zzz` never matches: only descendAll walks, no evalSegs per node.
    const r = js.shape(a, b.items, .{ .path = "$.v[?$..zzz]" });
    if (r) |_| @panic("expected WorkLimit") else |e| if (e != error.WorkLimit) @panic("wrong error");
}

test "work budget: exponential, quadratic and duplicate-union paths stop with WorkLimit, not a hang (sweep JS-2)" {
    const c1 = try runChild(exponentialBody);
    try testing.expect(!c1.died);
    const c2 = try runChild(quadraticBody);
    try testing.expect(!c2.died);
    const c3 = try runChild(unionBody);
    try testing.expect(!c3.died);
    const c4 = try runChild(descentOnlyBody);
    try testing.expect(!c4.died);
}

test "work budget: an ordinary query over a large document stays inside the automatic budget (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"data\":[");
    for (0..20_000) |i| {
        if (i != 0) try b.append(a, ',');
        try b.appendSlice(a, "{\"p\":{\"v\":1.5},\"t\":\"x\"}");
    }
    try b.appendSlice(a, "]}");
    const ds = try shapeIn(a, b.items, .{ .path = "$..v" });
    try testing.expectEqual(@as(usize, 20_000), ds.rows.len);
    const ds2 = try shapeIn(a, b.items, .{ .path = "$.data[?@.p.v>1]" });
    try testing.expectEqual(@as(usize, 20_000), ds2.rows.len);
}

// ── JS-3: the nesting cap ───────────────────────────────────────────────────

test "max_depth: nesting past the cap is DepthLimit before parsing (sweep JS-3)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // one MiB of '[': without the pre-scan this builds a million-entry parser stack.
    const bomb = try a.alloc(u8, 1 << 20);
    @memset(bomb, '[');
    try testing.expectError(error.DepthLimit, shapeIn(a, bomb, .{}));
    // exact boundary
    try testing.expectError(error.DepthLimit, shapeIn(a, "[[[[1]]]]", .{ .max_depth = 3 }));
    _ = try shapeIn(a, "[[[1]]]", .{ .max_depth = 3 });
    // brackets and escaped quotes inside strings do not count
    _ = try shapeIn(a, "[\"[[[[[[[[[[\", \"\\\"[[[[[[[[[\"]", .{ .max_depth = 1 });
    // default cap is 512
    const ok = try deepChainDoc(a, 512);
    _ = try shapeIn(a, ok, .{});
    const over = try deepChainDoc(a, 513);
    try testing.expectError(error.DepthLimit, shapeIn(a, over, .{}));
}

test "work budget: the automatic budget is 1M + 16 x input bytes (sweep JS-2)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 200k scalar items (400 KB) x 100 columns = 20.2M steps: past 16x (7.4M), inside 64x (26.6M).
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"d\":[1");
    for (0..199_999) |_| try b.appendSlice(a, ",1");
    try b.appendSlice(a, "]}");
    var cols: [100]js.JsonCol = undefined;
    for (&cols) |*c| c.* = .{ .name = "c", .key = "c" };
    try testing.expectError(error.WorkLimit, shapeIn(a, b.items, .{ .path = "d", .columns = &cols }));
    // the same document with an explicit budget just above the need is accepted
    // only after the explicit limit says so (control that the fixture is the cause)
    try testing.expectError(error.WorkLimit, shapeIn(a, b.items, .{ .path = "d", .columns = &cols, .max_work = 20_000_000 }));
}

// ── delta audit GW (gwa-a) ──────────────────────────────────────────────────

fn zerosDoc(a: std.mem.Allocator, comptime first: []const u8, n: usize, as_object: bool) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    if (as_object) {
        try b.appendSlice(a, "{\"big\":{\"k0\":" ++ first);
        for (0..n) |i| try b.appendSlice(a, try std.mem.print(try a.alloc(u8, 32), ",\"k{d}\":0", .{i + 1}));
        try b.appendSlice(a, "},\"m\":[1,2,3]}");
    } else {
        try b.appendSlice(a, "{\"big\":[" ++ first);
        for (0..n) |_| try b.appendSlice(a, ",0");
        try b.appendSlice(a, "],\"m\":[1,2,3]}");
    }
    return b.items;
}

test "work budget: every iteration after the stop is cut, in every loop (sweep audit GW-J1)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // existence queries stop at the first match; the bulk behind it must cost nothing
    const Case = struct { path: []const u8, first: []const u8, obj: bool };
    const cases = [_]Case{
        .{ .path = "$.m[?$.big[*]]", .first = "0", .obj = true }, // wildcard over an object
        .{ .path = "$.m[?$.big[?@>=0]]", .first = "0", .obj = true }, // filter over an object
        .{ .path = "$.m[?$.big..x]", .first = "{\"x\":1}", .obj = false }, // descendant, array loop
        .{ .path = "$.m[?$.big..x]", .first = "{\"x\":1}", .obj = true }, // descendant, object loop
        .{ .path = "$.m[?$.big[::-1]]", .first = "0", .obj = false }, // backward slice
        .{ .path = "$.m[?$.big[0:99999]]", .first = "0", .obj = false }, // forward slice
        .{ .path = "$.m[?$.big[*]]", .first = "0", .obj = false },
        .{ .path = "$.m[?$.big[?@>=0]]", .first = "0", .obj = false },
    };
    inline for (cases) |c| {
        const small = try zerosDoc(a, c.first, 3, c.obj);
        const big = try zerosDoc(a, c.first, 1500, c.obj);
        try testing.expectEqual(try minWork(small, c.path), try minWork(big, c.path));
    }
}

test "work budget: a duplicate selector after the match is not evaluated (sweep audit GW-J2)" {
    const doc = "{\"i\":[1,2],\"x\":1}";
    // child list: +1 for the extra selector in the list charge, per item; the second `x` is cut
    try testing.expectEqual(@as(usize, 2), try minWork(doc, "$.i[?$['x','x']]") - try minWork(doc, "$.i[?$['x']]"));
    // descendant list: +1 per item for the extra selector; the second `x` is cut
    try testing.expectEqual(@as(usize, 2), try minWork(doc, "$.i[?$..['x','x']]") - try minWork(doc, "$.i[?$..['x']]"));
}

test "filter: || and && keep every distinct term and short-circuit (sweep audit GW-J3)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = "[{\"a\":1,\"b\":2},{\"a\":2,\"b\":2},{\"a\":3,\"b\":3}]";
    try testing.expectEqual(@as(usize, 2), (try shapeIn(a, doc, .{ .path = "$[?@.a==1 || @.a==3]" })).rows.len);
    try testing.expectEqual(@as(usize, 1), (try shapeIn(a, doc, .{ .path = "$[?@.a==1 && @.b==2]" })).rows.len);
    try testing.expectEqual(@as(usize, 3), (try shapeIn(a, doc, .{ .path = "$[?@.a==3 || @.b==2 || @.a==9]" })).rows.len);
    // short-circuit is visible in the work count: a true first `||` term / a false first `&&` term
    // costs the chain node only (1), whatever follows
    const one = "[{\"a\":1}]";
    try testing.expectEqual(@as(usize, 1), try minWork(one, "$[?@.a==1 || @.a==1 || @.a==1]") - try minWork(one, "$[?@.a==1]"));
    try testing.expectEqual(@as(usize, 1), try minWork(one, "$[?@.a==2 && @.a==1 && @.a==1]") - try minWork(one, "$[?@.a==2]"));
}

test "path depth: a filter at path depth 64 is DepthLimit from evalExpr, 63 is fine (sweep audit GW-J4)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const deep = try deepChainDoc(a, 100);
    var p: std.ArrayList(u8) = .empty;
    try p.append(a, '$');
    for (0..63) |_| try p.appendSlice(a, "[0]");
    const base = p.items.len;
    try p.appendSlice(a, "[?1==1]");
    // evalSegs sits at depth 63 on the filter segment: evalExpr runs at depth 64, still allowed
    _ = try shapeIn(a, deep, .{ .path = p.items });
    p.items.len = base;
    try p.appendSlice(a, "[0][?1==1]");
    // one more step: evalExpr at depth 65. Reachable through path depth alone, not only
    // through expression nesting (the parser caps that at 32).
    try testing.expectError(error.DepthLimit, shapeIn(a, deep, .{ .path = p.items }));
}

test "max_depth: sibling containers do not accumulate, objects count, a stray closer is BadJson (sweep audit GW-J5)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    _ = try shapeIn(a, "[[1],[1],[1],[1],{\"k\":1},[1]]", .{ .max_depth = 2 });
    try testing.expectError(error.DepthLimit, shapeIn(a, "{\"a\":{\"a\":{\"a\":1}}}", .{ .max_depth = 2 }));
    _ = try shapeIn(a, "{\"a\":{\"a\":1}}", .{ .max_depth = 2 });
    try testing.expectError(error.BadJson, shapeIn(a, "]]", .{}));
    try testing.expectError(error.BadJson, shapeIn(a, "}", .{}));
}

test "work budget: the automatic budget is exactly 1M + 16 x bytes, and max_work overrides it (sweep audit GW-J6)" {
    // 20 000 scalar items, 40 007 bytes: budget 1 640 112. Legacy path: work = items x (columns + 1).
    const k = 20_000;
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(testing.allocator);
    try b.appendSlice(testing.allocator, "{\"d\":[1");
    for (0..k - 1) |_| try b.appendSlice(testing.allocator, ",1");
    try b.appendSlice(testing.allocator, "]}");
    var cols: [82]js.JsonCol = undefined;
    for (&cols) |*c| c.* = .{ .name = "c", .key = "c" };
    const Run = struct {
        fn go(doc: []const u8, ncols: usize, cs: []const js.JsonCol, work: ?usize) !void {
            var arena_state = newArena();
            defer arena_state.deinit();
            _ = try shapeIn(arena_state.allocator(), doc, .{ .path = "d", .columns = cs[0..ncols], .max_work = work });
        }
    };
    try Run.go(b.items, 81, &cols, null); // 20 000 x 82 = 1 640 000 <= 1 640 112
    try testing.expectError(error.WorkLimit, Run.go(b.items, 82, &cols, null)); // 20 000 x 83 = 1 660 000
    try Run.go(b.items, 82, &cols, 1_700_000); // an explicit max_work replaces the automatic one
}

test "work budget: rows x columns saturates instead of overflowing (sweep audit GW-J8)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "{\"d\":[1");
    for (0..15) |_| try b.appendSlice(a, ",1");
    try b.appendSlice(a, "]}");
    // fabricated column counts, never dereferenced: the charge precedes any use of the list
    const one: [1]js.JsonCol = .{.{ .name = "c", .key = "c" }};
    for ([_]usize{ 1 << 60, std.math.maxInt(usize) }) |n| {
        const cols: []const js.JsonCol = @as([*]const js.JsonCol, &one)[0..n];
        try testing.expectError(error.WorkLimit, shapeIn(a, b.items, .{ .path = "$.d", .columns = cols }));
    }
}

fn preAllocBuf(doc: []const u8) ![]align(16) u8 {
    const tmp_buf = try std.heap.page_allocator.alignedAlloc(u8, .@"16", 1 << 20); // global-alloc-ok: test-only helper; a scratch buffer to measure a parse, freed below
    defer std.heap.page_allocator.free(tmp_buf); // global-alloc-ok: frees the scratch buffer above
    var fba = std.heap.FixedBufferAllocator.init(tmp_buf);
    _ = try std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), doc, .{});
    return std.heap.page_allocator.alignedAlloc(u8, .@"16", fba.end_index + 4096); // global-alloc-ok: test-only helper; the caller frees it with page_allocator
}

test "work budget: rows and cells are charged before they are allocated (sweep audit GW-J7)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // default [x, y] shape: the `rows` array (1500 x 16 B) must not be allocated before the charge
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, "[1");
    for (0..1499) |_| try b.appendSlice(a, ",1");
    try b.appendSlice(a, "]");
    const buf1 = try preAllocBuf(b.items);
    defer std.heap.page_allocator.free(buf1);
    var fba1 = std.heap.FixedBufferAllocator.init(buf1);
    try testing.expectError(error.WorkLimit, shapeIn(fba1.allocator(), b.items, .{ .max_work = 10 }));
    // explicit columns: the `cols`/`keys` arrays (1000 entries) likewise
    const doc2 = "{\"d\":[1,2,3]}";
    const buf2 = try preAllocBuf(doc2);
    defer std.heap.page_allocator.free(buf2);
    var fba2 = std.heap.FixedBufferAllocator.init(buf2);
    var cols: [1000]js.JsonCol = undefined;
    for (&cols) |*c| c.* = .{ .name = "c", .key = "c" };
    try testing.expectError(error.WorkLimit, shapeIn(fba2.allocator(), doc2, .{ .path = "d", .columns = &cols, .max_work = 100 }));
}

test "work budget: object keys, string order and big numbers are charged by their own length (sweep audit GW-J9)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const k64 = try rep(a, 'k', 64);
    const k6400 = try rep(a, 'k', 6400);
    // equal one-key objects: the key is compared per evaluation (2 items): 2 x (100 - 1)
    const o_small = try docWith(a, "{{\"i\":[1,2],\"a\":{{\"{s}\":1}},\"b\":{{\"{s}\":1}}}}", .{ k64, k64 });
    const o_big = try docWith(a, "{{\"i\":[1,2],\"a\":{{\"{s}\":1}},\"b\":{{\"{s}\":1}}}}", .{ k6400, k6400 });
    try testing.expectEqual(@as(usize, 2 * 99), try minWork(o_big, "$.i[?$.a == $.b]") - try minWork(o_small, "$.i[?$.a == $.b]"));
    // `<` with a long left and a short right string: jsonEq charges the left length, jsonLt the SHORTER
    const s64 = try rep(a, 'a', 64);
    const s6400 = try rep(a, 'a', 6400);
    const t64 = try rep(a, 'b', 64);
    const l_small = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s64, t64 });
    const l_big = try docWith(a, "{{\"i\":[1,2],\"s\":\"{s}\",\"t\":\"{s}\"}}", .{ s6400, t64 });
    try testing.expectEqual(@as(usize, 2 * 99), try minWork(l_big, "$.i[?$.s < $.t]") - try minWork(l_small, "$.i[?$.s < $.t]"));
    // a number cell std.json keeps as text: len / 64 per cell, for a float column
    const n64 = try rep(a, '9', 64);
    const n640 = try rep(a, '9', 640);
    const col = [_]js.JsonCol{.{ .name = "n", .key = "n", .type = .float }};
    var w: [2]usize = undefined;
    for ([_][]const u8{ n64, n640 }, 0..) |digits, i| {
        const d = try docWith(a, "{{\"d\":[{{\"n\":{s}}}]}}", .{digits});
        var x: usize = 0;
        while (x < 1000) : (x += 1) {
            _ = js.shape(a, d, .{ .path = "d", .columns = &col, .max_work = x }) catch |e| switch (e) {
                error.WorkLimit => continue,
                else => return e,
            };
            break;
        }
        w[i] = x;
    }
    try testing.expectEqual(@as(usize, 9), w[1] - w[0]);
}

test "work budget: a column key path is charged to the shared counter (sweep audit GW-J10)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const doc = "{\"d\":[{\"a\":1}],\"v\":5}";
    const col = [_]js.JsonCol{.{ .name = "v", .key = "$.v", .type = .int }};
    var w: usize = 0;
    while (w < 1000) : (w += 1) {
        _ = js.shape(a, doc, .{ .path = "d", .columns = &col, .max_work = w }) catch |e| switch (e) {
            error.WorkLimit => continue,
            else => return e,
        };
        break;
    }
    // 1 item x (row + 1 column) = 2; the key path `$.v`: root evalSegs 1 + selector list 1 + `v` evalSegs 1 = 3
    try testing.expectEqual(@as(usize, 5), w);
}

test "work budget: the work charge comes before the depth check, so the first non-WorkLimit budget is exact (sweep audit GW-J11)" {
    var arena_state = newArena();
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const deep = try deepChainDoc(a, 100);
    var p: std.ArrayList(u8) = .empty;
    try p.append(a, '$');
    for (0..70) |_| try p.appendSlice(a, "[0]");
    var w: usize = 0;
    while (w < 1000) : (w += 1) {
        _ = shapeIn(a, deep, .{ .path = p.items, .max_work = w }) catch |e| switch (e) {
            error.WorkLimit => continue,
            error.DepthLimit => break,
            else => return e,
        };
        return error.ExpectedDepthLimit;
    }
    // evalSegs at depth 65 is entered after 1 (root) + 65 x (selector list 1 + evalSegs 1) = 131 steps,
    // and its own charge is what the budget must cover before DepthLimit can be returned
    try testing.expectEqual(@as(usize, 131), w);
}

// ── query API and match()/search() (grade-2 wave, 2026-11-02) ───────────────

fn strRepeat(a: std.mem.Allocator, s: []const u8, n: usize) ![]u8 {
    const out = try a.alloc(u8, s.len * n);
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    return out;
}

fn wrap(a: std.mem.Allocator, pre: []const u8, mid: []const u8, post: []const u8) ![]u8 {
    return std.mem.concat(a, u8, &.{ pre, mid, post });
}

test "compile: hostile text is InvalidPath, never a panic or a stack overflow" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const n = 1 << 20;
    const cases = [_][]const u8{
        try wrap(a, "$", try rep(a, '[', n), ""),
        try wrap(a, "$[?", try rep(a, '(', n), ""),
        try wrap(a, "$[?", try rep(a, '!', n), "@.a"),
        try wrap(a, "$[?", try rep(a, '@', n), ""),
        try rep(a, '$', n),
        try wrap(a, "$[?", try strRepeat(a, "length(", 4096), ""),
        try wrap(a, "$[?", try strRepeat(a, "@[?", 4096), ""),
        try wrap(a, "$[?", try strRepeat(a, "match(", 4096), ""),
        "",
        "$\xff",
        "$['\xff']",
        "\xc0\x80",
        " $",
        "$ ",
    };
    for (cases) |text| try testing.expectError(error.InvalidPath, js.compile(a, text, null));
    // Long but well-formed: linear, a path of its own size.
    _ = try js.compile(a, try wrap(a, "$", try strRepeat(a, ".a", 1 << 18), ""), null);
    _ = try js.compile(a, try wrap(a, "$[0", try strRepeat(a, ",0", 1 << 18), "]"), null);
}

test "compile: at most 64 calls of match/search, so a path cannot buy compiles" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const call = "match(@,'a{1000}')||";
    const ok = try wrap(a, "$[?", try strRepeat(a, call, 64), "@]");
    _ = try js.compile(a, ok, null);
    const over = try wrap(a, "$[?", try strRepeat(a, call, 65), "@]");
    try testing.expectError(error.InvalidPath, js.compile(a, over, null));
    // In `shape` the same path degrades like any other bad one.
    const d = try js.shape(a, "[1]", .{ .path = over });
    try testing.expectEqual(0, d.rows.len);
}

fn oneQuery(a: std.mem.Allocator, doc: []const u8, text: []const u8) !void {
    const root = try js.parseDocument(a, doc, .{});
    const path = js.compile(a, text, null) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidPath => return error.TestUnexpectedResult,
    };
    const all = try js.query(a, root, path, .{});
    const located = try js.queryLocated(a, root, path, .{});
    _ = try js.queryFirst(a, root, path, .{});
    try testing.expectEqual(all.len, located.len);
    try testing.expectEqual(2, all.len);
}

test "query: out of memory at every allocation is OutOfMemory (compile, regex, query, located)" {
    const doc = "{\"a\":[{\"b\":\"xay\"},{\"b\":\"q\",\"p\":\"q\"}],\"c\":[1,2,3]}";
    const text = "$.a[?search(@.b,'a|[b-d]+\\\\p{L}') || match(@.b,@.p) || length(@.b) > 9].b";
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var arena = newArena();
        defer arena.deinit();
        var failing = std.testing.FailingAllocator.init(arena.allocator(), .{ .fail_index = fail_index });
        const r = oneQuery(failing.allocator(), doc, text);
        if (failing.has_induced_failure) {
            try testing.expectError(error.OutOfMemory, r);
        } else {
            try r;
            break;
        }
        if (fail_index > 100_000) return error.TestUnexpectedResult;
    }
    try testing.expect(fail_index > 10);
}

test "queryLocated: the deepest trail fits, one level more is DepthLimit" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const fits = try js.parseDocument(a, try docWith(a, "{s}1{s}", .{ try rep(a, '[', 64), try rep(a, ']', 64) }), .{});
    const path = try js.compile(a, "$..*", null);
    const got = try js.queryLocated(a, fits, path, .{});
    try testing.expectEqual(64, got.len);
    try testing.expectEqual(1, got[63].value.integer);

    const deep = try js.parseDocument(a, try docWith(a, "{s}1{s}", .{ try rep(a, '[', 80), try rep(a, ']', 80) }), .{});
    try testing.expectError(error.DepthLimit, js.queryLocated(a, deep, path, .{}));
    try testing.expectError(error.DepthLimit, js.query(a, deep, path, .{}));
}

test "query: hostile path over a small document stops in its budget" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    var doc: std.ArrayList(u8) = .empty;
    try doc.append(a, '[');
    for (0..4096) |i| try doc.print(a, "{s}[[[[1,2],[3]],[[4]]],[[[5]]]]", .{if (i == 0) "" else ","});
    try doc.append(a, ']');
    const root = try js.parseDocument(a, doc.items, .{});
    for ([_][]const u8{
        "$[?count($..*) > 0]",
        "$..*..*..*..*..*..x",
        "$[*,*,*,*][*,*,*,*][*,*,*,*][*,*,*,*].x",
    }) |text| {
        const path = try js.compile(a, text, null);
        try testing.expectError(error.WorkLimit, js.query(a, root, path, .{ .max_work = 1_000_000, .max_matches = 1 << 30 }));
    }
    const located = try js.compile(a, "$..*", null);
    try testing.expectError(error.TooManyMatches, js.queryLocated(a, root, located, .{ .max_matches = 100 }));
}

test "regex: patterns from the document pay per compile, the same pattern compiles once" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const path = try js.compile(a, "$[?match(@.s,@.p)]", null);

    // 200 rows sharing one pattern fit a budget of far less than 200 compiles.
    var same: std.ArrayList(u8) = .empty;
    try same.append(a, '[');
    for (0..200) |i| try same.print(a, "{s}{{\"s\":\"aaa\",\"p\":\"a+\"}}", .{if (i == 0) "" else ","});
    try same.append(a, ']');
    const same_root = try js.parseDocument(a, same.items, .{});
    try testing.expectEqual(200, (try js.query(a, same_root, path, .{ .max_work = 40_000 })).len);

    // 200 distinct ones do not.
    var distinct: std.ArrayList(u8) = .empty;
    try distinct.append(a, '[');
    for (0..200) |i| try distinct.print(a, "{s}{{\"s\":\"aaa\",\"p\":\"a{{{d}}}\"}}", .{ if (i == 0) "" else ",", i });
    try distinct.append(a, ']');
    const distinct_root = try js.parseDocument(a, distinct.items, .{});
    try testing.expectError(error.WorkLimit, js.query(a, distinct_root, path, .{ .max_work = 40_000 }));
    // With budget for them, each row is judged on its own: only `a{3}` holds.
    try testing.expectEqual(1, (try js.query(a, distinct_root, path, .{})).len);
}

test "regex: an oversize, too-large or deep pattern is false, not an error" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const long = try rep(a, 'a', 5000);
    const nested = try docWith(a, "{s}a{s}", .{ try rep(a, '(', 200), try rep(a, ')', 200) });
    var doc: std.ArrayList(u8) = .empty;
    try doc.print(a, "[{{\"s\":\"{s}\",\"p\":\"{s}\"}},", .{ long, long });
    try doc.appendSlice(a, "{\"s\":\"aaaa\",\"p\":\"((a{1000}){1000}){1000}\"},");
    try doc.appendSlice(a, "{\"s\":\"aaaa\",\"p\":\"(a|aa|aaa){1000}{1000}\"},");
    try doc.print(a, "{{\"s\":\"a\",\"p\":\"{s}\"}}]", .{nested});
    const root = try js.parseDocument(a, doc.items, .{});
    try testing.expectEqual(0, (try js.query(a, root, try js.compile(a, "$[?match(@.s,@.p)]", null), .{})).len);
    try testing.expectEqual(0, (try js.query(a, root, try js.compile(a, "$[?search(@.s,@.p)]", null), .{})).len);
    // The same as a literal in the path: refused at compile, and still no error.
    const lit = try js.compile(a, "$[?search(@.s,'((a{1000}){1000}){1000}')]", null);
    try testing.expectEqual(0, (try js.query(a, root, lit, .{})).len);
}

test "regex: a long subject is charged by length, with no blow-up in the worst pattern" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    // The classic backtracking killer on a 64 KiB subject that fails at its end.
    const doc = try std.mem.concat(a, u8, &.{ "[\"", try rep(a, 'a', 1 << 16), "!\"]" });
    const root = try js.parseDocument(a, doc, .{});
    const path = try js.compile(a, "$[?match(@,'(a|aa)+')]", null);
    try testing.expectEqual(0, (try js.query(a, root, path, .{})).len);
    try testing.expectError(error.WorkLimit, js.query(a, root, path, .{ .max_work = 1 << 15 }));
}

test "parseDocument: depth and bad JSON are the declared errors" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.DepthLimit, js.parseDocument(a, try rep(a, '[', 1 << 20), .{}));
    try testing.expectError(error.DepthLimit, js.parseDocument(a, "[[[1]]]", .{ .max_depth = 2 }));
    _ = try js.parseDocument(a, "[[[1]]]", .{ .max_depth = 3 });
    for ([_][]const u8{ "", "{", "[1,]", "tru", "\"\xff\"", "\xef\xbb\xbf1" }) |bad| {
        try testing.expectError(error.BadJson, js.parseDocument(a, bad, .{}));
    }
}

// ── independent review of 9a4df485 (2026-11-02), MED-1..5, LOW-3 ────────────

test "review: distinct patterns from the document do not grow memory per compile (MED-1)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    var doc: std.ArrayList(u8) = .empty;
    try doc.append(a, '[');
    for (0..1000) |i| try doc.print(a, "{s}{{\"s\":\"a\",\"p\":\"a{{300}}x{d}\"}}", .{ if (i == 0) "" else ",", i });
    try doc.append(a, ']');
    const root = try js.parseDocument(a, doc.items, .{});
    const path = try js.compile(a, "$[?match(@.s,@.p)]", null);
    const before = arena.queryCapacity();
    try testing.expectEqual(0, (try js.query(a, root, path, .{ .max_work = 1 << 40 })).len);
    const grown = arena.queryCapacity() - before;
    if (grown > 2 << 20) {
        std.debug.print("1000 compiles grew the arena by {d} bytes\n", .{grown});
        return error.TestUnexpectedResult;
    }
}

test "review: 64 literal patterns at the engine's limit stay in a few MiB (MED-1)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const text = try wrap(a, "$[?", try strRepeat(a, "match(@,'a{1000}b{1000}')||", 64), "@]");
    _ = try js.compile(a, text, null);
    const cap = arena.queryCapacity();
    if (cap > 8 << 20) {
        std.debug.print("compile took {d} bytes\n", .{cap});
        return error.TestUnexpectedResult;
    }
}

test "review: a program past 1024 instructions is false, and so is a huge nested count (MED-1)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const root = try js.parseDocument(a, "[\"\"]", .{});
    for ([_]struct { []const u8, usize }{
        .{ "$[?match(@,'(){1000}')]", 1 },
        .{ "$[?match(@,'((){1000}){1000}')]", 0 },
        .{ "$[?match(@,'(((){1000}){1000}){1000}')]", 0 },
    }) |c| {
        const got = try js.query(a, root, try js.compile(a, c[0], null), .{});
        try testing.expectEqual(c[1], got.len);
    }
    const long = try js.parseDocument(a, try wrap(a, "[\"", try rep(a, 'a', 1100), "\"]"), .{});
    const over = try js.compile(a, "$[?match(@,'a{1000}a{100}')]", null);
    try testing.expectEqual(0, (try js.query(a, long, over, .{})).len);
}

test "review: a Normalized Path is charged by its bytes (MED-2)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    // 256 paths of 64 KiB: 16 MiB of text from a 65 KiB document.
    var doc: std.ArrayList(u8) = .empty;
    try doc.print(a, "{{\"{s}\":[", .{try rep(a, 'k', 1 << 16)});
    for (0..256) |i| try doc.print(a, "{s}0", .{if (i == 0) "" else ","});
    try doc.appendSlice(a, "]}");
    const root = try js.parseDocument(a, doc.items, .{});
    const path = try js.compile(a, "$.*[*]", null);
    try testing.expectError(error.WorkLimit, js.queryLocated(a, root, path, .{ .max_work = 1 << 20 }));
    // The same query with room for the bytes.
    try testing.expectEqual(256, (try js.queryLocated(a, root, path, .{ .max_work = 1 << 25 })).len);
    // An escaped name costs what it writes, six bytes for one.
    const esc = try wrap(a, "{\"", try strRepeat(a, "\\u0001", 1 << 12), "\":0}");
    const esc_root = try js.parseDocument(a, esc, .{});
    const star = try js.compile(a, "$.*", null);
    try testing.expectError(error.WorkLimit, js.queryLocated(a, esc_root, star, .{ .max_work = 1 << 14 }));
}

test "review: a subject is charged by the program too, past the DFA (MED-3)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try wrap(a, "[\"", try rep(a, 'a', 1 << 16), "\"]");
    const root = try js.parseDocument(a, doc, .{});
    // 208 instructions, a Pike VM with hundreds of threads: about 9 ns per
    // byte and instruction, 2 s per MiB, measured.
    const path = try js.compile(a, "$[?match(@,'.*a.{200}c')]", null);
    try testing.expectError(error.WorkLimit, js.query(a, root, path, .{ .max_work = 1 << 20 }));
    // A small program over the same subject stays inside that budget.
    const small = try js.compile(a, "$[?match(@,'a+')]", null);
    try testing.expectEqual(1, (try js.query(a, root, small, .{ .max_work = 1 << 20 })).len);
}

test "review: a Path does not borrow its text (MED-4)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    const text = try a.dupe(u8, "$.store.items[?@.name && match(@.name,'x')].name");
    const path = try js.compile(a, text, null);
    @memset(text, 'Z');
    const root = try js.parseDocument(a, "{\"store\":{\"items\":[{\"name\":\"x\"}]}}", .{});
    const got = try js.query(a, root, path, .{});
    try testing.expectEqual(1, got.len);
    try testing.expectEqualStrings("x", got[0].string);
}

test "review: 200 distinct short patterns fit the automatic budget of a 50 KB document (LOW-3)" {
    var arena = newArena();
    defer arena.deinit();
    const a = arena.allocator();
    var doc: std.ArrayList(u8) = .empty;
    try doc.append(a, '[');
    for (0..200) |i| try doc.print(a, "{s}{{\"s\":\"p{d}\",\"p\":\"p{d}\",\"pad\":\"{s}\"}}", .{ if (i == 0) "" else ",", i, i, try rep(a, '.', 220) });
    try doc.append(a, ']');
    const d = try js.shape(a, doc.items, .{ .path = "$[?match(@.s,@.p)]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(200, d.rows.len);
    // Patterns that alternate within the cache do not recompile: a budget for
    // eight compiles covers 1000 rows of eight patterns.
    var mix: std.ArrayList(u8) = .empty;
    try mix.append(a, '[');
    for (0..1000) |i| try mix.print(a, "{s}{{\"s\":\"p{d}\",\"p\":\"p{d}\"}}", .{ if (i == 0) "" else ",", i % 8, i % 8 });
    try mix.append(a, ']');
    const root = try js.parseDocument(a, mix.items, .{});
    const path = try js.compile(a, "$[?match(@.s,@.p)]", null);
    try testing.expectEqual(1000, (try js.query(a, root, path, .{ .max_work = 60_000 })).len);
}
