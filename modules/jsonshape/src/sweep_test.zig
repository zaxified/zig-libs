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
    return std.heap.ArenaAllocator.init(std.heap.page_allocator);
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
