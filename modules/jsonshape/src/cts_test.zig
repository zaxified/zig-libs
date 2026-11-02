// SPDX-License-Identifier: MIT
//! The official JSONPath Compliance Test Suite, frozen in `testdata/cts.json`
//! (BSD-2-Clause, see ../NOTICE; recipe in ../tools/README.md). Each of its cases
//! must fail `compile` when it says `invalid_selector`, and otherwise select the
//! listed nodes with the listed Normalized Paths, in one of the listed orders
//! where RFC 9535 leaves the order open. This is the module's external anchor.

const std = @import("std");
const testing = std.testing;
const js = @import("root.zig");

const J = std.json.Value;
const suite = @embedFile("testdata/cts.json");

/// What the frozen file holds. A regenerated file that lost cases fails here.
const expect_cases = 715;
const expect_invalid = 249;
const expect_regex = 56;

fn sameJson(x: J, y: J) bool {
    return switch (x) {
        .null => y == .null,
        .bool => |b| y == .bool and y.bool == b,
        .string => |s| y == .string and std.mem.eql(u8, s, y.string),
        .array => |arr| {
            if (y != .array or y.array.items.len != arr.items.len) return false;
            for (arr.items, y.array.items) |p, q| if (!sameJson(p, q)) return false;
            return true;
        },
        .object => |o| {
            if (y != .object or y.object.count() != o.count()) return false;
            var it = o.iterator();
            while (it.next()) |kv| {
                const other = y.object.get(kv.key_ptr.*) orelse return false;
                if (!sameJson(kv.value_ptr.*, other)) return false;
            }
            return true;
        },
        else => {
            const p = num(x) orelse return false;
            const q = num(y) orelse return false;
            return p == q;
        },
    };
}

fn num(v: J) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn sameNodes(got: []const J, want: J) bool {
    if (want.array.items.len != got.len) return false;
    for (got, want.array.items) |g, w| if (!sameJson(g, w)) return false;
    return true;
}

fn samePaths(got: []const js.Located, want: J) bool {
    if (want.array.items.len != got.len) return false;
    for (got, want.array.items) |g, w| if (!std.mem.eql(u8, g.path, w.string)) return false;
    return true;
}

/// One case. Returns whether it held, and prints why it did not.
fn runCase(a: std.mem.Allocator, case: J) !bool {
    const o = case.object;
    const name = o.get("name").?.string;
    const selector = o.get("selector").?.string;
    const compiled = js.compile(a, selector, null);
    if (o.get("invalid_selector") != null) {
        if (compiled) |_| {
            std.debug.print("CTS {s}: accepted invalid selector {s}\n", .{ name, selector });
            return false;
        } else |_| return true;
    }
    const path = compiled catch |e| {
        std.debug.print("CTS {s}: refused {s}: {t}\n", .{ name, selector, e });
        return false;
    };
    const doc = o.get("document").?;
    const nodes = try js.query(a, doc, path, .{});
    const located = try js.queryLocated(a, doc, path, .{});
    const first = try js.queryFirst(a, doc, path, .{});

    var ok = true;
    if (o.get("result")) |r| {
        ok = sameNodes(nodes, r) and samePaths(located, o.get("result_paths").?);
    } else {
        // Open order: the nodes and their paths must come from the same listing.
        const alts = o.get("results").?.array.items;
        const alt_paths = o.get("results_paths").?.array.items;
        ok = false;
        for (alts, alt_paths) |r, rp| {
            if (sameNodes(nodes, r) and samePaths(located, rp)) ok = true;
        }
    }
    if (!ok) {
        std.debug.print("CTS {s}: {s}: wrong nodelist, {d} nodes:", .{ name, selector, nodes.len });
        for (located) |l| std.debug.print(" {s}", .{l.path});
        std.debug.print("\n", .{});
        return false;
    }
    // The other two entry points agree with `query`.
    if (located.len != nodes.len) return false;
    for (located, nodes) |l, n| if (!sameJson(l.value, n)) return false;
    if ((first != null) != (nodes.len > 0)) return false;
    if (first) |f| if (!sameJson(f, nodes[0])) return false;
    return true;
}

test "JSONPath Compliance Test Suite: every case" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSliceLeaky(J, a, suite, .{});
    const cases = parsed.object.get("tests").?.array.items;

    var failed: usize = 0;
    var invalid: usize = 0;
    var uses_regex: usize = 0;
    for (cases) |case| {
        if (case.object.get("invalid_selector") != null) invalid += 1;
        const selector = case.object.get("selector").?.string;
        if (std.mem.find(u8, selector, "match(") != null or std.mem.find(u8, selector, "search(") != null) uses_regex += 1;
        if (!try runCase(a, case)) failed += 1;
    }
    if (failed != 0) std.debug.print("CTS: {d} of {d} cases failed\n", .{ failed, cases.len });
    try testing.expectEqual(@as(usize, 0), failed);
    try testing.expectEqual(@as(usize, expect_cases), cases.len);
    try testing.expectEqual(@as(usize, expect_invalid), invalid);
    try testing.expectEqual(@as(usize, expect_regex), uses_regex);
}
