// SPDX-License-Identifier: MIT

//! What a log filter does with `regex`: a pattern fixed at build time
//! (`comptimeCompile`, no allocator) gates lines cheaply, a pattern read at
//! run time (`Regex.compile`) pulls named fields out of the ones that pass,
//! and the iterator walks every match in a line. A pattern that does not
//! parse is a typed error, not a crash.
//!
//! Built by `zig build check-examples` against the PUBLISHED module.

const std = @import("std");
const regex = @import("regex");

/// A line worth looking at: it carries an HTTP status.
const has_status = regex.comptimeCompile("\\bstatus=[0-9]{3}\\b");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const lines = [_][]const u8{
        "ts=2026-10-07T12:00:01 method=GET path=/users/7 status=200 ms=12",
        "ts=2026-10-07T12:00:02 heartbeat",
        "ts=2026-10-07T12:00:03 method=POST path=/orders status=503 ms=1204",
    };

    var fields = try regex.Regex.compile(gpa, "method=(?P<method>[A-Z]+) path=(?P<path>\\S+) status=(?P<status>\\d+)");
    defer fields.deinit(gpa);
    var m = try regex.Matcher.init(gpa, &fields);
    defer m.deinit();

    var kept: usize = 0;
    for (lines) |line| {
        if (!has_status.isMatch(line)) continue; // no allocator, stack scratch only
        kept += 1;
        var g: [4]?regex.Span = undefined;
        if (!m.captures(line, 0, &g)) return error.ExampleBroken;
        std.debug.print("{s} {s} -> {s}\n", .{
            g[fields.groupIndex("method").?].?.slice(line),
            g[fields.groupIndex("path").?].?.slice(line),
            g[fields.groupIndex("status").?].?.slice(line),
        });
    }
    if (kept != 2) return error.ExampleBroken;

    // Every number in a line, in order (Go's FindAll).
    var digits = try regex.Regex.compile(gpa, "[0-9]+");
    defer digits.deinit(gpa);
    var dm = try regex.Matcher.init(gpa, &digits);
    defer dm.deinit();
    var it = dm.iterator(lines[2]);
    var n: usize = 0;
    while (it.next()) |s| : (n += 1) std.debug.print("number: {s}\n", .{s.slice(lines[2])});
    if (n != 8) return error.ExampleBroken; // 2026 10 07 12 00 03 503 1204

    // A pattern from config that does not parse names the problem.
    if (regex.Regex.compile(gpa, "status=(\\d+")) |_| return error.ExampleBroken else |e| {
        std.debug.print("bad pattern: {t}\n", .{e});
        if (e != error.MissingParen) return error.ExampleBroken;
    }
}
