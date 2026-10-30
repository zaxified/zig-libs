// SPDX-License-Identifier: MIT

//! A request log, sorted three ways: by endpoint name (unstable, byte
//! strings), by status keeping arrival order inside each status (stable,
//! allocating, then on caller scratch), and the median latency (selectNth).
//! Runs under a leak-checking allocator.

const std = @import("std");
const sort = @import("sort");

const Request = struct {
    path: []const u8,
    status: u16,
    latency_us: u32,
    arrival: u32,

    fn byStatus(_: void, a: Request, b: Request) bool {
        return a.status < b.status;
    }
};

/// A check that survives ReleaseFast (a debug assert compiles out there).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug.deinit() == .leak) @panic("leak");
    const gpa = debug.allocator();

    const paths = [_][]const u8{ "/api/users", "/health", "/api/orders", "/static/app.js", "/api/users/42", "/login" };
    var log: [300]Request = undefined;
    var prng = std.Random.DefaultPrng.init(2026);
    const r = prng.random();
    for (&log, 0..) |*q, i| q.* = .{
        .path = paths[r.uintLessThan(usize, paths.len)],
        .status = ([_]u16{ 200, 200, 200, 304, 404, 500 })[r.uintLessThan(usize, 6)],
        .latency_us = 100 + r.uintLessThan(u32, 50_000),
        .arrival = @intCast(i),
    };

    // 1. Endpoint names, lexicographic.
    var names = paths;
    sort.unstable([]const u8, &names, {}, sort.asc([]const u8));
    for (names[0 .. names.len - 1], names[1..]) |a, b| must(std.mem.order(u8, a, b) == .lt, @src());

    // 2. By status, arrival order kept within a status. `stable` takes its
    //    scratch from `gpa` (300 × 32 bytes is over 4 KiB of stack); a
    //    failing allocator shows the error it returns.
    var by_status = log;
    sort.stable(Request, std.testing.failing_allocator, &by_status, {}, Request.byStatus) catch |err| switch (err) {
        error.OutOfMemory => std.debug.print("no memory for the scratch: items untouched, retrying with gpa\n", .{}),
    };
    try sort.stable(Request, gpa, &by_status, {}, Request.byStatus);
    for (by_status[0 .. by_status.len - 1], by_status[1..]) |a, b| {
        must(a.status < b.status or (a.status == b.status and a.arrival < b.arrival), @src());
    }

    //    The same without an allocator: the caller brings the scratch.
    var again = log;
    var scratch: [300]Request = undefined;
    sort.stableBuffer(Request, &again, scratch[0..sort.stableScratchLen(again.len)], {}, Request.byStatus);
    must(std.mem.eql(u8, std.mem.sliceAsBytes(&again), std.mem.sliceAsBytes(&by_status)), @src());

    // 3. Median latency, in O(n), without sorting everything.
    var lat: [log.len]u32 = undefined;
    for (&lat, log) |*l, q| l.* = q.latency_us;
    const mid = lat.len / 2;
    sort.selectNth(u32, &lat, mid, {}, sort.asc(u32));
    for (lat[0..mid]) |x| must(x <= lat[mid], @src());
    for (lat[mid + 1 ..]) |x| must(x >= lat[mid], @src());

    std.debug.print("first endpoint {s}; first 500 at arrival {d}; median latency {d} µs\n", .{
        names[0],
        for (by_status) |q| (if (q.status == 500) break q.arrival) else 0,
        lat[mid],
    });
}
