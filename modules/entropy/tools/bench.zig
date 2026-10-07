// SPDX-License-Identifier: MIT

//! Comparative benchmark: `entropy.fill` against Go's `crypto/rand.Read` (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-entropy` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (standard library only). Run from the repository root.
//!
//! Fills of 32 B, 4 KiB and 1 MiB; both sides double the batch until it takes
//! over 100 ms and keep the best of five. Nothing to compare but the length:
//! the bytes are random by contract (the tests pin which std entry point
//! `fill` reaches).

const std = @import("std");
const entropy = @import("entropy");

const names = [_][]const u8{ "fill_32", "fill_4k", "fill_1m" };
const sizes = [_]usize{ 32, 4096, 1 << 20 };

fn timeIt(io: std.Io, buf: []u8) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            entropy.fill(io, buf);
            std.mem.doNotOptimizeAway(buf[0]);
        }
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            entropy.fill(io, buf);
            std.mem.doNotOptimizeAway(buf[0]);
        }
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    std.debug.print("bench-entropy: Go crypto/rand ...\n", .{});
    const go = try std.process.run(arena, io, .{
        .argv = &.{ "go", "run", "." },
        .environ_map = &env,
        .cwd = .{ .path = "modules/entropy/tools/go_bench" },
    });
    if (go.term != .exited or go.term.exited != 0) {
        std.debug.print("bench-entropy: go_bench failed:\n{s}\n", .{go.stderr});
        return 1;
    }
    var go_ns: [names.len]f64 = undefined;
    var lines = std.mem.tokenizeScalar(u8, go.stdout, '\n');
    var i: usize = 0;
    while (lines.next()) |line| : (i += 1) {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        if (!std.mem.eql(u8, f.next() orelse "", names[i])) return error.BadGoOutput;
        go_ns[i] = try std.fmt.parseFloat(f64, f.next() orelse return error.BadGoOutput);
    }
    if (i != names.len) return error.BadGoOutput;

    const buf = try arena.alloc(u8, 1 << 20);
    var out_buf: [2048]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;
    try w.print("{s:<8} {s:>12} {s:>12} {s:>8}\n", .{ "workload", "ours ns/op", "go ns/op", "ours/go" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    for (names, sizes, go_ns) |name, size, g| {
        const ours = timeIt(io, buf[0..size]);
        const r = ours / g;
        worst = @max(worst, r);
        best = @min(best, r);
        try w.print("{s:<8} {d:>12.1} {d:>12.1} {d:>8.2}\n", .{ name, ours, g, r });
    }
    try w.print("\nworst ours/go = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go crypto/rand.Read · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
