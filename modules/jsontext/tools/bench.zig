// SPDX-License-Identifier: MIT

//! Comparative benchmark: `jsontext.writeString` (default options) against Go's
//! `encoding/json` string encoder (`Encoder` with `SetEscapeHTML(false)`, the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-jsontext` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (standard library only). Run from the repository root.
//!
//! Four string shapes of 64 B and 4 KiB (generated identically on both sides,
//! see `fill`): ASCII with nothing to escape, valid UTF-8, ill-formed UTF-8,
//! control-heavy. Both sides double the batch until it takes over 100 ms and
//! keep the best of five. Go writes ill-formed bytes as the six-byte escape
//! `�`, we write the three-byte character: the bytes out differ, the work
//! asked of the encoder is the same.

const std = @import("std");
const jsontext = @import("jsontext");

const shapes = [_][]const u8{ "ascii", "utf8", "ill", "ctrl" };
const sizes = [_]usize{ 64, 4096 };

/// The same generator as `go_bench/main.go`.
fn fill(buf: []u8, shape: usize) void {
    const unit = "abc\xc3\xa9xyz\xe2\x82\xacdef\xf0\x9f\x98\x80 ";
    switch (shape) {
        0 => for (buf, 0..) |*b, i| {
            b.* = 'a' + @as(u8, @intCast(i * 7 % 26));
        },
        1 => {
            var n: usize = 0;
            while (n + unit.len <= buf.len) : (n += unit.len) @memcpy(buf[n..][0..unit.len], unit);
            @memset(buf[n..], 'x');
        },
        2 => for (buf, 0..) |*b, i| {
            b.* = if (i % 16 == 7) 0xE2 else if (i % 4 == 3) 0xFF else 'a' + @as(u8, @intCast(i % 26));
        },
        else => for (buf, 0..) |*b, i| {
            b.* = switch (i % 3) {
                0 => @intCast(i % 32),
                1 => '"',
                else => 'a' + @as(u8, @intCast(i % 26)),
            };
        },
    }
}

fn once(w: *std.Io.Writer, s: []const u8) void {
    w.end = 0;
    jsontext.writeString(w, s, .{}) catch unreachable;
    std.mem.doNotOptimizeAway(w.buffer[0]);
}

fn timeIt(io: std.Io, w: *std.Io.Writer, s: []const u8) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| once(w, s);
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| once(w, s);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    std.debug.print("bench-jsontext: Go encoding/json ...\n", .{});
    const go = try std.process.run(arena, io, .{
        .argv = &.{ "go", "run", "." },
        .environ_map = &env,
        .cwd = .{ .path = "modules/jsontext/tools/go_bench" },
    });
    if (go.term != .exited or go.term.exited != 0) {
        std.debug.print("bench-jsontext: go_bench failed:\n{s}\n", .{go.stderr});
        return 1;
    }
    var go_ns: [shapes.len * sizes.len]f64 = undefined;
    var lines = std.mem.tokenizeScalar(u8, go.stdout, '\n');
    var i: usize = 0;
    while (lines.next()) |line| : (i += 1) {
        if (i >= go_ns.len) return error.BadGoOutput;
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const want = try std.fmt.allocPrint(arena, "{s}_{d}", .{ shapes[i / sizes.len], sizes[i % sizes.len] });
        if (!std.mem.eql(u8, f.next() orelse "", want)) return error.BadGoOutput;
        go_ns[i] = try std.fmt.parseFloat(f64, f.next() orelse return error.BadGoOutput);
    }
    if (i != go_ns.len) return error.BadGoOutput;

    const in = try arena.alloc(u8, 4096);
    const out = try arena.alloc(u8, 64 * 1024);
    var w: std.Io.Writer = .fixed(out);
    var out_buf: [2048]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const o = &stdout.interface;
    try o.print("{s:<12} {s:>12} {s:>12} {s:>8}\n", .{ "workload", "ours ns/op", "go ns/op", "ours/go" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var k: usize = 0;
    for (shapes, 0..) |name, si| {
        for (sizes) |size| {
            fill(in[0..size], si);
            const ours = timeIt(io, &w, in[0..size]);
            const g = go_ns[k];
            const r = ours / g;
            worst = @max(worst, r);
            best = @min(best, r);
            try o.print("{s}_{d:<7} {d:>12.1} {d:>12.1} {d:>8.2}\n", .{ name, size, ours, g, r });
            k += 1;
        }
    }
    try o.print("\nworst ours/go = {d:.2} (best {d:.2})\n", .{ worst, best });
    try o.print("card: **Performance:** ref {d:.2}–{d:.2}× Go 1.26 encoding/json · fastest ? (measured <today>)\n", .{ best, worst });
    try o.flush();
    return 0;
}
