// SPDX-License-Identifier: MIT

//! Comparative benchmark: `clock.monotonicNs` / `clock.realtimeNs` against Rust
//! std's `Instant::now` / `SystemTime::now` (the reference), the program behind
//! the `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-clock` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `rustc` (standard
//! library only; built into `.zig-cache/clock-rust-bench`). Run from the
//! repository root.
//!
//! One read per op; both sides double the batch until it takes over 100 ms and
//! keep the best of five. `monotonicCoarseNs` is printed for information only:
//! Rust std has no coarse clock to pair it with.

const std = @import("std");
const clock = @import("clock");

fn timeIt(io: std.Io, comptime f: anytype) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f());
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f());
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const exe = ".zig-cache/clock-rust-bench";
    std.debug.print("bench-clock: rustc -O ...\n", .{});
    const build = try std.process.run(arena, io, .{
        .argv = &.{ "rustc", "-O", "--edition", "2021", "-o", exe, "modules/clock/tools/rust_bench/main.rs" },
    });
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("bench-clock: rustc failed:\n{s}\n", .{build.stderr});
        return 1;
    }
    const run = try std.process.run(arena, io, .{ .argv = &.{exe} });
    if (run.term != .exited or run.term.exited != 0) {
        std.debug.print("bench-clock: rust bench failed:\n{s}\n", .{run.stderr});
        return 1;
    }
    const names = [_][]const u8{ "monotonic", "realtime" };
    var ref_ns: [names.len]f64 = undefined;
    var lines = std.mem.tokenizeScalar(u8, run.stdout, '\n');
    var i: usize = 0;
    while (lines.next()) |line| : (i += 1) {
        if (i >= names.len) return error.BadRustOutput;
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        if (!std.mem.eql(u8, f.next() orelse "", names[i])) return error.BadRustOutput;
        ref_ns[i] = try std.fmt.parseFloat(f64, f.next() orelse return error.BadRustOutput);
    }
    if (i != names.len) return error.BadRustOutput;

    const ours = [_]f64{ timeIt(io, clock.monotonicNs), timeIt(io, clock.realtimeNs) };
    const coarse = timeIt(io, clock.monotonicCoarseNs);

    var out_buf: [2048]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;
    try w.print("{s:<10} {s:>12} {s:>12} {s:>8}\n", .{ "workload", "ours ns/op", "rust ns/op", "ours/ref" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    for (names, ours, ref_ns) |name, o, r| {
        const ratio = o / r;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        try w.print("{s:<10} {d:>12.2} {d:>12.2} {d:>8.2}\n", .{ name, o, r, ratio });
    }
    try w.print("{s:<10} {d:>12.2} {s:>12} {s:>8}\n", .{ "coarse", coarse, "-", "-" });
    try w.print("\nworst ours/ref = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Rust std Instant::now/SystemTime::now · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
