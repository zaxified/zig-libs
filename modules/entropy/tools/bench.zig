// SPDX-License-Identifier: MIT

//! Comparative benchmark: `entropy.fill` against Go's `crypto/rand.Read` (the
//! reference) and the field's other fast paths -- glibc's `arc4random_buf`, the
//! bare `getrandom(2)` wrapper (`c_bench/`) and the Rust `getrandom` crate
//! (`rust_bench/`) -- the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-entropy` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (standard library only), `cc` with glibc 2.36+ and `cargo` (the `getrandom`
//! crate from the registry; pinned in `rust_bench/Cargo.lock`). Run from the
//! repository root.
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

const Candidate = struct { name: []const u8, ns: [names.len]f64 };

fn parseRows(out: []const u8) ![names.len]f64 {
    var ns: [names.len]f64 = undefined;
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    var i: usize = 0;
    while (lines.next()) |line| : (i += 1) {
        if (i >= names.len) return error.BadOutput;
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        if (!std.mem.eql(u8, f.next() orelse "", names[i])) return error.BadOutput;
        ns[i] = try std.fmt.parseFloat(f64, f.next() orelse return error.BadOutput);
    }
    if (i != names.len) return error.BadOutput;
    return ns;
}

fn run(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8, cwd: ?[]const u8) ![]const u8 {
    const res = try std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = env,
        .cwd = if (cwd) |c| .{ .path = c } else .inherit,
    });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-entropy: {s} failed:\n{s}\n", .{ argv[0], res.stderr });
        return error.CandidateFailed;
    }
    return res.stdout;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    std.debug.print("bench-entropy: Go crypto/rand ...\n", .{});
    const go_ns = try parseRows(try run(arena, io, &env, &.{ "go", "run", "." }, "modules/entropy/tools/go_bench"));

    // The other candidates; one that cannot be built is reported and left out of the "fastest" figure.
    var others: [3]Candidate = undefined;
    var n_others: usize = 0;
    const work = ".zig-cache/bench-entropy";
    std.debug.print("bench-entropy: glibc arc4random_buf, getrandom(2) ...\n", .{});
    if (run(arena, io, &env, &.{ "mkdir", "-p", work }, null)) |_| {
        if (run(arena, io, &env, &.{ "cc", "-O2", "-o", work ++ "/cbench", "modules/entropy/tools/c_bench/main.c" }, null)) |_| {
            for ([_][]const u8{ "arc4random", "getrandom" }) |which| {
                const out = try run(arena, io, &env, &.{ work ++ "/cbench", which }, null);
                others[n_others] = .{ .name = if (std.mem.eql(u8, which, "arc4random")) "glibc arc4random_buf" else "getrandom(2)", .ns = try parseRows(out) };
                n_others += 1;
            }
        } else |_| {}
    } else |_| {}
    std.debug.print("bench-entropy: Rust getrandom crate ...\n", .{});
    if (run(arena, io, &env, &.{ "cargo", "build", "--release", "--quiet", "--manifest-path", "modules/entropy/tools/rust_bench/Cargo.toml", "--target-dir", work ++ "/rust" }, null)) |_| {
        const out = try run(arena, io, &env, &.{work ++ "/rust/release/entropy_rust_bench"}, null);
        others[n_others] = .{ .name = "Rust getrandom 0.3.4", .ns = try parseRows(out) };
        n_others += 1;
    } else |_| {}

    const buf = try arena.alloc(u8, 1 << 20);
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;
    try w.print("{s:<8} {s:>12} {s:>12}", .{ "workload", "ours ns/op", "go ns/op" });
    for (others[0..n_others]) |o| try w.print(" {s:>22}", .{o.name});
    try w.print(" {s:>8} {s:>12}\n", .{ "ours/go", "ours/fastest" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var worst_f: f64 = 0;
    var best_f: f64 = std.math.inf(f64);
    for (names, sizes, go_ns, 0..) |name, size, g, i| {
        const ours = timeIt(io, buf[0..size]);
        const r = ours / g;
        worst = @max(worst, r);
        best = @min(best, r);
        var fastest = g;
        try w.print("{s:<8} {d:>12.1} {d:>12.1}", .{ name, ours, g });
        for (others[0..n_others]) |o| {
            fastest = @min(fastest, o.ns[i]);
            try w.print(" {d:>22.1}", .{o.ns[i]});
        }
        const rf = ours / fastest;
        worst_f = @max(worst_f, rf);
        best_f = @min(best_f, rf);
        try w.print(" {d:>8.2} {d:>12.2}\n", .{ r, rf });
    }
    try w.print("\nworst ours/go = {d:.2} (best {d:.2}); ours/fastest of all {d} = {d:.2} (best {d:.2})\n", .{ worst, best, n_others + 1, worst_f, best_f });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go crypto/rand.Read · fastest {d:.2}–{d:.2}× best of Go, glibc arc4random_buf, getrandom(2), Rust getrandom (measured <today>)\n", .{ best, worst, best_f, worst_f });
    try w.flush();
    return 0;
}
