// SPDX-License-Identifier: MIT
//! The deterministic fuzz driver: a verdict in seconds, from seeds.
//!
//! `zig build --fuzz` explores; for a verdict it is blind — no progress, exit
//! 0 on a crash, no limit per input, so a hang reads as a slow run (measured
//! 2026-09-27: 22 minutes on a bug this driver's shape found in 9 seconds).
//! This runs the SAME harness over inputs drawn from seeds, in the ordinary
//! test binary:
//!
//!     <PREFIX>=<runs>[,<first seed>]   run, else the test is skipped
//!     <PREFIX>_ONLY=<substring>        only harnesses whose name contains it
//!     <PREFIX>_MS=<limit per input>    default 2000
//!     <PREFIX>_SEEDFILE=<path>         the current seed, for a crash
//!     <PREFIX>_INPUT=<path>            replay one saved `--fuzz` input
//!
//! A hang is `HANG <name> seed=N` and exit 124 within the limit; a failing
//! input is `FAIL <name> seed=N: <error>`; a panic leaves its seed in the seed
//! file. Any seed replays with `<PREFIX>=1,N`. One job per core, each with a
//! disjoint seed range, is the caller's runner (one process per job).
//!
//! ## The harness is generic over its source of choices
//!
//!     fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void
//!
//! using only `valueRangeAtMost`, `value`, `bytes`, `index` and `slice`.
//! `std.testing.fuzz` hands it a `*std.testing.Smith`, the driver a `*Rng`.
//! ⛔ Never `Smith{ .in = random bytes }` as the driver's source: in `.in` mode
//! Smith reads eight bytes per value and answers the range's MINIMUM for
//! anything outside it — for random bytes almost always (measured: 0 of
//! 20 000 runs took the branch under test, and the run "passed").
//!
//! ## Reach before verdict
//!
//! `hit("label")` counts how often a run got somewhere; the driver prints
//! `REACH <label>=<n>` when it is done. "0 of N reached it" is not clean.

const std = @import("std");
const linux = std.os.linux;

/// `std.testing.Smith`'s drawing methods, from a PRNG.
pub const Rng = struct {
    r: std.Random,

    pub fn valueRangeAtMost(self: *Rng, comptime T: type, at_least: T, at_most: T) T {
        return self.r.intRangeAtMost(T, at_least, at_most);
    }
    pub fn value(self: *Rng, comptime T: type) T {
        return switch (@typeInfo(T)) {
            .bool => self.r.boolean(),
            .@"enum" => self.r.enumValue(T),
            else => self.r.int(T),
        };
    }
    pub fn bytes(self: *Rng, buf: []u8) void {
        self.r.bytes(buf);
    }
    pub fn index(self: *Rng, len: usize) usize {
        return self.r.uintLessThan(usize, len);
    }
    /// A length in `0..buf.len` and that many bytes; the length, as Smith
    /// returns it. Short lengths are as likely as long ones would be rare
    /// under a uniform draw over a large buffer, so half the draws are
    /// taken from the first 64.
    pub fn slice(self: *Rng, buf: []u8) u32 {
        const cap: usize = if (buf.len > 64 and self.r.boolean()) 64 else buf.len;
        const n = self.r.uintAtMost(usize, cap);
        self.r.bytes(buf[0..n]);
        return @intCast(n);
    }
};

pub const Options = struct {
    /// The environment prefix, e.g. `"QAP_FUZZ"`.
    prefix: []const u8,
    /// This harness's name: what `FAIL`/`HANG` print and `_ONLY` selects by.
    name: []const u8,
    default_limit_ms: u64 = 2000,
};

// ── reach counters ───────────────────────────────────────────────────────────

const max_labels = 48;
var labels: [max_labels][]const u8 = undefined;
var counts: [max_labels]u64 = @splat(0);
var label_count: usize = 0;

/// Count one arrival at `label`. Cheap enough to leave in the harness: a
/// pointer compare over a handful of labels.
pub fn hit(comptime label: []const u8) void {
    const l: []const u8 = label;
    for (labels[0..label_count], 0..) |known, i| {
        if (known.ptr == l.ptr) {
            counts[i] += 1;
            return;
        }
    }
    if (label_count == max_labels) return;
    labels[label_count] = l;
    counts[label_count] = 1;
    label_count += 1;
}

fn reportReach(name: []const u8) void {
    for (labels[0..label_count], counts[0..label_count]) |l, c|
        std.debug.print("REACH {s} {s}={d}\n", .{ name, l, c });
    label_count = 0;
    counts = @splat(0);
}

// ── the watchdog ─────────────────────────────────────────────────────────────

var current_seed = std.atomic.Value(u64).init(0);
var current_start = std.atomic.Value(u64).init(0);
var current_limit = std.atomic.Value(u64).init(0);
var current_name: []const u8 = "";
var dog_running = false;

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn watchdog() void {
    while (true) {
        const req: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        _ = linux.nanosleep(&req, null);
        const start = current_start.load(.acquire);
        const limit = current_limit.load(.acquire);
        if (start != 0 and nowNs() -| start > limit) {
            std.debug.print("HANG {s} seed={d} (over {d} ms)\n", .{ current_name, current_seed.load(.acquire), limit / std.time.ns_per_ms });
            std.process.exit(124);
        }
    }
}

fn armWatchdog(name: []const u8, limit_ms: u64) !void {
    current_name = name;
    current_limit.store(limit_ms * std.time.ns_per_ms, .release);
    if (dog_running) return;
    const dog = try std.Thread.spawn(.{}, watchdog, .{});
    dog.detach();
    dog_running = true;
}

fn env(buf: []u8, prefix: []const u8, suffix: []const u8) ?[]const u8 {
    const key = std.fmt.bufPrint(buf, "{s}{s}", .{ prefix, suffix }) catch return null;
    return std.testing.environ.getPosix(key);
}

fn openZ(path: []const u8, flags: linux.O, mode: linux.mode_t) ?i32 {
    var pb: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= pb.len) return null;
    @memcpy(pb[0..path.len], path);
    pb[path.len] = 0;
    const rc = linux.open(pb[0..path.len :0], flags, mode);
    return if (linux.errno(rc) == .SUCCESS) @intCast(rc) else null;
}

/// Run `harness` over seeds as the environment says, or skip.
///
/// `harness` is `fn (comptime S: type, src: *S, gpa: std.mem.Allocator)
/// anyerror!void`. Its allocator here is a `DebugAllocator` that still finds
/// leaks but records no stack traces — unwinding the stack at every
/// allocation was most of a run's time.
pub fn run(comptime harness: anytype, opts: Options) !void {
    var kb: [96]u8 = undefined;
    if (env(&kb, opts.prefix, "_ONLY")) |only| {
        if (std.mem.indexOf(u8, opts.name, only) == null) return error.SkipZigTest;
    }
    const limit_ms = if (env(&kb, opts.prefix, "_MS")) |m| try std.fmt.parseInt(u64, m, 10) else opts.default_limit_ms;

    var da: std.heap.DebugAllocator(.{ .stack_trace_frames = 0 }) = .init;
    const gpa = da.allocator();
    defer if (da.deinit() == .leak) @panic("fuzz driver: leak");

    if (env(&kb, opts.prefix, "_INPUT")) |path| {
        const fd = openZ(path, .{ .ACCMODE = .RDONLY }, 0) orelse return error.FileNotFound;
        defer _ = linux.close(fd);
        var buf: [1 << 16]u8 = undefined;
        const n = linux.read(fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return error.InputOutput;
        try armWatchdog(opts.name, limit_ms);
        current_start.store(nowNs(), .release);
        var smith: std.testing.Smith = .{ .in = buf[0..n] };
        try harness(std.testing.Smith, &smith, gpa);
        current_start.store(0, .release);
        std.debug.print("REPLAY {s} ok ({d} bytes)\n", .{ opts.name, n });
        return;
    }

    const spec = env(&kb, opts.prefix, "") orelse return error.SkipZigTest;
    var parts = std.mem.splitScalar(u8, spec, ',');
    const runs = try std.fmt.parseInt(u64, parts.next().?, 10);
    const first = if (parts.next()) |f| try std.fmt.parseInt(u64, f, 10) else 0;
    const seed_fd: ?i32 = if (env(&kb, opts.prefix, "_SEEDFILE")) |path|
        openZ(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644)
    else
        null;
    defer if (seed_fd) |fd| {
        _ = linux.close(fd);
    };

    try armWatchdog(opts.name, limit_ms);
    const t0 = nowNs();
    var last_report = t0;
    var seed = first;
    while (seed < first + runs) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        if (seed_fd) |fd| {
            var sb: [160]u8 = undefined;
            const txt = std.fmt.bufPrint(&sb, "{s} {d}\n", .{ opts.name, seed }) catch unreachable;
            _ = linux.ftruncate(fd, 0);
            _ = linux.pwrite(fd, txt.ptr, txt.len, 0);
        }
        current_seed.store(seed, .release);
        current_start.store(nowNs(), .release);
        harness(Rng, &rng, gpa) catch |e| {
            current_start.store(0, .release);
            std.debug.print("FAIL {s} seed={d}: {t}\n", .{ opts.name, seed, e });
            return e;
        };
        current_start.store(0, .release);
        const now = nowNs();
        if (now - last_report > std.time.ns_per_s) {
            last_report = now;
            const done = seed + 1 - first;
            std.debug.print("runs {s} {d} of {d} ({d}/s)\n", .{ opts.name, done, runs, done * std.time.ns_per_s / (now - t0) });
        }
    }
    const ms = (nowNs() - t0) / std.time.ns_per_ms;
    std.debug.print("DONE {s} runs={d} in {d} ms ({d}/s)\n", .{ opts.name, runs, ms, if (ms == 0) runs * 1000 else runs * 1000 / ms });
    reportReach(opts.name);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Rng: every draw stays inside what was asked for, and a seed repeats" {
    var prng = std.Random.DefaultPrng.init(7);
    var rng: Rng = .{ .r = prng.random() };
    var seen_short = false;
    var seen_long = false;
    for (0..2000) |_| {
        const v = rng.valueRangeAtMost(u16, 10, 20);
        try testing.expect(v >= 10 and v <= 20);
        try testing.expect(rng.index(7) < 7);
        var buf: [300]u8 = undefined;
        const n = rng.slice(&buf);
        try testing.expect(n <= buf.len);
        if (n < 8) seen_short = true;
        if (n > 200) seen_long = true;
        _ = rng.value(bool);
        _ = rng.value(u64);
    }
    try testing.expect(seen_short and seen_long);

    var a = std.Random.DefaultPrng.init(42);
    var b = std.Random.DefaultPrng.init(42);
    var ra: Rng = .{ .r = a.random() };
    var rb: Rng = .{ .r = b.random() };
    var ba: [64]u8 = undefined;
    var bb: [64]u8 = undefined;
    ra.bytes(&ba);
    rb.bytes(&bb);
    try testing.expectEqualSlices(u8, &ba, &bb);
    try testing.expectEqual(ra.value(u32), rb.value(u32));
}

fn sample(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const n = src.valueRangeAtMost(u8, 1, 32);
    const b = try gpa.alloc(u8, n);
    defer gpa.free(b);
    src.bytes(b);
    if (n > 16) hit("long");
}

test "run: skipped unless the environment asks (TESTKIT_FUZZ)" {
    // With TESTKIT_FUZZ=<runs> this is the driver driving a harness of its
    // own; without it, the skip every consumer's driver test returns.
    run(sample, .{ .prefix = "TESTKIT_FUZZ", .name = "sample" }) catch |e| switch (e) {
        error.SkipZigTest => return,
        else => return e,
    };
}

test "a generic harness runs under Smith too" {
    var smith: std.testing.Smith = .{ .in = &.{ 20, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3 } };
    try sample(std.testing.Smith, &smith, testing.allocator);
}
