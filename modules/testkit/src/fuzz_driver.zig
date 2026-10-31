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
//!                                      (a harness runs `runs / Options.scale`)
//!     <PREFIX>_ONLY=<substring>        only harnesses whose name contains it
//!     <PREFIX>_MS=<limit per input>    default 2000 (0 = the default)
//!     <PREFIX>_SEEDFILE=<path>         the current seed, for a crash
//!     <PREFIX>_INPUT=<path>            replay one saved `--fuzz` input
//!     <PREFIX>_SHRINK=<seed>           shrink that seed (see shrink.zig;
//!                                      `_SHRINK_MS` default 60000, 0 = the
//!                                      default; `_SHRINK_OUT`)
//!     <PREFIX>_CHOICES=<path>          replay a shrunk choice tape, traced
//!
//! A hang is `HANG <name> seed=N` and exit 124 shortly after the limit (the
//! watchdog samples every 50 ms); a failing input is `FAIL <name> seed=N:
//! <error>`; a panic leaves its seed in the seed file. Each is followed by
//! the line that shrinks it. Any seed replays with `<PREFIX>=1,N`. One job
//! per core, each with a disjoint seed range, is the caller's runner (one
//! process per job).
//!
//! Cost: 1.00–1.04× a bare seed loop over the same harness, seed file
//! included (`zig build bench-testkit`, 2026-10-17).
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
const builtin = @import("builtin");
const linux = std.os.linux;
const shrinker = @import("shrink.zig");

/// Where the driver runs: Linux (it calls the kernel directly -- clock,
/// sleep, open) with 64-bit atomics (the watchdog's nanosecond state). That
/// is every lane that runs a fuzz verdict. Elsewhere `run` skips, without the
/// Linux code being compiled, so a module whose tests use the driver still
/// builds for the other targets it declares (brotli: mips32, Windows).
pub const supported = builtin.os.tag == .linux and @bitSizeOf(usize) == 64;

/// `std.testing.Smith`'s drawing methods, from a PRNG.
///
/// With a `tape` it also records every choice it makes (the shrinker's first
/// run of a failing seed), or answers every choice from the tape instead of
/// the PRNG (each shrink candidate, `<PREFIX>_CHOICES` replay). It stays this
/// one type either way, because harnesses branch on it (`if (S != Rng)`, 93
/// modules): a second source type would send the recorded run down the other
/// branch and record a different input than the one that failed.
pub const Rng = struct {
    r: std.Random,
    tape: ?*Tape = null,

    /// `at_least` must be <= `at_most` (checked panic otherwise; std's own
    /// `intRangeAtMost` only asserts, which is UB in ReleaseFast).
    pub fn valueRangeAtMost(self: *Rng, comptime T: type, at_least: T, at_most: T) T {
        if (at_least > at_most) @panic("testkit.Rng: valueRangeAtMost with at_least > at_most");
        const t = self.tape orelse return self.r.intRangeAtMost(T, at_least, at_most);
        const U = @Int(.unsigned, @bitSizeOf(T));
        const lo: U = @bitCast(at_least);
        const span: U = @as(U, @bitCast(at_most)) -% lo;
        const v: T = switch (t.mode) {
            .record => v: {
                const v = self.r.intRangeAtMost(T, at_least, at_most);
                t.putWide(U, @as(U, @bitCast(v)) -% lo);
                break :v v;
            },
            .replay => v: {
                var off = t.getWide(U);
                if (span != std.math.maxInt(U)) off %= span + 1;
                break :v @bitCast(lo +% off);
            },
        };
        if (t.trace) std.debug.print("  #{d} range {d}..{d} = {d}\n", .{ t.draws, at_least, at_most, v });
        t.draws += 1;
        return v;
    }
    pub fn value(self: *Rng, comptime T: type) T {
        const t = self.tape orelse return plainValue(self, T);
        const v: T = switch (@typeInfo(T)) {
            .bool => switch (t.mode) {
                .record => v: {
                    const v = self.r.boolean();
                    t.put(@intFromBool(v));
                    break :v v;
                },
                .replay => t.get() % 2 == 1,
            },
            .@"enum" => v: {
                const all = comptime std.enums.values(T);
                switch (t.mode) {
                    .record => {
                        const v = self.r.enumValue(T);
                        t.put(std.mem.findScalar(T, all, v).?);
                        break :v v;
                    },
                    .replay => break :v all[@intCast(t.get() % all.len)],
                }
            },
            else => v: {
                const U = @Int(.unsigned, @bitSizeOf(T));
                switch (t.mode) {
                    .record => {
                        const v = self.r.int(T);
                        t.putWide(U, @bitCast(v));
                        break :v v;
                    },
                    .replay => break :v @bitCast(t.getWide(U)),
                }
            },
        };
        if (t.trace) std.debug.print("  #{d} {s} = {any}\n", .{ t.draws, @typeName(T), v });
        t.draws += 1;
        return v;
    }
    fn plainValue(self: *Rng, comptime T: type) T {
        return switch (@typeInfo(T)) {
            .bool => self.r.boolean(),
            .@"enum" => self.r.enumValue(T),
            else => self.r.int(T),
        };
    }
    pub fn bytes(self: *Rng, buf: []u8) void {
        const t = self.tape orelse return self.r.bytes(buf);
        t.putOrGetBytes(self.r, buf);
        if (t.trace) traceBytes(t, "bytes", buf);
        t.draws += 1;
    }
    /// `len` must be > 0 (checked panic otherwise: there is no index into
    /// nothing, and std's `uintLessThan` only asserts).
    pub fn index(self: *Rng, len: usize) usize {
        if (len == 0) @panic("testkit.Rng: index(0)");
        const t = self.tape orelse return self.r.uintLessThan(usize, len);
        const v: usize = switch (t.mode) {
            .record => v: {
                const v = self.r.uintLessThan(usize, len);
                t.put(v);
                break :v v;
            },
            .replay => @intCast(t.get() % len),
        };
        if (t.trace) std.debug.print("  #{d} index <{d} = {d}\n", .{ t.draws, len, v });
        t.draws += 1;
        return v;
    }
    /// A length in `0..buf.len` and that many bytes; the length, as Smith
    /// returns it. Short lengths are as likely as long ones would be rare
    /// under a uniform draw over a large buffer, so half the draws are
    /// taken from the first 64.
    pub fn slice(self: *Rng, buf: []u8) u32 {
        const t = self.tape orelse return plainSlice(self.r, buf);
        const at = switch (t.mode) {
            .record => t.len,
            .replay => t.at,
        };
        const n: usize = switch (t.mode) {
            .record => n: {
                const n = plainSlice(self.r, buf);
                t.put(n);
                for (buf[0..n]) |b| t.put(b);
                break :n n;
            },
            .replay => n: {
                // `u32` is the return type: a buffer past 4 GiB is filled in part.
                const n: usize = @intCast(@min(t.get(), buf.len, std.math.maxInt(u32)));
                for (buf[0..n]) |*b| b.* = @truncate(t.get());
                break :n n;
            },
        };
        t.noteSpan(at, n);
        if (t.trace) traceBytes(t, "slice", buf[0..n]);
        t.draws += 1;
        return @intCast(n);
    }
    fn plainSlice(r: std.Random, buf: []u8) u32 {
        // `u32` is the return type: a buffer past 4 GiB is filled in part.
        const room = @min(buf.len, std.math.maxInt(u32));
        const cap: usize = if (room > 64 and r.boolean()) 64 else room;
        const n = r.uintAtMost(usize, cap);
        r.bytes(buf[0..n]);
        return @intCast(n);
    }
    fn traceBytes(t: *Tape, what: []const u8, b: []const u8) void {
        const shown = b[0..@min(b.len, 48)];
        std.debug.print("  #{d} {s}[{d}] = {x}{s}\n", .{ t.draws, what, b.len, shown, if (shown.len < b.len) " ..." else "" });
    }
};

/// The choices of one run, one `u64` per choice: a ranged draw's offset from
/// its minimum, an index, a length, a byte, a bool as 0/1, an enum's
/// position. Smaller entries are simpler inputs — that is the whole order the
/// shrinker minimises in. A replay that runs past the end reads zeros, and an
/// entry too large for its draw is reduced modulo the draw's span, so every
/// sequence of `u64` is a valid input.
pub const Tape = struct {
    mode: enum { record, replay },
    buf: []u64,
    /// Record: entries written. Replay: entries available.
    len: usize = 0,
    /// Replay: the next entry; past `len` once the run read beyond the tape.
    at: usize = 0,
    /// Record: a choice found the tape full (the run continued unrecorded).
    overflow: bool = false,
    /// Print every draw to stderr (`  #<n> range 0..255 = 17`).
    trace: bool = false,
    draws: usize = 0,
    /// Where the slices are (a length entry and its bytes), when given room:
    /// the shrinker cuts a slice as one piece — its length and its tail
    /// together — which no edit of single entries can do.
    spans: []Span = &.{},
    n_spans: usize = 0,

    pub const Span = struct { at: usize, len: usize };

    fn noteSpan(t: *Tape, at: usize, len: usize) void {
        if (t.n_spans == t.spans.len) return;
        t.spans[t.n_spans] = .{ .at = at, .len = len };
        t.n_spans += 1;
    }

    fn put(t: *Tape, v: u64) void {
        if (t.len == t.buf.len) {
            t.overflow = true;
            return;
        }
        t.buf[t.len] = v;
        t.len += 1;
    }
    fn get(t: *Tape) u64 {
        defer t.at += 1;
        return if (t.at < t.len) t.buf[t.at] else 0;
    }
    fn putWide(t: *Tape, comptime U: type, v: U) void {
        if (@bitSizeOf(U) <= 64) return t.put(v);
        if (@bitSizeOf(U) > 128) @compileError("fuzz.Rng: a draw wider than 128 bits");
        t.put(@truncate(v));
        t.put(@truncate(@as(u128, v) >> 64));
    }
    fn getWide(t: *Tape, comptime U: type) U {
        if (@bitSizeOf(U) <= 64) return @truncate(t.get());
        if (@bitSizeOf(U) > 128) @compileError("fuzz.Rng: a draw wider than 128 bits");
        const lo: u128 = t.get();
        const hi: u128 = t.get();
        return @truncate(lo | hi << 64);
    }
    fn putOrGetBytes(t: *Tape, r: std.Random, buf: []u8) void {
        switch (t.mode) {
            .record => {
                r.bytes(buf);
                for (buf) |b| t.put(b);
            },
            .replay => for (buf) |*b| {
                b.* = @truncate(t.get());
            },
        }
    }
};

pub const Options = struct {
    /// The environment prefix, e.g. `"QAP_FUZZ"`.
    prefix: []const u8,
    /// This harness's name: what `FAIL`/`HANG` print and `_ONLY` selects by.
    name: []const u8,
    default_limit_ms: u64 = 2000,
    /// How many of the budget's runs one run of this harness is worth. A
    /// runner hands every harness the same `<PREFIX>=<runs>`; a harness whose
    /// run is a whole protocol exchange rather than one parse says so here and
    /// gets `runs / scale` of them (at least one), so one budget suits both.
    scale: u64 = 1,
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
    resetReach();
}

/// Forget every reach count. For a test that runs a harness outside the
/// driver (an in-suite smoke loop), so its arrivals are not reported as the
/// next driver run's.
pub fn resetReach() void {
    label_count = 0;
    counts = @splat(0);
}

// ── the watchdog ─────────────────────────────────────────────────────────────

var current_seed = std.atomic.Value(u64).init(0);
var current_limit = std.atomic.Value(u64).init(0);
var current_name: []const u8 = "";
var current_prefix: []const u8 = "";

/// Bumped at every harness entry; `busy` while a harness runs. The watchdog
/// samples both every 50 ms: the same generation still busy for longer than
/// the limit is a hang. No clock is read per input — two reads per seed
/// were a tenth of a cheap harness's time (`zig build bench-testkit`,
/// 2026-10-17) — at the price of a hang being reported up to one sampling
/// period after the limit.
var dog_gen = std.atomic.Value(u64).init(0);
var dog_busy = std.atomic.Value(bool).init(false);

fn enter(seed: u64) void {
    current_seed.store(seed, .release);
    dog_gen.store(dog_gen.load(.monotonic) +% 1, .release);
    dog_busy.store(true, .release);
}

fn leave() void {
    dog_busy.store(false, .release);
}

fn printShrinkHint(seed: u64) void {
    std.debug.print("  smallest input: {s}_SHRINK={d} {s}_ONLY={s}\n", .{ current_prefix, seed, current_prefix, current_name });
}
var dog_running = false;

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Whether the watchdog, at `now`, holding the generation it last saw
/// change (`seen`, at `since`), must call a hang. Pure, for the tests.
fn hung(busy: bool, gen: u64, seen: *u64, since: *u64, now: u64, limit: u64) bool {
    if (!busy or gen != seen.*) {
        seen.* = gen;
        since.* = now;
        return false;
    }
    return now -| since.* > limit;
}

fn watchdog() void {
    var seen: u64 = 0;
    var since: u64 = nowNs();
    while (true) {
        const req: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        _ = linux.nanosleep(&req, null);
        const limit = current_limit.load(.acquire);
        if (hung(dog_busy.load(.acquire), dog_gen.load(.acquire), &seen, &since, nowNs(), limit)) {
            // A raw write, not `std.debug.print`: a harness hung inside a
            // print holds the stderr lock, and the watchdog would wait on it
            // forever instead of reporting the hang.
            const seed = current_seed.load(.acquire);
            var buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "HANG {s} seed={d} (over {d} ms)\n  smallest input: {s}_SHRINK={d} {s}_ONLY={s}\n", .{
                current_name, seed, limit / std.time.ns_per_ms, current_prefix, seed, current_prefix, current_name,
            }) catch "HANG (message too long)\n";
            _ = linux.write(2, msg.ptr, msg.len);
            std.process.exit(124);
        }
    }
}

/// `<PREFIX>_MS` in nanoseconds, saturating: the value is environment text, and
/// a plain product wraps (ReleaseFast) or panics (safe modes) from ~1.8e13 ms.
fn limitNs(limit_ms: u64) u64 {
    return limit_ms *| std.time.ns_per_ms;
}

/// Events per second, 0 when no time has passed; saturating (`n` can be large
/// on a long run of a trivial harness).
fn perSecond(n: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0) return n *| 1000;
    return @intCast(@min(@as(u128, n) * std.time.ns_per_s / elapsed_ns, std.math.maxInt(u64)));
}

fn armWatchdog(name: []const u8, limit_ms: u64) !void {
    current_name = name;
    current_limit.store(limitNs(limit_ms), .release);
    if (dog_running) return;
    const dog = try std.Thread.spawn(.{}, watchdog, .{});
    dog.detach();
    dog_running = true;
}

fn env(buf: []u8, prefix: []const u8, suffix: []const u8) ?[]const u8 {
    const key = std.mem.print(buf, "{s}{s}", .{ prefix, suffix }) catch return null;
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

/// Largest `<PREFIX>_INPUT` file read (a saved `--fuzz` input is a few KiB).
const input_cap: usize = 64 << 20;
/// Largest `<PREFIX>_CHOICES` file read: a tape holds at most `tape_cap`
/// entries, each at most 20 digits and a newline (comments and blank lines
/// have no bound of their own, so the file is capped, not just the parse).
const choices_cap: usize = shrinker.tape_cap * 21;

/// The whole file at `path`, `error.FileTooBig` past `cap` bytes (the path is
/// environment text and may name `/dev/zero` or a huge file); a read
/// interrupted by a signal is retried.
fn readFile(gpa: std.mem.Allocator, path: []const u8, cap: usize) ![]u8 {
    const fd = openZ(path, .{ .ACCMODE = .RDONLY }, 0) orelse return error.FileNotFound;
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.InputOutput,
        }
        if (n == 0) break;
        if (n > cap - out.items.len) return error.FileTooBig;
        try out.appendSlice(gpa, buf[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

/// Run `harness` once over the saved `--fuzz` input at `path`; its length.
/// The whole file: one `read` into a fixed buffer replayed a saved input over
/// 64 KiB (or a short read) cut short, and printed `ok` for an input that was
/// never run (review 2026-10-27).
fn replayInput(comptime harness: anytype, gpa: std.mem.Allocator, path: []const u8) !usize {
    const input = try readFile(gpa, path, input_cap);
    defer gpa.free(input);
    enter(0);
    var smith: std.testing.Smith = .{ .in = input };
    try harness(std.testing.Smith, &smith, gpa);
    leave();
    return input.len;
}

/// Run `harness` over seeds as the environment says, or skip.
///
/// `harness` is `fn (comptime S: type, src: *S, gpa: std.mem.Allocator)
/// anyerror!void`. Its allocator here is a `DebugAllocator` that still finds
/// leaks but records no stack traces — unwinding the stack at every
/// allocation was most of a run's time.
pub fn run(comptime harness: anytype, opts: Options) !void {
    if (comptime supported) return runHere(harness, opts) else return error.SkipZigTest;
}

/// `run` over several harnesses from one test: `.{ .{ harness, Options }, … }`.
///
/// A test must not chain `try run(a, …); try run(b, …);` — `run` skips a
/// harness `_ONLY` leaves out by returning `error.SkipZigTest`, so the `try`
/// ends the test there and every harness after it silently never runs (an
/// `_ONLY=b` verdict "passed" having run zero seeds, traceroute 2026-10-31).
/// This runs each one, and skips the test only if none of them ran.
pub fn runAll(comptime harnesses: anytype) !void {
    return runEach(harnesses, run);
}

/// `.{ .prefix = …, .name = … }` written inside the tuple is a struct of its
/// own, which Zig 0.17 does not coerce to `Options`; copy it field by field.
fn asOptions(comptime o: anytype) Options {
    if (@TypeOf(o) == Options) return o;
    var r: Options = .{ .prefix = o.prefix, .name = o.name };
    inline for (comptime std.meta.fieldNames(@TypeOf(o))) |f| @field(r, f) = @field(o, f);
    return r;
}

fn runEach(comptime harnesses: anytype, comptime runOne: anytype) !void {
    var ran = false;
    inline for (harnesses) |h| {
        if (runOne(h[0], comptime asOptions(h[1]))) {
            ran = true;
        } else |err| if (err != error.SkipZigTest) return err;
    }
    if (!ran) return error.SkipZigTest;
}

/// Whether a harness named `name` runs under `<PREFIX>_ONLY=only`.
pub fn selected(name: []const u8, only: ?[]const u8) bool {
    const o = only orelse return true;
    return std.mem.find(u8, name, o) != null;
}

/// `<PREFIX>=<runs>[,<first seed>]` for a harness of `scale`: how many seeds
/// (at least one) and the first.
pub const Spec = struct { runs: u64, first: u64 };

pub fn parseSpec(spec: []const u8, scale: u64) error{ InvalidCharacter, Overflow }!Spec {
    var parts = std.mem.splitScalar(u8, spec, ',');
    const runs = @max(1, try std.fmt.parseInt(u64, parts.next().?, 10) / @max(1, scale));
    const first = if (parts.next()) |f| try std.fmt.parseInt(u64, f, 10) else 0;
    return .{ .runs = runs, .first = first };
}

/// A `<PREFIX>_MS` / `<PREFIX>_SHRINK_MS` value: unset or `0` is `default_ms`
/// (a limit of 0 would call every input a hang).
fn msOrDefault(text: ?[]const u8, default_ms: u64) !u64 {
    const v = try std.fmt.parseInt(u64, text orelse return default_ms, 10);
    return if (v == 0) default_ms else v;
}

fn runHere(comptime harness: anytype, opts: Options) !void {
    var kb: [96]u8 = undefined;
    if (!selected(opts.name, env(&kb, opts.prefix, "_ONLY"))) return error.SkipZigTest;
    current_prefix = opts.prefix;
    current_name = opts.name;
    const limit_ms = try msOrDefault(env(&kb, opts.prefix, "_MS"), opts.default_limit_ms);

    // `.safety = true`: ReleaseFast's default looks for no leak, and the
    // `_CHOICES` replay hands this allocator to the harness.
    var da: std.heap.DebugAllocator(.{ .stack_trace_frames = 0, .safety = true }) = .init; // global-alloc-ok: the driver's own leak detector around each harness run, called only from `test` blocks
    const gpa = da.allocator();
    defer if (da.deinit() == .leak) @panic("fuzz driver: leak");

    if (env(&kb, opts.prefix, "_CHOICES")) |path| {
        const text = try readFile(gpa, path, choices_cap);
        defer gpa.free(text);
        const tape = try shrinker.parseTape(gpa, text);
        defer gpa.free(tape);
        try armWatchdog(opts.name, limit_ms);
        enter(0);
        std.debug.print("REPLAY {s} {d} choices from {s}:\n", .{ opts.name, tape.len, path });
        try shrinker.replayHere(harness, gpa, tape, true);
        leave();
        std.debug.print("REPLAY {s} ok\n", .{opts.name});
        return;
    }

    if (env(&kb, opts.prefix, "_SHRINK")) |seed_txt| {
        const seed = try std.fmt.parseInt(u64, seed_txt, 10);
        const budget = try msOrDefault(env(&kb, opts.prefix, "_SHRINK_MS"), 60_000);
        const r = shrinker.shrink(harness, gpa, .{
            .name = opts.name,
            .seed = seed,
            .limit_ms = limit_ms,
            .budget_ms = budget,
            .out_path = env(&kb, opts.prefix, "_SHRINK_OUT"),
        }) catch |e| switch (e) {
            error.SeedPasses => {
                std.debug.print("SHRINK {s} seed={d} passes: nothing to shrink\n", .{ opts.name, seed });
                return error.SkipZigTest;
            },
            else => return e,
        };
        gpa.free(r.tape);
        // The seed fails; so does this test, the way a FAIL line would.
        return error.FuzzFailureShrunk;
    }

    if (env(&kb, opts.prefix, "_INPUT")) |path| {
        try armWatchdog(opts.name, limit_ms);
        const n = try replayInput(harness, gpa, path);
        std.debug.print("REPLAY {s} ok ({d} bytes)\n", .{ opts.name, n });
        return;
    }

    const spec = try parseSpec(env(&kb, opts.prefix, "") orelse return error.SkipZigTest, opts.scale);
    const seed_fd: ?i32 = if (env(&kb, opts.prefix, "_SEEDFILE")) |path|
        // RDWR, not WRONLY: `SeedFile` maps it shared and writable.
        openZ(path, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o644)
    else
        null;
    defer if (seed_fd) |fd| {
        _ = linux.close(fd);
    };

    try armWatchdog(opts.name, limit_ms);
    return runSeeds(harness, opts.name, spec, gpa, seed_fd);
}

/// The seed file, `<name> <seed>\n`, rewritten before every seed so a
/// panic leaves the seed that caused it.
///
/// Written through a shared mapping of the file, not with `write`: the
/// mapped page is the page cache, so the text is in the file the moment it
/// is stored — a crashing process cannot lose it — and a store is a
/// `memcpy`. The `ftruncate` + `pwrite` this replaced cost ~9 µs per seed
/// (measured 2026-10-17, `zig build bench-testkit`: a 0.3 µs harness ran at
/// 29× its bare-loop time), and every runner sets the seed file. The size
/// changes only when the seed gains a digit. Falls back to a `pwrite` per
/// seed when the mapping fails (the fd is not readable, say).
const SeedFile = struct {
    fd: i32,
    map: ?[]align(std.heap.page_size_min) u8,
    size: usize = 0,
    /// `<name> ` once; the seed's digits are appended per seed.
    text: [160]u8 = undefined,
    head: usize = 0,
    /// The seed the file holds.
    last: u64 = 0,

    const map_len = 4096;

    fn open(fd: i32, name: []const u8) SeedFile {
        _ = linux.ftruncate(fd, 0);
        const m = std.posix.mmap(null, map_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0) catch null;
        var sf: SeedFile = .{ .fd = fd, .map = m };
        sf.head = @min(name.len, sf.text.len - 22);
        @memcpy(sf.text[0..sf.head], name[0..sf.head]);
        sf.text[sf.head] = ' ';
        sf.head += 1;
        return sf;
    }

    fn set(sf: *SeedFile, seed: u64) void {
        // The next seed of a run: add one to the decimal digits in place
        // (one byte, usually) instead of converting the number again.
        if (sf.map) |m| if (sf.size != 0 and sf.last +% 1 == seed and sf.last != std.math.maxInt(u64)) {
            var i = sf.size - 2; // the last digit, before '\n'
            while (m[i] == '9') : (i -= 1) {
                m[i] = '0';
                if (i == sf.head) break;
            } else {
                m[i] += 1;
                sf.last = seed;
                return;
            }
            // All nines: one digit more, the general path below.
        };
        sf.last = seed;
        var digits: [21]u8 = undefined;
        var i: usize = digits.len - 1;
        digits[i] = '\n';
        var v = seed;
        while (true) {
            i -= 1;
            digits[i] = '0' + @as(u8, @intCast(v % 10));
            v /= 10;
            if (v == 0) break;
        }
        const tail = digits[i..];
        const len = sf.head + tail.len;
        const m = sf.map orelse {
            @memcpy(sf.text[sf.head..][0..tail.len], tail);
            _ = linux.pwrite(sf.fd, &sf.text, len, 0);
            if (len < sf.size) _ = linux.ftruncate(sf.fd, @intCast(len));
            sf.size = len;
            return;
        };
        // The name is in the page since the first store; only the digits
        // move. Grow before the store (a store past the end of the file's
        // last page faults), shrink after it.
        const first = sf.size == 0;
        if (len > sf.size) _ = linux.ftruncate(sf.fd, @intCast(len));
        if (first) @memcpy(m[0..sf.head], sf.text[0..sf.head]);
        @memcpy(m[sf.head..][0..tail.len], tail);
        if (len < sf.size) _ = linux.ftruncate(sf.fd, @intCast(len));
        sf.size = len;
    }

    fn close(sf: *SeedFile) void {
        if (sf.map) |m| std.posix.munmap(m);
    }
};

/// The seed loop: every seed in `spec`, in order, each with a fresh `Rng`;
/// the first failure is printed with its seed and RETURNED (that return is
/// every fuzz verdict in the collection — a swallowed error would make all
/// of them green). Prints `DONE` and the reach counters at the end.
fn runSeeds(comptime harness: anytype, name: []const u8, spec: Spec, gpa: std.mem.Allocator, seed_fd: ?i32) !void {
    return runSeedsReporting(harness, name, spec, gpa, seed_fd, true);
}

/// `runSeeds` with the progress/verdict lines optional — the self-tests
/// run it silent, since this repo fails a passing step that writes to stderr.
/// Public for `tools/bench.zig`, which times it against a bare seed loop; a
/// harness's test calls `run`.
/// A fresh `SafeAllocator` after this many seeds, or once a batch's seeds
/// have allocated this many bytes (it never reuses freed memory, so the
/// bytes are what the batch holds).
const seeds_per_batch = 1024;
const bytes_per_batch = 64 << 20;

/// One seed's view of the batch allocator: counts what is live, so a leak is
/// pinned on the seed that made it. Atomic: a harness may allocate from
/// threads it spawns.
const SeedLedger = struct {
    child: std.mem.Allocator,
    live: std.atomic.Value(usize) = .init(0),
    bytes: std.atomic.Value(usize) = .init(0),

    fn allocator(l: *SeedLedger) std.mem.Allocator {
        return .{ .ptr = l, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const l: *SeedLedger = @ptrCast(@alignCast(ctx));
        const p = l.child.rawAlloc(len, a, ra) orelse return null;
        _ = l.live.fetchAdd(1, .monotonic);
        _ = l.bytes.fetchAdd(len, .monotonic);
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const l: *SeedLedger = @ptrCast(@alignCast(ctx));
        if (!l.child.rawResize(memory, a, new_len, ra)) return false;
        if (new_len > memory.len) _ = l.bytes.fetchAdd(new_len - memory.len, .monotonic);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const l: *SeedLedger = @ptrCast(@alignCast(ctx));
        const p = l.child.rawRemap(memory, a, new_len, ra) orelse return null;
        if (new_len > memory.len) _ = l.bytes.fetchAdd(new_len - memory.len, .monotonic);
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, a: std.mem.Alignment, ra: usize) void {
        const l: *SeedLedger = @ptrCast(@alignCast(ctx));
        l.child.rawFree(memory, a, ra);
        _ = l.live.fetchSub(1, .monotonic);
    }
};

pub fn runSeedsReporting(comptime harness: anytype, name: []const u8, spec: Spec, gpa: std.mem.Allocator, seed_fd: ?i32, report: bool) !void {
    // Count this run's arrivals only, not those of a test that ran the
    // harness before (a `testing.fuzz` smoke input, an in-suite loop).
    resetReach();
    const runs = spec.runs;
    const first = spec.first;
    const opts: struct { name: []const u8 } = .{ .name = name };
    var seed_file: ?SeedFile = if (seed_fd) |fd| .open(fd, opts.name) else null;
    defer if (seed_file) |*sf| sf.close();
    const t0 = nowNs();
    var last_report = t0;
    // One allocator per BATCH of seeds (std/heap/SafeAllocator.zig:621 init,
    // :653 deinit): the 0.17 `testing.allocator` never reuses memory, so a
    // loop of thousands of seeds on one allocator only grows; a fresh one per
    // batch bounds that. Not one per seed: its `threads: [128]Thread` made
    // init + deinit ~1 µs, 4.2x a 0.3 µs harness (bench-testkit `hex`,
    // 2026-10-20). A leak still fails the seed that made it, by number:
    // `SeedLedger` counts that seed's live allocations.
    var batch: ?std.heap.SafeAllocator = null;
    defer if (batch) |*b| {
        _ = b.deinitLog(false);
    };
    var batch_seeds: usize = 0;
    var batch_bytes: usize = 0;
    // By count, not `seed < first + runs`: that sum overflows for a range
    // ending at the top of u64, which ReleaseFast wraps into zero seeds run.
    for (0..runs) |i| {
        const seed = first +% i;
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        if (seed_file) |*sf| sf.set(seed);
        if (batch == null) {
            batch = .init(gpa, .{ .stack_trace_frames = 0 });
            batch_seeds = 0;
            batch_bytes = 0;
        }
        var ledger: SeedLedger = .{ .child = batch.?.allocator() };
        enter(seed);
        harness(Rng, &rng, ledger.allocator()) catch |e| {
            leave();
            if (report) {
                std.debug.print("FAIL {s} seed={d}: {t}\n", .{ opts.name, seed, e });
                printShrinkHint(seed);
            }
            return e;
        };
        leave();
        if (ledger.live.load(.monotonic) != 0) {
            if (report) {
                _ = batch.?.deinitLog(true);
                batch = null;
                std.debug.print("FAIL {s} seed={d}: memory leak\n", .{ opts.name, seed });
            }
            return error.MemoryLeakDetected;
        }
        batch_seeds += 1;
        batch_bytes +|= ledger.bytes.load(.monotonic);
        if (batch_seeds == seeds_per_batch or batch_bytes >= bytes_per_batch) {
            _ = batch.?.deinitLog(false); // every seed in it checked clean above
            batch = null;
        }
        // The clock, for the progress line, every 1024 seeds only.
        if (report and i % 1024 == 1023) {
            const now = nowNs();
            if (now - last_report > std.time.ns_per_s) {
                last_report = now;
                const done = i + 1;
                std.debug.print("runs {s} {d} of {d} ({d}/s)\n", .{ opts.name, done, runs, perSecond(done, now - t0) });
            }
        }
    }
    const ms = (nowNs() - t0) / std.time.ns_per_ms;
    if (report) {
        std.debug.print("DONE {s} runs={d} in {d} ms ({d}/s)\n", .{ opts.name, runs, ms, perSecond(runs, ms * std.time.ns_per_ms) });
        reportReach(opts.name);
    } else resetReach();
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

const RunEachProbe = struct {
    var calls: [4][]const u8 = undefined;
    var n: usize = 0;
    /// Skips every harness but `only` (null = skip all); `fail` fails.
    var only: ?[]const u8 = null;

    fn runOne(comptime harness: anytype, opts: Options) !void {
        _ = harness;
        calls[n] = opts.name;
        n += 1;
        if (std.mem.eql(u8, opts.name, "fail")) return error.Boom;
        if (!selected(opts.name, only)) return error.SkipZigTest;
    }

    fn reset(o: ?[]const u8) void {
        n = 0;
        only = o;
    }
};

test "runAll: a harness _ONLY leaves out does not stop the ones after it" {
    const hs = .{
        .{ sample, Options{ .prefix = "T", .name = "first" } },
        .{ sample, Options{ .prefix = "T", .name = "second" } },
        .{ sample, Options{ .prefix = "T", .name = "third" } },
    };
    // Only the last is selected: all three are tried, the test runs.
    RunEachProbe.reset("third");
    try runEach(hs, RunEachProbe.runOne);
    try std.testing.expectEqual(@as(usize, 3), RunEachProbe.n);
    try std.testing.expectEqualStrings("third", RunEachProbe.calls[2]);
    // None selected: the test is skipped, not passed.
    RunEachProbe.reset("none");
    try std.testing.expectError(error.SkipZigTest, runEach(hs, RunEachProbe.runOne));
    try std.testing.expectEqual(@as(usize, 3), RunEachProbe.n);
}

test "runAll: a failing harness fails the test at once" {
    const hs = .{
        .{ sample, Options{ .prefix = "T", .name = "fail" } },
        .{ sample, Options{ .prefix = "T", .name = "after" } },
    };
    RunEachProbe.reset(null);
    try std.testing.expectError(error.Boom, runEach(hs, RunEachProbe.runOne));
    try std.testing.expectEqual(@as(usize, 1), RunEachProbe.n);
}

test "Rng: both ends of a range are drawn (a harness must reach its boundaries)" {
    // Mutation 2026-10-17: an exclusive upper bound passed every other test.
    var prng = std.Random.DefaultPrng.init(1);
    var rng: Rng = .{ .r = prng.random() };
    var lo = false;
    var hi = false;
    for (0..500) |_| {
        const v = rng.valueRangeAtMost(u8, 3, 6);
        lo = lo or v == 3;
        hi = hi or v == 6;
    }
    try testing.expect(lo and hi);
}

test "Rng.slice: about half the draws on a big buffer are short (<= 64)" {
    // Mutation 2026-10-17: dropping the short-length bias passed every other
    // test (a uniform draw over 1000 bytes is <= 64 about 6% of the time).
    var prng = std.Random.DefaultPrng.init(3);
    var rng: Rng = .{ .r = prng.random() };
    var buf: [1000]u8 = undefined;
    var short: usize = 0;
    for (0..2000) |_| {
        if (rng.slice(&buf) <= 64) short += 1;
    }
    try testing.expect(short > 800 and short < 1300);
}

test "hit: counts every arrival per label" {
    // Mutation 2026-10-17: a `hit` that registered labels but never counted
    // passed every other test — and would print REACH lines that lie.
    resetReach();
    defer resetReach();
    hit("a");
    hit("b");
    hit("a");
    hit("a");
    try testing.expectEqual(@as(usize, 2), label_count);
    try testing.expectEqual(@as(u64, 3), counts[0]);
    try testing.expectEqual(@as(u64, 1), counts[1]);
}

var seen_seeds: std.ArrayList(u64) = .empty;
var fail_at: ?u64 = null;

/// Records which seed each run got (the first draw of a fresh
/// `DefaultPrng.init(seed)` identifies it) and fails at `fail_at`.
fn recorder(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const first_draw = src.value(u64);
    for (0..1000) |seed| {
        var p = std.Random.DefaultPrng.init(seed);
        if (p.random().int(u64) == first_draw) {
            seen_seeds.append(testing.allocator, seed) catch unreachable;
            if (fail_at) |f| if (f == seed) return error.HarnessFailed;
            if (seed % 3 == 0) hit("third");
            return;
        }
    }
    return error.UnknownSeed;
}

test "runSeeds: runs exactly the seeds of the spec, in order" {
    defer seen_seeds.clearAndFree(testing.allocator);
    fail_at = null;
    try runSeedsReporting(recorder, "rec", .{ .runs = 5, .first = 7 }, testing.allocator, null, false);
    try testing.expectEqualSlices(u64, &.{ 7, 8, 9, 10, 11 }, seen_seeds.items);
}

test "runSeeds: a failing seed stops the run and its error comes back" {
    defer seen_seeds.clearAndFree(testing.allocator);
    fail_at = 4;
    defer fail_at = null;
    try testing.expectError(error.HarnessFailed, runSeedsReporting(recorder, "rec", .{ .runs = 10, .first = 2 }, testing.allocator, null, false));
    try testing.expectEqualSlices(u64, &.{ 2, 3, 4 }, seen_seeds.items);
}

var leak_at: u64 = 0;

/// Leaks one allocation at seed `leak_at` only (the seed is read from the PRNG
/// the same way `recorder` does it).
fn leaker(comptime S: type, src: *S, a: std.mem.Allocator) anyerror!void {
    const first_draw = src.value(u64);
    var p = std.Random.DefaultPrng.init(leak_at);
    if (p.random().int(u64) == first_draw) _ = try a.alloc(u8, 16);
}

test "runSeeds: a leak in one seed fails the run (per-seed SafeAllocator is not a false green)" {
    leak_at = 3;
    try testing.expectError(error.MemoryLeakDetected, runSeedsReporting(leaker, "leak", .{ .runs = 6, .first = 0 }, testing.allocator, null, false));
    // The seed range that does not reach the leaking seed is green.
    try runSeedsReporting(leaker, "leak", .{ .runs = 3, .first = 0 }, testing.allocator, null, false);
    // Past a batch boundary (the batch allocator is renewed every
    // `seeds_per_batch` seeds; the ledger still pins the leak on its seed).
    leak_at = seeds_per_batch + 36;
    try testing.expectError(error.MemoryLeakDetected, runSeedsReporting(leaker, "leak", .{ .runs = 2 * seeds_per_batch + 2, .first = 0 }, testing.allocator, null, false));
    try runSeedsReporting(leaker, "leak", .{ .runs = seeds_per_batch + 36, .first = 0 }, testing.allocator, null, false);
}

/// Grows and shrinks one buffer through `realloc` and frees it: the ledger's
/// resize/remap paths must leave the seed clean.
fn regrower(comptime S: type, src: *S, a: std.mem.Allocator) anyerror!void {
    var buf = try a.alloc(u8, 1 + src.valueRangeAtMost(usize, 0, 64));
    defer a.free(buf);
    for (0..4) |_| buf = try a.realloc(buf, 1 + src.valueRangeAtMost(usize, 0, 9000));
}

test "runSeeds: realloc growth and shrink across batches is not a leak" {
    try runSeedsReporting(regrower, "regrow", .{ .runs = 3 * seeds_per_batch, .first = 0 }, testing.allocator, null, false);
}

test "runSeeds: reach counters are collected and reset after the report" {
    defer seen_seeds.clearAndFree(testing.allocator);
    fail_at = null;
    try runSeedsReporting(recorder, "rec", .{ .runs = 6, .first = 0 }, testing.allocator, null, false);
    // Collected during the run (seeds 0 and 3 are multiples of 3) and
    // cleared at its end: a fresh run starts from zero.
    try testing.expectEqual(@as(usize, 0), label_count);
    hit("x");
    try testing.expectEqual(@as(usize, 1), label_count);
    try testing.expectEqual(@as(u64, 1), counts[0]);
    label_count = 0;
    counts = @splat(0);
}

test "SeedFile: the file holds exactly `<name> <seed>\\n`, also across a digit" {
    if (!supported) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile(testing.io, "seed", .{ .read = true });
    defer f.close(testing.io);
    var sf: SeedFile = .open(f.handle, "h");
    defer sf.close();
    try testing.expect(sf.map != null);
    var buf: [64]u8 = undefined;
    // Jumps, and consecutive runs across a new digit (the in-place
    // increment) and across the top of u64.
    const seeds = [_]u64{ 9, 10, 7, 0, std.math.maxInt(u64), 123 } ++
        [_]u64{ 97, 98, 99, 100, 101, 999, 1000, 1001, 109, 110 } ++
        [_]u64{ std.math.maxInt(u64) - 2, std.math.maxInt(u64) - 1, std.math.maxInt(u64), 0, 1 };
    for (seeds) |seed| {
        sf.set(seed);
        const n = try f.readPositional(testing.io, &.{&buf}, 0);
        var want: [64]u8 = undefined;
        try testing.expectEqualStrings(try std.mem.print(&want, "h {d}\n", .{seed}), buf[0..n]);
    }
}

fn stuck(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    if (src.value(u8) < 64) while (true) {
        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
    };
}

fn runStuck() u8 {
    armWatchdog("stuck", 100) catch return 1;
    runSeedsReporting(stuck, "stuck", .{ .runs = 1000, .first = 0 }, std.heap.page_allocator, null, false) catch return 2; // global-alloc-ok: the body of a forked child that is killed by its watchdog, no caller to take one from
    return 0;
}

test "watchdog: a harness that stops is a HANG (exit 124) shortly after the limit" {
    if (!supported) return error.SkipZigTest;
    const child = @import("child.zig");
    const t0 = nowNs();
    const o = try child.run(runStuck, .{}, .{ .limit_ms = 5000 });
    try testing.expect(o.eql(.{ .exited = 124 }));
    const ms = (nowNs() - t0) / std.time.ns_per_ms;
    try testing.expect(ms >= 100 and ms < 1000);
}

test "hung: a hang is the same generation, busy, past the limit" {
    var seen: u64 = 0;
    var since: u64 = 0;
    // A new generation restarts the clock; idle never hangs.
    try testing.expect(!hung(true, 1, &seen, &since, 100, 50));
    try testing.expect(!hung(true, 1, &seen, &since, 150, 50)); // exactly at the limit
    try testing.expect(hung(true, 1, &seen, &since, 151, 50));
    try testing.expect(!hung(true, 2, &seen, &since, 1000, 50));
    try testing.expect(!hung(false, 2, &seen, &since, 5000, 50));
    try testing.expect(!hung(true, 2, &seen, &since, 5040, 50));
    try testing.expect(hung(true, 2, &seen, &since, 5051, 50));
}

test "runSeeds: the seed file names the failing seed" {
    if (!supported) return error.SkipZigTest;
    defer seen_seeds.clearAndFree(testing.allocator);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile(testing.io, "seed", .{ .read = true });
    defer f.close(testing.io);
    fail_at = 9;
    defer fail_at = null;
    try testing.expectError(error.HarnessFailed, runSeedsReporting(recorder, "rec", .{ .runs = 20, .first = 5 }, testing.allocator, f.handle, false));
    var buf: [64]u8 = undefined;
    const n = try f.readPositional(testing.io, &.{&buf}, 0);
    try testing.expectEqualStrings("rec 9\n", buf[0..n]);
}

test "parseSpec: runs, first seed, scale (at least one run)" {
    try testing.expectEqual(Spec{ .runs = 100, .first = 0 }, try parseSpec("100", 1));
    try testing.expectEqual(Spec{ .runs = 100, .first = 42 }, try parseSpec("100,42", 1));
    try testing.expectEqual(Spec{ .runs = 25, .first = 0 }, try parseSpec("100", 4));
    try testing.expectEqual(Spec{ .runs = 1, .first = 0 }, try parseSpec("3", 8));
    try testing.expectEqual(Spec{ .runs = 7, .first = 0 }, try parseSpec("7", 0));
    try testing.expectError(error.InvalidCharacter, parseSpec("x", 1));
    try testing.expectError(error.InvalidCharacter, parseSpec("5,y", 1));
}

test "selected: _ONLY picks harnesses by substring" {
    try testing.expect(selected("aaa-gate-verify", null));
    try testing.expect(selected("aaa-gate-verify", "verify"));
    try testing.expect(selected("aaa-gate-verify", "aaa-gate-verify"));
    try testing.expect(!selected("aaa-gate-verify", "throttle"));
}

test "a generic harness runs under Smith too" {
    var smith: std.testing.Smith = .{ .in = &.{ 20, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3 } };
    try sample(std.testing.Smith, &smith, testing.allocator);
}

var replay_seen: usize = 0;

fn lengthOf(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    replay_seen = src.in.?.len;
}

test "_INPUT replay: an input over 64 KiB is replayed whole" {
    if (!supported) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "input", .data = big });
    var pb: [128]u8 = undefined;
    const path = try std.mem.print(&pb, ".zig-cache/tmp/{s}/input", .{&tmp.sub_path});
    replay_seen = 0;
    try testing.expectEqual(big.len, try replayInput(lengthOf, testing.allocator, path));
    try testing.expectEqual(big.len, replay_seen);
}

var top_seeds: [4]u64 = undefined;
var top_n: usize = 0;

fn topRecorder(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    _ = src;
    top_seeds[top_n] = current_seed.load(.acquire);
    top_n += 1;
}

test "runSeeds: a range ending at the top of u64 runs every seed" {
    top_n = 0;
    try runSeedsReporting(topRecorder, "top", .{ .runs = 2, .first = std.math.maxInt(u64) - 1 }, testing.allocator, null, false);
    try testing.expectEqualSlices(u64, &.{ std.math.maxInt(u64) - 1, std.math.maxInt(u64) }, top_seeds[0..top_n]);
}

// ── sweep GK (2026-10-29) ────────────────────────────────────────────────────

test "limitNs saturates instead of overflowing on a huge <PREFIX>_MS (sweep TK-1)" {
    try testing.expectEqual(@as(u64, 2_000_000_000), limitNs(2000));
    try testing.expectEqual(std.math.maxInt(u64), limitNs(std.math.maxInt(u64)));
    try testing.expectEqual(std.math.maxInt(u64), limitNs(std.math.maxInt(u64) / std.time.ns_per_ms + 1));
}

test "perSecond neither divides by zero nor overflows on long runs (sweep TK-2)" {
    try testing.expectEqual(@as(u64, 500), perSecond(1000, 2 * std.time.ns_per_s));
    try testing.expectEqual(@as(u64, 7000), perSecond(7, 0));
    // 2e10 events in a second: `n * 1e9` wraps u64 (the old inline form).
    try testing.expectEqual(@as(u64, 20_000_000_000), perSecond(20_000_000_000, std.time.ns_per_s));
    try testing.expectEqual(std.math.maxInt(u64), perSecond(std.math.maxInt(u64), 1));
}

fn rngFor0(use_tape: bool, comptime inverted: bool) u8 {
    var prng = std.Random.DefaultPrng.init(1);
    var buf: [4]u64 = undefined;
    var tape: Tape = .{ .mode = .record, .buf = &buf };
    var rng: Rng = .{ .r = prng.random(), .tape = if (use_tape) &tape else null };
    if (inverted) std.mem.doNotOptimizeAway(rng.valueRangeAtMost(u8, 9, 3)) else std.mem.doNotOptimizeAway(rng.index(0));
    return 0;
}
fn rngIndex0Plain() u8 {
    return rngFor0(false, false);
}
fn rngIndex0Tape() u8 {
    return rngFor0(true, false);
}
fn rngInvertedPlain() u8 {
    return rngFor0(false, true);
}
fn rngInvertedTape() u8 {
    return rngFor0(true, true);
}

fn expectAborts(comptime f: fn () u8) !void {
    if (!supported) return error.SkipZigTest;
    const child = @import("child.zig");
    const out = try child.run(f, .{}, .{ .limit_ms = 5000 });
    try testing.expect(out.eql(.{ .signaled = @backingInt(linux.SIG.ABRT) }));
}

test "Rng.index(0) is a checked panic, with and without a tape (sweep TK-3)" {
    try expectAborts(rngIndex0Plain);
    try expectAborts(rngIndex0Tape);
}

test "Rng.valueRangeAtMost with at_least > at_most is a checked panic, with and without a tape (sweep TK-3)" {
    try expectAborts(rngInvertedPlain);
    try expectAborts(rngInvertedTape);
}

// ── blind review (2026-10-29) ────────────────────────────────────────────────

fn tmpPath(buf: []u8, tmp: anytype, name: []const u8) ![]const u8 {
    return std.mem.print(buf, ".zig-cache/tmp/{s}/{s}", .{ &tmp.sub_path, name });
}

test "readFile: a file over the cap is error.FileTooBig, not a bigger allocation (review R-TK-1)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try testing.allocator.alloc(u8, 10_000);
    defer testing.allocator.free(data);
    @memset(data, 'x');
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "f", .data = data });
    var pb: [128]u8 = undefined;
    const path = try tmpPath(&pb, tmp, "f");
    try testing.expectError(error.FileTooBig, readFile(testing.allocator, path, 9_999));
    const whole = try readFile(testing.allocator, path, 10_000);
    defer testing.allocator.free(whole);
    try testing.expectEqual(@as(usize, 10_000), whole.len);
    // The real caps: a tape's own maximum fits, with room for comments.
    try testing.expect(choices_cap >= shrinker.tape_cap * 21);
    try testing.expectEqual(@as(usize, 64 << 20), input_cap);
}

fn noopHandler(_: linux.SIG) callconv(.c) void {}

const EintrFeeder = struct {
    main_tid: linux.pid_t,
    wfd: i32,
    fn run(f: EintrFeeder) void {
        const nap: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        _ = linux.nanosleep(&nap, null);
        // The main thread is blocked in `read` on the empty pipe: interrupt it.
        _ = linux.tgkill(linux.getpid(), f.main_tid, .USR1);
        _ = linux.nanosleep(&nap, null);
        _ = linux.write(f.wfd, "abc", 3);
        _ = linux.close(f.wfd);
    }
};

test "readFile: a read interrupted by a signal is retried (review R-TK-1)" {
    if (!supported) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    // No SA_RESTART: the blocked read must return EINTR.
    const act: linux.Sigaction = .{ .handler = .{ .handler = noopHandler }, .mask = linux.sigemptyset(), .flags = 0 };
    var old: linux.Sigaction = undefined;
    _ = linux.sigaction(.USR1, &act, &old);
    defer _ = linux.sigaction(.USR1, &old, null);
    const feeder = try std.Thread.spawn(.{}, EintrFeeder.run, .{EintrFeeder{ .main_tid = linux.gettid(), .wfd = fds[1] }});
    defer feeder.join();
    var pb: [64]u8 = undefined;
    const path = try std.mem.print(&pb, "/proc/self/fd/{d}", .{fds[0]});
    const got = try readFile(testing.allocator, path, 1 << 20);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("abc", got);
}

test "msOrDefault: unset and 0 are the default, anything else is itself (review R-TK-4)" {
    try testing.expectEqual(@as(u64, 2000), try msOrDefault(null, 2000));
    try testing.expectEqual(@as(u64, 2000), try msOrDefault("0", 2000));
    try testing.expectEqual(@as(u64, 7), try msOrDefault("7", 2000));
    try testing.expectError(error.InvalidCharacter, msOrDefault("x", 2000));
}
