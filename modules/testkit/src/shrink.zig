// SPDX-License-Identifier: MIT
//! Shrinking a failing seed to a small input that fails the same way.
//!
//!     <PREFIX>_SHRINK=<seed>      shrink that seed (with `_ONLY` for one harness)
//!     <PREFIX>_SHRINK_MS=<ms>     the shrink's budget (default 60000)
//!     <PREFIX>_SHRINK_OUT=<path>  where the smallest choice tape is written
//!     <PREFIX>_CHOICES=<path>     replay a tape in-process, every draw printed
//!
//! A seed's input is the sequence of choices its harness made (`Tape`: one
//! `u64` per draw). The seed is first run once with the tape recording; then
//! candidate tapes — blocks deleted, blocks zeroed, single entries lowered —
//! are run against the same harness, and a candidate is kept when it ends
//! **the same way**: the same error, the same signal (a panic or a fault), a
//! leak, or a hang. Smaller entries are simpler inputs (shorter slices, lower
//! ranged values, earlier enum tags), so the result is a short tape of small
//! numbers, and its replay prints which draw got which value.
//!
//! Every run is a forked child (`child.zig`): a panicking or hanging
//! candidate costs one child, not the shrink. The child's stderr is closed
//! except for the last replay, which prints the draws and then the failure.
//! The approach is Hypothesis's (choice-sequence shrinking); no code of it is
//! used.

const std = @import("std");
const linux = std.os.linux;
const driver = @import("fuzz_driver.zig");
const child = @import("child.zig");

const Rng = driver.Rng;
const Tape = driver.Tape;

/// Choices one run may record (8 MiB of shared memory, reserved lazily).
pub const tape_cap = 1 << 20;

/// What the parent and its children share. The child's `Tape` lives here
/// too, so its length (record) and position (replay) survive a child that
/// panics halfway: a recorded prefix is still a prefix, and a candidate that
/// crashed after reading k entries is cut to those k.
const Shared = struct {
    tape: Tape,
    /// Replay: the entries the parent put in `log`.
    len: u64,
    err_len: u64,
    err_name: [120]u8,
    spans: [max_spans]Tape.Span,
    log: [tape_cap]u64,
};

/// Slices one run's structure is tracked for; later ones are still shrunk
/// entry by entry.
const max_spans = 4096;

const code_pass = 0;
const code_error = 10;
const code_leak = 11;
const code_overflow = 12;

fn mapShared() !*Shared {
    const m = std.posix.mmap(null, @sizeOf(Shared), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .ANONYMOUS = true, .NORESERVE = true }, -1, 0) catch
        return error.OutOfMemory;
    return @ptrCast(@alignCast(m.ptr));
}

fn unmapShared(sh: *Shared) void {
    const p: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(sh));
    std.posix.munmap(p[0..@sizeOf(Shared)]);
}

fn Children(comptime harness: anytype) type {
    return struct {
        /// One harness run in this (child) process; the exit code says how
        /// it ended, the shared header says what it consumed and which error.
        fn runOne(sh: *Shared, rng: *Rng) u8 {
            var da: std.heap.DebugAllocator(.{ .stack_trace_frames = 0 }) = .init; // global-alloc-ok: the shrinker's leak detector around one forked harness run
            var code: u8 = code_pass;
            harness(Rng, rng, da.allocator()) catch |e| {
                const n = @min(@errorName(e).len, sh.err_name.len);
                @memcpy(sh.err_name[0..n], @errorName(e)[0..n]);
                sh.err_len = n;
                code = code_error;
            };
            if (da.deinit() == .leak and code == code_pass) code = code_leak;
            return code;
        }

        fn record(sh: *Shared, seed: u64) u8 {
            var prng = std.Random.DefaultPrng.init(seed);
            sh.tape = .{ .mode = .record, .buf = &sh.log, .spans = &sh.spans };
            var rng: Rng = .{ .r = prng.random(), .tape = &sh.tape };
            const code = runOne(sh, &rng);
            return if (sh.tape.overflow) code_overflow else code;
        }

        fn replay(sh: *Shared, trace: bool) u8 {
            var prng = std.Random.DefaultPrng.init(0);
            sh.tape = .{ .mode = .replay, .buf = &sh.log, .len = @intCast(sh.len), .trace = trace, .spans = &sh.spans };
            var rng: Rng = .{ .r = prng.random(), .tape = &sh.tape };
            return runOne(sh, &rng);
        }
    };
}

pub const Options = struct {
    name: []const u8,
    seed: u64,
    limit_ms: u64,
    budget_ms: u64 = 60_000,
    out_path: ?[]const u8 = null,
    /// Print the SHRINK/SHRUNK lines and the final traced replay.
    report: bool = true,
};

pub const Result = struct {
    outcome: child.Outcome,
    /// The smallest tape found (owned by the caller's allocator).
    tape: []u64,
    from: usize,
    candidates: usize,
};

/// Shrink `opts.seed` of `harness`. `error.SeedPasses` when it does not fail.
pub fn shrink(comptime harness: anytype, gpa: std.mem.Allocator, opts: Options) !Result {
    const K = Children(harness);
    const sh = try mapShared();
    defer unmapShared(sh);
    sh.err_len = 0;
    sh.tape = .{ .mode = .record, .buf = &sh.log };

    const target = try child.run(K.record, .{ sh, opts.seed }, .{ .limit_ms = opts.limit_ms });
    if (target.eql(.{ .exited = code_pass })) return error.SeedPasses;
    if (target.eql(.{ .exited = code_overflow })) return error.TapeOverflow;
    var target_err: [120]u8 = undefined;
    const target_err_len: usize = @intCast(sh.err_len);
    @memcpy(target_err[0..target_err_len], sh.err_name[0..target_err_len]);

    var s: State = .{
        .sh = sh,
        .target = target,
        .target_err = target_err[0..target_err_len],
        .limit_ms = opts.limit_ms,
        .deadline = nowMs() + opts.budget_ms,
        .cur = try gpa.dupe(u64, sh.log[0..sh.tape.len]),
        .gpa = gpa,
        .replayFn = K.replay,
    };
    errdefer gpa.free(s.cur);
    defer s.spans.deinit(gpa);
    try s.takeSpans();
    const from = s.cur.len;
    if (opts.report) std.debug.print("SHRINK {s} seed={d}: {f} after {d} choices\n", .{ opts.name, opts.seed, fmtOutcome(target, s.target_err), from });

    try s.passes();

    if (opts.report) {
        std.debug.print("SHRUNK {s} seed={d}: {d} -> {d} choices ({d} candidates)\n", .{ opts.name, opts.seed, from, s.cur.len, s.candidates });
        if (opts.out_path) |p| {
            writeTape(p, s.cur) catch |e| std.debug.print("SHRUNK {s}: could not write {s} ({t})\n", .{ opts.name, p, e });
        } else if (s.cur.len <= 64) {
            std.debug.print("choices:", .{});
            for (s.cur) |v| std.debug.print(" {d}", .{v});
            std.debug.print("\n", .{});
        }
        // The smallest input, with every draw printed, and then its failure.
        @memcpy(sh.log[0..s.cur.len], s.cur);
        sh.len = s.cur.len;
        std.debug.print("replay of the smallest input:\n", .{});
        _ = try child.run(K.replay, .{ sh, true }, .{ .limit_ms = opts.limit_ms, .show_stderr = true });
    }
    return .{ .outcome = target, .tape = s.cur, .from = from, .candidates = s.candidates };
}

const State = struct {
    sh: *Shared,
    target: child.Outcome,
    target_err: []const u8,
    limit_ms: u64,
    deadline: u64,
    cur: []u64,
    gpa: std.mem.Allocator,
    candidates: usize = 0,
    replayFn: *const fn (*Shared, bool) u8,
    /// The slices of `cur`, from the run that produced it.
    spans: std.ArrayList(Tape.Span) = .empty,

    fn takeSpans(s: *State) !void {
        s.spans.clearRetainingCapacity();
        for (s.sh.spans[0..s.sh.tape.n_spans]) |sp| {
            if (sp.at + sp.len < s.cur.len) try s.spans.append(s.gpa, sp);
        }
    }

    fn outOfTime(s: *const State) bool {
        return nowMs() >= s.deadline;
    }

    /// Run `cand`; when it ends like the target, it becomes `cur` (cut to
    /// what the run consumed) and this returns true.
    fn tryTape(s: *State, cand: []const u64) !bool {
        if (s.outOfTime()) return false;
        s.candidates += 1;
        @memcpy(s.sh.log[0..cand.len], cand);
        s.sh.len = cand.len;
        s.sh.err_len = 0;
        s.sh.tape.at = cand.len;
        const out = try child.run(s.replayFn, .{ s.sh, false }, .{ .limit_ms = s.limit_ms });
        if (!out.eql(s.target)) return false;
        if (s.target.eql(.{ .exited = code_error }) and
            !std.mem.eql(u8, s.sh.err_name[0..@intCast(s.sh.err_len)], s.target_err)) return false;
        const keep = @min(cand.len, s.sh.tape.at);
        const next = try s.gpa.dupe(u64, cand[0..keep]);
        s.gpa.free(s.cur);
        s.cur = next;
        try s.takeSpans();
        return true;
    }

    /// `cur` with the slice at `sp` cut to `n` bytes (its first `n`, or
    /// its last `n` when `from_front`).
    fn sliceCut(s: *State, out: *std.ArrayList(u64), sp: Tape.Span, n: usize, from_front: bool) !void {
        out.clearRetainingCapacity();
        try out.appendSlice(s.gpa, s.cur[0..sp.at]);
        try out.append(s.gpa, n);
        const bytes = s.cur[sp.at + 1 ..][0..sp.len];
        try out.appendSlice(s.gpa, if (from_front) bytes[sp.len - n ..] else bytes[0..n]);
        try out.appendSlice(s.gpa, s.cur[sp.at + 1 + sp.len ..]);
    }

    fn cutSlice(s: *State, scratch: *std.ArrayList(u64), sp: Tape.Span, from_front: bool) !bool {
        if (sp.len == 0) return false;
        try s.sliceCut(scratch, sp, 0, from_front);
        if (try s.tryTape(scratch.items)) return true;
        // 0 passes, sp.len fails: the shortest failing length between.
        var lo: usize = 0;
        var hi: usize = sp.len;
        var any = false;
        // The span moves with every accepted cut; keep cutting the original
        // shape against the current tape only while it is still there.
        while (hi - lo > 1 and !s.outOfTime()) {
            const mid = lo + (hi - lo) / 2;
            const cur_sp: Tape.Span = .{ .at = sp.at, .len = hi };
            if (cur_sp.at + cur_sp.len >= s.cur.len or s.cur[cur_sp.at] != hi) break;
            try s.sliceCut(scratch, cur_sp, mid, from_front);
            if (try s.tryTape(scratch.items)) {
                hi = mid;
                any = true;
            } else lo = mid;
        }
        return any;
    }

    fn passes(s: *State) !void {
        var scratch: std.ArrayList(u64) = .empty;
        defer scratch.deinit(s.gpa);
        var changed = true;
        while (changed and !s.outOfTime()) {
            changed = false;
            // 0. Cut slices as a whole, last first: a shorter length with its
            //    bytes cut from the end, then from the front, by binary
            //    search on the new length.
            var si: usize = s.spans.items.len;
            while (si > 0 and !s.outOfTime()) {
                si -= 1;
                if (si >= s.spans.items.len) continue;
                inline for (.{ false, true }) |from_front| {
                    if (si < s.spans.items.len) {
                        const sp = s.spans.items[si];
                        if (try s.cutSlice(&scratch, sp, from_front)) changed = true;
                    }
                }
            }
            // 1. Delete blocks, large to small; a large block steps by its
            //    size, a small one by one entry.
            var k: usize = std.math.floorPowerOfTwo(usize, @max(s.cur.len, 1));
            while (k >= 1) : (k /= 2) {
                var i: usize = s.cur.len -| k;
                while (true) {
                    if (i + k <= s.cur.len) {
                        scratch.clearRetainingCapacity();
                        try scratch.appendSlice(s.gpa, s.cur[0..i]);
                        try scratch.appendSlice(s.gpa, s.cur[i + k ..]);
                        if (try s.tryTape(scratch.items)) changed = true;
                    }
                    const step: usize = if (k > 8) k else 1;
                    if (i < step or s.outOfTime()) break;
                    i -= step;
                }
                if (k == 1) break;
            }
            // 2. Zero blocks of up to eight entries.
            k = 8;
            while (k >= 1) : (k /= 2) {
                var i: usize = 0;
                while (i < s.cur.len and !s.outOfTime()) : (i += 1) {
                    const end = @min(i + k, s.cur.len);
                    if (std.mem.allEqual(u64, s.cur[i..end], 0)) continue;
                    scratch.clearRetainingCapacity();
                    try scratch.appendSlice(s.gpa, s.cur);
                    @memset(scratch.items[i..end], 0);
                    if (try s.tryTape(scratch.items)) changed = true;
                }
                if (k == 1) break;
            }
            // 3. Lower single entries: the lowest value that still fails, by
            //    binary search between a value that does not and one that does.
            var i: usize = 0;
            while (i < s.cur.len and !s.outOfTime()) : (i += 1) {
                if (s.cur[i] == 0) continue;
                var lo: u64 = 0; // known not to fail (zeroing was tried)
                var hi: u64 = s.cur[i];
                while (hi - lo > 1 and !s.outOfTime()) {
                    const mid = lo + (hi - lo) / 2;
                    scratch.clearRetainingCapacity();
                    try scratch.appendSlice(s.gpa, s.cur);
                    scratch.items[i] = mid;
                    if (try s.tryTape(scratch.items)) {
                        hi = mid;
                        changed = true;
                        if (i >= s.cur.len) break;
                    } else lo = mid;
                }
            }
        }
    }
};

const OutcomeFmt = struct {
    o: child.Outcome,
    err: []const u8,
    pub fn format(f: OutcomeFmt, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (f.o) {
            .exited => |c| switch (c) {
                code_error => try w.print("error.{s}", .{f.err}),
                code_leak => try w.writeAll("a leak"),
                else => try w.print("exit {d}", .{c}),
            },
            .signaled => |sig| try w.print("signal {d} (a panic is 6)", .{sig}),
            .hang => try w.writeAll("a hang"),
        }
    }
};

fn fmtOutcome(o: child.Outcome, err: []const u8) OutcomeFmt {
    return .{ .o = o, .err = err };
}

// ── tape files: one decimal entry per line ──────────────────────────────────

fn writeTape(path: []const u8, tape: []const u64) !void {
    var pb: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= pb.len) return error.NameTooLong;
    @memcpy(pb[0..path.len], path);
    pb[path.len] = 0;
    const rc = linux.open(pb[0..path.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var line: [24]u8 = undefined;
    for (tape) |v| {
        const txt = std.mem.print(&line, "{d}\n", .{v}) catch unreachable;
        var off: usize = 0;
        while (off < txt.len) {
            const n = linux.write(fd, txt[off..].ptr, txt.len - off);
            if (linux.errno(n) != .SUCCESS) return error.WriteFailed;
            off += n;
        }
    }
}

/// Parse a tape file (one decimal `u64` per line; blank lines and `#`
/// comments ignored).
pub fn parseTape(gpa: std.mem.Allocator, text: []const u8) ![]u64 {
    var out: std.ArrayList(u64) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const l = std.mem.trim(u8, raw, " \t\r");
        if (l.len == 0 or l[0] == '#') continue;
        try out.append(gpa, try std.fmt.parseInt(u64, l, 10));
    }
    return out.toOwnedSlice(gpa);
}

/// Replay `tape` in this process, printing every draw: for a debugger, or
/// for reading what the smallest input was. Returns the harness's error.
pub fn replayHere(comptime harness: anytype, gpa: std.mem.Allocator, tape: []u64, trace: bool) !void {
    var prng = std.Random.DefaultPrng.init(0);
    var t: Tape = .{ .mode = .replay, .buf = tape, .len = tape.len, .trace = trace };
    var rng: Rng = .{ .r = prng.random(), .tape = &t };
    try harness(Rng, &rng, gpa);
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Fails when, after a ranged draw of at least 10, a drawn slice holds 0x42
/// at an even offset of 4 or more. The smallest failing tape is therefore
/// [10, length 5, 0, 0, 0, 0, 0x42].
fn needle(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const k = src.valueRangeAtMost(u16, 0, 1000);
    var buf: [200]u8 = undefined;
    const n = src.slice(&buf);
    const junk = try gpa.alloc(u8, 3);
    defer gpa.free(junk);
    if (k < 10) return;
    var i: usize = 4;
    while (i < n) : (i += 2) if (buf[i] == 0x42) return error.FoundNeedle;
}

fn panicky(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const v = src.valueRangeAtMost(u32, 0, 1 << 20);
    const w = src.value(u8);
    if (v >= 777 and w >= 3) @panic("planted");
}

fn findSeed(comptime harness: anytype) !u64 {
    for (0..100_000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        var seed_alloc: std.heap.SafeAllocator = .init(testing.allocator, .{ .stack_trace_frames = 0 });
        defer _ = seed_alloc.deinit();
        harness(Rng, &rng, seed_alloc.allocator()) catch return seed;
    }
    return error.NoFailingSeed;
}

test "shrink: an error input shrinks to the minimal one, which still fails" {
    if (!child.supported) return error.SkipZigTest;
    const seed = try findSeed(needle);
    const r = try shrink(needle, testing.allocator, .{ .name = "needle", .seed = seed, .limit_ms = 5000, .report = false });
    defer testing.allocator.free(r.tape);
    try testing.expectEqualSlices(u64, &.{ 10, 5, 0, 0, 0, 0, 0x42 }, r.tape);
    try testing.expect(r.tape.len < r.from);
    try testing.expectError(error.FoundNeedle, replayHere(needle, testing.allocator, r.tape, false));
}

test "shrink: a panic shrinks too (the child dies, the shrink does not)" {
    if (!child.supported) return error.SkipZigTest;
    // Find a failing seed without panicking here: the predicate, by hand
    // (seed 0 already fails).
    var seed: u64 = 0;
    while (true) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        const v = rng.valueRangeAtMost(u32, 0, 1 << 20);
        const w = rng.value(u8);
        if (v >= 777 and w >= 3) break;
    }
    const r = try shrink(panicky, testing.allocator, .{ .name = "panicky", .seed = seed, .limit_ms = 5000, .report = false });
    defer testing.allocator.free(r.tape);
    try testing.expect(r.outcome == .signaled);
    try testing.expectEqualSlices(u64, &.{ 777, 3 }, r.tape);
}

test "shrink: a passing seed is refused" {
    if (!child.supported) return error.SkipZigTest;
    var seed: u64 = 0;
    while (true) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        const v = rng.valueRangeAtMost(u32, 0, 1 << 20);
        const w = rng.value(u8);
        if (!(v >= 777 and w >= 3)) break;
    }
    try testing.expectError(error.SeedPasses, shrink(panicky, testing.allocator, .{ .name = "p", .seed = seed, .limit_ms = 5000, .report = false }));
}

test "Tape: a recorded run replays to the same draws, every method" {
    var log: [4096]u64 = undefined;
    var rec: Tape = .{ .mode = .record, .buf = &log };
    var p1 = std.Random.DefaultPrng.init(99);
    var a: Rng = .{ .r = p1.random(), .tape = &rec };
    var p2 = std.Random.DefaultPrng.init(99);
    var plain: Rng = .{ .r = p2.random() };
    const E = enum { x, y, z };
    var b1: [300]u8 = undefined;
    var b2: [300]u8 = undefined;
    var seen: [10]u64 = undefined;
    // Recording does not change what the PRNG answers.
    seen[0] = a.valueRangeAtMost(u16, 3, 900);
    try testing.expectEqual(seen[0], plain.valueRangeAtMost(u16, 3, 900));
    seen[1] = @bitCast(@as(i64, a.valueRangeAtMost(i8, -100, 100)));
    try testing.expectEqual(seen[1], @as(u64, @bitCast(@as(i64, plain.valueRangeAtMost(i8, -100, 100)))));
    seen[2] = @intFromBool(a.value(bool));
    try testing.expectEqual(seen[2], @intFromBool(plain.value(bool)));
    seen[3] = @backingInt(a.value(E));
    try testing.expectEqual(seen[3], @backingInt(plain.value(E)));
    seen[4] = a.value(u64);
    try testing.expectEqual(seen[4], plain.value(u64));
    const wide = a.value(u128);
    try testing.expectEqual(wide, plain.value(u128));
    seen[5] = a.index(17);
    try testing.expectEqual(seen[5], plain.index(17));
    const n = a.slice(&b1);
    try testing.expectEqual(n, plain.slice(&b2));
    try testing.expectEqualSlices(u8, b2[0..n], b1[0..n]);
    var c1: [20]u8 = undefined;
    var c2: [20]u8 = undefined;
    a.bytes(&c1);
    plain.bytes(&c2);
    try testing.expectEqualSlices(u8, &c2, &c1);
    const big = a.valueRangeAtMost(u128, 5, std.math.maxInt(u128));
    try testing.expectEqual(big, plain.valueRangeAtMost(u128, 5, std.math.maxInt(u128)));

    // And the replay gives the same values back.
    var rep: Tape = .{ .mode = .replay, .buf = log[0..rec.len], .len = rec.len };
    var p3 = std.Random.DefaultPrng.init(12345);
    var r: Rng = .{ .r = p3.random(), .tape = &rep };
    try testing.expectEqual(seen[0], r.valueRangeAtMost(u16, 3, 900));
    try testing.expectEqual(seen[1], @as(u64, @bitCast(@as(i64, r.valueRangeAtMost(i8, -100, 100)))));
    try testing.expectEqual(seen[2], @intFromBool(r.value(bool)));
    try testing.expectEqual(seen[3], @backingInt(r.value(E)));
    try testing.expectEqual(seen[4], r.value(u64));
    try testing.expectEqual(wide, r.value(u128));
    try testing.expectEqual(seen[5], r.index(17));
    var b3: [300]u8 = undefined;
    try testing.expectEqual(n, r.slice(&b3));
    try testing.expectEqualSlices(u8, b1[0..n], b3[0..n]);
    var c3: [20]u8 = undefined;
    r.bytes(&c3);
    try testing.expectEqualSlices(u8, &c1, &c3);
    try testing.expectEqual(big, r.valueRangeAtMost(u128, 5, std.math.maxInt(u128)));
    try testing.expectEqual(rec.len, rep.at);
}

test "Tape: any entries are a valid input (modulo the span), and past the end reads zeros" {
    var log = [_]u64{ 1000, 7, std.math.maxInt(u64), 9 };
    var t: Tape = .{ .mode = .replay, .buf = &log, .len = log.len };
    var p = std.Random.DefaultPrng.init(0);
    var r: Rng = .{ .r = p.random(), .tape = &t };
    try testing.expectEqual(@as(u8, 3 + 1000 % 8), r.valueRangeAtMost(u8, 3, 10));
    try testing.expectEqual(@as(usize, 7 % 5), r.index(5));
    try testing.expectEqual(@as(i8, -128 + @as(i16, @intCast(std.math.maxInt(u64) % 256))), r.valueRangeAtMost(i8, -128, 127));
    var buf: [4]u8 = undefined;
    // Length 9 clamps to the buffer; the bytes run past the tape: zeros.
    try testing.expectEqual(@as(u32, 4), r.slice(&buf));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &buf);
    try testing.expectEqual(@as(u16, 0), r.value(u16));
}

test "parseTape: decimals per line, comments and blanks ignored" {
    const t = try parseTape(testing.allocator, "# smallest\n10\n\n 5 \r\n66\n");
    defer testing.allocator.free(t);
    try testing.expectEqualSlices(u64, &.{ 10, 5, 66 }, t);
    try testing.expectError(error.InvalidCharacter, parseTape(testing.allocator, "1\nx\n"));
}
