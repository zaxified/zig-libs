// SPDX-License-Identifier: MIT

//! sink.zig — `Sink`, the thread-safe writer that turns `Entry` records
//! into access-log lines on one shared `std.Io.Writer` (a log file, stdout)
//! from any number of request threads or tasks at once.
//!
//! Moved here from `metrics.AccessLog` on 2026-10-06, so that one module owns
//! access logging: the formats are `root.write`'s (JSON Lines, logfmt,
//! Combined — all fields), the concurrency below is the group commit the
//! `metrics` audit (F4) measured and hardened. `metrics.RequestMetrics`
//! still offers the per-request hook; wiring it to a `Sink` is a few lines
//! (see the module README).

const std = @import("std");
const root = @import("root.zig");
const Entry = root.Entry;
const Format = root.Format;
const write = root.write;

/// Spinlock acquire (std SmpAllocator pattern) — see the module doc for why
/// a spinlock and what it guards.
///
/// History: a yield was tried once before and measured worse on an 8-core box
/// with 8 contending threads, where there is no idle core for `sched_yield`
/// to hand off to (audit F2/F4 disposition), so the lock stayed a pure spin
/// and F2 (2026-09-15) and F4 (2026-09-16) were fixed by shrinking the
/// critical sections instead — `writeText` snapshots under the lock and
/// formats outside it, `Sink.log` never holds the lock across writer
/// I/O. That measurement never had more threads than cores; the bounded spin
/// below is for that case, and the F4 bench is re-measured with it.
fn lockSpin(m: *std.atomic.Mutex) void {
    var spins: u32 = 0;
    while (!m.tryLock()) {
        if (spins < spin_before_yield) {
            spins += 1;
            std.atomic.spinLoopHint();
        } else {
            // ⚠ Bounded spin, then yield (2026-09-18). A pure spin is only
            // fair while every contender has a core: with more runnable
            // threads than cores, a waiter burns its whole time slice while
            // the holder is descheduled. Measured on the `Sink F4`
            // test (8 threads x 400 lines x 3 rounds, ReleaseSafe): 0.7 s on
            // 8 or 2 cores, 49.8 s on 1 core -- and past its 3-minute limit
            // on the 4-core arm64 CI runner, which runs many test binaries
            // at once. The yield only starts after `spin_before_yield`
            // failed tries, so an uncontended or briefly held lock never
            // reaches it.
            std.Thread.yield() catch {};
        }
    }
}

/// Failed `tryLock`s `lockSpin` spins through before it starts yielding.
const spin_before_yield = 64;

/// A shared access-log writer: `log(entry)` formats one line in
/// `options.format` and writes it to `writer`, safely from many threads or
/// `std.Io` tasks at once.
///
/// ```zig
/// var file_writer = log_file.writer(io, &buf);
/// var sink = accesslog.Sink.init(&file_writer.interface, .{ .io = io });
/// // per request, after the response is sent:
/// var addr_buf: [64]u8 = undefined;
/// sink.log(accesslog.entryFromRequest(req, res, &addr_buf, .{ .timestamp_ns = now_ns }));
/// ```
///
/// Thread-safety: by default (`synchronized = true`) concurrent calls share
/// `writer` through a group commit rather than a lock held across I/O (the
/// `metrics` audit, F4: a spinlock held across `writer.flush()` made every
/// other request thread spin for the whole syscall — 25.4 µs of CPU per line
/// at 8 threads against 1.47 µs at one, into a plain file). Now:
///
/// - each line is formatted under the spinlock straight into an inline
///   pending batch (no syscall, no stack buffer, no allocation);
/// - at most one caller at a time — the *flusher* — touches `writer`, and it
///   does so with the spinlock released: it swaps the batch out, writes and
///   flushes it, and repeats until the batch is empty, so concurrent callers
///   only append;
/// - a line is never split: it enters the batch whole or not at all, and a
///   line too long for the batch is written whole by its own caller after it
///   becomes the flusher. Lines from different calls interleave only at line
///   boundaries; lines from one thread keep their call order;
/// - when the batch is full, a caller waits (lock released, watching a
///   progress counter rather than the lock) for the flusher to swap it out.
///   The flusher hands the role to such a waiter after each batch, so under
///   a sustained rate the sink cannot keep up with, no single request is
///   left writing everyone else's lines indefinitely.
///
/// When no `log` call is in flight, every logged line has been handed to
/// `writer.writeAll` and flushed — the batch is empty — so there is no
/// `deinit` and nothing to drain before dropping a `Sink`. A call can return
/// while its line is still in the batch, but only when another call is the
/// flusher and is committed to writing it before it returns. Set
/// `synchronized = false` only when the caller already serializes writes to
/// `writer`; the batch is then unused and each call writes and flushes
/// directly.
///
/// Allocation-free: the pending batch is inline in the struct (2 × 4 KiB).
/// The writer is flushed after every batch, so records reach the sink
/// promptly. Writer errors are swallowed — an access log must never fail the
/// request that produced it; with batching, a failed write is swallowed by
/// whichever call was the flusher, and the lines it carried are lost exactly
/// as a single failed line would be (the error, if any, stays on the caller's
/// writer, e.g. `std.Io.File.Writer.err`). Escaping is the formats' own (see
/// `writeJsonLines` / `writeLogfmt` / `writeCombined`), so no field can forge
/// a line here either.
pub const Sink = struct {
    writer: *std.Io.Writer,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,

    // Group-commit state (see the doc comment above). Every field below is
    // written only with `lock` held, and read only with it held except
    // `progress`. `pending[pending_idx]` is the
    // batch callers append to; the other buffer is the one the flusher may be
    // writing with the lock released, which is why a swap (not a copy or a
    // reset in place) is what hands a batch over.
    pending: [2][pending_capacity]u8 = undefined,
    pending_idx: u1 = 0,
    pending_len: usize = 0,
    /// Some call owns `writer` (is the flusher). Cleared only with the lock
    /// held and either `pending_len == 0` or `waiters > 0`.
    flushing: bool = false,
    /// Calls whose line did not fit while another call was the flusher,
    /// waiting with the lock released until they can append or take over.
    waiters: u32 = 0,
    /// Bumped, with the lock held, whenever a waiter's answer can change:
    /// the batch was swapped out (there is room) or the flusher role was
    /// given up. Waiters watch it WITHOUT the lock — the one field read
    /// outside it — so waiting never competes with the flusher for `lock`.
    progress: std.atomic.Value(u32) = .init(0),

    const pending_capacity = 4096;

    pub const Options = struct {
        /// The line format, as for `root.write`.
        format: Format = .json_lines,
        /// Guard the writer with the sink's spinlock so concurrent request
        /// tasks never interleave lines. Disable only if the caller serializes
        /// writes to `writer` itself.
        synchronized: bool = true,
        /// The `std.Io` that `writer` blocks in, if any. A call whose line
        /// does not fit while another call is writing a batch waits for it;
        /// with an `Io` it parks on a futex instead of spinning, which is
        /// required when the `Io` runs several tasks on one thread (a
        /// spinning waiter would starve a flusher suspended in `writer`).
        io: ?std.Io = null,
    };

    pub fn init(writer: *std.Io.Writer, options: Options) Sink {
        return .{ .writer = writer, .options = options };
    }

    /// Format one entry as a line and write it. Best-effort: writer errors are
    /// swallowed. When `synchronized`, the spinlock is held only while the
    /// line is formatted into the pending batch, never across `writer` I/O —
    /// see the type's doc comment for the group commit.
    pub fn log(self: *Sink, entry: Entry) void {
        if (!self.options.synchronized) {
            write(entry, self.options.format, self.writer) catch {};
            self.writer.flush() catch {};
            return;
        }
        lockSpin(&self.lock);
        var waiting = false;
        while (true) {
            if (waiting) {
                self.waiters -= 1;
                waiting = false;
            }
            if (self.appendPending(entry)) {
                // Someone else owns the writer and must write the batch
                // (including this line) before it gives the role up.
                if (self.flushing) return self.lock.unlock();
                self.flushing = true;
                self.writeBatch(); // this line is in it
                return self.finishFlushing();
            }
            if (!self.flushing) {
                // Too long for what is left of the batch (or for any batch).
                // Take the writer: first everything queued before this call,
                // then this line, whole, straight to the writer.
                self.flushing = true;
                self.writeBatch();
                self.lock.unlock();
                write(entry, self.options.format, self.writer) catch {};
                self.writer.flush() catch {};
                lockSpin(&self.lock);
                return self.finishFlushing();
            }
            // Batch full and a flusher is active: wait for it to swap the
            // batch out or hand the role over. Never with the lock held, and
            // without touching the lock until `progress` moves: waiters that
            // re-took the lock on every spin kept the flusher from getting it
            // back after each write (F4 test past its 3-minute limit on the
            // 4-core arm64 CI runner; 15 s on 4 x86 cores vs 1.1 s on one).
            self.waiters += 1;
            waiting = true;
            const seen = self.progress.load(.monotonic);
            self.lock.unlock();
            self.waitForProgress(seen);
            lockSpin(&self.lock);
        }
    }

    /// Format `entry` into the current batch. Lock held. On overflow the
    /// partial bytes past `pending_len` are simply not committed.
    fn appendPending(self: *Sink, entry: Entry) bool {
        var w: std.Io.Writer = .fixed(self.pending[self.pending_idx][self.pending_len..]);
        write(entry, self.options.format, &w) catch return false;
        self.pending_len += w.end;
        return true;
    }

    /// Flusher only, lock held on entry and on return: swap the batch out,
    /// then write and flush it with the lock released. Appenders move on to
    /// the other buffer, which nobody is writing.
    fn writeBatch(self: *Sink) void {
        std.debug.assert(self.flushing);
        if (self.pending_len == 0) return;
        const idx = self.pending_idx;
        const len = self.pending_len;
        self.pending_idx ^= 1;
        self.pending_len = 0;
        self.bumpProgress();
        self.lock.unlock();
        self.writer.writeAll(self.pending[idx][0..len]) catch {};
        self.writer.flush() catch {};
        lockSpin(&self.lock);
    }

    /// Flusher only, lock held on entry, released on return. Keeps writing
    /// batches until none is left — or until a waiter exists, in which case
    /// the role is handed over with lines still queued: a waiter re-checks
    /// with the lock held and either appends while another call is flushing
    /// or becomes the flusher itself, so a non-empty batch is never orphaned.
    fn finishFlushing(self: *Sink) void {
        while (self.pending_len != 0 and self.waiters == 0) self.writeBatch();
        self.flushing = false;
        self.bumpProgress();
        self.lock.unlock();
    }

    /// Lock held: tell waiters their answer may have changed.
    fn bumpProgress(self: *Sink) void {
        _ = self.progress.fetchAdd(1, .monotonic);
        if (self.options.io) |io| io.futexWake(u32, &self.progress.raw, std.math.maxInt(u32));
    }

    /// Wait, lock released, until `progress` differs from `seen`. With an
    /// `Io`, parked on its futex. Without, a bounded spin, then yields, as in
    /// `lockSpin`: with more waiters than cores the flusher needs the core.
    /// No ordering is needed — the waiter re-reads everything under `lock`
    /// afterwards; this only decides when to try.
    fn waitForProgress(self: *Sink, seen: u32) void {
        const progress = &self.progress;
        if (self.options.io) |io| {
            while (progress.load(.monotonic) == seen) io.futexWaitUncancelable(u32, &progress.raw, seen);
            return;
        }
        var spins: u32 = 0;
        while (progress.load(.monotonic) == seen) {
            if (spins < spin_before_yield) {
                spins += 1;
                std.atomic.spinLoopHint();
            } else {
                std.Thread.yield() catch {};
            }
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Sink: synchronized writes never interleave across threads" {
    // Room for every line: a JSON Lines record of these entries is ~200
    // octets, and a full fixed writer would fail the write (swallowed) and
    // show up here as a torn line instead.
    var buf: [256 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = Sink.init(&w, .{ .format = .json_lines, .synchronized = true });

    const Worker = struct {
        fn run(a: *Sink, id: usize) void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                a.log(.{
                    .timestamp_ns = 0,
                    .method = "GET",
                    .target = "/t",
                    .status = @intCast(200 + id),
                    .latency_ns = 1,
                    .response_bytes = 0,
                });
            }
        }
    };

    const n_threads = 4;
    var threads: [n_threads]std.Thread = undefined;
    for (&threads, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id });
    for (&threads) |t| t.join();

    // Every '\n'-delimited line must be a whole, well-formed record — proof
    // that no two threads' lines interleaved under the lock.
    var it = std.mem.tokenizeScalar(u8, w.buffered(), '\n');
    var count: usize = 0;
    while (it.next()) |line| {
        count += 1;
        try testing.expect(line.len > 2 and line[0] == '{' and line[line.len - 1] == '}');
        const ok = std.mem.indexOf(u8, line, "\"status\":200,") != null or
            std.mem.indexOf(u8, line, "\"status\":201,") != null or
            std.mem.indexOf(u8, line, "\"status\":202,") != null or
            std.mem.indexOf(u8, line, "\"status\":203,") != null;
        try testing.expect(ok);
    }
    try testing.expectEqual(@as(usize, n_threads * 100), count);
}

fn sleepMs(ms: u64) void {
    const ts: std.os.linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(&ts, null);
}

// `metrics` audit F15/M32, moved with the code: a stress test over many
// iterations never opens the window where a dropped lock shows, so force it —
// hold the lock from the test and check that `log` cannot get past it.
test "F15/M32: Sink.log actually takes its lock when synchronized" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = Sink.init(&w, .{ .format = .json_lines, .synchronized = true });

    lockSpin(&access.lock);

    var done = std.atomic.Value(bool).init(false);
    const Ctx = struct {
        access: *Sink,
        done: *std.atomic.Value(bool),
        fn run(ctx: *@This()) void {
            ctx.access.log(.{ .timestamp_ns = 0, .method = "GET", .target = "/m32", .status = 200, .latency_ns = 1, .response_bytes = 0 });
            ctx.done.store(true, .seq_cst);
        }
    };
    var ctx: Ctx = .{ .access = &access, .done = &done };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    sleepMs(50);
    try testing.expect(!done.load(.seq_cst));

    access.lock.unlock();
    t.join();
    try testing.expect(done.load(.seq_cst));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "/m32") != null);
}

// ── F4 bench (opt-in): Sink under concurrency into a real file ────────
//
//   ACCESSLOG_BENCH_F4=1 LINES=80 scripts/modtest accesslog -Doptimize=ReleaseFast -Dtest-filter=F4
//
// The sink is a buffered `std.Io.File.Writer` on a file under `.zig-cache/tmp`
// (disk, not tmpfs), so every `flush()` is a real `pwritev`. Arms are
// interleaved inside every rep; each pass re-reads the file and fails unless it
// holds exactly threads × lines newline-terminated records.

fn f4ClockNs(clock: std.os.linux.clockid_t) u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(clock, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Arms: `spin_over_flush` is the pre-F4 `metrics.AccessLog.log`, verbatim
/// (spinlock held across formatting AND `writer.flush()`), kept here only as
/// the bench's "before" arm; `group_commit` is the shipped `Sink.log`.
const F4Arm = enum { spin_over_flush, group_commit };

fn f4SpinOverFlush(self: *Sink, entry: Entry) void {
    lockSpin(&self.lock);
    defer self.lock.unlock();
    write(entry, self.options.format, self.writer) catch {};
    self.writer.flush() catch {};
}

/// The audit's BENCH E sink shape: every drain sleeps (so the time is a
/// blocked syscall, not CPU) and counts the newlines it swallowed.
const F4SlowSink = struct {
    interface: std.Io.Writer,
    delay_ns: u64,
    newlines: usize = 0,

    fn init(buf: []u8, delay_ns: u64) F4SlowSink {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buf }, .delay_ns = delay_ns };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *F4SlowSink = @alignCast(@fieldParentPtr("interface", w));
        self.newlines += std.mem.count(u8, w.buffered(), "\n");
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.newlines += std.mem.count(u8, d, "\n");
            n += d.len;
        }
        const last = data[data.len - 1];
        self.newlines += std.mem.count(u8, last, "\n") * splat;
        n += last.len * splat;
        const ts: std.os.linux.timespec = .{ .sec = 0, .nsec = @intCast(self.delay_ns) };
        _ = std.os.linux.nanosleep(&ts, null);
        return n;
    }
};

const F4Sink = enum { file, slow_0_2ms };

const F4Result = struct { cpu_ns: u64, wall_ns: u64 };

fn f4Run(access: *Sink, arm: F4Arm, threads: usize, lines: usize) !F4Result {
    const Worker = struct {
        fn run(a: *Sink, which: F4Arm, id: usize, n: usize) void {
            for (0..n) |i| {
                const e: Entry = .{
                    .timestamp_ns = 0,
                    .method = "GET",
                    .target = "/api/v1/tasks/1234567?expand=owner",
                    .status = 200,
                    .latency_ns = id * 1_000_000 + i,
                    .response_bytes = 512,
                };
                switch (which) {
                    .spin_over_flush => f4SpinOverFlush(a, e),
                    .group_commit => a.log(e),
                }
            }
        }
    };
    var pool: [8]std.Thread = undefined;
    const c0 = f4ClockNs(.PROCESS_CPUTIME_ID);
    const w0 = f4ClockNs(.MONOTONIC);
    for (pool[0..threads], 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ access, arm, id, lines });
    for (pool[0..threads]) |t| t.join();
    const w1 = f4ClockNs(.MONOTONIC);
    const c1 = f4ClockNs(.PROCESS_CPUTIME_ID);
    return .{ .cpu_ns = c1 - c0, .wall_ns = w1 - w0 };
}

fn f4Pass(arm: F4Arm, sink: F4Sink, threads: usize, lines: usize) !F4Result {
    var wbuf: [4096]u8 = undefined;
    switch (sink) {
        .file => {
            const io = testing.io;
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const file = try tmp.dir.createFile(io, "f4.log", .{});
            var fw = file.writer(io, &wbuf);
            var access = Sink.init(&fw.interface, .{});
            const res = try f4Run(&access, arm, threads, lines);
            file.close(io);
            const data = try tmp.dir.readFileAlloc(io, "f4.log", testing.allocator, .unlimited);
            defer testing.allocator.free(data);
            try testing.expectEqual(threads * lines, std.mem.count(u8, data, "\n"));
            return res;
        },
        .slow_0_2ms => {
            var s = F4SlowSink.init(&wbuf, 200_000);
            var access = Sink.init(&s.interface, .{});
            const res = try f4Run(&access, arm, threads, lines);
            try testing.expectEqual(threads * lines, s.newlines + std.mem.count(u8, s.interface.buffered(), "\n"));
            return res;
        },
    }
}

test "bench (opt-in via ACCESSLOG_BENCH_F4): F4 Sink.log cost under concurrency" {
    if (@import("builtin").mode == .Debug or std.testing.environ.getPosix("ACCESSLOG_BENCH_F4") == null) return error.SkipZigTest;
    const reps = 7;
    const tcounts = [_]usize{ 1, 2, 4, 8 };
    const arms = comptime std.enums.values(F4Arm);
    const sinks = comptime std.enums.values(F4Sink);
    var cpu: [sinks.len][tcounts.len][arms.len][reps]f64 = undefined;
    var wall: [sinks.len][tcounts.len][arms.len][reps]f64 = undefined;
    // Every (sink, threads, arm) cell once per rep, arms adjacent, so drift
    // over the run lands on both arms of a pair alike.
    for (0..reps) |r| {
        for (sinks, 0..) |sink, si| {
            const lines: usize = if (sink == .file) 5000 else 100;
            for (tcounts, 0..) |tc, ti| {
                for (arms, 0..) |arm, ai| {
                    const res = try f4Pass(arm, sink, tc, lines);
                    const total: f64 = @floatFromInt(tc * lines);
                    cpu[si][ti][ai][r] = @as(f64, @floatFromInt(res.cpu_ns)) / total;
                    wall[si][ti][ai][r] = @as(f64, @floatFromInt(res.wall_ns)) / total;
                }
            }
        }
    }
    for (sinks, 0..) |sink, si| {
        for (tcounts, 0..) |tc, ti| {
            // Per-rep before/after ratio (one instant), then its spread.
            var ratio: [reps]f64 = undefined;
            for (0..reps) |r| ratio[r] = cpu[si][ti][0][r] / cpu[si][ti][1][r];
            std.mem.sort(f64, &ratio, {}, std.sort.asc(f64));
            for (arms, 0..) |arm, ai| {
                var c = cpu[si][ti][ai];
                var w = wall[si][ti][ai];
                std.mem.sort(f64, &c, {}, std.sort.asc(f64));
                std.mem.sort(f64, &w, {}, std.sort.asc(f64));
                std.debug.print("F4 {t:<10} T={d} {t:<15} CPU ns/line {d:>8.0} {d:>8.0} {d:>8.0}  wall ns/line {d:>8.0} {d:>8.0} {d:>8.0}\n", .{
                    sink, tc, arm, c[0], c[reps / 2], c[reps - 1], w[0], w[reps / 2], w[reps - 1],
                });
            }
            std.debug.print("F4 {t:<10} T={d} CPU before/after per rep: min={d:.2} med={d:.2} max={d:.2}\n", .{
                sink, tc, ratio[0], ratio[reps / 2], ratio[reps - 1],
            });
        }
    }
}

// ── F4 regression tests: the group commit keeps lines whole, once, in order ──

fn f4PollUntil(flag: *const std.atomic.Value(bool), timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (!flag.load(.seq_cst)) : (waited += 1) {
        if (waited >= timeout_ms) return false;
        sleepMs(1);
    }
    return true;
}

fn f4AssertIdle(a: *Sink) !void {
    lockSpin(&a.lock);
    defer a.lock.unlock();
    try testing.expectEqual(@as(usize, 0), a.pending_len);
    try testing.expect(!a.flushing);
    try testing.expectEqual(@as(u32, 0), a.waiters);
}

/// Deterministic per-(thread, seq) path: "/t<id>/s<seq>/" + padding. Every
/// 37th line is longer than a whole batch (the owner path); the rest vary in
/// length so batch boundaries fall at every offset.
fn f4Path(buf: []u8, id: usize, seq: usize) []const u8 {
    const head = std.fmt.bufPrint(buf, "/t{d}/s{d}/", .{ id, seq }) catch unreachable;
    const pad: usize = if (seq % 37 == 5) Sink.pending_capacity + 300 else (id * 31 + seq * 7) % 180;
    @memset(buf[head.len..][0..pad], 'a' + @as(u8, @intCast((id + seq) % 26)));
    return buf[0 .. head.len + pad];
}

test "Sink F4: threads x lines into a real file -- every line whole, exactly once, in per-thread order" {
    const io = testing.io;
    const threads = 8;
    const lines = 400;
    const rounds: usize = if (std.testing.environ.getPosix("ACCESSLOG_F4_ROUNDS")) |s| std.fmt.parseInt(usize, s, 10) catch 3 else 3;

    const Worker = struct {
        fn run(a: *Sink, id: usize) void {
            var pbuf: [Sink.pending_capacity + 512]u8 = undefined;
            for (0..lines) |seq| a.log(.{
                .timestamp_ns = 0,
                .method = "GET",
                .target = f4Path(&pbuf, id, seq),
                .status = 200,
                .latency_ns = id * 1_000_000 + seq,
                .response_bytes = seq,
            });
        }
    };
    const Line = struct { target: []const u8, latency_ns: u64, response_bytes: u64 };

    // Without an `Io` the waiters spin on OS threads; with one (spinlock
    // audit after the simio kv pilot) they park on its futex, and the
    // callers are tasks of that `Io`.
    for (0..rounds * 2) |round| {
        const with_io = round % 2 == 1;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const file = try tmp.dir.createFile(io, "f4.log", .{});
        // A small writer buffer, so `writeAll`/`flush` drain constantly: any
        // two callers inside the writer at once show up as torn bytes.
        var wbuf: [256]u8 = undefined;
        var fw = file.writer(io, &wbuf);
        var access = Sink.init(&fw.interface, .{ .io = if (with_io) io else null });

        if (with_io) {
            var tasks: [threads]std.Io.Future(void) = undefined;
            for (&tasks, 0..) |*t, id| t.* = try io.concurrent(Worker.run, .{ &access, id });
            for (&tasks) |*t| t.await(io);
        } else {
            var pool: [threads]std.Thread = undefined;
            for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id });
            for (pool) |t| t.join();
        }
        try f4AssertIdle(&access);
        file.close(io);

        const data = try tmp.dir.readFileAlloc(io, "f4.log", testing.allocator, .unlimited);
        defer testing.allocator.free(data);
        try testing.expect(data.len > 0 and data[data.len - 1] == '\n');

        var next_seq: [threads]usize = @splat(0);
        var count: usize = 0;
        var pbuf: [Sink.pending_capacity + 512]u8 = undefined;
        var it = std.mem.splitScalar(u8, data[0 .. data.len - 1], '\n');
        while (it.next()) |raw| {
            count += 1;
            const parsed = try std.json.parseFromSlice(Line, testing.allocator, raw, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const id = parsed.value.latency_ns / 1_000_000;
            const seq = parsed.value.latency_ns % 1_000_000;
            try testing.expect(id < threads);
            // Exactly once and in call order per thread: the next line of
            // thread `id` must be exactly the next sequence number.
            try testing.expectEqual(next_seq[id], seq);
            next_seq[id] += 1;
            try testing.expectEqual(seq, parsed.value.response_bytes);
            try testing.expectEqualStrings(f4Path(&pbuf, id, seq), parsed.value.target);
        }
        try testing.expectEqual(@as(usize, threads * lines), count);
    }
}

test "Sink F4: a writer that always fails neither hangs callers nor leaves the batch owned" {
    const Failing = struct {
        interface: std.Io.Writer,
        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            _ = w;
            _ = data;
            _ = splat;
            return error.WriteFailed;
        }
    };
    var wbuf: [64]u8 = undefined;
    var sink: Failing = .{ .interface = .{ .vtable = &.{ .drain = Failing.drain }, .buffer = &wbuf } };
    var access = Sink.init(&sink.interface, .{});

    const threads = 4;
    var done: [threads]std.atomic.Value(bool) = @splat(std.atomic.Value(bool).init(false));
    const Worker = struct {
        fn run(a: *Sink, id: usize, flag: *std.atomic.Value(bool)) void {
            var pbuf: [Sink.pending_capacity + 512]u8 = undefined;
            for (0..300) |seq| a.log(.{ .timestamp_ns = 0, .method = "POST", .target = f4Path(&pbuf, id, seq), .status = 500, .latency_ns = 1, .response_bytes = null });
            flag.store(true, .seq_cst);
        }
    };
    var pool: [threads]std.Thread = undefined;
    for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id, &done[id] });
    var all = true;
    for (&done) |*d| all = all and f4PollUntil(d, 10_000);
    try testing.expect(all); // a stuck `flushing` would spin every caller forever
    for (pool) |t| t.join();
    try f4AssertIdle(&access);
}

/// A sink with no buffer (every write is one drain) whose drains each need a
/// permit from the test, so a test can park the flusher inside the write.
const F4Gate = struct {
    interface: std.Io.Writer,
    drains: std.atomic.Value(u32) = .init(0),
    permits: std.atomic.Value(u32) = .init(0),
    newlines: std.atomic.Value(usize) = .init(0),

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *F4Gate = @alignCast(@fieldParentPtr("interface", w));
        _ = self.drains.fetchAdd(1, .seq_cst);
        while (true) {
            const p = self.permits.load(.seq_cst);
            if (p > 0 and self.permits.cmpxchgWeak(p, p - 1, .seq_cst, .seq_cst) == null) break;
            sleepMs(1);
        }
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            _ = self.newlines.fetchAdd(std.mem.count(u8, d, "\n"), .seq_cst);
            n += d.len;
        }
        _ = self.newlines.fetchAdd(std.mem.count(u8, data[data.len - 1], "\n") * splat, .seq_cst);
        return n + data[data.len - 1].len * splat;
    }
};

test "Sink F4: a line appended while the flusher writes is written before the flusher returns" {
    // The promptness half of the contract: a call may return with its line
    // still queued only because an active flusher is committed to writing it.
    // Park the flusher A in its first drain, append B's line (B returns at
    // once), let A go: when A returns, B's line must be on the sink and the
    // batch empty. Without the flusher's re-check B's line would sit in the
    // batch until some later call happened to come along.
    var gate: F4Gate = .{ .interface = .{ .vtable = &.{ .drain = F4Gate.drain }, .buffer = &.{} } };
    var access = Sink.init(&gate.interface, .{});
    const entry: Entry = .{ .timestamp_ns = 0, .method = "GET", .target = "/p", .status = 200, .latency_ns = 1, .response_bytes = 0 };

    const Logger = struct {
        fn run(a: *Sink, e: Entry, flag: *std.atomic.Value(bool)) void {
            a.log(e);
            flag.store(true, .seq_cst);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    var b_done = std.atomic.Value(bool).init(false);
    const ta = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &a_done });
    while (gate.drains.load(.seq_cst) < 1) sleepMs(1);
    const tb = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &b_done });
    const b_returned = f4PollUntil(&b_done, 2_000); // B only appends
    gate.permits.store(1_000_000, .seq_cst);
    ta.join();
    tb.join();
    try testing.expect(b_returned);
    try testing.expectEqual(@as(usize, 2), gate.newlines.load(.seq_cst));
    try f4AssertIdle(&access);
}

test "Sink F4: the flusher hands off to a waiter instead of writing everyone's lines forever" {
    // A sink with no buffer (so every batch is one drain) whose drains each
    // need a permit from the test. Thread A becomes the flusher and parks in
    // its first drain; the test fills the batch; thread W arrives with a line
    // that does not fit and waits. One permit later A must RETURN — with W's
    // line and the fill still queued — rather than go on to write them.
    const Gate = F4Gate;
    var gate: Gate = .{ .interface = .{ .vtable = &.{ .drain = Gate.drain }, .buffer = &.{} } };
    var access = Sink.init(&gate.interface, .{});
    const entry: Entry = .{ .timestamp_ns = 0, .method = "GET", .target = "/fill", .status = 200, .latency_ns = 7, .response_bytes = 1 };

    const Logger = struct {
        fn run(a: *Sink, e: Entry, flag: *std.atomic.Value(bool)) void {
            a.log(e);
            flag.store(true, .seq_cst);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    var w_done = std.atomic.Value(bool).init(false);
    const ta = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &a_done });
    while (gate.drains.load(.seq_cst) < 1) sleepMs(1);

    var one: [256]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&one);
    try write(entry, .json_lines, &ow);
    const line_len = ow.end;
    // Bounded lock acquisition: an implementation that holds the lock across
    // writer I/O would park A inside the gated drain WITH the lock, and a
    // plain `lockSpin` here would hang the suite instead of failing it.
    const bounded = struct {
        fn lock(m: *std.atomic.Mutex) bool {
            for (0..2_000) |_| {
                if (m.tryLock()) return true;
                sleepMs(1);
            }
            return false;
        }
    };
    var fills: usize = 0;
    const filled = while (true) {
        if (!bounded.lock(&access.lock)) break false;
        const room = Sink.pending_capacity - access.pending_len;
        access.lock.unlock();
        if (room < line_len) break true;
        access.log(entry); // A is the flusher: this only appends
        fills += 1;
    };
    if (!filled) {
        gate.permits.store(1_000_000, .seq_cst);
        ta.join();
        return error.TestUnexpectedResult; // lock held across the sink write
    }

    const tw = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &w_done });
    const saw_waiter = for (0..2_000) |_| {
        if (!bounded.lock(&access.lock)) break false;
        const waiting = access.waiters;
        access.lock.unlock();
        if (waiting == 1) break true;
        sleepMs(1);
    } else false;
    if (!saw_waiter) {
        gate.permits.store(1_000_000, .seq_cst);
        ta.join();
        tw.join();
        return error.TestUnexpectedResult; // W never became a waiter
    }

    gate.permits.store(1, .seq_cst);
    const handed_off = f4PollUntil(&a_done, 2_000);
    const drains_when_a_returned = gate.drains.load(.seq_cst);

    gate.permits.store(1_000_000, .seq_cst); // release everything before asserting
    ta.join();
    tw.join();
    try testing.expect(handed_off);
    try testing.expect(drains_when_a_returned <= 2); // A's one batch (+ W's, parked)
    try testing.expect(w_done.load(.seq_cst));
    try f4AssertIdle(&access);
    try testing.expectEqual(fills + 2, gate.newlines.load(.seq_cst));
}
