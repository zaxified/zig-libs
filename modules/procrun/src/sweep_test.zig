// SPDX-License-Identifier: MIT

//! No-panic sweep (wave GO) regression tests. Every test name ends with the
//! finding id.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const pr = @import("root.zig");
const testing = std.testing;

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleepMs(ms: u64) void {
    var req: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.nanosleep(&req, null);
}

const Seen = struct {
    n: std.atomic.Value(usize) = .init(0),

    fn onOut(cx: ?*anyopaque, chunk: []const u8) void {
        _ = chunk;
        const s: *Seen = @ptrCast(@alignCast(cx.?));
        _ = s.n.fetchAdd(1, .monotonic);
    }
};

test "stream_permits = 0 still delivers output (sweep PR-1)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Seen = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo hi" },
        .stream_permits = 0,
    }, .{ .ctx = &seen, .on_stdout = Seen.onOut });
    // Unfixed: the reader parks on the semaphore before the first chunk and
    // nothing releases it but a cancel/kill.
    var waited: usize = 0;
    while (seen.n.load(.monotonic) == 0 and waited < 100) : (waited += 1) sleepMs(20);
    const before_kill = seen.n.load(.monotonic);
    h.kill(); // releases the reader in any case, so the test cannot hang
    _ = h.wait();
    try testing.expect(before_kill >= 1);
}

test "a huge stream_permits: kill and ack are total (sweep PR-1)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Seen = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "5" },
        .stream_permits = std.math.maxInt(usize),
    }, .{ .ctx = &seen, .on_stdout = Seen.onOut });
    // Unfixed: `wake` posted `permits + 1` times, the first `+= 1` overflowing.
    h.kill();
    h.ack(); // and an ack on top of the saturated count
    h.cancel();
    _ = h.wait();
}

test "Handle.signal / signalGroup with a number the kernel rejects (sweep PR-3)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Seen = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "5" },
        .new_process_group = true,
    }, .{ .ctx = &seen, .on_stdout = Seen.onOut });
    // Unfixed: EINVAL reaches `std.posix.kill`'s `unreachable`.
    h.signal(200);
    h.signalGroup(200);
    h.killGroup();
    _ = h.wait();
}

test "rlimit byte limits near maxInt(u64) do not overflow (sweep PR-2)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Unfixed: `numerator + denominator - 1` overflows in `ceilDiv` (a panic
    // here; in ReleaseFast a wrapped, tiny limit). What the shell makes of
    // such a number is its business -- only "no crash" is asserted.
    if (pr.run(testing.allocator, io, .{
        .argv = &.{"true"},
        .rlimit = .{
            .file_size_bytes = std.math.maxInt(u64),
            .address_space_bytes = std.math.maxInt(u64),
        },
    }, "")) |o| {
        var out = o;
        out.deinit(testing.allocator);
    } else |_| {}
}

test "runTimeout is bounded when a descendant holds the stdin pipe unread (sweep PR-4)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 1 << 20); // far past the pipe's capacity
    defer testing.allocator.free(body);
    @memset(body, 'x');

    // The direct child exits at once; its background `sleep` keeps a dup of
    // the stdin pipe's read end (and reads nothing), no group, no kill reaches
    // it. Unfixed, the stdin writer sat in a blocking write until the sleep
    // ended: runTimeout returned after ~2 s instead of its 100 ms deadline.
    const t0 = nowNs();
    var out = try pr.runTimeout(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "exec 3<&0; sleep 2 0<&3 >/dev/null 2>&1 & exit 0" },
        .stdin = .pipe,
    }, body, 100 * std.time.ns_per_ms);
    defer out.deinit(testing.allocator);
    const elapsed_ms = (nowNs() - t0) / std.time.ns_per_ms;
    // Let the stray sleep end before the test does (no process outlives it).
    sleepMs(2100 -| elapsed_ms);
    try testing.expect(elapsed_ms < 1200);
    // The deadline is still reported through what Output already carries.
    try testing.expect(out.timed_out);
}

test "runTimeout still passes a large stdin body through (sweep PR-4)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 2 << 20);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = @truncate(i *% 31);

    var out = try pr.runTimeout(testing.allocator, io, .{ .argv = &.{"cat"}, .stdin = .pipe }, body, 30 * std.time.ns_per_s);
    defer out.deinit(testing.allocator);
    try testing.expect(!out.timed_out);
    try testing.expectEqualSlices(u8, body, out.stdout);
}

/// Counts lines (optionally slowly) and records how many had been delivered
/// when `on_exit` first fired.
const Tail = struct {
    n: std.atomic.Value(usize) = .init(0),
    at_exit: std.atomic.Value(usize) = .init(std.math.maxInt(usize)),
    delay_ms: u64 = 0,

    fn onLine(cx: ?*anyopaque, line: []const u8, truncated: bool) void {
        _ = line;
        _ = truncated;
        const s: *Tail = @ptrCast(@alignCast(cx.?));
        if (s.delay_ms != 0) sleepMs(s.delay_ms);
        _ = s.n.fetchAdd(1, .monotonic);
    }

    fn onExit(cx: ?*anyopaque, term: pr.Term) void {
        _ = term;
        const s: *Tail = @ptrCast(@alignCast(cx.?));
        _ = s.at_exit.cmpxchgStrong(std.math.maxInt(usize), s.n.load(.monotonic), .acq_rel, .monotonic);
    }
};

test "closeStdin then wait returns for a child that reads stdin to EOF (sweep D7, documented contract)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Seen = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{"cat"},
        .stdin = .pipe,
    }, .{ .ctx = &seen, .on_stdout = Seen.onOut });
    try h.writeStdin("hello\n");
    try h.closeStdin();
    const t = h.wait();
    try testing.expect(t == .exited and t.exited == 0);
    try testing.expect(seen.n.load(.monotonic) >= 1);
}

const AckJob = struct {
    h: pr.Handle,
    seen: *Tail,
    done: std.atomic.Value(bool) = .init(false),

    fn run(j: *AckJob) void {
        var acked: usize = 0;
        while (!j.done.load(.acquire)) {
            if (j.seen.n.load(.monotonic) > acked) {
                sleepMs(20);
                j.h.ack();
                acked += 1;
            } else sleepMs(1);
        }
    }
};

test "a slow consumer loses no tail after the child exited (sweep D8)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const N = 30;
    var seen: Tail = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "i=0; while [ $i -lt 30 ]; do echo line$i; i=$((i+1)); done" },
        .stream_permits = 1,
    }, .{ .ctx = &seen, .on_stdout_line = Tail.onLine, .on_exit = Tail.onExit });
    // One permit, acked 20 ms apart from another thread: delivery takes
    // ~600 ms, far past the 250 ms idle grace, while the child is long gone.
    var job: AckJob = .{ .h = h, .seen = &seen };
    const th = try std.Thread.spawn(.{}, AckJob.run, .{&job});
    _ = h.wait();
    job.done.store(true, .release);
    th.join();
    try testing.expectEqual(@as(usize, N), seen.n.load(.monotonic));
    try testing.expectEqual(@as(usize, N), seen.at_exit.load(.monotonic));
}

test "on_exit fires after the last callback (sweep D8)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Tail = .{ .delay_ms = 60 };
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo a; echo b; echo c; echo d; echo e" },
    }, .{ .ctx = &seen, .on_stdout_line = Tail.onLine, .on_exit = Tail.onExit });
    _ = h.wait();
    try testing.expectEqual(@as(usize, 5), seen.n.load(.monotonic));
    try testing.expectEqual(@as(usize, 5), seen.at_exit.load(.monotonic));
}

test "wait returns after a grace when a descendant keeps the pipes open (sweep D8)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Seen = .{};
    const t0 = nowNs();
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo before; sleep 3 & exit 0" },
    }, .{ .ctx = &seen, .on_stdout = Seen.onOut });
    const t = h.wait();
    const elapsed_ms = (nowNs() - t0) / std.time.ns_per_ms;
    // Let the stray sleep end before the test does (no process outlives it).
    sleepMs(3200 -| elapsed_ms);
    // Unfixed: the readers sit on the pipes until the sleep ends (~3 s).
    try testing.expect(elapsed_ms < 2000);
    try testing.expect(t == .exited and t.exited == 0);
    try testing.expect(seen.n.load(.monotonic) >= 1); // output before the exit is delivered
}

test "runTimeout returns the Output when its kill breaks the stdin pipe (sweep D9)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 4 << 20);
    defer testing.allocator.free(body);
    @memset(body, 'x');

    // The child never reads stdin and outlives the deadline; the kill closes
    // the read end under the still-writing stdin thread (EPIPE). Unfixed:
    // error.BrokenPipe replaced the Output.
    var out = try pr.runTimeout(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo partial; exec sleep 5" },
        .stdin = .pipe,
    }, body, 200 * std.time.ns_per_ms);
    defer out.deinit(testing.allocator);
    try testing.expect(out.timed_out);
    try testing.expectEqualStrings("partial\n", out.stdout);
}

/// Collects stdout chunks (single reader thread; read it after `wait`).
const Collect = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    delay_first_ms: u64 = 0,

    fn onOut(cx: ?*anyopaque, chunk: []const u8) void {
        const s: *Collect = @ptrCast(@alignCast(cx.?));
        if (s.len == 0 and s.delay_first_ms != 0) sleepMs(s.delay_first_ms);
        const n = @min(chunk.len, s.buf.len - s.len);
        @memcpy(s.buf[s.len..][0..n], chunk[0..n]);
        s.len += n;
    }

    fn text(s: *const Collect) []const u8 {
        return s.buf[0..s.len];
    }
};

fn requestLater(c: *pr.Cancel, io: std.Io, ms: u64) void {
    sleepMs(ms);
    c.request(io);
}

test "Spec.cancel bounds a stdin write held open by a descendant (sweep audit GO-PR-A)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(body);
    @memset(body, 'x');

    // No deadline, only a Cancel: the stdin writer is bounded by the killer's
    // `stop_ns` alone. A background `sleep` holds a dup of the pipe's read end
    // and never reads it, so killing the direct child does not wake the write.
    var cancel: pr.Cancel = .{};
    const th = try std.Thread.spawn(.{}, requestLater, .{ &cancel, io, 300 });
    defer th.join();
    const t0 = nowNs();
    var out = try pr.run(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "exec 3<&0; sleep 3 0<&3 >/dev/null 2>&1 & exec sleep 3 </dev/null" },
        .stdin = .pipe,
        .cancel = &cancel,
    }, body);
    defer out.deinit(testing.allocator);
    const elapsed_ms = (nowNs() - t0) / std.time.ns_per_ms;
    sleepMs(3300 -| elapsed_ms); // the stray sleep must end before the test does
    try testing.expect(out.canceled);
    try testing.expect(elapsed_ms < 2000);
}

test "a child that exits early without reading stdin still gives BrokenPipe (sweep audit GO-PR-B)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 4 << 20);
    defer testing.allocator.free(body);
    @memset(body, 'x');
    // Documented on `run`: only a kill by the call itself turns EPIPE into an Output.
    try testing.expectError(error.BrokenPipe, pr.runTimeout(testing.allocator, io, .{
        .argv = &.{"true"},
        .stdin = .pipe,
    }, body, 30 * std.time.ns_per_s));
}

test "a Cancel that kills a non-reading child returns the Output, not BrokenPipe (sweep audit GO-PR-C)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const body = try testing.allocator.alloc(u8, 4 << 20);
    defer testing.allocator.free(body);
    @memset(body, 'x');

    var cancel: pr.Cancel = .{};
    const th = try std.Thread.spawn(.{}, requestLater, .{ &cancel, io, 300 });
    defer th.join();
    var out = try pr.run(testing.allocator, io, .{
        .argv = &.{ "sleep", "5" },
        .stdin = .pipe,
        .cancel = &cancel,
    }, body);
    defer out.deinit(testing.allocator);
    try testing.expect(out.canceled);
}

test "wait keeps a descendant's output that arrives inside the idle grace (sweep audit GO-PR-D)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The first callback takes 150 ms, so the reader is back in its idle
    // `poll` only after the direct child is long gone; the descendant writes
    // at ~300 ms, inside the 250 ms grace that starts at ~150 ms.
    var c: Collect = .{ .delay_first_ms = 150 };
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo a; (sleep 0.3; echo late) & exit 0" },
    }, .{ .ctx = &c, .on_stdout = Collect.onOut });
    _ = h.wait();
    sleepMs(400); // let the descendant end before the test does
    try testing.expectEqualStrings("a\nlate\n", c.text());
}

test "wait does not cut the stream of a child that is still running (sweep audit GO-PR-E)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 600 ms of silence from a LIVE child is longer than the post-exit grace
    // (250 ms), which must only ever run after the child has exited.
    var c: Collect = .{};
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo a; sleep 0.6; echo b" },
    }, .{ .ctx = &c, .on_stdout = Collect.onOut });
    _ = h.wait();
    try testing.expectEqualStrings("a\nb\n", c.text());
}

test "line mode: wait returns after a grace when a descendant keeps the pipes open (sweep audit GO-PR-F)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: Tail = .{};
    const t0 = nowNs();
    const h = try pr.spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo before; sleep 3 & exit 0" },
    }, .{ .ctx = &seen, .on_stdout_line = Tail.onLine });
    _ = h.wait();
    const elapsed_ms = (nowNs() - t0) / std.time.ns_per_ms;
    sleepMs(3200 -| elapsed_ms);
    try testing.expect(elapsed_ms < 2000);
    try testing.expectEqual(@as(usize, 1), seen.n.load(.monotonic));
}
