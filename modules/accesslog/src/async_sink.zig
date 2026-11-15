// SPDX-License-Identifier: MIT

//! async_sink.zig — `AsyncSink`, a non-blocking sibling of `Sink` (consumer
//! request 2026-11-15).
//!
//! `Sink` is group commit: when its batch is full a caller waits for the
//! flusher, so a stalled destination (a journal socket, a full pipe) stalls
//! the requests that log. A server that must never block on its log wants the
//! other trade: a bounded queue, one writer task that owns the destination,
//! and a `log` that drops the line and counts it when the queue is full
//! (zap/zerolog non-blocking writers, log4j `AsyncAppender` with
//! `blocking=false`). `Sink` stays allocation-free and task-free; this is the
//! type that allocates once and runs a task.
//!
//! ```zig
//! var q: accesslog.AsyncSink = undefined;
//! try q.init(gpa, io, &file_writer.interface, .{ .max_bytes = 1 << 20, .max_lines = 4096 });
//! defer q.deinit(); // drains what is queued, then stops the writer
//! q.logEntry(entry); // or q.log("a line"); never blocks on the destination
//! if (q.dropped() != 0) { ... }
//! ```
//!
//! Guarantees:
//! - `log`/`logEntry` never wait for the destination. They take a mutex held
//!   only for a memcpy into the queue and a counter bump, never across I/O.
//! - A line is queued whole or dropped whole (and counted), never cut. Lines
//!   from one thread keep their order; the writer writes them in queue order.
//! - Memory is the one allocation made by `init` (`max_bytes` plus the
//!   struct); nothing allocates afterwards.
//! - Writer errors are swallowed like `Sink`'s: the lines of a failed write
//!   are lost (and are not counted in `dropped`, which counts queue
//!   overflow only).
//!
//! The writer task is a concurrent task of `io` (`Io.Group.concurrent`);
//! `init` fails with `error.ConcurrencyUnavailable` when `io` can run none.

const std = @import("std");
const root = @import("root.zig");
const Entry = root.Entry;

pub const AsyncSink = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    options: Options,
    /// Ring of queued bytes (`options.max_bytes` long).
    ring: []u8,

    mutex: std.Io.Mutex = .init,
    /// Signalled to the writer: data queued, or `closing` set.
    wake: std.Io.Condition = .init,
    /// Signalled to `flush`/`deinit`: the writer finished a batch or exited.
    drained: std.Io.Condition = .init,
    group: std.Io.Group = .init,

    // All below are guarded by `mutex`.
    head: usize = 0,
    /// Bytes queued (including a batch the writer is writing right now:
    /// its space is released only after the write).
    used: usize = 0,
    /// Lines queued (same accounting as `used`).
    lines: usize = 0,
    /// Lines ever accepted / ever written (or lost to a writer error).
    accepted: u64 = 0,
    completed: u64 = 0,
    dropped_lines: u64 = 0,
    closing: bool = false,
    writer_done: bool = false,

    pub const Options = struct {
        /// Capacity of the queue in bytes; also the longest line that can be
        /// queued (a longer one is dropped and counted). Allocated once.
        max_bytes: usize = 256 * 1024,
        /// Capacity of the queue in lines.
        max_lines: usize = 4096,
        /// The line format for `logEntry`, as for `root.write`.
        format: root.Format = .json_lines,
        /// A `LogFormat` template for `logEntry`; replaces `format`. Borrowed.
        template: ?*const root.LogFormat = null,
    };

    pub const InitError = std.mem.Allocator.Error || error{ ConcurrencyUnavailable, InvalidOptions };

    /// Largest line `logEntry` renders (a longer one is dropped and counted).
    pub const entry_line_max = 8 * 1024;

    /// Initialise in place (the writer task holds a pointer to `self`, so the
    /// sink must not move afterwards) and start the writer task. `writer` is
    /// used only by that task until `deinit` returns. `options.max_bytes` and
    /// `max_lines` must be non-zero (`error.InvalidOptions`).
    pub fn init(
        self: *AsyncSink,
        gpa: std.mem.Allocator,
        io: std.Io,
        writer: *std.Io.Writer,
        options: Options,
    ) InitError!void {
        if (options.max_bytes == 0 or options.max_lines == 0) return error.InvalidOptions;
        const ring = try gpa.alloc(u8, options.max_bytes);
        errdefer gpa.free(ring);
        self.* = .{ .gpa = gpa, .io = io, .writer = writer, .options = options, .ring = ring };
        try self.group.concurrent(io, run, .{self});
    }

    /// Drain every queued line to the writer, stop the writer task and free
    /// the queue. Call once, after the last `log`.
    pub fn deinit(self: *AsyncSink) void {
        const io = self.io;
        self.mutex.lockUncancelable(io);
        self.closing = true;
        self.wake.broadcast(io);
        while (!self.writer_done) self.drained.waitUncancelable(io, &self.mutex);
        self.mutex.unlock(io);
        // The task has finished its body; this only reaps it.
        self.group.await(io) catch self.group.cancel(io);
        self.gpa.free(self.ring);
        self.* = undefined;
    }

    /// Queue `line` (a newline is added when it does not end in one). Never
    /// blocks on the destination: when the queue has no room for the whole
    /// line, or already holds `max_lines`, or the line is longer than
    /// `max_bytes`, the line is dropped and counted. Thread-safe.
    ///
    /// Returns true when the line was queued, false when it was dropped (and
    /// counted in `dropped()`), so a caller that keeps its own per-class
    /// counts can count the `false` returns. An empty `line` is ignored: it
    /// returns true and is neither queued nor counted (nothing was lost).
    pub fn log(self: *AsyncSink, line: []const u8) bool {
        if (line.len == 0) return true;
        const need_nl = line[line.len - 1] != '\n';
        const need = line.len + @intFromBool(need_nl);
        const io = self.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.closing or need > self.ring.len - self.used or self.lines >= self.options.max_lines) {
            self.dropped_lines +|= 1;
            return false;
        }
        const cap = self.ring.len;
        const tail = (self.head + self.used) % cap;
        const first = @min(line.len, cap - tail);
        @memcpy(self.ring[tail..][0..first], line[0..first]);
        @memcpy(self.ring[0 .. line.len - first], line[first..]);
        if (need_nl) self.ring[(tail + line.len) % cap] = '\n';
        self.used += need;
        self.lines += 1;
        self.accepted += 1;
        self.wake.signal(io);
        return true;
    }

    /// Format `entry` per `options.format`/`template` and queue it like
    /// `log`. A line the formatter cannot produce (more than
    /// `entry_line_max` bytes, or a template error) is dropped and counted.
    /// Returns true when queued, false when dropped (see `log`).
    pub fn logEntry(self: *AsyncSink, entry: Entry) bool {
        var scratch: [entry_line_max]u8 = undefined;
        var fw: std.Io.Writer = .fixed(&scratch);
        const rendered = if (self.options.template) |t| t.write(entry, &fw) else root.write(entry, self.options.format, &fw);
        if (rendered) |_| {
            return self.log(fw.buffered());
        } else |_| {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.dropped_lines +|= 1;
            return false;
        }
    }

    /// Lines dropped so far: queue full, line over `max_bytes`, a line
    /// `logEntry` could not format, or logged after `deinit` began.
    pub fn dropped(self: *AsyncSink) u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.dropped_lines;
    }

    /// Wait until every line accepted before this call has been handed to
    /// the writer and the writer flushed. Blocks as long as the destination
    /// does; not for use on a path that must never block.
    pub fn flush(self: *AsyncSink) void {
        const io = self.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const target = self.accepted;
        while (self.completed < target and !self.writer_done) self.drained.waitUncancelable(io, &self.mutex);
    }

    fn run(self: *AsyncSink) void {
        const io = self.io;
        self.mutex.lockUncancelable(io);
        while (true) {
            while (self.lines == 0 and !self.closing) self.wake.waitUncancelable(io, &self.mutex);
            if (self.lines == 0) break; // closing and drained
            // Take everything queued now. Its space stays reserved (still
            // counted in `used`) until written, so producers append behind
            // it and never overwrite it.
            const bytes = self.used;
            const n_lines = self.lines;
            const head = self.head;
            self.mutex.unlock(io);

            const first = @min(bytes, self.ring.len - head);
            self.writer.writeAll(self.ring[head..][0..first]) catch {};
            self.writer.writeAll(self.ring[0 .. bytes - first]) catch {};
            self.writer.flush() catch {};

            self.mutex.lockUncancelable(io);
            self.head = (head + bytes) % self.ring.len;
            self.used -= bytes;
            self.lines -= n_lines;
            self.completed += n_lines;
            self.drained.broadcast(io);
        }
        self.writer_done = true;
        self.drained.broadcast(io);
        self.mutex.unlock(io);
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A destination that blocks in `drain` until `release` is set, and records
/// every byte it receives.
const GateWriter = struct {
    interface: std.Io.Writer,
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    open: std.atomic.Value(bool),
    /// Set when the writer task has entered `drain` (and so is stalled).
    entered: std.atomic.Value(bool) = .init(false),

    fn init(gpa: std.mem.Allocator, buf: []u8, open: bool) GateWriter {
        return .{
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buf },
            .gpa = gpa,
            .open = .init(open),
        };
    }

    fn deinit(self: *GateWriter) void {
        self.out.deinit(self.gpa);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *GateWriter = @alignCast(@fieldParentPtr("interface", w));
        self.entered.store(true, .release);
        while (!self.open.load(.acquire)) std.Thread.yield() catch {};
        self.out.appendSlice(self.gpa, w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.out.appendSlice(self.gpa, d) catch return error.WriteFailed;
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.out.appendSlice(self.gpa, last) catch return error.WriteFailed;
        n += last.len * splat;
        return n;
    }
};

test "AsyncSink: nothing lost when the queue never fills; newline added; deinit drains" {
    var buf: [16]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 4096, .max_lines = 64 });
    _ = q.log("one");
    _ = q.log("two\n");
    try testing.expect(q.log("")); // empty: ignored, not a drop
    q.flush();
    try testing.expectEqualStrings("one\ntwo\n", gw.out.items);
    _ = q.log("three");
    q.deinit(); // drains "three"
    try testing.expectEqualStrings("one\ntwo\nthree\n", gw.out.items);
}

test "AsyncSink: a stalled destination makes log drop and count, never block; queued lines survive" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, false);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    // 3 lines of 4 bytes ("aaa\n") fit by bytes; the line cap is 3 too.
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 12, .max_lines = 3 });

    try testing.expect(q.log("aaa"));
    // Wait for the writer to take line 1 and stall in the destination.
    while (!gw.entered.load(.acquire)) std.Thread.yield() catch {};
    // The taken batch still holds its space; two more lines fit, the rest drop.
    try testing.expect(q.log("bbb"));
    try testing.expect(q.log("ccc")); // 3 lines, 12 bytes: queue exactly full
    try testing.expectEqual(@as(u64, 0), q.dropped());
    try testing.expect(!q.log("ddd")); // full by lines and bytes
    try testing.expect(!q.log("e")); // still full
    try testing.expectEqual(@as(u64, 2), q.dropped());

    gw.open.store(true, .release);
    q.deinit();
    try testing.expectEqualStrings("aaa\nbbb\nccc\n", gw.out.items);
}

test "AsyncSink: byte capacity drops a line that does not fit whole; over-long line is dropped" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 8, .max_lines = 100 });
    try testing.expect(!q.log("123456789")); // 10 bytes with newline: never fits
    try testing.expect(q.log("1234567")); // 8 bytes with newline: exactly the capacity
    q.flush();
    try testing.expectEqual(@as(u64, 1), q.dropped());
    // Wrap-around: head is now 8 % 8 == 0 again; push lines across the seam.
    _ = q.log("abc");
    q.flush();
    _ = q.log("defg");
    q.flush();
    _ = q.log("hi");
    q.deinit();
    try testing.expectEqualStrings("1234567\nabc\ndefg\nhi\n", gw.out.items);
}

test "AsyncSink: logEntry formats with the configured format; an unformattable line is counted" {
    var buf: [16]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .format = .logfmt });
    try testing.expect(q.logEntry(.{ .timestamp_ns = 0, .method = "GET", .target = "/x", .status = 200 }));
    var huge: [AsyncSink.entry_line_max + 16]u8 = undefined;
    @memset(&huge, 'a');
    try testing.expect(!q.logEntry(.{ .timestamp_ns = 0, .method = "GET", .target = &huge, .status = 200 }));
    try testing.expectEqual(@as(u64, 1), q.dropped());
    q.deinit();
    try testing.expect(std.mem.find(u8, gw.out.items, "method=GET") != null);
    try testing.expect(std.mem.find(u8, gw.out.items, "target=/x") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, gw.out.items, "\n"));
}

test "AsyncSink: bad options are an error, not a panic" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try testing.expectError(error.InvalidOptions, q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 0 }));
    try testing.expectError(error.InvalidOptions, q.init(testing.allocator, testing.io, &gw.interface, .{ .max_lines = 0 }));
}

test "AsyncSink: concurrent loggers, roomy queue: every line exactly once, per-thread order kept" {
    const threads = 6;
    const per = 300;
    var buf: [64]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 1 << 20, .max_lines = threads * per });

    const Worker = struct {
        fn run(a: *AsyncSink, id: usize) void {
            var b: [32]u8 = undefined;
            for (0..per) |seq| _ = a.log(std.fmt.bufPrint(&b, "t{d} s{d}", .{ id, seq }) catch unreachable);
        }
    };
    var pool: [threads]std.Thread = undefined;
    for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &q, id });
    for (pool) |t| t.join();
    try testing.expectEqual(@as(u64, 0), q.dropped());
    q.deinit();

    var next: [threads]usize = @splat(0);
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, gw.out.items[0 .. gw.out.items.len - 1], '\n');
    while (it.next()) |l| {
        var f = std.mem.splitScalar(u8, l, ' ');
        const id = try std.fmt.parseInt(usize, f.next().?[1..], 10);
        const seq = try std.fmt.parseInt(usize, f.next().?[1..], 10);
        try testing.expectEqual(next[id], seq);
        next[id] += 1;
        count += 1;
    }
    try testing.expectEqual(@as(usize, threads * per), count);
}

test "AsyncSink: concurrent loggers on a tiny queue: accepted + dropped == logged, lines whole" {
    const threads = 6;
    const per = 300;
    var buf: [64]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 64, .max_lines = 8 });

    const Worker = struct {
        fn run(a: *AsyncSink, id: usize) void {
            var b: [32]u8 = undefined;
            for (0..per) |seq| _ = a.log(std.fmt.bufPrint(&b, "t{d} s{d} end", .{ id, seq }) catch unreachable);
        }
    };
    var pool: [threads]std.Thread = undefined;
    for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &q, id });
    for (pool) |t| t.join();
    const lost = q.dropped();
    q.deinit();

    var count: u64 = 0;
    var it = std.mem.splitScalar(u8, gw.out.items[0 .. gw.out.items.len - 1], '\n');
    while (it.next()) |l| {
        try testing.expect(std.mem.startsWith(u8, l, "t") and std.mem.endsWith(u8, l, " end"));
        count += 1;
    }
    try testing.expect(count >= 1);
    try testing.expectEqual(@as(u64, threads * per), count + lost);
}

test "AsyncSink: the line cap binds before the byte cap (mutation 2026-11-15)" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, false);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 4096, .max_lines = 2 });
    var stopped = false;
    // a failing expect must not leave the writer stalled behind the closed gate
    defer if (!stopped) {
        gw.open.store(true, .release);
        q.deinit();
    };
    _ = q.log("a");
    while (!gw.entered.load(.acquire)) std.Thread.yield() catch {};
    // The batch being written still counts: one more line fits, the next does not.
    _ = q.log("b");
    try testing.expectEqual(@as(u64, 0), q.dropped());
    _ = q.log("c");
    _ = q.log("d");
    try testing.expectEqual(@as(u64, 2), q.dropped());
    stopped = true;
    gw.open.store(true, .release);
    q.deinit();
    try testing.expectEqualStrings("a\nb\n", gw.out.items);
}

test "AsyncSink: a line logged once deinit has begun is dropped and counted, never queued (mutation 2026-11-15)" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, false);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 4096, .max_lines = 64 });
    _ = q.log("first");
    while (!gw.entered.load(.acquire)) std.Thread.yield() catch {};
    const closer = try std.Thread.spawn(.{}, struct {
        fn run(s: *AsyncSink) void {
            s.deinit();
        }
    }.run, .{&q});
    // Wait until deinit has set `closing`; the stalled writer keeps it from finishing.
    while (true) {
        q.mutex.lockUncancelable(q.io);
        const c = q.closing;
        q.mutex.unlock(q.io);
        if (c) break;
        std.Thread.yield() catch {};
    }
    try testing.expect(!q.log("late"));
    const lost = q.dropped();
    gw.open.store(true, .release);
    closer.join();
    try testing.expectEqual(@as(u64, 1), lost);
    try testing.expectEqualStrings("first\n", gw.out.items);
}

test "AsyncSink: logEntry renders through the template when one is set (mutation 2026-11-15)" {
    var buf: [16]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    const tpl = try root.LogFormat.parse("%m %U %>s");
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .format = .json_lines, .template = &tpl });
    _ = q.logEntry(.{ .timestamp_ns = 0, .method = "GET", .target = "/x", .status = 200 });
    q.deinit();
    try testing.expectEqualStrings("GET /x 200\n", gw.out.items);
}

test "AsyncSink: log returns true exactly for queued lines; an empty line is ignored and not counted" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 8, .max_lines = 100 });
    try testing.expect(q.log(""));
    try testing.expectEqual(@as(u64, 0), q.dropped());
    try testing.expect(!q.log("123456789")); // over max_bytes
    try testing.expectEqual(@as(u64, 1), q.dropped());
    try testing.expect(q.log("ok"));
    q.deinit();
    try testing.expectEqualStrings("ok\n", gw.out.items);
}

test "AsyncSink: logEntry returns false when the formatted line is dropped by the queue (mutation 2026-11-15)" {
    var buf: [8]u8 = undefined;
    var gw: GateWriter = .init(testing.allocator, &buf, true);
    defer gw.deinit();
    const tpl = try root.LogFormat.parse("%m %U %>s");
    var q: AsyncSink = undefined;
    try q.init(testing.allocator, testing.io, &gw.interface, .{ .max_bytes = 8, .max_lines = 100, .template = &tpl });
    // "GET /x 200" renders fine but is longer than max_bytes: the queue drops it.
    try testing.expect(!q.logEntry(.{ .timestamp_ns = 0, .method = "GET", .target = "/x", .status = 200 }));
    try testing.expectEqual(@as(u64, 1), q.dropped());
    q.deinit();
    try testing.expectEqualStrings("", gw.out.items);
}
