// SPDX-License-Identifier: MIT

//! What a write-behind coordinator does with `workerpool`: start a fixed
//! roster of worker threads, submit a batch of "flush this dirty entry"
//! closures from the request path, wait for them all to finish, then confirm
//! the pool drained cleanly before tearing it down.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const workerpool = @import("workerpool");

/// Stand-in for a dirty cache entry that needs flushing to a sink. `flushed`
/// counts how many entries actually made it out.
const Sink = struct {
    flushed: std.atomic.Value(u32) = .init(0),
};

/// The closure a real write-behind coordinator would submit: "persist this
/// entry". `ctx` points at the `Sink` shared across all jobs in this batch.
fn flushEntry(ctx: *anyopaque) void {
    const sink: *Sink = @ptrCast(@alignCast(ctx));
    _ = sink.flushed.fetchAdd(1, .monotonic);
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // The pool needs an `Io` for its idle-worker futex wait/wake; a real
    // server passes the same `Io.Threaded` it uses everywhere else.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try workerpool.WorkerPool.init(gpa, .{ .io = io, .n_workers = 4 });
    defer pool.deinit();

    var sink = Sink{};
    const batch_size: u32 = 1000;
    var i: u32 = 0;
    while (i < batch_size) : (i += 1) {
        pool.submit(.{ .func = flushEntry, .ctx = &sink }) catch |err| switch (err) {
            error.Shutdown => {
                std.debug.print("pool is shutting down, dropping remaining work\n", .{});
                break;
            },
            error.SubmitFailed => {
                std.debug.print("backing storage exhausted, dropping remaining work\n", .{});
                break;
            },
        };
    }

    // Graceful drain: blocks until every accepted job has run.
    pool.drain();

    std.debug.print("flushed {d}/{d} entries\n", .{ sink.flushed.load(.monotonic), batch_size });
    std.debug.print("submitted={d} completed={d} drained_cleanly={}\n", .{
        pool.submittedCount(),
        pool.completedCount(),
        pool.drainedCleanly(),
    });

    // Submitting after a drain is a documented, nameable error — not a panic.
    if (pool.submit(.{ .func = flushEntry, .ctx = &sink })) |_| {
        unreachable; // the pool has already stopped accepting work
    } else |err| switch (err) {
        error.Shutdown => std.debug.print("post-drain submit correctly refused\n", .{}),
        error.SubmitFailed => return err,
    }
}
