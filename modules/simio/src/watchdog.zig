// SPDX-License-Identifier: MIT

//! Wall-clock guard for a run. A task that spins without calling `std.Io`
//! (a busy loop, a spinlock whose holder is suspended in an `Io` call) never
//! returns to the scheduler, and nothing inside the simulation can interrupt
//! it: without this the run hangs silently until something outside kills the
//! process. The watchdog is a second OS thread that only reads atomics the
//! scheduler bumps on every switch into a task; when none has happened for
//! `Options.watchdog_ms` of wall time it names the task, its host and the
//! virtual time, then aborts (or, for tests, raises a flag).

const std = @import("std");
const linux = std.os.linux;

pub const Action = enum {
    /// Print what is stuck and abort the process.
    abort,
    /// Only set `fired`: for a test whose spinning task polls it.
    flag,
};

pub const Watchdog = struct {
    limit_ns: u64,
    action: Action,
    stop: std.atomic.Value(u32) = .init(0),
    /// Bumped by the scheduler before every switch into a task.
    progress: std.atomic.Value(u64) = .init(0),
    /// The task running now, 0 while the scheduler itself runs.
    fiber_id: std.atomic.Value(u64) = .init(0),
    host_id: std.atomic.Value(u32) = .init(0),
    virtual_ns: std.atomic.Value(u64) = .init(0),
    fired: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn start(w: *Watchdog) void {
        if (w.limit_ns == 0 or w.thread != null) return;
        w.stop.store(0, .release);
        w.fired.store(false, .release);
        // No watchdog is better than a failed run: spawning is best effort.
        w.thread = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, watch, .{w}) catch null;
    }

    pub fn finish(w: *Watchdog) void {
        const t = w.thread orelse return;
        w.stop.store(1, .release);
        _ = linux.futex_3arg(&w.stop.raw, .{ .cmd = .WAKE, .private = true }, 1);
        t.join();
        w.thread = null;
    }

    /// The scheduler is about to run task `fiber_id` of `host_id`.
    pub fn enter(w: *Watchdog, fiber_id: u64, host_id: u32, virtual_ns: u64) void {
        w.fiber_id.store(fiber_id, .monotonic);
        w.host_id.store(host_id, .monotonic);
        w.virtual_ns.store(virtual_ns, .monotonic);
        _ = w.progress.fetchAdd(1, .release);
    }

    /// The task gave control back.
    pub fn leave(w: *Watchdog) void {
        w.fiber_id.store(0, .monotonic);
        _ = w.progress.fetchAdd(1, .release);
    }

    fn watch(w: *Watchdog) void {
        var last = w.progress.load(.acquire);
        var since = monoNs();
        const tick_ns = @min(w.limit_ns / 4, std.time.ns_per_s);
        while (w.stop.load(.acquire) == 0) {
            const ts: linux.timespec = .{
                .sec = @intCast(tick_ns / std.time.ns_per_s),
                .nsec = @intCast(tick_ns % std.time.ns_per_s),
            };
            _ = linux.futex_4arg(&w.stop.raw, .{ .cmd = .WAIT, .private = true }, 0, &ts);
            const p = w.progress.load(.acquire);
            const now = monoNs();
            if (p != last) {
                last = p;
                since = now;
                continue;
            }
            if (now - since < w.limit_ns or w.fired.load(.acquire)) continue;
            w.fired.store(true, .release);
            if (w.action == .flag) continue;
            const id = w.fiber_id.load(.monotonic);
            if (id == 0) {
                std.debug.print("simio watchdog: the scheduler made no progress for {d} ms of wall time (virtual time {d} ms); aborting\n", .{
                    w.limit_ns / std.time.ns_per_ms, w.virtual_ns.load(.monotonic) / std.time.ns_per_ms,
                });
            } else {
                std.debug.print("simio watchdog: task {d} on host {d} has run {d} ms of wall time without calling std.Io (virtual time {d} ms) — a busy loop that never yields, e.g. a spinlock whose holder is suspended in an Io call; aborting\n", .{
                    id, w.host_id.load(.monotonic), w.limit_ns / std.time.ns_per_ms, w.virtual_ns.load(.monotonic) / std.time.ns_per_ms,
                });
            }
            std.process.abort();
        }
    }
};

fn monoNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}
