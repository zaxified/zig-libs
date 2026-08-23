// SPDX-License-Identifier: MIT

//! What a single-owner event-loop process does with `pollworker`: drive a
//! `Loop` (readiness via `Loop.poll` over a real pipe, maintenance callbacks
//! via `addTask`/`tick`) alongside a `JobTable` worker pool submitted
//! through real `spawnDetached` fork/exec calls -- fill a small table to
//! capacity and see a submission rejected (`error.TableFull`, the
//! denied-request pressure path), a task that fails (`/bin/false`, reported
//! `ok = false` rather than treated as success), `release` rolling a
//! claimed-but-unfinished slot back to FREE (the shape "shutdown with work
//! still queued" takes here -- there is no cancel API, so a slot the loop
//! decides not to wait on is rolled back exactly like a worker that failed
//! to launch), and two allocator-failure points inside `spawnDetached`
//! forced with `std.testing.FailingAllocator`. Everything runs under a
//! leak-checking allocator; every detached worker is drained before the
//! allocator is torn down, so a still-running child can never race the
//! leak check.
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps`: none;
//! no `test_deps`, no private declarations).

const std = @import("std");
const pollworker = @import("pollworker");
const linux = std.os.linux;

const Job = struct { res: pollworker.ProcResult = undefined };

/// Bounded spin-wait for `n` slots to reach DONE (mirrors the module's own
/// test harness -- there is no eventfd/wake notification yet, documented as
/// deferred; the loop is expected to poll `drain` each tick).
fn waitDone(table: anytype, n: usize) !void {
    var spins: usize = 0;
    while (doneCount(table) < n) : (spins += 1) {
        if (spins > 200_000_000) return error.ExampleTimeout;
    }
}

fn doneCount(table: anytype) usize {
    var n: usize = 0;
    for (&table.slots) |*s| {
        if (s.state.load(.acquire) == 2) n += 1; // State.done
    }
    return n;
}

fn report(job: *Job, res: pollworker.ProcResult) void {
    job.res = res;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    if (@as(isize, @bitCast(linux.access("/bin/true", linux.F_OK))) < 0 or
        @as(isize, @bitCast(linux.access("/bin/false", linux.F_OK))) < 0)
    {
        std.debug.print("skipping: /bin/true or /bin/false not present on this host\n", .{});
        return;
    }

    // 1. `Loop`: readiness over a real pipe. A short poll on an idle pipe
    // times out (0 ready); once a byte is written, the same poll reports
    // the read end readable -- the exact seam a real accept loop drives.
    {
        var fds: [2]i32 = undefined;
        std.debug.assert(@as(isize, @bitCast(linux.pipe(&fds))) >= 0);
        const rfd = fds[0];
        const wfd = fds[1];
        defer _ = linux.close(rfd);
        defer _ = linux.close(wfd);

        var pfd = [_]pollworker.Loop.pollfd{.{ .fd = rfd, .events = pollworker.Loop.POLL.IN, .revents = 0 }};
        std.debug.assert(try pollworker.Loop.poll(&pfd, 20) == 0); // nothing written: timeout

        const byte = [_]u8{'x'};
        std.debug.assert(@as(isize, @bitCast(linux.write(wfd, &byte, 1))) == 1);
        pfd[0].revents = 0;
        std.debug.assert(try pollworker.Loop.poll(&pfd, 1000) == 1);
        std.debug.assert(pfd[0].revents & pollworker.Loop.POLL.IN != 0);
        std.debug.print("Loop.poll: idle pipe timed out, then reported readable after a write\n", .{});
    }

    // 2. `Loop.tick`: maintenance callbacks run in registration order, every
    // tick -- the shape a real loop uses to drive `JobTable.drain` off the
    // hot poll path.
    var loop: pollworker.Loop = .{};
    defer loop.deinit(gpa);
    var tick_count: u32 = 0;
    const TickCounter = struct {
        fn bump(ctx: ?*anyopaque) void {
            const n: *u32 = @ptrCast(@alignCast(ctx.?));
            n.* += 1;
        }
    };
    try loop.addTask(gpa, .{ .context = &tick_count, .run = TickCounter.bump });
    loop.tick();
    loop.tick();
    std.debug.assert(tick_count == 2);

    // 3. Capacity pressure: a 2-slot table filled by two real `/bin/true`
    // submissions, then a third submission is rejected -- `TableFull` by
    // name, not silently queued or dropped.
    {
        const SmallTable = pollworker.JobTable(2, Job);
        var table: SmallTable = .{};

        try table.spawnDetached(gpa, &.{"/bin/true"}, report);
        try table.spawnDetached(gpa, &.{"/bin/true"}, report);
        std.debug.assert(table.busy() == 2);

        if (table.spawnDetached(gpa, &.{"/bin/true"}, report)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.TableFull => std.debug.print("3rd submission on a 2-slot table rejected: TableFull (expected)\n", .{}),
            else => return err,
        }
        std.debug.assert(table.busy() == 2); // the rejected attempt claimed nothing

        try waitDone(&table, 2);
        const Sum = struct {
            var oks: u32 = 0;
            fn onDone(job: *Job) void {
                if (job.res.ok) oks += 1;
            }
        };
        Sum.oks = 0;
        table.drain(Sum.onDone);
        std.debug.assert(Sum.oks == 2);
        std.debug.assert(table.busy() == 0);

        // Capacity recovered: the table accepts new work again.
        try table.spawnDetached(gpa, &.{"/bin/true"}, report);
        try waitDone(&table, 1);
        table.drain(Sum.onDone);
        std.debug.assert(Sum.oks == 3);
        std.debug.print("capacity recovered after drain: a 4th submission was accepted and completed\n", .{});
    }

    // 4. A worker/task that fails: `/bin/false` exits nonzero, folded into
    // `ProcResult.ok = false` -- a failure result, not a spawn error and not
    // silently treated as success.
    var table: pollworker.JobTable(4, Job) = .{};
    {
        try table.spawnDetached(gpa, &.{"/bin/false"}, report);
        try waitDone(&table, 1);
        const Fail = struct {
            var saw_failure = false;
            fn onDone(job: *Job) void {
                saw_failure = !job.res.ok and job.res.exit_code == 1;
            }
        };
        Fail.saw_failure = false;
        table.drain(Fail.onDone);
        std.debug.assert(Fail.saw_failure);
        std.debug.assert(table.busy() == 0);
        std.debug.print("failing task: /bin/false reported ok=false, exit_code=1\n", .{});
    }

    // 5. "Shutdown with work still queued": `pollworker` has no cancel API
    // (documented -- a submitted job runs to completion off-loop). The
    // shape shutdown-with-outstanding-work takes here is a slot the loop
    // claimed but decided not to run a worker for after all (e.g. the loop
    // is tearing down before dispatch) -- `release` rolls it back to FREE
    // without ever going through DONE, so it does not leak a permanently
    // "busy" slot nor get silently reported to `on_done`.
    {
        const job = table.claim().?;
        std.debug.assert(table.busy() == 1); // outstanding at "shutdown" time
        table.release(job);
        std.debug.assert(table.busy() == 0); // rolled back, not stuck RUNNING
        // Genuinely FREE, reclaimable without going through `drain` first.
        const job2 = table.claim().?;
        std.debug.assert(table.busy() == 1);
        table.release(job2);
        std.debug.assert(table.busy() == 0);
        std.debug.print("shutdown with outstanding work: claimed-but-unrun slot rolled back via release\n", .{});
    }

    // 6. Allocator failure, error return partway through `spawnDetached`:
    // the very first allocation (the argv array) fails. Must surface
    // `error.OutOfMemory` by name, and the claimed slot must be rolled back
    // (`errdefer self.release(job)`) rather than left stuck RUNNING.
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (table.spawnDetached(failing.allocator(), &.{"/bin/true"}, report)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("spawnDetached under a FailingAllocator (arg 0): OutOfMemory (expected)\n", .{}),
            else => return err,
        }
        std.debug.assert(table.busy() == 0); // the claim was rolled back, not leaked
    }

    // 7. Allocator failure, later in the same call: argv (array + one
    // dupeZ'd arg + the pointer vector) succeeds, then the `SpawnCtx`
    // allocation fails. Must still surface `error.OutOfMemory` and unwind
    // the now-fully-built `OwnedArgv` (`errdefer owned.deinit()`), leaving
    // nothing for the leak check to find.
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 3 });
        if (table.spawnDetached(failing.allocator(), &.{"/bin/true"}, report)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("spawnDetached under a FailingAllocator (ctx): OutOfMemory (expected)\n", .{}),
            else => return err,
        }
        std.debug.assert(table.busy() == 0);
    }

    std.debug.print("pollworker example done\n", .{});
}
