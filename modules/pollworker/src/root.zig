// SPDX-License-Identifier: MIT
//! pollworker — single-owner poll() loop + a fork/detach job table for offloading
//! blocking work off the loop thread. A worker forks/execs an arbitrary argv, and
//! its result is drained back on the loop's next tick. Linux, no libc.
//!
//! Two independent pieces:
//!  * `Loop`            — a thin wrapper over `poll(2)` plus a per-tick maintenance
//!                        callback list. The single owner drives it: `poll` the fds,
//!                        service readiness, then `tick()` the maintenance callbacks.
//!  * `JobTable(N,Job)` — a fixed-size, lock-free FREE→RUNNING→DONE slot table. The
//!                        loop `claim()`s a slot, a worker fills it and marks it DONE,
//!                        and the loop `drain()`s DONE slots on its next tick. The
//!                        `spawnDetached` convenience runs the RUNNING→DONE half on a
//!                        detached thread that fork/exec/waitpid's an arbitrary argv,
//!                        keeping the between-fork-and-exec window async-signal-safe.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const meta = .{
    .platform = .linux,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "single-owner event loop + detached-fork worker pool",
    .deps = .{},
};

// ── Loop ────────────────────────────────────────────────────────────────────

/// Single-owner poll loop building block. Holds a list of maintenance callbacks
/// to run once per tick; `poll` is a thin, allocation-free wrapper over the
/// `poll(2)` syscall. The owner composes them:
///
/// ```
/// while (!quit) {
///     const n = Loop.poll(&fds, 250) catch |e| switch (e) {
///         error.Interrupted => 0,   // a signal — re-check the quit flag
///         error.PollFailed => break,
///     };
///     if (n > 0 and fds[0].revents & Loop.POLL.IN != 0) accept(...);
///     loop.tick();                  // reap, publish, refresh — every tick
/// }
/// ```
pub const Loop = struct {
    /// A maintenance callback plus its opaque context, run once per `tick()`.
    pub const Task = struct {
        context: ?*anyopaque = null,
        run: *const fn (context: ?*anyopaque) void,
    };

    tasks: std.ArrayList(Task) = .empty,

    /// Re-exported poll event bits so callers need not reach into std.os.linux.
    pub const POLL = linux.POLL;
    pub const pollfd = linux.pollfd;

    pub const PollError = error{
        /// The syscall was interrupted by a signal (EINTR). The owner typically
        /// treats this as "no readiness" and loops to re-check its quit flag.
        Interrupted,
        /// A hard poll failure (EINVAL/ENOMEM/EFAULT). Non-recoverable here.
        PollFailed,
    };

    pub fn deinit(self: *Loop, gpa: std.mem.Allocator) void {
        self.tasks.deinit(gpa);
    }

    /// Register a maintenance callback to run every `tick()`, in registration order.
    pub fn addTask(self: *Loop, gpa: std.mem.Allocator, task: Task) std.mem.Allocator.Error!void {
        try self.tasks.append(gpa, task);
    }

    /// Run every registered maintenance callback once, in order. Loop-thread only.
    pub fn tick(self: *const Loop) void {
        for (self.tasks.items) |t| t.run(t.context);
    }

    /// Thin wrapper over `poll(2)`. Blocks up to `timeout_ms` (-1 = wait forever,
    /// 0 = return immediately). Returns the number of fds with events (0 on
    /// timeout). `fds[i].revents` is filled by the kernel. Allocation-free.
    pub fn poll(fds: []pollfd, timeout_ms: i32) PollError!usize {
        const rc = linux.poll(fds.ptr, @intCast(fds.len), timeout_ms);
        if (@as(isize, @bitCast(rc)) < 0) {
            return switch (linux.errno(rc)) {
                .INTR => error.Interrupted,
                else => error.PollFailed,
            };
        }
        return rc;
    }
};

// ── JobTable ─────────────────────────────────────────────────────────────────

/// Outcome of a detached child process, folded into a Job by `spawnDetached`.
pub const ProcResult = struct {
    /// The child exited normally with status 0.
    ok: bool,
    /// Exit code (0..255) iff the child exited normally, else null.
    exit_code: ?u8,
    /// Terminating signal number iff the child was killed by a signal, else null.
    term_signal: ?u8,
    /// The fork/exec/wait plumbing itself failed; the child's fate is unknown.
    spawn_failed: bool,
};

/// A fixed-size, lock-free table of `N` job slots carrying a `Job` payload.
///
/// State machine per slot (single writer per transition):
///   FREE --claim()--> RUNNING --finish()--> DONE --drain()--> FREE
///        (loop)                (worker)             (loop)
///
/// The loop thread is the sole caller of `claim`/`drain`/`release`; a worker
/// thread is the sole caller of `finish` for the slot it owns. Handoff is via
/// each slot's atomic state with acquire/release ordering, so the payload writes
/// on one side are visible to the other without a lock.
///
/// Back-pressure is the fixed slot count: `claim` returns null (and
/// `spawnDetached` returns `error.TableFull`) when every slot is busy.
pub fn JobTable(comptime N: usize, comptime Job: type) type {
    if (N == 0) @compileError("JobTable needs N >= 1");
    return struct {
        const Self = @This();

        pub const capacity = N;
        pub const State = enum(u8) { free = 0, running = 1, done = 2 };

        /// Worker-side callback: runs on the worker thread when the child is
        /// reaped, folding the process outcome into its (RUNNING, worker-owned)
        /// Job slot. It touches only its own slot, so it never races the loop.
        pub const Report = *const fn (job: *Job, res: ProcResult) void;

        /// Loop-side callback: runs on the loop thread from `drain`, once per
        /// DONE slot, before the slot is recycled to FREE.
        pub const OnDone = *const fn (job: *Job) void;

        const Slot = struct {
            state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(State.free)),
            job: Job = undefined,
        };

        slots: [N]Slot = [_]Slot{.{}} ** N,

        /// Reserve a FREE slot and mark it RUNNING; returns a pointer to its Job
        /// for the caller/worker to populate, or null when all slots are busy.
        /// Loop-thread only. The returned Job is NOT zeroed — the caller owns it.
        pub fn claim(self: *Self) ?*Job {
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @intFromEnum(State.free)) continue;
                s.state.store(@intFromEnum(State.running), .release);
                return &s.job;
            }
            return null;
        }

        /// Worker-thread handoff: publish a RUNNING slot as DONE for the loop's
        /// next `drain`. All writes to `job` made before this call are visible to
        /// the draining loop thread.
        pub fn finish(self: *Self, job: *Job) void {
            _ = self;
            const slot: *Slot = @fieldParentPtr("job", job);
            slot.state.store(@intFromEnum(State.done), .release);
        }

        /// Loop-thread rollback: return a claimed-but-unused slot to FREE without
        /// going through DONE (e.g. a worker failed to launch).
        pub fn release(self: *Self, job: *Job) void {
            _ = self;
            const slot: *Slot = @fieldParentPtr("job", job);
            slot.state.store(@intFromEnum(State.free), .release);
        }

        /// Reap every DONE slot: call `on_done(&job)` then recycle it to FREE.
        /// Loop-thread only.
        pub fn drain(self: *Self, on_done: OnDone) void {
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @intFromEnum(State.done)) continue;
                on_done(&s.job);
                s.state.store(@intFromEnum(State.free), .release);
            }
        }

        /// Number of slots not currently FREE (RUNNING + DONE). Loop-thread only.
        pub fn busy(self: *const Self) usize {
            var n: usize = 0;
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @intFromEnum(State.free)) n += 1;
            }
            return n;
        }

        pub const SpawnError = error{
            TableFull,
            EmptyArgv,
            ThreadSpawnFailed,
        } || std.mem.Allocator.Error;

        /// Claim a slot and run `argv` to completion on a detached worker thread:
        /// the worker forks, execs `argv` with an empty environment, waits, folds
        /// the `ProcResult` into the slot's Job via `report`, then marks it DONE.
        /// The loop later `drain`s it. Loop-thread only (it claims a slot).
        ///
        /// `argv` is copied into a heap block owned by the worker (freed after the
        /// child is reaped), so the caller's slice need not outlive this call.
        /// The between-fork-and-exec window uses only raw syscalls — no allocation.
        pub fn spawnDetached(
            self: *Self,
            gpa: std.mem.Allocator,
            argv: []const []const u8,
            report: Report,
        ) SpawnError!void {
            if (argv.len == 0) return error.EmptyArgv;
            const job = self.claim() orelse return error.TableFull;
            errdefer self.release(job);

            var owned = try OwnedArgv.init(gpa, argv);
            errdefer owned.deinit();

            const ctx = try gpa.create(SpawnCtx);
            errdefer gpa.destroy(ctx);
            ctx.* = .{ .table = self, .job = job, .argv = owned, .report = report, .gpa = gpa };

            const th = std.Thread.spawn(.{}, spawnEntry, .{ctx}) catch return error.ThreadSpawnFailed;
            th.detach();
        }

        const SpawnCtx = struct {
            table: *Self,
            job: *Job,
            argv: OwnedArgv,
            report: Report,
            gpa: std.mem.Allocator,
        };

        fn spawnEntry(ctx: *SpawnCtx) void {
            const res = runChild(ctx.argv.ptrs);
            ctx.report(ctx.job, res);
            // Release our own heap BEFORE publishing DONE: once the loop observes
            // DONE it may tear down (or leak-check) the allocator, and this
            // detached thread must not touch it again after that signal.
            const table = ctx.table;
            const job = ctx.job;
            ctx.argv.deinit();
            ctx.gpa.destroy(ctx);
            table.finish(job);
        }
    };
}

/// Empty environment for detached execs. The generic primitive does not inherit
/// the parent environment (see DEFER in the README); callers that need PATH etc.
/// should exec absolute paths, which need no environment.
const empty_envp = [_:null]?[*:0]const u8{};

/// An owned, execve-ready copy of an argv: NUL-terminated arg bytes plus a
/// null-terminated pointer vector. Freed as a unit after the child is reaped.
const OwnedArgv = struct {
    args: [][:0]u8,
    ptrs: [:null]?[*:0]const u8,
    gpa: std.mem.Allocator,

    fn init(gpa: std.mem.Allocator, argv: []const []const u8) std.mem.Allocator.Error!OwnedArgv {
        const args = try gpa.alloc([:0]u8, argv.len);
        var i: usize = 0;
        errdefer {
            for (args[0..i]) |a| gpa.free(a);
            gpa.free(args);
        }
        while (i < argv.len) : (i += 1) args[i] = try gpa.dupeZ(u8, argv[i]);

        const ptrs = try gpa.allocSentinel(?[*:0]const u8, argv.len, null);
        for (args, 0..) |a, k| ptrs[k] = a.ptr;
        return .{ .args = args, .ptrs = ptrs, .gpa = gpa };
    }

    fn deinit(self: OwnedArgv) void {
        for (self.args) |a| self.gpa.free(a);
        self.gpa.free(self.args);
        self.gpa.free(self.ptrs);
    }
};

/// Fork, exec `argv_ptrs` (an execve-ready, null-terminated pointer vector), and
/// wait for the child. The child side is async-signal-safe: only `execve` and
/// `exit_group`, no allocation. Runs on a worker thread.
fn runChild(argv_ptrs: [:null]?[*:0]const u8) ProcResult {
    const spawn_failed: ProcResult = .{ .ok = false, .exit_code = null, .term_signal = null, .spawn_failed = true };

    const path = argv_ptrs[0].?;
    const argv_z: [*:null]const ?[*:0]const u8 = @ptrCast(argv_ptrs.ptr);

    const forked = linux.fork();
    const pid: isize = @bitCast(forked);
    if (pid < 0) return spawn_failed;
    if (pid == 0) { // CHILD — async-signal-safe only until the image is replaced
        _ = linux.execve(path, argv_z, &empty_envp);
        linux.exit_group(127); // execve returned → target missing/not executable
    }

    var status: u32 = 0;
    while (true) {
        const w = linux.waitpid(@intCast(pid), &status, 0);
        if (@as(isize, @bitCast(w)) < 0) {
            if (linux.errno(w) == .INTR) continue; // interrupted → retry
            return spawn_failed;
        }
        break;
    }
    return decodeStatus(status);
}

/// Decode a `wait(2)` status word into a `ProcResult` (no libc W* macros).
fn decodeStatus(status: u32) ProcResult {
    if ((status & 0x7f) == 0) { // exited normally
        const code: u8 = @intCast((status >> 8) & 0xff);
        return .{ .ok = code == 0, .exit_code = code, .term_signal = null, .spawn_failed = false };
    }
    const sig: u8 = @intCast(status & 0x7f); // killed by a signal
    return .{ .ok = false, .exit_code = null, .term_signal = sig, .spawn_failed = false };
}

// ── tests ────────────────────────────────────────────────────────────────────

test "Loop.poll: pipe becomes readable within timeout" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    try std.testing.expect(@as(isize, @bitCast(linux.pipe(&fds))) >= 0);
    const r = fds[0];
    const wfd = fds[1];
    defer _ = linux.close(r);
    defer _ = linux.close(wfd);

    // Nothing written yet → a short poll must time out (0 ready).
    var pfd = [_]Loop.pollfd{.{ .fd = r, .events = Loop.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try Loop.poll(&pfd, 20));

    // Write a byte, then poll must report the read end readable.
    const one = [_]u8{'x'};
    try std.testing.expect(@as(isize, @bitCast(linux.write(wfd, &one, 1))) == 1);
    pfd[0].revents = 0;
    const n = try Loop.poll(&pfd, 1000);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(pfd[0].revents & Loop.POLL.IN != 0);
}

test "Loop.tick: runs maintenance callbacks in order" {
    const S = struct {
        var counter: u32 = 0;
        fn bump(ctx: ?*anyopaque) void {
            const p: *u32 = @ptrCast(@alignCast(ctx.?));
            p.* += 1;
            counter += 1;
        }
    };
    S.counter = 0;
    var mine: u32 = 0;

    var loop: Loop = .{};
    defer loop.deinit(std.testing.allocator);
    try loop.addTask(std.testing.allocator, .{ .context = &mine, .run = S.bump });
    try loop.addTask(std.testing.allocator, .{ .context = &mine, .run = S.bump });

    loop.tick();
    try std.testing.expectEqual(@as(u32, 2), S.counter);
    try std.testing.expectEqual(@as(u32, 2), mine);
    loop.tick();
    try std.testing.expectEqual(@as(u32, 4), S.counter);
}

test "JobTable: claim/finish/drain handoff + slot reuse under N>capacity" {
    const Job = struct {
        value: u32 = 0,
        state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0), // 0 unset, 1 set by worker
    };
    const Table = JobTable(2, Job);

    const Worker = struct {
        fn run(job: *Job, v: u32) void {
            // Simulate work on the worker thread, then hand the slot back.
            job.value = v;
            job.state.store(1, .release);
            g_table.finish(job);
        }
        var g_table: *Table = undefined;
    };

    var table: Table = .{};
    Worker.g_table = &table;

    const Drainer = struct {
        var sum: u32 = 0;
        var count: u32 = 0;
        fn onDone(job: *Job) void {
            std.testing.expect(job.state.load(.acquire) == 1) catch unreachable; // visible write
            sum += job.value;
            count += 1;
        }
    };
    Drainer.sum = 0;
    Drainer.count = 0;

    // Push 6 jobs through a 2-slot table: capacity forces reuse across rounds.
    var pushed: u32 = 0;
    var next_val: u32 = 1;
    while (pushed < 6) {
        // Fill every currently-free slot and spawn a worker for each.
        var threads: [2]?std.Thread = .{ null, null };
        var launched: usize = 0;
        while (pushed < 6) {
            const job = table.claim() orelse break; // table full → go drain
            const v = next_val;
            next_val += 1;
            pushed += 1;
            threads[launched] = try std.Thread.spawn(.{}, Worker.run, .{ job, v });
            launched += 1;
        }
        try std.testing.expect(launched >= 1);
        for (threads[0..launched]) |t| t.?.join();

        // All launched workers have finished → both were RUNNING, now DONE.
        try std.testing.expectEqual(launched, table.busy());
        table.drain(Drainer.onDone);
        try std.testing.expectEqual(@as(usize, 0), table.busy()); // recycled to FREE
    }

    try std.testing.expectEqual(@as(u32, 6), Drainer.count);
    try std.testing.expectEqual(@as(u32, 1 + 2 + 3 + 4 + 5 + 6), Drainer.sum);
}

test "JobTable.spawnDetached: /bin/true succeeds, /bin/false fails (real fork/exec)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Skip cleanly on the rare host without coreutils in /bin.
    if (@as(isize, @bitCast(linux.access("/bin/true", linux.F_OK))) < 0) return error.SkipZigTest;
    if (@as(isize, @bitCast(linux.access("/bin/false", linux.F_OK))) < 0) return error.SkipZigTest;

    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(4, Job);

    const H = struct {
        // Runs on the worker thread; visible to the loop via the DONE release store.
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        var ok_count: u32 = 0;
        var fail_count: u32 = 0;
        fn onDone(job: *Job) void {
            if (job.res.ok) ok_count += 1 else fail_count += 1;
        }
    };
    H.ok_count = 0;
    H.fail_count = 0;

    const gpa = std.testing.allocator;
    var table: Table = .{};

    try table.spawnDetached(gpa, &.{"/bin/true"}, H.report);
    try table.spawnDetached(gpa, &.{"/bin/false"}, H.report);
    // Both slots are RUNNING immediately (claim marks them before returning).
    try std.testing.expectEqual(@as(usize, 2), table.busy());

    // Wait (bounded) until both detached workers publish DONE, then drain.
    var spins: usize = 0;
    while (doneCount(&table) < 2) {
        spins += 1;
        try std.testing.expect(spins < 5_000_000_000); // guard against a hang
    }
    table.drain(H.onDone);

    try std.testing.expectEqual(@as(u32, 1), H.ok_count);
    try std.testing.expectEqual(@as(u32, 1), H.fail_count);
    try std.testing.expectEqual(@as(usize, 0), table.busy());
}

/// Test helper: number of slots currently in the DONE state.
fn doneCount(table: anytype) usize {
    var n: usize = 0;
    for (&table.slots) |*s| {
        if (s.state.load(.acquire) == 2) n += 1; // State.done
    }
    return n;
}
