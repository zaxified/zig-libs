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
//!  * `Waker`           — eventfd (self-pipe fallback) that a worker writes on job
//!                        completion so the loop's `poll` returns at once; the
//!                        analogue of libuv's `uv_async_send`.
//!  * `Timers`          — one-shot / repeating timers in a min-heap with an injected
//!                        millisecond clock; feeds the `poll` timeout (`uv_timer_*`).
//!  * `Env`             — the child's environment for `spawnDetachedEnv`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Single-owner `poll(2)` loop plus a lock-free fork/exec job table, for offloading blocking work off the loop thread.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
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
    /// Timers driven by this loop. The loop only stores them; the owner passes
    /// the clock (`nowMs`) to `timeoutMs` / `runTimers`.
    timers: Timers = .{},

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
        self.timers.deinit(gpa);
    }

    /// Monotonic clock in milliseconds (`CLOCK_MONOTONIC`), the value to hand to
    /// `timeoutMs` / `runTimers`. Tests pass a fake clock instead.
    pub fn nowMs() error{ClockFailed}!u64 {
        var ts: linux.timespec = undefined;
        if (@as(isize, @bitCast(linux.clock_gettime(.MONOTONIC, &ts))) < 0) return error.ClockFailed;
        const sec: u64 = @intCast(ts.sec);
        const nsec: u64 = @intCast(ts.nsec);
        return sec *| 1000 +| nsec / 1_000_000;
    }

    /// The `poll` timeout to use this tick: `caller_ms` (-1 = none) shortened to
    /// the next timer's due time. See `Timers.pollTimeout`.
    pub fn timeoutMs(self: *const Loop, now: u64, caller_ms: i32) i32 {
        return self.timers.pollTimeout(now, caller_ms);
    }

    /// Fire every timer due at `now`. Loop-thread only. See `Timers.run`.
    pub fn runTimers(self: *Loop, now: u64) usize {
        return self.timers.run(now);
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
            state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@backingInt(State.free)),
            job: Job = undefined,
        };

        slots: [N]Slot = @as([N]Slot, @splat(.{})),
        /// Optional completion waker (`setWaker`). Written by the loop thread only
        /// while no job is busy, read by workers in `finish`.
        waker: ?*const Waker = null,
        /// Workers currently inside `finish` with a waker set (see `quiesce`).
        finishing: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

        /// Reserve a FREE slot and mark it RUNNING; returns a pointer to its Job
        /// for the caller/worker to populate, or null when all slots are busy.
        /// Loop-thread only. The returned Job is NOT zeroed — the caller owns it.
        pub fn claim(self: *Self) ?*Job {
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @backingInt(State.free)) continue;
                s.state.store(@backingInt(State.running), .release);
                return &s.job;
            }
            return null;
        }

        /// Worker-thread handoff: publish a RUNNING slot as DONE for the loop's
        /// next `drain`. All writes to `job` made before this call are visible to
        /// the draining loop thread.
        ///
        /// With a waker set (`setWaker`) the DONE store is followed by `Waker.wake`,
        /// so a loop blocked in `poll` on the waker fd returns immediately.
        pub fn finish(self: *Self, job: *Job) void {
            const slot: *Slot = @fieldParentPtr("job", job);
            const w = self.waker orelse {
                slot.state.store(@backingInt(State.done), .release);
                return;
            };
            // Announce BEFORE publishing DONE: a loop that observed DONE and then
            // calls `quiesce` is guaranteed to see this worker still inside.
            _ = self.finishing.fetchAdd(1, .acq_rel);
            slot.state.store(@backingInt(State.done), .release);
            w.wake();
            _ = self.finishing.fetchSub(1, .release);
        }

        /// Attach (or detach, with null) the waker that `finish` signals. Refused
        /// with `error.Busy` while any slot is RUNNING/DONE, so no worker can read
        /// the pointer mid-change; it also calls `quiesce()` itself, since a worker
        /// past its DONE store may still hold the old waker. Loop-thread only. The
        /// waker must outlive every job; `quiesce()` is MANDATORY before
        /// `Waker.deinit` and before destroying the table.
        pub fn setWaker(self: *Self, w: ?*const Waker) error{Busy}!void {
            if (self.busy() != 0) return error.Busy;
            self.quiesce();
            self.waker = w;
        }

        /// Block until no worker is still inside `finish`. Call after the last job
        /// was observed DONE and before destroying the table or closing the
        /// waker: a worker touches both for a few instructions after its DONE
        /// store. Cheap no-op when no waker is set. Loop-thread only.
        pub fn quiesce(self: *Self) void {
            while (self.finishing.load(.acquire) != 0) std.Thread.yield() catch {};
        }

        /// Loop-thread rollback: return a claimed-but-unused slot to FREE without
        /// going through DONE (e.g. a worker failed to launch).
        pub fn release(self: *Self, job: *Job) void {
            _ = self;
            const slot: *Slot = @fieldParentPtr("job", job);
            slot.state.store(@backingInt(State.free), .release);
        }

        /// Reap every DONE slot: call `on_done(&job)` then recycle it to FREE.
        /// Loop-thread only.
        pub fn drain(self: *Self, on_done: OnDone) void {
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @backingInt(State.done)) continue;
                on_done(&s.job);
                s.state.store(@backingInt(State.free), .release);
            }
        }

        /// Number of slots not currently FREE (RUNNING + DONE). Loop-thread only.
        pub fn busy(self: *const Self) usize {
            var n: usize = 0;
            for (&self.slots) |*s| {
                if (s.state.load(.acquire) != @backingInt(State.free)) n += 1;
            }
            return n;
        }

        pub const SpawnError = error{
            TableFull,
            EmptyArgv,
            ThreadSpawnFailed,
        } || EnvError;

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
            return self.spawnDetachedEnv(gpa, argv, .empty, report);
        }

        /// `spawnDetached` with an explicit child environment (`Env`). Like
        /// libuv's `uv_process_options_t.env` the environment is replaced as a
        /// whole: `.empty` (the `spawnDetached` default), `.inherit` (a snapshot of
        /// the parent's, taken now on the loop thread) or `.list` of `NAME=value`.
        /// The snapshot/copy is owned by the worker and freed with the argv.
        pub fn spawnDetachedEnv(
            self: *Self,
            gpa: std.mem.Allocator,
            argv: []const []const u8,
            env: Env,
            report: Report,
        ) SpawnError!void {
            if (argv.len == 0) return error.EmptyArgv;
            const job = self.claim() orelse return error.TableFull;
            errdefer self.release(job);

            var owned = try OwnedArgv.init(gpa, argv);
            errdefer owned.deinit();

            var owned_env = try OwnedEnv.init(gpa, env);
            errdefer owned_env.deinit();

            const ctx = try gpa.create(SpawnCtx);
            errdefer gpa.destroy(ctx);
            ctx.* = .{ .table = self, .job = job, .argv = owned, .envp = owned_env, .report = report, .gpa = gpa };

            const th = std.Thread.spawn(.{}, spawnEntry, .{ctx}) catch return error.ThreadSpawnFailed;
            th.detach();
        }

        const SpawnCtx = struct {
            table: *Self,
            job: *Job,
            argv: OwnedArgv,
            envp: OwnedEnv,
            report: Report,
            gpa: std.mem.Allocator,
        };

        fn spawnEntry(ctx: *SpawnCtx) void {
            const res = runChild(ctx.argv.ptrs, ctx.envp.ptrs);
            ctx.report(ctx.job, res);
            // Release our own heap BEFORE publishing DONE: once the loop observes
            // DONE it may tear down (or leak-check) the allocator, and this
            // detached thread must not touch it again after that signal.
            const table = ctx.table;
            const job = ctx.job;
            ctx.argv.deinit();
            ctx.envp.deinit();
            ctx.gpa.destroy(ctx);
            table.finish(job);
        }
    };
}

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
        while (i < argv.len) : (i += 1) args[i] = try gpa.dupeSentinel(u8, argv[i], 0);

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
fn runChild(argv_ptrs: [:null]?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) ProcResult {
    const spawn_failed: ProcResult = .{ .ok = false, .exit_code = null, .term_signal = null, .spawn_failed = true };

    const path = argv_ptrs[0].?;
    const argv_z: [*:null]const ?[*:0]const u8 = @ptrCast(argv_ptrs.ptr);

    const forked = linux.fork();
    const pid: isize = @bitCast(forked);
    if (pid < 0) return spawn_failed;
    if (pid == 0) { // CHILD — async-signal-safe only until the image is replaced
        // Close inherited fds (>= 3, keeping stdio) so the exec'd target cannot
        // leak or act on the parent's listen/control sockets. Best-effort and
        // async-signal-safe (a single syscall); on a pre-5.9 kernel without
        // close_range this is a no-op ENOSYS and the caller's CLOEXEC-at-creation
        // convention remains the backstop.
        _ = linux.close_range(3, std.math.maxInt(i32), @bitCast(@as(u32, 0)));
        _ = linux.execve(path, argv_z, envp);
        linux.exit_group(127); // execve returned → target missing/not executable
    }

    var status: i32 = 0;
    while (true) {
        const w = linux.waitpid(@intCast(pid), &status, 0);
        if (@as(isize, @bitCast(w)) < 0) {
            if (linux.errno(w) == .INTR) continue; // interrupted → retry
            return spawn_failed;
        }
        break;
    }
    return decodeStatus(@bitCast(status));
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

// ── Waker ────────────────────────────────────────────────────────────────────

/// Wakes a loop blocked in `Loop.poll`, from any thread: the analogue of libuv's
/// `uv_async_send`. Backed by a non-blocking, close-on-exec `eventfd`; when the
/// kernel refuses one (ENOSYS/EMFILE...) `init` falls back to a non-blocking
/// self-pipe. Put `fd()` in the pollset with `POLL.IN`; when it is readable call
/// `clear()` and then look at what changed (`JobTable.drain`).
///
/// Like `uv_async_send`, wakes are coalesced: any number of `wake` calls before the
/// next `clear` produce a single readable edge, and a wake is never lost (a `wake`
/// after `clear` leaves the fd readable again).
pub const Waker = struct {
    read_fd: i32,
    /// Equal to `read_fd` for an eventfd; the pipe's write end otherwise.
    write_fd: i32,

    pub const InitError = error{WakerFailed};

    pub fn init() InitError!Waker {
        const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        if (@as(isize, @bitCast(rc)) >= 0) {
            const fd_: i32 = @intCast(rc);
            return .{ .read_fd = fd_, .write_fd = fd_ };
        }
        return initPipe();
    }

    /// The self-pipe flavour of `init` (also reachable directly, for tests and
    /// for kernels without eventfd).
    pub fn initPipe() InitError!Waker {
        var fds: [2]i32 = undefined;
        if (@as(isize, @bitCast(linux.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true }))) < 0) return error.WakerFailed;
        return .{ .read_fd = fds[0], .write_fd = fds[1] };
    }

    /// Close the fds. With a `JobTable` using this waker, call `table.quiesce()`
    /// first (after the last job was DONE): a worker may still be inside `wake`.
    pub fn deinit(self: *Waker) void {
        _ = linux.close(self.read_fd);
        if (self.write_fd != self.read_fd) _ = linux.close(self.write_fd);
        self.* = undefined;
    }

    /// The fd to register for `POLL.IN`.
    pub fn fd(self: *const Waker) i32 {
        return self.read_fd;
    }

    /// Make `fd()` readable. Thread-safe, async-signal-safe, never blocks and
    /// never fails: a full pipe / saturated counter already means "readable".
    pub fn wake(self: *const Waker) void {
        const one: u64 = 1;
        const bytes: []const u8 = if (self.write_fd == self.read_fd) std.mem.asBytes(&one) else std.mem.asBytes(&one)[0..1];
        while (true) {
            const rc = linux.write(self.write_fd, bytes.ptr, bytes.len);
            if (@as(isize, @bitCast(rc)) < 0 and linux.errno(rc) == .INTR) continue;
            return; // success, or EAGAIN = already pending
        }
    }

    /// Consume all pending wakes so `fd()` stops being readable until the next
    /// `wake`. Loop order must be `clear()` THEN
    /// `drain()`: drain-then-clear can erase the wake of a job finishing in between. Loop-thread only. Bounded: at most pipe-capacity / 64 reads.
    pub fn clear(self: *const Waker) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const rc = linux.read(self.read_fd, &buf, buf.len);
            if (@as(isize, @bitCast(rc)) < 0) {
                if (linux.errno(rc) == .INTR) continue;
                return; // EAGAIN: drained
            }
            if (rc == 0) return;
            // An eventfd yields its whole counter in one 8-byte read; the next read
            // is EAGAIN. A pipe may hold more: keep reading until it says so.
        }
    }
};

// ── Timers ───────────────────────────────────────────────────────────────────

/// One-shot and repeating timers in a binary min-heap ordered by `(due, start
/// order)`, modelled on libuv's `uv_timer_*` (docs.libuv.org, "uv_timer_t"):
///
///  * `start(h, now, timeout, repeat)` arms the timer to fire `timeout` ms after
///    `now`; with `repeat > 0` it then re-fires every `repeat` ms. Starting an active
///    timer re-arms it.
///  * a timeout of 0 fires on the next `run`; timers due at the same instant fire in
///    the order they were started.
///  * a repeating timer is rescheduled to `run`'s `now + repeat` BEFORE its callback
///    runs (so no drift correction, and the callback may `stop`/`close` it).
///  * `again(h, now)` stops the timer and, if its repeat is non-zero, restarts it
///    with `repeat` as the timeout; with repeat 0 it just stops.
///  * `stop` leaves the handle usable (`start`/`again` re-arm it); `close` frees it.
///
/// The clock is injected as a millisecond counter (`Loop.nowMs()` in production, a
/// plain integer in tests); a wall-clock jump therefore cannot reorder timers.
///
/// Bounds: at most `max_timers` handles exist at once (`error.TooManyTimers`);
/// `add` is the only call that allocates and it reserves heap room for every slot,
/// so `start`/`stop`/`again`/`run` never allocate and never fail on memory.
/// Handles carry a generation, so a stale handle (closed, slot reused) is
/// `error.InvalidHandle`, never another timer. Owner-thread only.
pub const Timers = struct {
    pub const Handle = struct { index: u32, generation: u32 };
    /// Runs on the loop thread from `run`. May call any `Timers` method,
    /// including `add` (needs the allocator, so it is the caller's to keep).
    pub const Callback = *const fn (context: ?*anyopaque, timer: Handle) void;
    pub const AddError = error{ OutOfMemory, TooManyTimers };
    pub const HandleError = error{InvalidHandle};

    const none = std.math.maxInt(u32);

    const Slot = struct {
        generation: u32 = 0,
        in_use: bool = false,
        cb: Callback = undefined,
        context: ?*anyopaque = null,
        due: u64 = 0,
        repeat: u64 = 0,
        seq: u64 = 0,
        heap_pos: u32 = none,
        next_free: u32 = none,
    };

    slots: std.ArrayList(Slot) = .empty,
    /// Slot indices; `heap.items[0]` is the next timer to fire.
    heap: std.ArrayList(u32) = .empty,
    free_head: u32 = none,
    next_seq: u64 = 0,
    /// Upper bound on simultaneously existing handles (active or not).
    max_timers: u32 = 65536,

    pub fn deinit(self: *Timers, gpa: std.mem.Allocator) void {
        self.slots.deinit(gpa);
        self.heap.deinit(gpa);
        self.* = .{};
    }

    /// Create an inactive timer. Returns `error.TooManyTimers` at `max_timers`.
    pub fn add(self: *Timers, gpa: std.mem.Allocator, cb: Callback, context: ?*anyopaque) AddError!Handle {
        if (self.free_head != none) {
            const idx = self.free_head;
            const s = &self.slots.items[idx];
            self.free_head = s.next_free;
            // A reused slot must not inherit the previous timer's schedule.
            s.* = .{ .generation = s.generation, .in_use = true, .cb = cb, .context = context };
            return .{ .index = idx, .generation = s.generation };
        }
        if (self.slots.items.len >= self.max_timers) return error.TooManyTimers;
        try self.slots.ensureUnusedCapacity(gpa, 1);
        try self.heap.ensureTotalCapacity(gpa, self.slots.items.len + 1);
        const idx: u32 = @intCast(self.slots.items.len);
        self.slots.appendAssumeCapacity(.{ .in_use = true, .cb = cb, .context = context });
        return .{ .index = idx, .generation = 0 };
    }

    fn slotOf(self: *Timers, h: Handle) HandleError!*Slot {
        if (h.index >= self.slots.items.len) return error.InvalidHandle;
        const s = &self.slots.items[h.index];
        if (!s.in_use or s.generation != h.generation) return error.InvalidHandle;
        return s;
    }

    /// Arm `h` to fire `timeout_ms` after `now`, then every `repeat_ms` (0 = once).
    pub fn start(self: *Timers, h: Handle, now: u64, timeout_ms: u64, repeat_ms: u64) HandleError!void {
        const s = try self.slotOf(h);
        if (s.heap_pos != none) self.removeAt(s.heap_pos);
        s.repeat = repeat_ms;
        s.due = now +| timeout_ms;
        self.arm(h.index);
    }

    /// Disarm `h` (no-op if inactive). The handle stays valid.
    pub fn stop(self: *Timers, h: Handle) HandleError!void {
        const s = try self.slotOf(h);
        if (s.heap_pos != none) self.removeAt(s.heap_pos);
    }

    /// libuv `uv_timer_again`: stop, and if the repeat interval is non-zero
    /// restart with it as the timeout.
    pub fn again(self: *Timers, h: Handle, now: u64) HandleError!void {
        const s = try self.slotOf(h);
        if (s.heap_pos != none) self.removeAt(s.heap_pos);
        if (s.repeat == 0) return;
        s.due = now +| s.repeat;
        self.arm(h.index);
    }

    /// Change the repeat interval; takes effect at the next (re)schedule, as in libuv.
    pub fn setRepeat(self: *Timers, h: Handle, repeat_ms: u64) HandleError!void {
        (try self.slotOf(h)).repeat = repeat_ms;
    }

    pub fn getRepeat(self: *Timers, h: Handle) HandleError!u64 {
        return (try self.slotOf(h)).repeat;
    }

    pub fn isActive(self: *Timers, h: Handle) HandleError!bool {
        return (try self.slotOf(h)).heap_pos != none;
    }

    /// Milliseconds until `h` fires (0 if due, inactive or unknown), like `uv_timer_get_due_in`.
    pub fn dueIn(self: *Timers, h: Handle, now: u64) u64 {
        const s = self.slotOf(h) catch return 0;
        if (s.heap_pos == none or s.due <= now) return 0;
        return s.due - now;
    }

    /// Stop `h` and release its slot; the handle (and copies of it) become invalid.
    pub fn close(self: *Timers, h: Handle) HandleError!void {
        const s = try self.slotOf(h);
        if (s.heap_pos != none) self.removeAt(s.heap_pos);
        s.in_use = false;
        s.generation +%= 1;
        s.cb = undefined;
        s.context = null;
        s.next_free = self.free_head;
        self.free_head = h.index;
    }

    /// Number of armed timers.
    pub fn activeCount(self: *const Timers) usize {
        return self.heap.items.len;
    }

    /// The `poll` timeout for this tick: `caller_ms` (-1 = block forever) lowered to
    /// the next timer's due time (0 if one is already due), never above i32 max.
    pub fn pollTimeout(self: *const Timers, now: u64, caller_ms: i32) i32 {
        if (self.heap.items.len == 0) return caller_ms;
        const due = self.slots.items[self.heap.items[0]].due;
        const wait: u64 = if (due <= now) 0 else due - now;
        const w: i32 = @intCast(@min(wait, std.math.maxInt(i32)));
        return if (caller_ms < 0) w else @min(w, caller_ms);
    }

    /// Fire every timer due at `now`, earliest first (ties in start order), and
    /// return how many fired. A timer started from inside a callback waits for the
    /// next `run` even if it is already due, so a callback that keeps re-arming
    /// itself with 0 ms cannot hold the loop. (The check looks at the heap top only:
    /// an older timer sorted behind such a new one fires one `run` later;
    /// `pollTimeout` reports 0 so the next poll does not block.)
    pub fn run(self: *Timers, now: u64) usize {
        const horizon = self.next_seq;
        var fired: usize = 0;
        while (self.heap.items.len > 0) {
            const idx = self.heap.items[0];
            var s = &self.slots.items[idx];
            if (s.due > now or s.seq >= horizon) break;
            self.removeAt(0);
            const cb = s.cb;
            const context = s.context;
            const h: Handle = .{ .index = idx, .generation = s.generation };
            if (s.repeat != 0) {
                s.due = now +| s.repeat;
                self.arm(idx);
            }
            s = undefined; // the callback may grow `slots`
            fired += 1;
            cb(context, h);
        }
        return fired;
    }

    // -- heap ----------------------------------------------------------------

    fn less(self: *const Timers, a: u32, b: u32) bool {
        const x = &self.slots.items[a];
        const y = &self.slots.items[b];
        if (x.due != y.due) return x.due < y.due;
        return x.seq < y.seq;
    }

    fn place(self: *Timers, pos: usize, idx: u32) void {
        self.heap.items[pos] = idx;
        self.slots.items[idx].heap_pos = @intCast(pos);
    }

    /// Insert slot `idx` (due/repeat already set) with a fresh start-order number.
    /// Room was reserved by `add`, so this cannot fail.
    fn arm(self: *Timers, idx: u32) void {
        self.slots.items[idx].seq = self.next_seq;
        self.next_seq +%= 1;
        self.heap.appendAssumeCapacity(idx);
        const pos = self.heap.items.len - 1;
        self.place(pos, idx);
        self.siftUp(pos);
    }

    fn removeAt(self: *Timers, pos: usize) void {
        const gone = self.heap.items[pos];
        self.slots.items[gone].heap_pos = none;
        const last = self.heap.pop().?;
        if (pos == self.heap.items.len) return; // it was the last element
        self.place(pos, last);
        self.siftDown(pos);
        self.siftUp(pos);
    }

    fn siftUp(self: *Timers, start_pos: usize) void {
        var pos = start_pos;
        const idx = self.heap.items[pos];
        while (pos > 0) {
            const parent = (pos - 1) / 2;
            const p = self.heap.items[parent];
            if (!self.less(idx, p)) break;
            self.place(pos, p);
            pos = parent;
        }
        self.place(pos, idx);
    }

    fn siftDown(self: *Timers, start_pos: usize) void {
        var pos = start_pos;
        const idx = self.heap.items[pos];
        const n = self.heap.items.len;
        while (true) {
            var child = 2 * pos + 1;
            if (child >= n) break;
            if (child + 1 < n and self.less(self.heap.items[child + 1], self.heap.items[child])) child += 1;
            if (!self.less(self.heap.items[child], idx)) break;
            self.place(pos, self.heap.items[child]);
            pos = child;
        }
        self.place(pos, idx);
    }
};

// ── Env ──────────────────────────────────────────────────────────────────────

/// The environment a detached child gets (`JobTable.spawnDetachedEnv`). Like
/// libuv's `uv_process_options_t.env` it replaces the environment as a whole.
pub const Env = union(enum) {
    /// No variables at all (the `spawnDetached` default). Such a child needs absolute exec paths.
    empty,
    /// A snapshot of the parent's environment, read libc-free from
    /// `/proc/self/environ` when the job is submitted. That file is the
    /// environment at exec time: a later `setenv`/`putenv` is NOT reflected.
    inherit,
    /// Exactly these `NAME=value` strings (each with a non-empty name, no NUL).
    list: []const []const u8,
};

/// Hard bounds on a child environment (a request over either is `error.EnvTooLarge`).
pub const env_max_entries = 4096;
pub const env_max_bytes = 1 << 20;

pub const EnvError = error{
    /// A `.list` entry has no `=`, an empty name, or an embedded NUL.
    InvalidEnv,
    /// More than `env_max_entries` entries or `env_max_bytes` bytes.
    EnvTooLarge,
    /// `.inherit` could not read `/proc/self/environ` (procfs not mounted).
    EnvUnavailable,
} || std.mem.Allocator.Error;

/// An owned, execve-ready environment block: packed NUL-terminated strings plus a
/// null-terminated pointer vector. `.empty` allocates nothing.
const OwnedEnv = struct {
    buf: []u8,
    ptrs: [*:null]const ?[*:0]const u8,
    vec: []?[*:0]const u8,
    gpa: std.mem.Allocator,

    fn init(gpa: std.mem.Allocator, env: Env) EnvError!OwnedEnv {
        var buf: []u8 = &.{};
        switch (env) {
            .empty => return .{ .buf = buf, .ptrs = &empty_envp, .vec = &.{}, .gpa = gpa },
            .list => |items| {
                if (items.len > env_max_entries) return error.EnvTooLarge;
                var total: usize = 0;
                for (items) |e| {
                    const eq = std.mem.findScalar(u8, e, '=') orelse return error.InvalidEnv;
                    if (eq == 0 or std.mem.findScalar(u8, e, 0) != null) return error.InvalidEnv;
                    total += e.len + 1;
                    if (total > env_max_bytes) return error.EnvTooLarge;
                }
                buf = try gpa.alloc(u8, total);
                var at: usize = 0;
                for (items) |e| {
                    @memcpy(buf[at..][0..e.len], e);
                    buf[at + e.len] = 0;
                    at += e.len + 1;
                }
            },
            .inherit => buf = try readEnviron(gpa),
        }
        errdefer gpa.free(buf);
        const count = splitEnviron(buf, null);
        if (count > env_max_entries) return error.EnvTooLarge;
        const vec = try gpa.alloc(?[*:0]const u8, count + 1);
        _ = splitEnviron(buf, vec);
        vec[count] = null;
        return .{ .buf = buf, .ptrs = @ptrCast(vec.ptr), .vec = vec, .gpa = gpa };
    }

    fn deinit(self: OwnedEnv) void {
        self.gpa.free(self.vec);
        self.gpa.free(self.buf);
    }
};

/// Count the non-empty NUL-terminated strings of `buf` (which must end in NUL or
/// be empty) and, when `out` is given, store a pointer to each (`out` needs room).
fn splitEnviron(buf: []u8, out: ?[]?[*:0]const u8) usize {
    var n: usize = 0;
    var start: usize = 0;
    for (buf, 0..) |c, i| {
        if (c != 0) continue;
        if (i > start) {
            if (out) |o| o[n] = @ptrCast(buf.ptr + start);
            n += 1;
        }
        start = i + 1;
    }
    return n;
}

/// Read `/proc/self/environ` (bounded by `env_max_bytes`) into an owned buffer
/// that ends in NUL.
fn readEnviron(gpa: std.mem.Allocator) EnvError![]u8 {
    const orc = linux.open("/proc/self/environ", .{ .CLOEXEC = true }, 0);
    if (@as(isize, @bitCast(orc)) < 0) return error.EnvUnavailable;
    const fd_: i32 = @intCast(orc);
    defer _ = linux.close(fd_);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd_, &chunk, chunk.len);
        if (@as(isize, @bitCast(rc)) < 0) {
            if (linux.errno(rc) == .INTR) continue;
            return error.EnvUnavailable;
        }
        if (rc == 0) break;
        if (list.items.len + rc > env_max_bytes) return error.EnvTooLarge;
        try list.appendSlice(gpa, chunk[0..rc]);
    }
    if (list.items.len == 0 or list.items[list.items.len - 1] != 0) {
        if (list.items.len + 1 > env_max_bytes) return error.EnvTooLarge;
        try list.append(gpa, 0);
    }
    return list.toOwnedSlice(gpa);
}

// ── tests ────────────────────────────────────────────────────────────────────

test "decodeStatus: normal exit (zero and nonzero code) and signal-killed (with/without core dump)" {
    // Normal exit: low 7 bits of the wait(2) status are 0; the code is bits 8..15.
    try std.testing.expectEqual(ProcResult{ .ok = true, .exit_code = 0, .term_signal = null, .spawn_failed = false }, decodeStatus(0 << 8));
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = 1, .term_signal = null, .spawn_failed = false }, decodeStatus(1 << 8));
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = 137, .term_signal = null, .spawn_failed = false }, decodeStatus(137 << 8));

    // Killed by a signal: low 7 bits are the signal number (nonzero), no exit code.
    // SIGKILL = 9.
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = null, .term_signal = 9, .spawn_failed = false }, decodeStatus(9));
    // The core-dump flag (bit 7, 0x80) must not leak into the reported signal.
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = null, .term_signal = 9, .spawn_failed = false }, decodeStatus(0x80 | 9));
    // SIGSEGV = 11.
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = null, .term_signal = 11, .spawn_failed = false }, decodeStatus(11));
    // A high real-time-signal number (bit 6 set) must round-trip too.
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = null, .term_signal = 64, .spawn_failed = false }, decodeStatus(64));
}

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

test "JobTable.release: rolls a claimed-but-unused slot back to FREE, not DONE" {
    const Job = struct { value: u32 = 0 };
    const Table = JobTable(2, Job);
    var table: Table = .{};

    const job = table.claim().?;
    try std.testing.expectEqual(@as(usize, 1), table.busy());
    table.release(job);
    // If release left the slot DONE instead of FREE, `busy()` would still
    // report it as occupied, and `drain` (not `claim`) would be the only way
    // to recycle it.
    try std.testing.expectEqual(@as(usize, 0), table.busy());
    // A genuinely FREE slot is reclaimable by `claim`, without going through
    // `drain` first.
    try std.testing.expect(table.claim() != null);
    try std.testing.expectEqual(@as(usize, 1), table.busy());
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

/// Test helper: run one argv through `spawnDetached` to completion and return
/// what the worker reported.
fn runToCompletion(argv: []const []const u8) !ProcResult {
    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(1, Job);
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        var got: ProcResult = undefined;
        fn onDone(job: *Job) void {
            got = job.res;
        }
    };
    var table: Table = .{};
    try table.spawnDetached(std.testing.allocator, argv, H.report);
    var spins: usize = 0;
    while (doneCount(&table) < 1) {
        spins += 1;
        try std.testing.expect(spins < 5_000_000_000);
    }
    table.drain(H.onDone);
    return H.got;
}

fn haveFile(path: [*:0]const u8) bool {
    return @as(isize, @bitCast(linux.access(path, linux.F_OK))) >= 0;
}

test "spawnDetached: every argv element reaches the child" {
    if (!haveFile("/bin/sh")) return error.SkipZigTest;
    const r = try runToCompletion(&.{ "/bin/sh", "-c", "exit 3" });
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = 3, .term_signal = null, .spawn_failed = false }, r);
}

test "spawnDetached: a target that cannot be exec'd exits 127, not 0" {
    const r = try runToCompletion(&.{"/nonexistent/pollworker-no-such-binary"});
    try std.testing.expectEqual(ProcResult{ .ok = false, .exit_code = 127, .term_signal = null, .spawn_failed = false }, r);
}

test "spawnDetached: the child does not inherit the parent's non-CLOEXEC fds" {
    if (!haveFile("/bin/sh") or !haveFile("/proc/self/fd")) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    try std.testing.expect(@as(isize, @bitCast(linux.pipe(&fds))) >= 0); // no CLOEXEC
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var cmd_buf: [64]u8 = undefined;
    const cmd = try std.mem.print(&cmd_buf, "[ -e /proc/self/fd/{d} ] && exit 1; exit 0", .{fds[1]});
    const r = try runToCompletion(&.{ "/bin/sh", "-c", cmd });
    try std.testing.expectEqual(@as(?u8, 0), r.exit_code);
}

test "spawnDetached: an empty argv is refused and claims no slot" {
    const Job = struct { res: ProcResult = undefined };
    var table: JobTable(1, Job) = .{};
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
    };
    try std.testing.expectError(error.EmptyArgv, table.spawnDetached(std.testing.allocator, &.{}, H.report));
    try std.testing.expectEqual(@as(usize, 0), table.busy());
}

test "spawnDetached: an allocation failure at any step leaks nothing and frees the slot" {
    if (!haveFile("/bin/true")) return error.SkipZigTest;
    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(1, Job);
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        fn onDone(_: *Job) void {}
    };
    var idx: usize = 0;
    while (true) : (idx += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = idx });
        var table: Table = .{};
        table.spawnDetached(failing.allocator(), &.{ "/bin/true", "x" }, H.report) catch |e| {
            try std.testing.expectEqual(error.OutOfMemory, e);
            try std.testing.expectEqual(@as(usize, 0), table.busy());
            try std.testing.expectEqual(failing.allocations, failing.deallocations);
            continue;
        };
        // Every allocation succeeded: let the worker finish and free its own.
        var spins: usize = 0;
        while (doneCount(&table) < 1) {
            spins += 1;
            try std.testing.expect(spins < 5_000_000_000);
        }
        table.drain(H.onDone);
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
        try std.testing.expect(idx >= 4); // the failure sweep did reach the later steps
        break;
    }
}

test "JobTable.drain leaves a RUNNING slot alone" {
    const Job = struct { value: u32 = 0 };
    var table: JobTable(2, Job) = .{};
    const H = struct {
        var calls: u32 = 0;
        fn onDone(_: *Job) void {
            calls += 1;
        }
    };
    H.calls = 0;
    const running = table.claim().?;
    const done = table.claim().?;
    table.finish(done);
    table.drain(H.onDone);
    try std.testing.expectEqual(@as(u32, 1), H.calls);
    try std.testing.expectEqual(@as(usize, 1), table.busy()); // the RUNNING one
    table.finish(running);
    table.drain(H.onDone);
    try std.testing.expectEqual(@as(u32, 2), H.calls);
}

fn ignoreSignal(_: linux.SIG) callconv(.c) void {}

test "Loop.poll: a signal during the wait is Interrupted, not PollFailed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const act: linux.Sigaction = .{ .handler = .{ .handler = ignoreSignal }, .mask = linux.sigemptyset(), .flags = 0 };
    var old: linux.Sigaction = undefined;
    _ = linux.sigaction(.USR1, &act, &old);
    defer _ = linux.sigaction(.USR1, &old, null);

    var fds: [2]i32 = undefined;
    try std.testing.expect(@as(isize, @bitCast(linux.pipe(&fds))) >= 0);
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const S = struct {
        var stop = std.atomic.Value(bool).init(false);
        // Keep signalling until the poller has seen one, so a signal that
        // lands before `poll` blocks cannot make this flaky.
        fn kick(tid: linux.pid_t) void {
            const ts: linux.timespec = .{ .sec = 0, .nsec = 5_000_000 };
            while (!stop.load(.acquire)) {
                _ = linux.tgkill(linux.getpid(), tid, .USR1);
                _ = linux.nanosleep(&ts, null);
            }
        }
    };
    S.stop.store(false, .release);
    const th = try std.Thread.spawn(.{}, S.kick, .{linux.gettid()});
    defer th.join();
    defer S.stop.store(true, .release);

    var pfd = [_]Loop.pollfd{.{ .fd = fds[0], .events = Loop.POLL.IN, .revents = 0 }};
    var tries: usize = 0;
    while (true) : (tries += 1) {
        try std.testing.expect(tries < 1000);
        _ = Loop.poll(&pfd, 10_000) catch |e| {
            try std.testing.expectEqual(error.Interrupted, e);
            break;
        };
    }
}

/// Test helper: number of slots currently in the DONE state.
fn doneCount(table: anytype) usize {
    var n: usize = 0;
    for (&table.slots) |*s| {
        if (s.state.load(.acquire) == 2) n += 1; // State.done
    }
    return n;
}

// ── tests: Waker ─────────────────────────────────────────────────────────────

fn expectReadable(w: *const Waker, want: bool) !void {
    var pfd = [_]Loop.pollfd{.{ .fd = w.fd(), .events = Loop.POLL.IN, .revents = 0 }};
    const n = try Loop.poll(&pfd, 0);
    try std.testing.expectEqual(@as(usize, @intFromBool(want)), n);
}

fn wakerSemantics(w: *Waker) !void {
    try expectReadable(w, false);
    w.wake();
    try expectReadable(w, true);
    // Coalesced: many wakes, one clear, no residue.
    w.wake();
    w.wake();
    w.clear();
    try expectReadable(w, false);
    // Clearing an idle waker is a no-op, not a block.
    w.clear();
    // A wake after a clear is not lost.
    w.wake();
    try expectReadable(w, true);
}

test "Waker (eventfd): wake makes the fd readable, clear resets it, wakes coalesce (uv_async_send)" {
    var w = try Waker.init();
    defer w.deinit();
    try std.testing.expectEqual(w.read_fd, w.write_fd); // a real eventfd on this kernel
    try wakerSemantics(&w);
}

test "Waker (self-pipe fallback): same semantics, including a flood larger than the pipe" {
    var w = try Waker.initPipe();
    defer w.deinit();
    try std.testing.expect(w.read_fd != w.write_fd);
    try wakerSemantics(&w);
    // 100k wakes overflow a 64 KiB pipe: the surplus must be dropped, not block.
    w.clear();
    for (0..100_000) |_| w.wake();
    try expectReadable(&w, true);
    w.clear();
    try expectReadable(&w, false);
}

test "Waker: wake from another thread unblocks a poll with a long timeout" {
    var w = try Waker.init();
    defer w.deinit();
    const T = struct {
        fn run(wk: *const Waker) void {
            wk.wake();
        }
    };
    const th = try std.Thread.spawn(.{}, T.run, .{&w});
    var pfd = [_]Loop.pollfd{.{ .fd = w.fd(), .events = Loop.POLL.IN, .revents = 0 }};
    // Returns as soon as the wake lands; the 60 s bound only matters on failure.
    try std.testing.expectEqual(@as(usize, 1), try Loop.poll(&pfd, 60_000));
    th.join();
    w.clear();
}

test "JobTable.setWaker: spawnDetached completion wakes poll; no drain-by-polling needed" {
    if (!haveFile("/bin/true")) return error.SkipZigTest;
    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(2, Job);
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        var seen: u32 = 0;
        fn onDone(_: *Job) void {
            seen += 1;
        }
    };
    H.seen = 0;
    var w = try Waker.init();
    defer w.deinit();
    var table: Table = .{};
    try table.setWaker(&w);
    try table.spawnDetached(std.testing.allocator, &.{"/bin/true"}, H.report);
    try std.testing.expectError(error.Busy, table.setWaker(null)); // a job is busy

    var pfd = [_]Loop.pollfd{.{ .fd = w.fd(), .events = Loop.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try Loop.poll(&pfd, 60_000));
    w.clear();
    table.drain(H.onDone);
    try std.testing.expectEqual(@as(u32, 1), H.seen);
    table.quiesce();
    try table.setWaker(null);
}

test "JobTable.finish: a direct worker finish also wakes; without a waker nothing is touched" {
    const Job = struct { v: u32 = 0 };
    var table: JobTable(1, Job) = .{};
    var w = try Waker.init();
    defer w.deinit();
    try table.setWaker(&w);
    const job = table.claim().?;
    try expectReadable(&w, false);
    table.finish(job);
    try expectReadable(&w, true);
    table.quiesce();
    try std.testing.expectEqual(@as(u32, 0), table.finishing.load(.acquire));
    w.clear();
    table.drain(struct {
        fn f(_: *Job) void {}
    }.f);
    try table.setWaker(null);
    const job2 = table.claim().?;
    table.finish(job2); // no waker: no wake
    try expectReadable(&w, false);
}

// ── tests: Timers ────────────────────────────────────────────────────────────

const TimerLog = struct {
    var order: [64]u32 = undefined;
    var n: usize = 0;
    fn reset() void {
        n = 0;
    }
    fn rec(ctx: ?*anyopaque, _: Timers.Handle) void {
        order[n] = @intCast(@intFromPtr(ctx));
        n += 1;
    }
    fn got() []const u32 {
        return order[0..n];
    }
};

fn tag(v: usize) ?*anyopaque {
    return @ptrFromInt(v);
}

test "Timers: due order, ties in start order, one-shot fires once (uv_timer_start)" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    TimerLog.reset();
    const a = try t.add(gpa, TimerLog.rec, tag(1));
    const b = try t.add(gpa, TimerLog.rec, tag(2));
    const c = try t.add(gpa, TimerLog.rec, tag(3));
    const d = try t.add(gpa, TimerLog.rec, tag(4));
    try t.start(a, 1000, 50, 0);
    try t.start(b, 1000, 10, 0);
    try t.start(c, 1000, 50, 0); // ties with a, started later
    try t.start(d, 1000, 0, 0); // 0 ms: due now
    try std.testing.expectEqual(@as(usize, 4), t.activeCount());

    try std.testing.expectEqual(@as(usize, 1), t.run(1000));
    try std.testing.expectEqualSlices(u32, &.{4}, TimerLog.got());
    try std.testing.expectEqual(@as(usize, 0), t.run(1009)); // b is at 1010
    try std.testing.expectEqual(@as(usize, 1), t.run(1010));
    // A late run drains everything due, still in (due, start) order.
    try std.testing.expectEqual(@as(usize, 2), t.run(9999));
    try std.testing.expectEqualSlices(u32, &.{ 4, 2, 1, 3 }, TimerLog.got());
    try std.testing.expectEqual(@as(usize, 0), t.run(99999)); // one-shots do not refire
    try std.testing.expectEqual(@as(usize, 0), t.activeCount());
    try std.testing.expect(!(try t.isActive(a))); // handle survives, inactive
}

test "Timers: repeat reschedules from the run's now, before the callback (uv_timer repeat)" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    TimerLog.reset();
    const a = try t.add(gpa, TimerLog.rec, tag(1));
    try t.start(a, 0, 10, 25);
    try std.testing.expectEqual(@as(u64, 10), t.dueIn(a, 0));
    try std.testing.expectEqual(@as(usize, 1), t.run(10));
    try std.testing.expectEqual(@as(u64, 25), t.dueIn(a, 10));
    // Run late (now=100): fires once, next due is now + repeat, not a catch-up burst.
    try std.testing.expectEqual(@as(usize, 1), t.run(100));
    try std.testing.expectEqual(@as(usize, 0), t.run(100));
    try std.testing.expectEqual(@as(u64, 25), t.dueIn(a, 100));
    try std.testing.expectEqual(@as(usize, 2), TimerLog.n);
}

test "Timers: stop, restart, again, setRepeat (uv_timer_stop / uv_timer_again / uv_timer_set_repeat)" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    TimerLog.reset();
    const a = try t.add(gpa, TimerLog.rec, tag(1));
    try t.start(a, 0, 10, 0);
    try t.stop(a);
    try t.stop(a); // idempotent
    try std.testing.expectEqual(@as(usize, 0), t.run(1000));
    try std.testing.expectEqual(@as(usize, 0), t.activeCount());

    // again with repeat 0 only stops
    try t.start(a, 0, 10, 0);
    try t.again(a, 5);
    try std.testing.expect(!(try t.isActive(a)));

    // again with repeat > 0 restarts using repeat as the timeout
    try t.setRepeat(a, 40);
    try std.testing.expectEqual(@as(u64, 40), try t.getRepeat(a));
    try t.again(a, 100);
    try std.testing.expectEqual(@as(u64, 40), t.dueIn(a, 100));
    try std.testing.expectEqual(@as(usize, 0), t.run(139));
    try std.testing.expectEqual(@as(usize, 1), t.run(140));

    // starting an active timer re-arms it instead of adding a second entry
    try t.start(a, 200, 10, 0);
    try t.start(a, 200, 30, 0);
    try std.testing.expectEqual(@as(usize, 1), t.activeCount());
    try std.testing.expectEqual(@as(usize, 0), t.run(210));
    try std.testing.expectEqual(@as(usize, 1), t.run(230));
}

test "Timers.pollTimeout: caps the poll wait at the next due time" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    try std.testing.expectEqual(@as(i32, -1), t.pollTimeout(0, -1)); // no timers: caller's choice
    try std.testing.expectEqual(@as(i32, 250), t.pollTimeout(0, 250));
    const a = try t.add(gpa, TimerLog.rec, null);
    try t.start(a, 1000, 70, 0);
    try std.testing.expectEqual(@as(i32, 70), t.pollTimeout(1000, -1));
    try std.testing.expectEqual(@as(i32, 70), t.pollTimeout(1000, 250));
    try std.testing.expectEqual(@as(i32, 30), t.pollTimeout(1000, 30)); // caller already shorter
    try std.testing.expectEqual(@as(i32, 20), t.pollTimeout(1050, -1));
    try std.testing.expectEqual(@as(i32, 0), t.pollTimeout(1070, -1)); // due
    try std.testing.expectEqual(@as(i32, 0), t.pollTimeout(5000, -1)); // overdue
    // A huge timeout clamps to i32 max instead of wrapping.
    try t.start(a, 0, std.math.maxInt(u64), 0);
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), t.pollTimeout(0, -1));
    // Saturating arithmetic: now near u64 max does not overflow.
    try t.start(a, std.math.maxInt(u64) - 1, 100, 100);
    try std.testing.expectEqual(@as(usize, 1), t.run(std.math.maxInt(u64)));
}

test "Timers: a callback may stop/close timers and start new ones; a 0 ms restart waits for the next run" {
    const gpa = std.testing.allocator;
    const S = struct {
        var t: Timers = .{};
        var victim: Timers.Handle = undefined;
        var self_h: Timers.Handle = undefined;
        var fired_self: u32 = 0;
        var fired_victim: u32 = 0;
        fn killer(_: ?*anyopaque, _: Timers.Handle) void {
            t.close(victim) catch unreachable; // cancel a not-yet-fired timer
        }
        fn victimCb(_: ?*anyopaque, _: Timers.Handle) void {
            fired_victim += 1;
        }
        fn selfRestart(_: ?*anyopaque, h: Timers.Handle) void {
            fired_self += 1;
            t.start(h, 0, 0, 0) catch unreachable; // 0 ms restart from inside the callback
        }
    };
    S.t = .{};
    defer S.t.deinit(gpa);
    S.fired_self = 0;
    S.fired_victim = 0;

    const k = try S.t.add(gpa, S.killer, null);
    S.victim = try S.t.add(gpa, S.victimCb, null);
    try S.t.start(k, 0, 5, 0);
    try S.t.start(S.victim, 0, 6, 0);
    try std.testing.expectEqual(@as(usize, 1), S.t.run(100)); // killer ran, victim cancelled
    try std.testing.expectEqual(@as(u32, 0), S.fired_victim);
    try std.testing.expectError(error.InvalidHandle, S.t.start(S.victim, 0, 1, 0)); // stale

    S.self_h = try S.t.add(gpa, S.selfRestart, null);
    try S.t.start(S.self_h, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 1), S.t.run(0)); // once, not forever
    try std.testing.expectEqual(@as(u32, 1), S.fired_self);
    try std.testing.expectEqual(@as(i32, 0), S.t.pollTimeout(0, -1)); // and it is due again
    try std.testing.expectEqual(@as(usize, 1), S.t.run(0));
    try std.testing.expectEqual(@as(u32, 2), S.fired_self);
}

test "Timers: a callback that adds timers (slot storage grows under run) is safe" {
    const gpa = std.testing.allocator;
    const S = struct {
        var t: Timers = .{};
        var made: u32 = 0;
        fn grow(_: ?*anyopaque, _: Timers.Handle) void {
            for (0..40) |_| {
                const h = t.add(std.testing.allocator, grow2, null) catch return;
                t.start(h, 0, 1, 0) catch unreachable;
                made += 1;
            }
        }
        fn grow2(_: ?*anyopaque, _: Timers.Handle) void {}
    };
    S.t = .{};
    S.made = 0;
    defer S.t.deinit(gpa);
    const h = try S.t.add(gpa, S.grow, null);
    try S.t.start(h, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 1), S.t.run(0));
    try std.testing.expectEqual(@as(u32, 40), S.made);
    try std.testing.expectEqual(@as(usize, 40), S.t.run(1));
}

test "Timers: handles are generation-checked; closed slots are reused" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    const a = try t.add(gpa, TimerLog.rec, tag(1));
    try t.close(a);
    try std.testing.expectError(error.InvalidHandle, t.stop(a));
    try std.testing.expectError(error.InvalidHandle, t.close(a));
    try std.testing.expectEqual(@as(u64, 0), t.dueIn(a, 0));
    const b = try t.add(gpa, TimerLog.rec, tag(2)); // reuses a's slot
    try std.testing.expectEqual(a.index, b.index);
    try std.testing.expect(a.generation != b.generation);
    try std.testing.expectError(error.InvalidHandle, t.start(a, 0, 1, 0)); // a must not arm b
    try t.start(b, 0, 1, 0);
    try std.testing.expectError(error.InvalidHandle, t.stop(.{ .index = 999, .generation = 0 }));
}

test "Timers: the handle count is bounded (TooManyTimers) and allocation failure is an error, never a panic" {
    const gpa = std.testing.allocator;
    var t: Timers = .{ .max_timers = 3 };
    defer t.deinit(gpa);
    const a = try t.add(gpa, TimerLog.rec, null);
    _ = try t.add(gpa, TimerLog.rec, null);
    _ = try t.add(gpa, TimerLog.rec, null);
    try std.testing.expectError(error.TooManyTimers, t.add(gpa, TimerLog.rec, null));
    try t.close(a); // freeing one makes room again
    _ = try t.add(gpa, TimerLog.rec, null);
    try std.testing.expectError(error.TooManyTimers, t.add(gpa, TimerLog.rec, null));

    var idx: usize = 0;
    while (idx < 6) : (idx += 1) {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = idx });
        var u: Timers = .{};
        defer u.deinit(failing.allocator());
        for (0..4) |_| {
            _ = u.add(failing.allocator(), TimerLog.rec, null) catch |e| {
                try std.testing.expectEqual(error.OutOfMemory, e);
                break;
            };
        }
        // A failed add leaves the table consistent and usable for what exists.
        for (0..u.slots.items.len) |i| try u.start(.{ .index = @intCast(i), .generation = 0 }, 0, @intCast(i), 0);
        try std.testing.expectEqual(u.slots.items.len, u.run(100));
    }
}

test "Timers: heap model test — random start/stop/again/run against a brute-force list" {
    const gpa = std.testing.allocator;
    const N = 24;
    const S = struct {
        var fired: [N]u32 = undefined;
        var seqs: [64 * N]u8 = undefined;
        var nfire: usize = 0;
        fn cb(ctx: ?*anyopaque, _: Timers.Handle) void {
            const id = @intFromPtr(ctx);
            seqs[nfire] = @intCast(id);
            nfire += 1;
        }
    };
    var prng = std.Random.DefaultPrng.init(0x5eed_0001);
    const rnd = prng.random();
    var t: Timers = .{};
    defer t.deinit(gpa);
    var hs: [N]Timers.Handle = undefined;
    // Model: per timer (active, due, seq, repeat).
    var m_active: [N]bool = @splat(false);
    var m_due: [N]u64 = @splat(0);
    var m_seq: [N]u64 = @splat(0);
    var m_rep: [N]u64 = @splat(0);
    var next_seq: u64 = 0;
    for (&hs, 0..) |*h, i| h.* = try t.add(gpa, S.cb, tag(i));
    var now: u64 = 0;
    S.nfire = 0;
    for (0..4000) |_| {
        const i = rnd.uintLessThan(usize, N);
        switch (rnd.uintLessThan(u8, 5)) {
            0, 1 => {
                const to = rnd.uintLessThan(u64, 50);
                const rep = if (rnd.boolean()) rnd.uintLessThan(u64, 30) else 0;
                try t.start(hs[i], now, to, rep);
                m_active[i] = true;
                m_due[i] = now + to;
                m_rep[i] = rep;
                m_seq[i] = next_seq;
                next_seq += 1;
            },
            2 => {
                try t.stop(hs[i]);
                m_active[i] = false;
            },
            3 => {
                try t.again(hs[i], now);
                m_active[i] = false;
                if (m_rep[i] != 0) {
                    m_active[i] = true;
                    m_due[i] = now + m_rep[i];
                    m_seq[i] = next_seq;
                    next_seq += 1;
                }
            },
            else => {
                now += rnd.uintLessThan(u64, 40);
                S.nfire = 0;
                _ = t.run(now);
                // Model: repeatedly take the due timer with the least (due, seq).
                var expect: [N]u8 = undefined;
                var ne: usize = 0;
                const horizon = next_seq;
                while (true) {
                    var best: ?usize = null;
                    for (0..N) |k| {
                        if (!m_active[k] or m_due[k] > now or m_seq[k] >= horizon) continue;
                        if (best == null or m_due[k] < m_due[best.?] or (m_due[k] == m_due[best.?] and m_seq[k] < m_seq[best.?])) best = k;
                    }
                    const k = best orelse break;
                    expect[ne] = @intCast(k);
                    ne += 1;
                    if (m_rep[k] != 0) {
                        m_due[k] = now + m_rep[k];
                        m_seq[k] = next_seq;
                        next_seq += 1;
                    } else m_active[k] = false;
                }
                try std.testing.expectEqualSlices(u8, expect[0..ne], S.seqs[0..S.nfire]);
            },
        }
        var act: usize = 0;
        for (m_active) |a| act += @intFromBool(a);
        try std.testing.expectEqual(act, t.activeCount());
    }
}

test "Loop: timers feed the poll timeout; runTimers fires after the poll waits it out" {
    const gpa = std.testing.allocator;
    const S = struct {
        var hit: u32 = 0;
        fn cb(_: ?*anyopaque, _: Timers.Handle) void {
            hit += 1;
        }
    };
    S.hit = 0;
    var loop: Loop = .{};
    defer loop.deinit(gpa);
    const t0 = try Loop.nowMs();
    try std.testing.expect((try Loop.nowMs()) >= t0); // monotonic
    const h = try loop.timers.add(gpa, S.cb, null);
    try loop.timers.start(h, t0, 4, 0);
    const wait = loop.timeoutMs(t0, 60_000);
    try std.testing.expectEqual(@as(i32, 4), wait);

    var fds: [2]i32 = undefined;
    try std.testing.expect(@as(isize, @bitCast(linux.pipe(&fds))) >= 0);
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var pfd = [_]Loop.pollfd{.{ .fd = fds[0], .events = Loop.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try Loop.poll(&pfd, wait)); // timed out, no fd ready
    try std.testing.expectEqual(@as(usize, 1), loop.runTimers(t0 + 4)); // fake clock: deterministic
    try std.testing.expectEqual(@as(u32, 1), S.hit);
}

// ── tests: Env ───────────────────────────────────────────────────────────────

/// Run `/bin/sh -c script` with `env`, return the exit code.
fn runSh(env: Env, script: []const u8) !?u8 {
    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(1, Job);
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        var got: ProcResult = undefined;
        fn onDone(job: *Job) void {
            got = job.res;
        }
    };
    var table: Table = .{};
    try table.spawnDetachedEnv(std.testing.allocator, &.{ "/bin/sh", "-c", script }, env, H.report);
    var spins: usize = 0;
    while (doneCount(&table) < 1) {
        spins += 1;
        try std.testing.expect(spins < 5_000_000_000);
    }
    table.drain(H.onDone);
    return H.got.exit_code;
}

test "spawnDetachedEnv: .empty child sees no variables, .list child sees exactly the list (uv_process_options env)" {
    if (!haveFile("/bin/sh")) return error.SkipZigTest;
    // `env` would need PATH; the shell's own `[ -z "${X+x}" ]` does not. (The shell
    // itself may define PATH/PWD internally, so those are not probed.)
    try std.testing.expectEqual(@as(?u8, 0), try runSh(.empty, "[ -z \"${PW_A+x}\" ] && [ -z \"${HOME+x}\" ] && [ -z \"${USER+x}\" ] && [ -z \"${LANG+x}\" ]"));
    const list: []const []const u8 = &.{ "PW_A=hello", "PW_B=a=b c", "PW_EMPTY=" };
    try std.testing.expectEqual(@as(?u8, 0), try runSh(.{ .list = list }, "[ \"$PW_A\" = hello ] && [ \"$PW_B\" = 'a=b c' ] && [ -z \"$PW_EMPTY\" ] && [ -n \"${PW_EMPTY+x}\" ] && [ -z \"${HOME+x}\" ]"));
    // An empty list is the same as .empty.
    try std.testing.expectEqual(@as(?u8, 0), try runSh(.{ .list = &.{} }, "[ -z \"${PW_A+x}\" ]"));
}

test "spawnDetachedEnv: .inherit hands the child the parent's variables" {
    if (!haveFile("/bin/sh") or !haveFile("/proc/self/environ")) return error.SkipZigTest;
    // Compare against what we read ourselves: the child sees a non-empty
    // environment iff /proc/self/environ has entries (PATH almost always).
    const buf = try readEnviron(std.testing.allocator);
    defer std.testing.allocator.free(buf);
    const n = splitEnviron(buf, null);
    if (n == 0) return error.SkipZigTest;
    // `set` lists variables only in the shell's own environment view; count via a
    // shell loop over its exported names would need `env`, so assert on one
    // variable that is certainly present when n > 0: the first entry's name.
    const first = std.mem.sliceTo(buf, 0);
    const eq = std.mem.findScalar(u8, first, '=') orelse return error.SkipZigTest;
    var script_buf: [512]u8 = undefined;
    if (eq > 100 or std.mem.findScalar(u8, first[0..eq], '\'') != null) return error.SkipZigTest;
    const script = try std.mem.print(&script_buf, "[ -n \"${{{s}+x}}\" ]", .{first[0..eq]});
    try std.testing.expectEqual(@as(?u8, 0), try runSh(.inherit, script));
}

test "spawnDetachedEnv: invalid or oversized environments are refused and claim no slot" {
    const Job = struct { res: ProcResult = undefined };
    var table: JobTable(1, Job) = .{};
    const H = struct {
        fn report(_: *Job, _: ProcResult) void {}
    };
    const gpa = std.testing.allocator;
    const bad = [_][]const []const u8{
        &.{"NOEQUALS"},
        &.{"=novalue_name"},
        &.{"A=b\x00c"},
        &.{ "OK=1", "" },
    };
    for (bad) |l| {
        try std.testing.expectError(error.InvalidEnv, table.spawnDetachedEnv(gpa, &.{"/bin/true"}, .{ .list = l }, H.report));
        try std.testing.expectEqual(@as(usize, 0), table.busy());
    }
    // Too many entries.
    const many = try gpa.alloc([]const u8, env_max_entries + 1);
    defer gpa.free(many);
    @memset(many, "A=1");
    try std.testing.expectError(error.EnvTooLarge, table.spawnDetachedEnv(gpa, &.{"/bin/true"}, .{ .list = many }, H.report));
    // Too many bytes.
    const big = try gpa.alloc(u8, env_max_bytes);
    defer gpa.free(big);
    @memset(big, 'x');
    big[0] = 'A';
    big[1] = '=';
    try std.testing.expectError(error.EnvTooLarge, table.spawnDetachedEnv(gpa, &.{"/bin/true"}, .{ .list = &.{big} }, H.report));
    try std.testing.expectEqual(@as(usize, 0), table.busy());
}

test "splitEnviron: model test against a brute-force split on random NUL-heavy buffers" {
    var prng = std.Random.DefaultPrng.init(0xe4f1_0002);
    const rnd = prng.random();
    var buf: [64]u8 = undefined;
    var out: [64]?[*:0]const u8 = undefined;
    for (0..2000) |_| {
        const len = rnd.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = if (rnd.uintLessThan(u8, 4) == 0) 0 else 'a' + rnd.uintLessThan(u8, 3);
        if (len > 0) buf[len - 1] = 0; // readEnviron guarantees a trailing NUL
        const b = buf[0..len];
        var want: usize = 0;
        var it = std.mem.splitScalar(u8, b, 0);
        while (it.next()) |seg| want += @intFromBool(seg.len > 0);
        try std.testing.expectEqual(want, splitEnviron(b, null));
        try std.testing.expectEqual(want, splitEnviron(b, &out));
        var k: usize = 0;
        it = std.mem.splitScalar(u8, b, 0);
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            try std.testing.expectEqualStrings(seg, std.mem.sliceTo(out[k].?, 0));
            k += 1;
        }
    }
}

test "spawnDetachedEnv: an allocation failure at every step leaks nothing (.list and .inherit)" {
    if (!haveFile("/bin/true") or !haveFile("/proc/self/environ")) return error.SkipZigTest;
    const Job = struct { res: ProcResult = undefined };
    const Table = JobTable(1, Job);
    const H = struct {
        fn report(job: *Job, res: ProcResult) void {
            job.res = res;
        }
        fn onDone(_: *Job) void {}
    };
    const envs = [_]Env{ .{ .list = &.{ "A=1", "B=2" } }, .inherit };
    for (envs) |env| {
        var idx: usize = 0;
        while (true) : (idx += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = idx });
            var table: Table = .{};
            table.spawnDetachedEnv(failing.allocator(), &.{"/bin/true"}, env, H.report) catch |e| {
                try std.testing.expectEqual(error.OutOfMemory, e);
                try std.testing.expectEqual(@as(usize, 0), table.busy());
                try std.testing.expectEqual(failing.allocations, failing.deallocations);
                continue;
            };
            var spins: usize = 0;
            while (doneCount(&table) < 1) {
                spins += 1;
                try std.testing.expect(spins < 5_000_000_000);
            }
            table.drain(H.onDone);
            try std.testing.expectEqual(failing.allocations, failing.deallocations);
            try std.testing.expect(idx >= 5);
            break;
        }
    }
}

test "Timers.add: a reused slot starts clean (no stale repeat/due/seq)" {
    const gpa = std.testing.allocator;
    var t: Timers = .{};
    defer t.deinit(gpa);
    const a = try t.add(gpa, TimerLog.rec, null);
    try t.start(a, 0, 10, 25);
    try t.close(a);
    const b = try t.add(gpa, TimerLog.rec, null);
    try std.testing.expectEqual(a.index, b.index);
    try std.testing.expectEqual(@as(u64, 0), try t.getRepeat(b));
    try t.again(b, 100); // repeat 0: must only stop
    try std.testing.expect(!(try t.isActive(b)));
    try std.testing.expectEqual(@as(usize, 0), t.activeCount());
}

test "JobTable.setWaker waits out a worker still inside finish" {
    const Job = struct { v: u32 = 0 };
    var table: JobTable(1, Job) = .{};
    var w = try Waker.init();
    defer w.deinit();
    try table.setWaker(&w);
    // Simulate a worker past its DONE store but not yet done with the waker.
    _ = table.finishing.fetchAdd(1, .acq_rel);
    const T = struct {
        fn run(tb: *JobTable(1, Job)) void {
            const ts: linux.timespec = .{ .sec = 0, .nsec = 5_000_000 };
            _ = linux.nanosleep(&ts, null);
            _ = tb.finishing.fetchSub(1, .release);
        }
    };
    const th = try std.Thread.spawn(.{}, T.run, .{&table});
    try table.setWaker(null); // must block until the fake worker leaves
    try std.testing.expectEqual(@as(u32, 0), table.finishing.load(.acquire));
    th.join();
}
