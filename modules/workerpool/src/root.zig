// SPDX-License-Identifier: MIT

//! workerpool — an in-process, fixed-width worker pool over the lock-free
//! `lockfree.SegQueue`. A closed roster of `std.Thread`s pulls type-erased
//! jobs off one shared unbounded queue and runs them; the pool owns its
//! threads and offers a clean lifecycle: `init` → `submit`/`Submitter.submit`
//! → `drain` (graceful) or `shutdownNow` (abrupt) → `deinit`. `wait` blocks
//! until the pool is idle without shutting it down.
//!
//! This is the execution substrate for the P2 write-behind data-layer
//! coordinator (DL5): it submits "flush this dirty entry to the sink" jobs and
//! the pool executes them off the request path.
//!
//! **Job shape — type-erased closure.** A job is `{ func: *const fn(*anyopaque)
//! void, ctx: *anyopaque }`. This is chosen over a generic `WorkerPool(Job)`
//! *deliberately*: a write-behind coordinator submits heterogeneous work
//! (flush entry A to sink X, flush entry B to sink Y, run a compaction) whose
//! only common shape is "a closure to run later". A comptime job type would
//! force one concrete `Job`/`run` per pool; the type-erased closure lets one
//! non-generic pool carry any callable and keeps the API monomorphic (smaller
//! binary, no per-instantiation code bloat). The caller owns `ctx`'s lifetime
//! and must keep it valid until the job runs (see `Job`).
//!
//! **Wakeup — no busy-spin, no lost wakeup, no shutdown deadlock.** Idle
//! workers block on an `std.Io` futex (`futexWaitUncancelable`) keyed by a
//! monotonic `notify` generation counter, never spinning at 100% CPU. `submit`
//! bumps `notify` and wakes one worker *after* publishing the job; the
//! lifecycle calls bump `notify` and wake *all* workers *after* the state
//! transition. Each worker snapshots `notify`, re-checks the queue and the
//! state, and only then parks on that exact generation — so any producer or
//! shutdown that raced between the empty-observation and the park bumps the
//! generation and makes the park return immediately (see `Worker.run`).
//!
//! **Backpressure — unbounded by default, never blocking.** The queue grows
//! on demand, so `submit` never blocks; it fails with a typed error on
//! allocator exhaustion (`error.SubmitFailed`), after shutdown
//! (`error.Shutdown`) and, only when `Options.max_queued` is set, with
//! `error.QueueFull` once that many jobs are queued and not yet started
//! (SPEC §5). A blocking submit is deferred: a caller retries or sheds.
//!
//! **Pause.** `pause` stops workers from starting new jobs (jobs already
//! running finish); `resume` lets them go on. Submissions are still accepted
//! while paused. `drain`/`shutdownNow` override a pause (SPEC §4).
//!
//! **The queue.** Jobs travel by value in a `lockfree.SegQueue(Job)`: no
//! per-job allocation, no epoch domain, no participant per thread, so
//! `submit` from any thread takes no lock (2026-10-14; it was a Michael-Scott
//! queue over EBR with a heap box per job and a spinlock on the shared submit
//! path). The queue allocates a block per 63 jobs from the pool's allocator and
//! workers free them, so that allocator must be thread-safe.
//!
//! See `SPEC.md` for the drain semantics, the wakeup correctness argument and
//! the backpressure policy.

const std = @import("std");
const builtin = @import("builtin");
const lockfree = @import("lockfree");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "In-process fixed-width worker pool over `lockfree.SegQueue` — type-erased closure jobs carried by value, Io-futex idle wakeup (no busy-spin, no lost-wakeup), graceful drain / abrupt shutdown",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // std.Thread + std.atomic + the std.Io futex are cross-OS; the pool logic
    // is portable. (The blocking wait needs an `Io`, which the caller supplies.)
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // `submit`, `Submitter.submit`, and the job accounting are safe from any
    // thread. The *lifecycle* (`drain`/`shutdownNow`/`deinit`) is single-owner:
    // one thread orchestrates teardown after producers have quiesced.
    .concurrency = .threadsafe,
    .model_after = "std.Thread.Pool / crossbeam worker pool over an unbounded MPMC queue (lockfree.SegQueue)",
    .deps = .{"lockfree"},
};

// ── public types ─────────────────────────────────────────────────────────────

/// A unit of work: a type-erased closure. `func(ctx)` is invoked on a worker
/// thread exactly once. The caller owns `ctx` and must keep it valid until the
/// job has run — for fire-and-forget work, `ctx` typically points at
/// caller-owned state (a dirty-cache entry, a request context) whose lifetime
/// outlives the flush. `func` must not panic (a panic in a worker aborts the
/// process, as with any std.Thread body).
pub const Job = struct {
    func: *const fn (ctx: *anyopaque) void,
    ctx: *anyopaque,
};

pub const Options = struct {
    /// The `Io` whose futex backs the idle-worker wait/wake. Required — there
    /// is no io-less blocking wait in Zig 0.16 std (`std.Thread.Condition`/
    /// `Futex` are gone; futexes moved onto the `Io` vtable). Pass the same
    /// `std.Io.Threaded` the rest of the server uses. Must outlive the pool.
    io: std.Io,
    /// Number of worker threads. `null` ⇒ a cpu-count-derived default
    /// (`getCpuCount`, min 1). Caller-overridable; clamped to ≥ 1.
    n_workers: ?usize = null,
    /// How many `Submitter` handles may be held at once (`registerSubmitter`
    /// refuses past it). Default 0 ⇒ only `submit`. A `Submitter` no longer
    /// buys anything over `submit` — both enqueue lock-free since the queue
    /// needs no per-thread participant — and is kept for source compatibility.
    max_submitters: usize = 0,
    /// How long a worker that found the queue empty -- and a `wait` caller
    /// that found the pool busy -- keeps looking before it parks, in
    /// nanoseconds. 0 parks at once. Default 50 µs (owner, 2026-10-25; was 0):
    /// rayon and the Go runtime spin by default too, and without it the pool
    /// measured 2-12x slower than rayon-core, threadpool and ants (pingpong
    /// 11.9x ants), with it faster than each on every bench row.
    ///
    /// With short jobs a worker otherwise parks between every two, and every
    /// submit then pays a `futexWake` and every job a park -- two futex
    /// syscalls per job. A spinning worker is not counted as idle, so a
    /// submit that lands during its spin skips the wake, and the worker takes
    /// the job without entering the kernel. The spin always ends in the same
    /// park as before: an idle pool costs `spin_ns` of CPU per worker after
    /// its last job, then nothing.
    spin_ns: u64 = 50 * std.time.ns_per_us,
    /// Upper bound on jobs that are submitted and not yet started
    /// (`queuedCount`). 0 (the default) = unbounded, as before. When set,
    /// `submit`/`Submitter.submit` refuse with `error.QueueFull` instead of
    /// queueing past it; no box is allocated and no accounting changes. The
    /// bound is exact -- concurrent submitters can never overshoot it.
    max_queued: usize = 0,
};

pub const InitError = error{
    /// `std.Thread.spawn` failed (resource limit) after some workers were
    /// already running; the partially-built pool is torn down before this
    /// returns, so no threads leak.
    SpawnFailed,
} || std.mem.Allocator.Error;

pub const SubmitError = error{
    /// The pool is no longer accepting work (`drain`/`shutdownNow` has begun).
    Shutdown,
    /// The queue needed a new block (one per 63 jobs) and the allocator
    /// refused it. The job was NOT enqueued and no accounting changed.
    SubmitFailed,
    /// `Options.max_queued` jobs are already queued and not yet started. The
    /// job was NOT enqueued and no accounting changed; retry later or shed.
    /// Only returned when `max_queued > 0`.
    QueueFull,
};

pub const RegisterSubmitterError = error{
    /// `Options.max_submitters` handles are already held.
    TooManySubmitters,
    /// The pool is shutting down; new submitters are refused.
    Shutdown,
};

/// Lifecycle state. Monotonic: `running` → (`draining` | `stopping_now`) →
/// `stopped`. Read by workers on every loop turn; written by the lifecycle
/// calls.
const State = enum(u8) { running, draining, stopping_now, stopped };

// ── internals ────────────────────────────────────────────────────────────────

/// The job queue: `Job`s by value, any thread pushes and pops.
const JobQueue = lockfree.SegQueue(Job, .{});

const Worker = struct {
    pool: *WorkerPool,
    thread: std.Thread = undefined,
    /// Set while this worker is between its `paused` check and its pop
    /// (`takeJob`); `pause` waits for it to clear. On its own cache line:
    /// every take writes it.
    taking: std.atomic.Value(bool) align(std.atomic.cache_line) = .init(false),
};

// ── the pool ─────────────────────────────────────────────────────────────────

pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    queue: JobQueue,

    workers: []Worker,

    /// `Options.max_submitters`, and the `Submitter`s currently held.
    max_submitters: usize = 0,
    submitters: std.atomic.Value(usize) = .init(0),

    /// Idle-worker wakeup generation. Bumped (and a futex wake issued) after
    /// every publish and every state transition; workers park on a snapshot of
    /// it. Monotonic; wraparound is harmless (the futex compares for equality).
    notify: std.atomic.Value(u32) = .init(0),

    /// Count of workers that have committed to (are about to, or already did)
    /// block on `notify` in `futexWaitUncancelable` — incremented strictly
    /// before that call, decremented strictly after it returns (see
    /// `workerRun`). `enqueueJob` skips its wake when this is 0: nobody is
    /// asleep to miss it, and a worker still mid-flight self-corrects via the
    /// futex's own compare-current-value-at-entry semantics (see F4 in
    /// SPEC.md) — a wake is only ever REQUIRED for a worker already parked in
    /// the kernel, and this counter is a safe superset of that set (it may be
    /// briefly nonzero for a worker that turns out not to block at all, which
    /// only costs one avoidable wake — never zero while a worker is actually
    /// asleep).
    idle: std.atomic.Value(usize) = .init(0),
    /// `Options.spin_ns`.
    spin_ns: u64 = 0,
    /// `Options.max_queued` (0 = unbounded).
    max_queued: usize = 0,
    /// BOUNDED pools only (`max_queued > 0`): jobs reserved or queued and not
    /// yet taken by a worker. Incremented at admission by a CAS loop below
    /// `max_queued` BEFORE the box is allocated, decremented when a worker
    /// dequeues (or `shutdownNow` frees the job) and on every rollback path of
    /// `enqueueJob`. An unbounded pool never touches it: its `queuedCount` is
    /// derived (`submitted − started − dropped`), so the hot path pays one
    /// counter (`started`) for both `queuedCount` and `workingCount`, not four
    /// read-modify-writes on lines every worker shares.
    queued: std.atomic.Value(usize) = .init(0),
    /// Jobs a worker has taken off the queue (`workingCount` = `started −
    /// completed`; `queuedCount` of an unbounded pool = `submitted − started −
    /// dropped`).
    started: std.atomic.Value(u64) = .init(0),
    /// Queued jobs `shutdownNow` freed without running them.
    dropped: std.atomic.Value(u64) = .init(0),
    /// `pause` flag. Workers park on `notify` while it is set and the pool is
    /// `running`; `resume` clears it and wakes them (SPEC §4).
    paused: std.atomic.Value(bool) = .init(false),

    state: std.atomic.Value(State) = .init(.running),

    // observability (also lets tests assert exact run counts)
    submitted: std.atomic.Value(u64) = .init(0),
    completed: std.atomic.Value(u64) = .init(0),

    /// `wait` callers blocked (or about to block) on `done_gen`. A worker
    /// finishing a job bumps `done_gen` and wakes only when this is nonzero,
    /// so a pool nobody waits on pays one load per job and no syscall.
    waiters: std.atomic.Value(usize) = .init(0),
    /// Completion generation for `wait`: bumped after a job completes while a
    /// waiter is registered, and after a shutdown. Waiters park on a
    /// snapshot of it (same compare-at-entry argument as `notify`).
    done_gen: std.atomic.Value(u32) = .init(0),
    /// `wait` callers that may be asleep in the kernel on `done_gen` (the
    /// `idle` discipline for waiters): incremented right before the park,
    /// decremented right after. A completion bumps `done_gen` for any
    /// registered waiter but issues the `futexWake` only when this is
    /// nonzero, so a waiter that is spinning costs the workers no syscall.
    parked_waiters: std.atomic.Value(usize) = .init(0),

    /// Build and start the pool. Returns a heap-owned `*WorkerPool` so worker
    /// threads can hold a stable back-pointer (a by-value pool would move on
    /// return, dangling those pointers). `deinit` frees it.
    ///
    /// On any failure the partially-constructed pool is fully unwound —
    /// spawned workers are stopped and joined, all storage freed — so a
    /// failed `init` leaks nothing. `allocator` must be thread-safe (see the
    /// file comment).
    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!*WorkerPool {
        const n_workers = blk: {
            const requested = options.n_workers orelse (std.Thread.getCpuCount() catch 4);
            break :blk @max(@as(usize, 1), requested);
        };
        const self = try allocator.create(WorkerPool);
        errdefer allocator.destroy(self);

        // Construct directly into `self.*` fields (workers keep a pointer to
        // the pool, so its address is final). Unspecified fields take their
        // struct-declaration defaults (counters, state).
        self.* = .{
            .allocator = allocator,
            .io = options.io,
            .spin_ns = options.spin_ns,
            .max_queued = options.max_queued,
            .max_submitters = options.max_submitters,
            .queue = undefined,
            .workers = &.{},
        };

        self.queue = try JobQueue.init(allocator);
        errdefer self.queue.deinit();

        const workers = try allocator.alloc(Worker, n_workers);
        errdefer allocator.free(workers);
        self.workers = workers;
        for (workers) |*w| w.* = .{ .pool = self };

        // Spawn. On a spawn failure, stop + join the workers already running,
        // then let the errdefers above free everything.
        var spawned: usize = 0;
        errdefer if (spawned != 0) {
            self.state.store(.stopping_now, .seq_cst);
            self.wakeAll();
            for (workers[0..spawned]) |*w| w.thread.join();
        };
        while (spawned < n_workers) : (spawned += 1) {
            workers[spawned].thread = std.Thread.spawn(.{}, workerRun, .{&workers[spawned]}) catch
                return error.SpawnFailed;
        }

        return self;
    }

    /// Graceful shutdown: stop accepting new work, let every already-submitted
    /// (and in-flight) job run to completion, then join all workers. After
    /// `drain` returns, the queue is empty and every submitted job has run.
    ///
    /// Precondition: no thread may call `submit`/`Submitter.submit` concurrently
    /// with `drain` — the caller quiesces its producers first (the usual
    /// thread-pool contract). Idempotent: a second call is a no-op.
    pub fn drain(self: *WorkerPool) void {
        if (self.state.cmpxchgStrong(.running, .draining, .seq_cst, .seq_cst) != null) return;
        self.wakeAll();
        for (self.workers) |*w| w.thread.join();
        self.state.store(.stopped, .seq_cst);
    }

    /// Abrupt shutdown: stop accepting new work and let each worker finish only
    /// its current in-flight job, then join. Jobs still queued are NOT run;
    /// they are taken off the queue and counted as dropped. Use when queued work is safe to drop
    /// (e.g. process teardown). Precondition + idempotency as `drain`.
    pub fn shutdownNow(self: *WorkerPool) void {
        if (self.state.cmpxchgStrong(.running, .stopping_now, .seq_cst, .seq_cst) != null) return;
        self.wakeAll();
        for (self.workers) |*w| w.thread.join();
        self.dropQueued();
        self.state.store(.stopped, .seq_cst);
        // Dropped jobs will never complete: release any `wait` caller.
        self.wakeWaiters();
    }

    /// Stop workers from starting new jobs. Idempotent. Jobs a worker is
    /// running when this is called finish; queued jobs and jobs submitted
    /// meanwhile stay queued (`submit` keeps accepting, up to `max_queued`)
    /// until `resume`. A worker that had already taken its next job off the
    /// queue at the instant of the call counts as running and finishes it.
    /// `drain` and `shutdownNow` override a pause. `wait` on a paused pool
    /// with queued jobs blocks until `resume` (as the reference's
    /// `thpool_wait` would). Wakes nobody: a parked worker notices the flag
    /// when it next wakes. Blocks only while a worker is between its pause
    /// check and its dequeue (a few instructions), so that once this returns
    /// no job submitted afterwards can start: the worker sets `taking` before
    /// it reads `paused`, this sets `paused` before it reads `taking` (both
    /// seq_cst), so one of the two sees the other. (Audit 2026-10-25: without
    /// it a worker that had checked the flag just before the call could still
    /// dequeue and start a job submitted after it returned.)
    pub fn pause(self: *WorkerPool) void {
        self.paused.store(true, .seq_cst);
        for (self.workers) |*w| {
            var turn: u32 = 0;
            while (w.taking.load(.seq_cst)) : (turn +%= 1) {
                // A worker preempted inside its window: give it the core.
                if (turn % 1024 == 1023) std.Thread.yield() catch {} else std.atomic.spinLoopHint();
            }
        }
    }

    /// Undo `pause` and wake every parked worker. Idempotent.
    pub fn @"resume"(self: *WorkerPool) void {
        if (self.paused.swap(false, .seq_cst)) self.wakeAll();
    }

    /// Whether `pause` is in effect.
    pub fn isPaused(self: *const WorkerPool) bool {
        return self.paused.load(.seq_cst);
    }

    /// Block until every job accepted so far has run — nothing queued,
    /// nothing in flight — with the pool still running afterwards; it keeps
    /// accepting work (Pithikos C-Thread-Pool's `thpool_wait`, a `WaitGroup`
    /// over the whole pool). Returns `true` once the pool is idle, `false`
    /// when it was shut down with `shutdownNow` instead (dropped jobs never
    /// complete, so waiting on them would hang). After `drain` it returns
    /// `true` at once.
    ///
    /// Idle means `completedCount() == submittedCount()`, observed at one
    /// instant. Producers that keep submitting can therefore keep a waiter
    /// waiting: pause them for a guaranteed return, as with `drain`. Any
    /// number of threads may wait at once.
    ///
    /// **Never call it from a job of the same pool**: that job counts as not
    /// yet completed, so the wait could only end by its own completion — a
    /// deadlock. It is detected and panics instead of hanging.
    ///
    /// Lost-wakeup argument: the waiter registers (`waiters`) BEFORE it
    /// snapshots `done_gen` and checks the counts; a worker increments
    /// `completed` BEFORE it reads `waiters` (both seq_cst). So a completion
    /// the check missed necessarily sees the registration; the one among
    /// them that brings `completed` up to the `submitted` it then reads bumps
    /// `done_gen`, and the park on the stale snapshot returns at once. A
    /// completion that does not reach it leaves a job outstanding whose own
    /// completion will (`submitted` only falls on a `SubmitFailed` rollback,
    /// which wakes by itself).
    pub fn wait(self: *WorkerPool) bool {
        if (current_pool == self) @panic("workerpool: wait() called from a job of the same pool (would deadlock)");
        _ = self.waiters.fetchAdd(1, .seq_cst);
        defer _ = self.waiters.fetchSub(1, .seq_cst);
        var spun = false;
        while (true) {
            const gen = self.done_gen.load(.seq_cst);
            if (self.completed.load(.seq_cst) == self.submitted.load(.seq_cst)) return true;
            switch (self.state.load(.seq_cst)) {
                .running, .draining => {},
                .stopping_now, .stopped => return false,
            }
            // `Options.spin_ns` holds for the waiter too, once per call: watch
            // the completion generation for a while before parking, so a short
            // job's waiter does not pay a park and a wake (pingpong 1.57 → see
            // SPEC). Only once: a long wait over a stream of completions would
            // otherwise never park and burn a core (review 2026-10-25).
            if (self.spin_ns != 0 and !spun) {
                spun = true;
                if (self.spinUntilChanged(&self.done_gen, gen)) continue;
            }
            // Test seam -- see `wait_seam`.
            if (builtin.is_test) {
                if (wait_seam.load(.seq_cst)) |f| f();
            }
            _ = self.parked_waiters.fetchAdd(1, .seq_cst);
            self.io.futexWaitUncancelable(u32, &self.done_gen.raw, gen);
            _ = self.parked_waiters.fetchSub(1, .seq_cst);
        }
    }

    /// Stop (gracefully, if still running) and release every resource. Safe to
    /// call after `drain`/`shutdownNow`, or directly (then it drains first).
    pub fn deinit(self: *WorkerPool) void {
        if (self.state.load(.seq_cst) == .running) self.drain();
        // Defensive: drop anything still queued (nothing after a graceful
        // drain or a `shutdownNow`; a second, empty pass is safe).
        self.dropQueued();

        const allocator = self.allocator;
        allocator.free(self.workers);
        self.queue.deinit();
        allocator.destroy(self);
    }

    /// Submit a job from any thread (zero setup, lock-free).
    ///
    /// Non-blocking; the queue is unbounded unless `Options.max_queued` is set.
    /// Errors: `Shutdown` (pool no longer accepting), `SubmitFailed`
    /// (allocator exhaustion) or `QueueFull` (only with `max_queued`).
    pub fn submit(self: *WorkerPool, job: Job) SubmitError!void {
        return self.enqueueJob(job);
    }

    /// Claim a `Submitter` handle; release it with `Submitter.deinit`.
    /// Bounded by `Options.max_submitters`. Its `submit` is the pool's
    /// `submit` (kept for source compatibility, see `max_submitters`).
    pub fn registerSubmitter(self: *WorkerPool) RegisterSubmitterError!Submitter {
        if (self.state.load(.seq_cst) != .running) return error.Shutdown;
        var cur = self.submitters.load(.seq_cst);
        while (true) {
            if (cur >= self.max_submitters) return error.TooManySubmitters;
            cur = self.submitters.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse break;
        }
        return .{ .pool = self };
    }

    /// Jobs run so far (monotone). For observability / test assertions.
    pub fn completedCount(self: *const WorkerPool) u64 {
        return self.completed.load(.seq_cst);
    }
    /// Jobs accepted so far (monotone).
    pub fn submittedCount(self: *const WorkerPool) u64 {
        return self.submitted.load(.seq_cst);
    }
    pub fn workerCount(self: *const WorkerPool) usize {
        return self.workers.len;
    }
    /// Workers currently running a job (a snapshot, `started − completed`;
    /// no lock and no counter of its own). A worker is counted from the moment it takes the job
    /// off the queue until the job returns, so it is 0 whenever `wait`
    /// reports idle.
    pub fn workingCount(self: *const WorkerPool) usize {
        // `completed` first: a job's `started` increment precedes its
        // `completed` one, so the later `started` load is never behind it.
        const done = self.completed.load(.seq_cst);
        const began = self.started.load(.seq_cst);
        return @intCast(began -| done);
    }
    /// Jobs submitted and not yet started (a snapshot; includes a job whose
    /// submit is in flight). With `Options.max_queued` set it never exceeds it.
    pub fn queuedCount(self: *const WorkerPool) usize {
        if (self.max_queued != 0) return self.queued.load(.seq_cst);
        // `started` and `dropped` first: both only ever trail `submitted`.
        const began = self.started.load(.seq_cst);
        const gone = self.dropped.load(.seq_cst);
        const in = self.submitted.load(.seq_cst);
        return @intCast(in -| began -| gone);
    }

    /// True iff every job `submit`/`Submitter.submit` ever accepted has run
    /// (`submittedCount() == completedCount()`). Meant to be checked after
    /// `drain()` returns (W2 `workerpool` F6): `drain`'s own precondition
    /// — "no thread may call `submit` concurrently with `drain`" — is the
    /// caller's to uphold, and a violation is otherwise silent: `enqueueJob`'s
    /// shutdown check and its enqueue are two separate steps, not one atomic
    /// operation, so a `submit` racing `drain` can return success for a job
    /// whose box is then queued behind (or after) the point where the last
    /// worker already observed `.draining` and stopped looking — the job is
    /// accepted, never run, and `submittedCount` is left permanently ahead of
    /// `completedCount` with nothing pointing at why. This does not fix the
    /// race (the precondition is the caller's contract, not something this
    /// module can enforce without a lock on every `submit`) — it makes a
    /// violation of it observable instead of silent. Meaningless after
    /// `shutdownNow`, which intentionally drops queued jobs — see
    /// `submittedCount`/`completedCount` directly for that case.
    pub fn drainedCleanly(self: *const WorkerPool) bool {
        return self.submitted.load(.seq_cst) == self.completed.load(.seq_cst);
    }

    // ── internal machinery ───────────────────────────────────────────────────

    /// The one enqueue path, from any thread.
    fn enqueueJob(self: *WorkerPool, job: Job) SubmitError!void {
        if (self.state.load(.seq_cst) != .running) return error.Shutdown;

        // Admission first, before anything is counted. Released by the worker
        // that dequeues the job, or right here on a rollback.
        try self.reserveSlot();

        // Counted before the push, so `queuedCount` never sees the job taken
        // before it was submitted; a failed push leaves the queue unchanged.
        _ = self.submitted.fetchAdd(1, .monotonic);
        self.queue.push(job) catch {
            // seq_cst + the `waiters` load: a `wait` that saw this job counted
            // and parked must be released by its withdrawal (audit 2026-10-25:
            // it otherwise slept on an idle pool until some other job ended).
            _ = self.submitted.fetchSub(1, .seq_cst);
            self.releaseSlot();
            if (self.waiters.load(.seq_cst) > 0) self.wakeWaiters();
            return error.SubmitFailed;
        };

        // Bump `notify` unconditionally — this is what defeats the lost-wakeup
        // window: a worker that observed the queue empty and snapshotted the
        // old generation will find it changed at its own compare-and-block
        // entry and return immediately, wake or no wake (see `idle`'s doc).
        // The actual `futexWake` syscall is only needed to release a worker
        // that is *already* asleep in the kernel, so skip it when `idle`
        // (F4) says nobody is (a saturated pool would otherwise pay a wake
        // call on every single submit for no one to receive it).
        _ = self.notify.fetchAdd(1, .seq_cst);
        if (self.idle.load(.seq_cst) > 0) self.io.futexWake(u32, &self.notify.raw, 1);
    }

    /// Reserve one queued-job slot: a plain increment when unbounded, a CAS
    /// loop that refuses at `max_queued` otherwise (so concurrent submitters
    /// can never overshoot the bound).
    fn reserveSlot(self: *WorkerPool) error{QueueFull}!void {
        if (self.max_queued == 0) return;
        var cur = self.queued.load(.seq_cst);
        while (true) {
            if (cur >= self.max_queued) return error.QueueFull;
            cur = self.queued.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse return;
        }
    }

    /// Give back a slot `reserveSlot` took (bounded pools only).
    fn releaseSlot(self: *WorkerPool) void {
        if (self.max_queued != 0) _ = self.queued.fetchSub(1, .seq_cst);
    }

    /// Worker-side dequeue: the job is counted as started before its slot is
    /// released, so `queued + working` never dips below the true count.
    /// Null while paused (and running): see `pause` for the `taking` handshake.
    fn takeJob(self: *WorkerPool, w: *Worker) ?Job {
        w.taking.store(true, .seq_cst);
        defer w.taking.store(false, .release);
        if (self.paused.load(.seq_cst) and self.state.load(.seq_cst) == .running) return null;
        const job = self.queue.pop() orelse return null;
        _ = self.started.fetchAdd(1, .seq_cst);
        self.releaseSlot();
        return job;
    }

    /// `Options.spin_ns`: watch `gen_word` for up to `spin_ns`; true when it
    /// moved off `seen` (the caller re-evaluates instead of parking).
    fn spinUntilChanged(self: *WorkerPool, gen_word: *const std.atomic.Value(u32), seen: u32) bool {
        const until = std.Io.Timestamp.now(self.io, .awake).nanoseconds + self.spin_ns;
        var turn: u32 = 0;
        while (true) : (turn +%= 1) {
            if (gen_word.load(.seq_cst) != seen) return true;
            std.atomic.spinLoopHint();
            // The clock every 64 turns: a vDSO call, cheap, not free.
            if (turn % 64 == 63 and std.Io.Timestamp.now(self.io, .awake).nanoseconds >= until) return false;
        }
    }

    /// Bump the generation and wake every parked worker. Called after a state
    /// transition so no worker stays parked through a shutdown.
    fn wakeAll(self: *WorkerPool) void {
        _ = self.notify.fetchAdd(1, .seq_cst);
        self.io.futexWake(u32, &self.notify.raw, std.math.maxInt(u32));
    }

    /// Bump the completion generation and wake every `wait` caller.
    fn wakeWaiters(self: *WorkerPool) void {
        _ = self.done_gen.fetchAdd(1, .seq_cst);
        self.io.futexWake(u32, &self.done_gen.raw, std.math.maxInt(u32));
    }

    /// Run one dequeued job.
    fn runJob(self: *WorkerPool, job: Job) void {
        job.func(job.ctx);
        // seq_cst, not monotonic: `wait`'s lost-wakeup argument needs this
        // increment ordered before the `waiters` load below.
        const done = self.completed.fetchAdd(1, .seq_cst) + 1;
        // Only the completion that makes the pool idle can end a `wait`, so
        // only it wakes (a long wait over a stream of jobs no longer takes a
        // wake per job). A later submit's completion makes its own check; a
        // `SubmitFailed` rollback and a shutdown wake by themselves.
        if (self.waiters.load(.seq_cst) > 0 and done == self.submitted.load(.seq_cst)) {
            // Bump first, then look for a sleeper: a waiter that counts itself
            // parked after this load parks on a generation this bump already
            // moved, and its futex compare returns at once (the `idle` F4
            // argument).
            _ = self.done_gen.fetchAdd(1, .seq_cst);
            if (self.parked_waiters.load(.seq_cst) > 0) self.io.futexWake(u32, &self.done_gen.raw, std.math.maxInt(u32));
        }
    }

    /// Take any jobs still in the queue without running them, counting them
    /// as dropped. Single-threaded caller (all workers joined).
    fn dropQueued(self: *WorkerPool) void {
        while (self.queue.pop()) |_| {
            _ = self.dropped.fetchAdd(1, .seq_cst);
            self.releaseSlot();
        }
    }
};

/// A counted submission handle (`Options.max_submitters`). `submit` is the
/// pool's lock-free `submit`; the handle once carried its own EBR participant
/// and is kept for source compatibility. Release with `deinit` before the pool
/// is torn down.
pub const Submitter = struct {
    pool: *WorkerPool,

    pub fn submit(self: *Submitter, job: Job) SubmitError!void {
        return self.pool.enqueueJob(job);
    }

    pub fn deinit(self: *Submitter) void {
        _ = self.pool.submitters.fetchSub(1, .seq_cst);
        self.* = undefined;
    }
};

/// **Test-only seam inside the lost-wakeup window.** `null` in every build;
/// only the teeth test at the bottom of this file ever installs anything, and
/// the call site is `comptime`-gated on `builtin.is_test`, so a release build
/// does not even load it.
///
/// It sits between a worker's FINAL queue re-check and its park. That is the
/// only instant at which a test can deterministically place a producer inside
/// the window SPEC §4 argues about, so:
///
///   **INVARIANT: `workerRun` must snapshot `notify` ABOVE the final
///   `queue.dequeue` re-check.** Any edit that moves the snapshot below this
///   seam reintroduces the classic lost wakeup (worker sees empty → producer
///   publishes, bumps the generation and wakes nobody → worker snapshots the
///   *new* generation and parks on it forever) and hangs that test into its
///   watchdog.
var park_seam: std.atomic.Value(?*const fn () void) = .init(null);

/// **Test-only seam BEFORE the `notify` snapshot**: between a worker's first
/// look at an empty queue and the generation it will park on. A job published
/// there bumps `notify` before the snapshot, so only the FINAL re-check of the
/// queue can find it -- this seam is how a test proves that re-check is
/// load-bearing. Same rules as `park_seam`: `null` in every build, the call
/// site is `comptime`-gated on `builtin.is_test`.
var snapshot_seam: std.atomic.Value(?*const fn () void) = .init(null);

/// **Test-only seam inside `wait`**, between its last check of the counts and
/// state and its park on `done_gen`. Lets a test run a whole `shutdownNow`
/// there, so the only thing that can release the waiter is `shutdownNow`'s own
/// `wakeWaiters`. Same rules as `park_seam`.
var wait_seam: std.atomic.Value(?*const fn () void) = .init(null);

/// **Test-only seam inside the pause park window**: after a worker has
/// snapshotted `notify` and re-confirmed `paused`, before it counts itself idle
/// and parks. A `resume` run there bumps the generation the worker is about to
/// park on, so only the snapshot-before-recheck order keeps the park from
/// sleeping through it. Same rules as `park_seam`.
var pause_seam: std.atomic.Value(?*const fn () void) = .init(null);

/// **Test-only seam BEFORE the pause branch's `notify` snapshot**: a worker
/// has seen the flag set and not yet taken the generation it will park on. A
/// `resume` or a shutdown landing here bumps the generation BEFORE the
/// snapshot, so only the re-check of the flag and the state after it keeps
/// the park from sleeping through it (audit 2026-10-25, mutants 744/752).
/// Same rules as `park_seam`.
var pause_snapshot_seam: std.atomic.Value(?*const fn () void) = .init(null);

/// The pool whose worker the current thread is, if any — how `wait` detects
/// being called from one of its own jobs.
threadlocal var current_pool: ?*const WorkerPool = null;

// The worker thread body. A free function (not a method) so `std.Thread.spawn`
// can name it; takes the stable `*Worker`.
fn workerRun(w: *Worker) void {
    const self = w.pool;
    current_pool = self;
    outer: while (true) {
        const st = self.state.load(.seq_cst);
        // Abrupt stop: drop whatever is queued, exit now (in-flight job, if
        // any, already completed before this loop turn).
        if (st == .stopping_now) break;

        // `pause`: while paused (and still running -- `draining` overrides it)
        // no new job is started. Park on `notify` with the same discipline as
        // the empty-queue park: snapshot the generation FIRST, then re-check
        // both the state and the flag, so a `resume` / shutdown that lands in
        // between bumped the generation and makes the wait return at once.
        if (st == .running and self.paused.load(.seq_cst)) {
            // Test seam -- see `pause_snapshot_seam`.
            if (builtin.is_test) {
                if (pause_snapshot_seam.load(.seq_cst)) |f| f();
            }
            const gen = self.notify.load(.seq_cst);
            if (self.state.load(.seq_cst) == .running and self.paused.load(.seq_cst)) {
                // Test seam -- see `pause_seam`.
                if (builtin.is_test) {
                    if (pause_seam.load(.seq_cst)) |f| f();
                }
                _ = self.idle.fetchAdd(1, .seq_cst);
                self.io.futexWaitUncancelable(u32, &self.notify.raw, gen);
                _ = self.idle.fetchSub(1, .seq_cst);
            }
            continue;
        }

        if (self.takeJob(w)) |job| {
            self.runJob(job);
            continue;
        }
        // Queue observed empty.
        if (st == .draining) break; // graceful: nothing left ⇒ done.

        // `Options.spin_ns`: keep looking for a while before parking. Not
        // counted in `idle`, so a submit meanwhile bumps `notify` and skips
        // the wake; the bump is what this watches (one shared load per turn,
        // not a dequeue attempt that contends with the other workers).
        if (self.spin_ns != 0 and self.spinUntilChanged(&self.notify, self.notify.load(.seq_cst))) continue :outer;

        // Test seam -- see `snapshot_seam`.
        if (builtin.is_test) {
            if (snapshot_seam.load(.seq_cst)) |f| f();
        }
        // st == .running: park until woken. Snapshot the generation FIRST,
        // then re-check the queue and state, so any submit/shutdown that raced
        // in between bumped the generation and makes the wait return at once.
        const gen = self.notify.load(.seq_cst);
        if (self.takeJob(w)) |job| {
            self.runJob(job);
            continue;
        }
        // Test seam — see `park_seam`. Deliberately placed at the TOP of the
        // pre-park window (immediately after the last look at the queue), so a
        // snapshot moved anywhere below it is caught.
        if (builtin.is_test) {
            if (park_seam.load(.seq_cst)) |f| f();
        }
        if (self.state.load(.seq_cst) != .running) continue; // re-handle stop/drain
        // F4: counted as idle for exactly the span that can include actually
        // being asleep in the kernel — incremented immediately before the
        // call that may block, decremented immediately after it returns, so
        // `enqueueJob`'s gate is never 0 while this worker could be parked.
        _ = self.idle.fetchAdd(1, .seq_cst);
        self.io.futexWaitUncancelable(u32, &self.notify.raw, gen);
        _ = self.idle.fetchSub(1, .seq_cst);
        // Woken (real, or spurious) — loop and re-evaluate.
    }
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Real threads throughout. Each test builds its own `std.Io.Threaded` for the
// futex, and a watchdog converts any wakeup/shutdown deadlock into a loud panic
// (a bounded failure) instead of a silent hang. Run under both Debug and
// ReleaseFast (`zig build test-workerpool [-Doptimize=ReleaseFast]`).

const testing = std.testing;

/// Shared job target: every job bumps `n`.
const Counter = struct {
    n: std.atomic.Value(u64) = .init(0),
};
fn incr(ctx: *anyopaque) void {
    const c: *Counter = @ptrCast(@alignCast(ctx));
    _ = c.n.fetchAdd(1, .monotonic);
}

/// A job that spins briefly (busy work) then bumps — used to make workers
/// "busy" during a shutdown test without libc sleep.
const SpinCounter = struct {
    n: std.atomic.Value(u64) = .init(0),
    spins: u64 = 20_000,
};
fn spinIncr(ctx: *anyopaque) void {
    const c: *SpinCounter = @ptrCast(@alignCast(ctx));
    var i: u64 = 0;
    while (i < c.spins) : (i += 1) std.atomic.spinLoopHint();
    _ = c.n.fetchAdd(1, .monotonic);
}

/// Deadlock guard: panics if `done` is not set within `timeout_ms`. Start
/// before the operation under test, `finish()` after it, then `join`.
const Watchdog = struct {
    io: std.Io,
    timeout_ms: i64,
    done: std.atomic.Value(u32) = .init(0),
    thread: std.Thread = undefined,

    fn run(wd: *Watchdog) void {
        const start_ns = std.Io.Timestamp.now(wd.io, .awake).nanoseconds;
        const deadline = start_ns + @as(i96, wd.timeout_ms) * std.time.ns_per_ms;
        while (wd.done.load(.seq_cst) == 0) {
            wd.io.futexWaitTimeout(u32, &wd.done.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(50),
                .clock = .awake,
            } }) catch {};
            if (wd.done.load(.seq_cst) != 0) return;
            if (std.Io.Timestamp.now(wd.io, .awake).nanoseconds >= deadline)
                @panic("workerpool test watchdog: operation did not complete in time (deadlock?)");
        }
    }
    fn start(wd: *Watchdog) !void {
        wd.thread = try std.Thread.spawn(.{}, run, .{wd});
    }
    fn finish(wd: *Watchdog) void {
        wd.done.store(1, .seq_cst);
        wd.io.futexWake(u32, &wd.done.raw, std.math.maxInt(u32));
        wd.thread.join();
    }
};

test "submit N ≫ n_workers: every job runs exactly once" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 4 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    const n: u64 = 20_000;
    for (0..n) |_| try pool.submit(.{ .func = incr, .ctx = &c });

    pool.drain(); // graceful: returns only after all queued jobs have run
    try testing.expectEqual(n, c.n.load(.seq_cst));
    try testing.expectEqual(n, pool.completedCount());
    try testing.expectEqual(n, pool.submittedCount());
}

test "graceful drain runs every queued job; no leak (DebugAllocator clean)" {
    // testing.allocator is a DebugAllocator: a leak or double-free fails the
    // test. Exercises the full init→submit→drain→deinit lifecycle.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });

    var c = Counter{};
    const n: u64 = 5000;
    for (0..n) |_| try pool.submit(.{ .func = incr, .ctx = &c });

    pool.drain();
    try testing.expectEqual(n, c.n.load(.seq_cst));

    // Submitting after drain is refused, not a panic.
    try testing.expectError(error.Shutdown, pool.submit(.{ .func = incr, .ctx = &c }));

    // Nothing left behind in the queue.
    try testing.expect(pool.queue.isEmpty());

    pool.deinit(); // frees everything; DebugAllocator verifies no leak
}

// Regression (audit W2 `workerpool` F6): `drain`'s producer-quiescence
// precondition, if violated, used to be silent — `submittedCount` could sit
// permanently ahead of `completedCount` with no diagnostic pointing at it.
// `drainedCleanly()` makes that observable.
test "F6: drainedCleanly() is true after a normal, precondition-respecting drain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var c = Counter{};
    for (0..500) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    pool.drain();

    try testing.expectEqual(pool.submittedCount(), pool.completedCount());
    try testing.expect(pool.drainedCleanly());
}

test "F6: drainedCleanly() reports false when submitted permanently exceeds completed" {
    // Exercises `drainedCleanly()`'s own logic deterministically rather than
    // racing a real `submit` against a real `drain` (inherently timing-
    // dependent, and the precondition violation this guards is explicitly
    // out-of-contract usage, not something this test should need to
    // reproduce nondeterministically to prove the accessor is correct).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();

    var c = Counter{};
    for (0..10) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    pool.drain();
    try testing.expect(pool.drainedCleanly());

    // Simulate exactly the shape F6 describes: a job accepted (`submitted`
    // incremented) that never ran (`completed` left behind) — the state
    // `enqueueJob`'s non-atomic shutdown-check-then-enqueue can leave behind
    // if a `submit` slips in around `drain`.
    _ = pool.submitted.fetchAdd(1, .monotonic);
    try testing.expect(!pool.drainedCleanly());
    try testing.expectEqual(pool.submittedCount(), pool.completedCount() + 1);

    // Restore, so `deinit`'s own bookkeeping (which does not itself depend
    // on submitted == completed) tears down cleanly.
    _ = pool.submitted.fetchSub(1, .monotonic);
}

fn sleepMsIo(io: std.Io, ms: i64) void {
    var word = std.atomic.Value(u32).init(0);
    io.futexWaitTimeout(u32, &word.raw, 0, .{ .duration = .{
        .raw = .fromMilliseconds(ms),
        .clock = .awake,
    } }) catch {};
}

fn awaitCount(io: std.Io, c: *const Counter, n: u64) void {
    while (c.n.load(.seq_cst) < n) sleepMsIo(io, 1);
}

test "spin_ns: a worker keeps looking instead of parking, then parks" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    // Control: without a spin the worker is asleep 50 ms after its job.
    {
        const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
        defer pool.deinit();
        var c = Counter{};
        try pool.submit(.{ .func = incr, .ctx = &c });
        awaitCount(io, &c, 1);
        sleepMsIo(io, 50);
        try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));
    }
    // With one: 50 ms after its job it is still looking -- not idle, so the
    // next submit skips the futexWake -- takes that job, and once the spin
    // has run out it is asleep like the control.
    {
        const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .spin_ns = 300 * std.time.ns_per_ms });
        defer pool.deinit();
        var c = Counter{};
        try pool.submit(.{ .func = incr, .ctx = &c });
        awaitCount(io, &c, 1);
        sleepMsIo(io, 50);
        try testing.expectEqual(@as(usize, 0), pool.idle.load(.seq_cst));
        try pool.submit(.{ .func = incr, .ctx = &c });
        awaitCount(io, &c, 2);
        try testing.expectEqual(@as(usize, 0), pool.idle.load(.seq_cst));
        sleepMsIo(io, 600);
        try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));
    }
}

test "spin_ns: a job submitted during the spin is taken at once, not when the spin runs out" {
    // `Options.spin_ns` doc: a submit that lands during the spin "skips the
    // wake, and the worker takes the job without entering the kernel" -- the
    // spin watches `notify` for exactly that. With a 5 s spin the job must
    // run long before the spin would have ended. Mutation 2026-10-04: a spin
    // that ignored `notify` survived (the job then waited out the spin).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .spin_ns = 5 * std.time.ns_per_s });
    defer pool.deinit();
    sleepMsIo(io, 50); // the idle worker is now spinning
    var c = Counter{};
    const t0 = std.Io.Clock.Timestamp.now(io, .awake);
    try pool.submit(.{ .func = incr, .ctx = &c });
    awaitCount(io, &c, 1);
    const ms = @divTrunc(t0.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds, std.time.ns_per_ms);
    try testing.expect(ms < 2_500);
}

test "n_workers = 0 is clamped to one worker; registerSubmitter after drain is Shutdown" {
    // `Options.n_workers` doc: "clamped to >= 1" -- a pool of zero workers
    // would accept jobs that never run. `RegisterSubmitterError.Shutdown`:
    // "The pool is shutting down; new submitters are refused." Mutation
    // 2026-10-04: dropping either guard survived.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 0, .max_submitters = 1 });
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 1), pool.workerCount());
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });
    awaitCount(io, &c, 1);
    pool.drain();
    try testing.expectError(error.Shutdown, pool.registerSubmitter());
}

test "idle → wake: a submit into an idle pool runs promptly" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    // Let the workers reach the parked state (no busy-spin): wait a beat.
    var idle = std.atomic.Value(u32).init(0);
    io.futexWaitTimeout(u32, &idle.raw, 0, .{ .duration = .{
        .raw = .fromMilliseconds(100),
        .clock = .awake,
    } }) catch {};

    var wd = Watchdog{ .io = io, .timeout_ms = 5000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });

    // Poll for the one job to run — proves the parked worker woke on submit.
    // (The counter is u64 so it can't be a futex word; poll in short slices,
    // bounded by the watchdog.)
    var idle2 = std.atomic.Value(u32).init(0);
    while (c.n.load(.seq_cst) == 0) {
        io.futexWaitTimeout(u32, &idle2.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(5),
            .clock = .awake,
        } }) catch {};
    }
    try testing.expectEqual(@as(u64, 1), c.n.load(.seq_cst));
}

/// A job that busy-waits until `gate` becomes nonzero, so a test can hold a
/// worker "busy" (never parked) for exactly as long as it needs to.
fn waitForGate(ctx: *anyopaque) void {
    const gate: *std.atomic.Value(u32) = @ptrCast(@alignCast(ctx));
    while (gate.load(.seq_cst) == 0) std.atomic.spinLoopHint();
}

test "F4: idle tracks reality — 0 while the only worker is busy, back to 1 once parked" {
    // Regression guard on the F4 wake-gating fix itself (not just "the suite
    // still passes"): `idle` must be 0 whenever a worker could not possibly
    // be parked, and must return to nonzero once it genuinely parks again —
    // `enqueueJob`'s gate trusts this counter to decide whether a wake is
    // needed at all.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 5000 };
    try wd.start();
    defer wd.finish();

    var scratch = std.atomic.Value(u32).init(0);
    const pollUntil = struct {
        fn call(dio: std.Io, s: *std.atomic.Value(u32), pool_: *WorkerPool, want_idle: bool) void {
            while ((pool_.idle.load(.seq_cst) != 0) != want_idle) {
                dio.futexWaitTimeout(u32, &s.raw, 0, .{ .duration = .{
                    .raw = .fromMilliseconds(5),
                    .clock = .awake,
                } }) catch {};
            }
        }
    }.call;

    // The one worker starts with nothing queued: it parks, so idle -> 1.
    pollUntil(io, &scratch, pool, true);
    try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));

    // A job that occupies the worker until released: idle must drop to 0
    // while it runs — this worker cannot be asleep in the futex right now.
    var gate = std.atomic.Value(u32).init(0);
    try pool.submit(.{ .func = waitForGate, .ctx = &gate });
    pollUntil(io, &scratch, pool, false);
    try testing.expectEqual(@as(usize, 0), pool.idle.load(.seq_cst));

    // Release the job; the worker finds the queue empty again and parks —
    // idle must climb back to 1.
    gate.store(1, .seq_cst);
    io.futexWake(u32, &gate.raw, 1);
    pollUntil(io, &scratch, pool, true);
    try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));
}

test "drain is idempotent: a second call (and a shutdownNow after) is a safe no-op" {
    // The documented contract on both `drain` and `shutdownNow` is "a second
    // call is a no-op" -- guarded by a cmpxchg from `.running`. Nothing in the
    // suite previously called either lifecycle method twice on the same pool,
    // so a broken guard (e.g. an unconditional state store that re-enters the
    // join loop on already-joined threads) went unnoticed.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    for (0..100) |_| try pool.submit(.{ .func = incr, .ctx = &c });

    pool.drain();
    try testing.expectEqual(@as(u64, 100), c.n.load(.seq_cst));

    // Second drain(): must not re-join already-joined threads or re-wake.
    pool.drain();
    try testing.expectEqual(@as(u64, 100), c.n.load(.seq_cst));

    // shutdownNow() after a completed drain() must also be a no-op, not a
    // second join of the same threads.
    pool.shutdownNow();
    try testing.expectEqual(@as(u64, 100), c.n.load(.seq_cst));
}

test "shutdown while idle terminates cleanly" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 4 });
    defer pool.deinit();

    // No work submitted: workers park immediately. drain() must wake them and
    // return (the watchdog fires if a parked worker is never woken).
    var wd = Watchdog{ .io = io, .timeout_ms = 5000 };
    try wd.start();
    defer wd.finish();

    pool.drain();
    try testing.expectEqual(@as(u64, 0), pool.completedCount());
}

test "shutdown while busy terminates; in-flight jobs complete under drain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 4 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var c = SpinCounter{ .spins = 50_000 };
    const n: u64 = 2000;
    for (0..n) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });

    pool.drain(); // must run all queued spin-jobs, then return
    try testing.expectEqual(n, c.n.load(.seq_cst));
}

test "shutdownNow: in-flight completes, queued dropped, no leak" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    const n: u64 = 50_000;
    for (0..n) |_| try pool.submit(.{ .func = incr, .ctx = &c });

    pool.shutdownNow(); // abrupt: not all N necessarily run
    const ran = c.n.load(.seq_cst);
    // Some may have run, but never more than submitted; the rest were taken
    // off the queue as dropped (the deferred deinit + DebugAllocator prove no
    // leak/double-free of the queue's blocks).
    try testing.expect(ran <= n);
    try testing.expectEqual(ran, pool.completedCount());
    try testing.expectEqual(n, ran + pool.dropped.load(.seq_cst));
    try testing.expect(pool.queue.isEmpty());
}

// ── F3: the error ladder (audit W2 `workerpool` F3) ─────────────────────────
//
// Every non-happy path below was previously unreached by any test: no
// `FailingAllocator` anywhere in the suite (`rg 'FailingAllocator'
// modules/workerpool/` returned nothing), so a double-decrement, a missed
// rollback, or a broken `init` unwind could ship silently.

test "F3: TooManySubmitters is refused once max_submitters is exhausted" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Zero extra submitter slots: even the FIRST registerSubmitter must fail.
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .max_submitters = 0 });
    defer pool.deinit();

    try testing.expectError(error.TooManySubmitters, pool.registerSubmitter());

    // One slot: the first registration succeeds, the second is refused, and
    // releasing the first frees the slot for reuse (not a permanent budget).
    const pool2 = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .max_submitters = 1 });
    defer pool2.deinit();

    var s1 = try pool2.registerSubmitter();
    try testing.expectError(error.TooManySubmitters, pool2.registerSubmitter());
    s1.deinit();
    var s2 = try pool2.registerSubmitter(); // the freed slot is reusable
    s2.deinit();
}

test "F3: init's errdefer ladder never leaks under allocator exhaustion, at every allocation site" {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Sweep every possible allocation-failure point inside `init` (the pool,
    // the queue's first block, the workers slice — one `errdefer` per site,
    // per the doc comment on `init`). Deliberately on
    // `page_allocator` (not the leak-panicking `testing.allocator`): this
    // loop asserts leak-freedom ITSELF, via each `FailingAllocator`'s own
    // `allocations`/`deallocations` counters, precisely so it can also
    // report — rather than crash the whole suite on — the one KNOWN,
    // out-of-scope leak below, instead of a leak-detecting backing allocator
    // panicking mid-sweep with no chance to attribute it.
    //
    // This used to tolerate exactly one leaking index: `lockfree.NodePool.
    // acquire` created a `Slot` and only then appended it to its own tracking
    // list, so a failure of that second allocation left the `Slot` recorded
    // nowhere and `NodePool.deinit`'s sweep could not find it. That was found
    // here and fixed in `lockfree` (`acquire` now reserves the list capacity
    // before creating the slot, so there is no fallible step between
    // allocating and recording). The tolerance is therefore gone: ANY net
    // leak at ANY fail index is now a defect, in this ladder or in a
    // dependency, and this test says so.
    var idx: usize = 0;
    var leaking_indices_seen: usize = 0;
    const safety_bound = 64; // generous; init allocates far fewer times than this
    while (idx < safety_bound) : (idx += 1) {
        var failing = std.testing.FailingAllocator.init(std.heap.page_allocator, .{ .fail_index = idx });
        if (WorkerPool.init(failing.allocator(), .{ .io = io, .n_workers = 1, .max_submitters = 0 })) |pool| {
            // `init` succeeded at this fail_index: every earlier index was
            // swept above. Done.
            pool.deinit();
            try testing.expect(idx > 0); // sanity: init does allocate
            try testing.expectEqual(@as(usize, 0), leaking_indices_seen); // no fail index may leak
            return;
        } else |err| {
            try testing.expect(err == error.OutOfMemory); // never SpawnFailed: spawning doesn't use this allocator
            const leaked = failing.allocations - failing.deallocations;
            if (leaked != 0) {
                leaking_indices_seen += 1;
                try testing.expectEqual(@as(usize, 0), leaked); // fails, naming the index and the byte count
            }
        }
    }
    // If we get here, `init` never succeeded within `safety_bound`
    // allocations — the sweep bound itself needs raising, not a real defect,
    // but fail loudly rather than silently passing having tested nothing.
    try testing.expect(false);
}

/// Queue `JobQueue.block_slots - 1` jobs on a paused pool, so the next push
/// claims a block's last slot and must take a new block from the allocator
/// (the queue's spare is empty on a fresh pool).
fn fillToBlockEdge(pool: *WorkerPool, c: *Counter) !void {
    pool.pause();
    for (0..JobQueue.block_slots - 1) |_| try pool.submit(.{ .func = incr, .ctx = c });
}

test "F3: SubmitFailed when the queue cannot get a block leaves accounting untouched" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A real, healthy pool first, so `init`'s own allocations are not in the
    // budget tested below; then fill the first block up to its last slot.
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var c = Counter{};
    try fillToBlockEdge(pool, &c);

    // The next push needs a block: fail that allocation. Only the queue's
    // allocator needs swapping (`push` reads `queue.allocator`).
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    pool.queue.allocator = failing.allocator();
    defer pool.queue.allocator = testing.allocator;

    const before_submitted = pool.submittedCount();
    const before_queued = pool.queue.len();
    try testing.expectError(error.SubmitFailed, pool.submit(.{ .func = incr, .ctx = &c }));
    try testing.expect(failing.has_induced_failure); // the block allocation was the one refused
    try testing.expectEqual(before_submitted, pool.submittedCount()); // rolled back exactly
    try testing.expectEqual(before_queued, pool.queue.len()); // nothing claimed
    try testing.expectEqual(before_submitted, pool.queuedCount());

    // Healthy afterward: restore a real allocator; the same push now gets its
    // block, and every accepted job runs.
    pool.queue.allocator = testing.allocator;
    try pool.submit(.{ .func = incr, .ctx = &c });
    pool.@"resume"();
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, JobQueue.block_slots), c.n.load(.seq_cst));
}

test "STRESS: many concurrent producers via Submitter + pool consuming (MP)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const n_producers = 8;
    const per_producer: u64 = 20_000;

    const pool = try WorkerPool.init(testing.allocator, .{
        .io = io,
        .n_workers = 6,
        .max_submitters = n_producers,
    });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};

    const Producer = struct {
        pool: *WorkerPool,
        counter: *Counter,
        count: u64,
        fn run(self: *@This()) void {
            var sub = self.pool.registerSubmitter() catch @panic("registerSubmitter");
            defer sub.deinit();
            var i: u64 = 0;
            while (i < self.count) : (i += 1)
                sub.submit(.{ .func = incr, .ctx = self.counter }) catch @panic("submit");
        }
    };

    var producers: [n_producers]Producer = undefined;
    var threads: [n_producers]std.Thread = undefined;
    for (&producers, 0..) |*pr, i| {
        pr.* = .{ .pool = pool, .counter = &c, .count = per_producer };
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{pr});
    }
    // Producers must quiesce (join) before drain — the lifecycle contract.
    for (&threads) |*t| t.join();

    pool.drain();
    try testing.expectEqual(n_producers * per_producer, c.n.load(.seq_cst));
    try testing.expectEqual(n_producers * per_producer, pool.completedCount());
}

// W2-B/workerpool-F5: several real OS threads all calling the SAME
// `WorkerPool.submit` concurrently (it was a spinlock-serialized path until
// 2026-10-14; now it is the queue's lock-free multi-producer push) — checks no
// job is lost or double-counted under contention.
test "STRESS: many concurrent producers via the shared submit path" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const n_producers = 8;
    const per_producer: u64 = 5_000;

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 6 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};

    const Producer = struct {
        pool: *WorkerPool,
        counter: *Counter,
        count: u64,
        fn run(self: *@This()) void {
            var i: u64 = 0;
            while (i < self.count) : (i += 1)
                self.pool.submit(.{ .func = incr, .ctx = self.counter }) catch @panic("submit");
        }
    };

    var producers: [n_producers]Producer = undefined;
    var threads: [n_producers]std.Thread = undefined;
    for (&producers, 0..) |*pr, i| {
        pr.* = .{ .pool = pool, .counter = &c, .count = per_producer };
        threads[i] = try std.Thread.spawn(.{}, Producer.run, .{pr});
    }
    for (&threads) |*t| t.join();

    pool.drain();
    try testing.expectEqual(n_producers * per_producer, c.n.load(.seq_cst));
    try testing.expectEqual(n_producers * per_producer, pool.completedCount());
}

test "STRESS: repeated idle→submit→wake hammers the park/wake boundary" {
    // The "idle → wake" test above fires the park→submit→wake edge exactly
    // once (after a 100 ms settle). A lost-wakeup regression that strands a job
    // only intermittently would slip through that single shot. This loops the
    // edge thousands of times against one long-lived pool: each iteration waits
    // for its job to run — so the workers drain to empty and re-park — before
    // the next submit races those parked (or just-about-to-park) workers. A
    // single lost wakeup stalls the completion poll and the watchdog panics.
    // (x86-TSO caveat: a green run here is necessary, not sufficient — the
    // seq_cst ordering discipline is what makes it sound on weak memory.)
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    var poll = std.atomic.Value(u32).init(0);
    const iters: u64 = 5000;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        try pool.submit(.{ .func = incr, .ctx = &c });
        // Block until THIS job has run before submitting the next, so workers
        // observe the queue empty and re-park between iterations — maximizing
        // the number of genuine park→wake transitions exercised.
        while (c.n.load(.seq_cst) < i + 1) {
            io.futexWaitTimeout(u32, &poll.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            } }) catch {};
        }
    }
    try testing.expectEqual(iters, c.n.load(.seq_cst));
    pool.drain();
    try testing.expectEqual(iters, pool.completedCount());
}

test "STRESS: submitter register/deinit churn (the max_submitters budget is reusable)" {
    // Register/deinit a `Submitter` thousands of times against a budget of
    // one WHILE the workers consume: a handle whose `deinit` failed to give
    // its place back would make the second `registerSubmitter` refuse.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{
        .io = io,
        .n_workers = 4,
        .max_submitters = 1,
    });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    const cycles: u64 = 4000;
    const per_cycle: u64 = 8;
    var i: u64 = 0;
    while (i < cycles) : (i += 1) {
        var sub = try pool.registerSubmitter();
        var j: u64 = 0;
        while (j < per_cycle) : (j += 1)
            try sub.submit(.{ .func = incr, .ctx = &c });
        sub.deinit(); // unregister → the single submitter slot is reused next cycle
    }

    pool.drain();
    try testing.expectEqual(cycles * per_cycle, c.n.load(.seq_cst));
    try testing.expectEqual(cycles * per_cycle, pool.completedCount());
}

// ── TEETH: the lost-wakeup ordering (SPEC §4) ───────────────────────────────
//
// The STRESS test above hammers the park/wake edge 5 000 times and still could
// not see an inverted `notify` snapshot: with 2 workers the *sibling* absorbs
// the stranded job, and even with one worker the window between the queue
// re-check and the park is a few instructions wide, so a random race never
// lands in it. More iterations do not help — the window has to be held open.
//
// So it is held open: `park_seam` blocks the (single) worker exactly inside the
// window while the test publishes a job, bumps the generation and issues the
// wake. The wake reaches nobody, because the worker is not parked yet. The job
// can therefore only ever run if the generation the worker parks on is the one
// it snapshotted BEFORE its last look at the queue — which is precisely the
// property SPEC §4's argument rests on.

const LostWakeup = struct {
    io: std.Io,
    /// Worker → test: "I am inside the pre-park window."
    in_window: std.atomic.Value(u32) = .init(0),
    /// Test → worker: "the job is published and the wake has been issued."
    released: std.atomic.Value(u32) = .init(0),
    /// One-shot: only the first park of the run is intercepted.
    used: std.atomic.Value(u32) = .init(0),
};

var lost_wakeup_ctx: std.atomic.Value(?*LostWakeup) = .init(null);

fn lostWakeupSeam() void {
    const ctx = lost_wakeup_ctx.load(.seq_cst) orelse return;
    if (ctx.used.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    ctx.in_window.store(1, .seq_cst);
    ctx.io.futexWake(u32, &ctx.in_window.raw, std.math.maxInt(u32));
    while (ctx.released.load(.seq_cst) == 0) {
        ctx.io.futexWaitTimeout(u32, &ctx.released.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(5),
            .clock = .awake,
        } }) catch {};
    }
}

test "TEETH: the notify snapshot must precede the final queue re-check" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = LostWakeup{ .io = io };
    lost_wakeup_ctx.store(&ctx, .seq_cst);
    defer lost_wakeup_ctx.store(null, .seq_cst);
    park_seam.store(lostWakeupSeam, .seq_cst);
    defer park_seam.store(null, .seq_cst);

    // Exactly ONE worker: with two, the sibling picks the stranded job up and
    // the defect is masked — the reason the 5 000-iteration stress test is
    // structurally incapable of catching this.
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    // The worker starts with an empty queue, so it walks straight into the
    // window and blocks in the seam.
    while (ctx.in_window.load(.seq_cst) == 0) {
        io.futexWaitTimeout(u32, &ctx.in_window.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } }) catch {};
    }

    // Publish + bump + wake while the worker is inside the window: the wake
    // lands on an empty futex queue and is lost, by construction.
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });

    ctx.released.store(1, .seq_cst);
    io.futexWake(u32, &ctx.released.raw, std.math.maxInt(u32));

    // Correct code: the worker holds the pre-submit generation, the futex value
    // no longer matches, the wait returns at once and the job runs.
    // Inverted snapshot: the worker parks on the post-submit generation with
    // the job sitting in the queue and nothing left to wake it — this poll
    // never finishes and the watchdog panics.
    var poll = std.atomic.Value(u32).init(0);
    while (c.n.load(.seq_cst) == 0) {
        io.futexWaitTimeout(u32, &poll.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } }) catch {};
    }
    try testing.expectEqual(@as(u64, 1), c.n.load(.seq_cst));

    pool.drain();
    try testing.expectEqual(@as(u64, 1), pool.completedCount());
    try testing.expect(pool.queue.isEmpty());
}

// ── TEETH: the final re-check, and shutdownNow's waiter wake ────────────────
//
// Two more properties only a held-open window can show (2026-10-04: the
// mutation run left both alive -- removing either changed no test).

/// Shared state for the two seams below; one test at a time installs it.
const SeamCtx = struct {
    io: std.Io,
    pool: ?*WorkerPool = null,
    job_ctx: ?*Counter = null,
    /// One-shot guards.
    used: std.atomic.Value(u32) = .init(0),
    /// Worker held in `park_seam` (wait test) ...
    held: std.atomic.Value(u32) = .init(0),
    /// ... until the test releases it.
    release: std.atomic.Value(u32) = .init(0),
    used_wait: std.atomic.Value(u32) = .init(0),
};

var seam_ctx: std.atomic.Value(?*SeamCtx) = .init(null);

fn pollFlag(io: std.Io, v: *std.atomic.Value(u32)) void {
    while (v.load(.seq_cst) == 0) {
        io.futexWaitTimeout(u32, &v.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } }) catch {};
    }
}

/// `snapshot_seam`: the worker has just seen an empty queue and has not yet
/// taken its `notify` snapshot -- publish a job right here, from the worker's
/// own thread, so its generation bump lands BEFORE the snapshot.
fn submitBeforeSnapshot() void {
    const ctx = seam_ctx.load(.seq_cst) orelse return;
    if (ctx.used.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    ctx.pool.?.submit(.{ .func = incr, .ctx = ctx.job_ctx.? }) catch unreachable;
}

test "TEETH: a job published before the notify snapshot is found by the final re-check" {
    // The worker's last look at the queue (after the snapshot) exists for a
    // job published between its first empty look and the snapshot: that
    // job's `notify` bump is already IN the snapshot, so the park would not
    // return for it, and with `idle` still 0 the submit issued no wake. Only
    // the re-check can find it. Held open by `snapshot_seam`; one worker so no
    // sibling absorbs the job. Without the re-check the worker parks with the
    // job queued and the watchdog fires.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    var ctx = SeamCtx{ .io = io, .job_ctx = &c };
    seam_ctx.store(&ctx, .seq_cst);
    defer seam_ctx.store(null, .seq_cst);

    // Installed before the pool exists, so the worker's very first empty
    // look takes the seam.
    snapshot_seam.store(submitBeforeSnapshot, .seq_cst);
    defer snapshot_seam.store(null, .seq_cst);
    const pool = blk: {
        // The seam needs the pool pointer before the worker can reach it:
        // hold the seam off (`used` = 1) until `ctx.pool` is set.
        ctx.used.store(1, .seq_cst);
        const p = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
        ctx.pool = p;
        break :blk p;
    };
    defer pool.deinit();
    // Wait until the worker has committed to parking (`idle` is raised just
    // before the futex wait, after its snapshot), then arm the seam and bump
    // the generation: the worker's park returns, it loops, finds the queue
    // empty and takes the armed seam on its next empty look.
    while (pool.idle.load(.seq_cst) == 0) std.atomic.spinLoopHint();
    ctx.used.store(0, .seq_cst);
    pool.wakeAll();

    var poll = std.atomic.Value(u32).init(0);
    while (c.n.load(.seq_cst) == 0) {
        io.futexWaitTimeout(u32, &poll.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } }) catch {};
    }
    try testing.expectEqual(@as(u32, 1), ctx.used.load(.seq_cst));
    pool.drain();
    try testing.expectEqual(@as(u64, 1), pool.completedCount());
}

/// `park_seam` for the wait test: hold the worker in its pre-park window.
fn holdWorker() void {
    const ctx = seam_ctx.load(.seq_cst) orelse return;
    if (ctx.held.load(.seq_cst) != 0) return; // one-shot
    ctx.held.store(1, .seq_cst);
    ctx.io.futexWake(u32, &ctx.held.raw, std.math.maxInt(u32));
    pollFlag(ctx.io, &ctx.release);
}

fn shutdownNowThread(pool: *WorkerPool) void {
    pool.shutdownNow();
}

/// `wait_seam`: the waiter has checked counts and state (running) and is
/// about to park. Run a complete `shutdownNow` right here: the worker is let
/// go only once the state says `stopping_now`, so it drops the queued job
/// without running it -- no completion will ever bump `done_gen` again.
fn shutdownInsideWait() void {
    const ctx = seam_ctx.load(.seq_cst) orelse return;
    if (ctx.used_wait.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    const pool = ctx.pool.?;
    const th = std.Thread.spawn(.{}, shutdownNowThread, .{pool}) catch unreachable;
    while (pool.state.load(.seq_cst) == .running) std.atomic.spinLoopHint();
    ctx.release.store(1, .seq_cst);
    ctx.io.futexWake(u32, &ctx.release.raw, std.math.maxInt(u32));
    th.join();
}

test "TEETH: shutdownNow releases a wait() that parked on work it then dropped" {
    // `wait` doc: "false when it was shut down with `shutdownNow` instead
    // (dropped jobs never complete, so waiting on them would hang)". The
    // worker is held before parking while one job is queued (no completion
    // can come from it), the waiter checks -- 0 of 1 done, running -- and
    // `shutdownNow` runs to the end before it parks. Nothing but
    // `shutdownNow`'s own `wakeWaiters` changes `done_gen` from the waiter's
    // snapshot, so without it the waiter parks forever (the watchdog fires).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var ctx = SeamCtx{ .io = io };
    seam_ctx.store(&ctx, .seq_cst);
    defer seam_ctx.store(null, .seq_cst);
    park_seam.store(holdWorker, .seq_cst);
    defer park_seam.store(null, .seq_cst);

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    ctx.pool = pool;
    pollFlag(io, &ctx.held); // the worker is in its pre-park window

    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c }); // queued; the held worker is not idle, no wake

    wait_seam.store(shutdownInsideWait, .seq_cst);
    defer wait_seam.store(null, .seq_cst);
    try testing.expect(!pool.wait());
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst)); // dropped, never run
    try testing.expect(pool.queue.isEmpty());
}

// ── TEETH: what shutdownNow leaves behind ───────────────────────────────────

test "TEETH: shutdownNow takes every queued job off the queue and counts it dropped" {
    // `queue.deinit` would free the blocks of a non-empty queue too, so the
    // allocator cannot tell whether `dropQueued` ran; the accounting can: every
    // submitted job either ran or was dropped, and the queue is empty.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    // Slow jobs, so the abrupt stop is guaranteed to leave a real backlog in
    // the queue — otherwise there would be nothing for `dropQueued` to do
    // and the test would assert a vacuous truth.
    var c = SpinCounter{ .spins = 2_000 };
    const n: u64 = 50_000;
    for (0..n) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });

    pool.shutdownNow();
    const ran = c.n.load(.seq_cst);
    try testing.expect(ran < n); // the backlog was real
    try testing.expectEqual(n, ran + pool.dropped.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
    try testing.expect(pool.queue.isEmpty());
}

test "TEETH: graceful drain leaves the queue empty" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    const n: u64 = 5_000;
    for (0..n) |_| try pool.submit(.{ .func = incr, .ctx = &c });

    pool.drain();
    try testing.expectEqual(n, pool.completedCount());
    try testing.expect(pool.queue.isEmpty());
}

test "default n_workers derives from cpu count and is ≥ 1" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = threaded.io() });
    defer pool.deinit();
    try testing.expect(pool.workerCount() >= 1);
}

test "meta is well-formed" {
    try testing.expect(meta.platform == .any);
    try testing.expect(meta.concurrency == .threadsafe);
}

// ── wait() ───────────────────────────────────────────────────────────────────

test "wait: returns at once on an idle pool, and after the work while the pool keeps running" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    try testing.expect(pool.wait()); // nothing submitted

    var c = SpinCounter{};
    for (0..200) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 200), c.n.load(.seq_cst));
    try testing.expectEqual(pool.submittedCount(), pool.completedCount());

    // Still running: more work, another wait.
    for (0..300) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 500), c.n.load(.seq_cst));

    // After drain, wait reports idle at once.
    pool.drain();
    try testing.expect(pool.wait());
}

fn waitThread(pool: *WorkerPool, out: *std.atomic.Value(u32)) void {
    out.store(if (pool.wait()) 1 else 2, .seq_cst);
}

test "wait: several waiters at once all return" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    var c = SpinCounter{};
    for (0..400) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });
    var results: [4]std.atomic.Value(u32) = @splat(.init(0));
    var threads: [4]std.Thread = undefined;
    for (&threads, &results) |*t, *r| t.* = try std.Thread.spawn(.{}, waitThread, .{ pool, r });
    for (threads) |t| t.join();
    for (results) |r| try testing.expectEqual(@as(u32, 1), r.load(.seq_cst));
    try testing.expectEqual(@as(u64, 400), c.n.load(.seq_cst));
}

test "wait: no lost wakeup — thousands of submit-one-then-wait rounds" {
    // Each round leaves the waiter racing the single completion that ends it:
    // a missed wake would park the waiter forever and trip the watchdog.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 4 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 20_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    const rounds: u64 = 5000;
    for (0..rounds) |i| {
        try pool.submit(.{ .func = incr, .ctx = &c });
        try testing.expect(pool.wait());
        try testing.expectEqual(@as(u64, i + 1), c.n.load(.seq_cst));
    }
}

/// A job that blocks until its gate opens — to hold a worker busy while a
/// shutdown and a waiter race.
const Gate = struct {
    io: std.Io,
    open: std.atomic.Value(u32) = .init(0),
    entered: std.atomic.Value(u32) = .init(0),
};
fn gatedJob(ctx: *anyopaque) void {
    const g: *Gate = @ptrCast(@alignCast(ctx));
    g.entered.store(1, .seq_cst);
    g.io.futexWake(u32, &g.entered.raw, std.math.maxInt(u32));
    while (g.open.load(.seq_cst) == 0) g.io.futexWaitUncancelable(u32, &g.open.raw, 0);
}

fn shutdownThread(pool: *WorkerPool) void {
    pool.shutdownNow();
}

test "wait: shutdownNow releases a waiter with false instead of hanging on dropped jobs" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 10_000 };
    try wd.start();
    defer wd.finish();

    var gate = Gate{ .io = io };
    var c = Counter{};
    try pool.submit(.{ .func = gatedJob, .ctx = &gate });
    for (0..50) |_| try pool.submit(.{ .func = incr, .ctx = &c }); // queued behind the gate
    while (gate.entered.load(.seq_cst) == 0) io.futexWaitUncancelable(u32, &gate.entered.raw, 0);

    var result = std.atomic.Value(u32).init(0);
    const waiter = try std.Thread.spawn(.{}, waitThread, .{ pool, &result });
    const stopper = try std.Thread.spawn(.{}, shutdownThread, .{pool});
    // shutdownNow needs the in-flight job to finish before it can join.
    while (pool.state.load(.seq_cst) == .running) std.atomic.spinLoopHint();
    gate.open.store(1, .seq_cst);
    io.futexWake(u32, &gate.open.raw, std.math.maxInt(u32));
    stopper.join();
    waiter.join();

    try testing.expectEqual(@as(u32, 2), result.load(.seq_cst)); // false: shut down
    try testing.expect(pool.completedCount() < pool.submittedCount()); // jobs were dropped
    try testing.expect(!pool.wait()); // and a later wait says so at once
}

// ── pause / resume ───────────────────────────────────────────────────────────

/// Settle time for "nothing may happen now" assertions.
const settle_ms = 50;

test "pause: submitted jobs stay queued, nothing starts; resume + wait runs them all" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    try testing.expect(!pool.isPaused());
    pool.pause();
    pool.pause(); // idempotent
    try testing.expect(pool.isPaused());
    sleepMsIo(io, 20); // a worker caught between its check and its dequeue has settled

    var c = Counter{};
    const n: u64 = 200;
    for (0..n) |_| try pool.submit(.{ .func = incr, .ctx = &c }); // still accepted
    sleepMsIo(io, settle_ms);
    try testing.expectEqual(@as(u64, 0), pool.completedCount());
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, n), pool.queuedCount());
    try testing.expectEqual(@as(usize, 0), pool.workingCount());

    pool.@"resume"();
    pool.@"resume"(); // idempotent
    try testing.expect(!pool.isPaused());
    try testing.expect(pool.wait());
    try testing.expectEqual(n, c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
    try testing.expect(pool.queue.isEmpty());
}

test "pause: a job already running when pause() is called finishes; the next one waits" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var gate = Gate{ .io = io };
    var c = Counter{};
    try pool.submit(.{ .func = gatedJob, .ctx = &gate });
    while (gate.entered.load(.seq_cst) == 0) io.futexWaitUncancelable(u32, &gate.entered.raw, 0);
    try testing.expectEqual(@as(usize, 1), pool.workingCount());

    pool.pause();
    try pool.submit(.{ .func = incr, .ctx = &c }); // queued behind the paused pool
    gate.open.store(1, .seq_cst);
    io.futexWake(u32, &gate.open.raw, std.math.maxInt(u32));

    // The running job completes ...
    while (pool.completedCount() < 1) sleepMsIo(io, 1);
    sleepMsIo(io, settle_ms);
    // ... the worker does not start the next one.
    try testing.expectEqual(@as(u64, 1), pool.completedCount());
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, 1), pool.queuedCount());
    try testing.expectEqual(@as(usize, 0), pool.workingCount());

    pool.@"resume"();
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 1), c.n.load(.seq_cst));
}

test "pause: drain overrides a pause and runs everything" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    pool.pause();
    sleepMsIo(io, 20);
    var c = Counter{};
    for (0..100) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    sleepMsIo(io, settle_ms);
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));

    pool.drain(); // must wake the parked workers and let them finish the queue
    try testing.expectEqual(@as(u64, 100), c.n.load(.seq_cst));
    try testing.expect(pool.drainedCleanly());
    try testing.expect(pool.queue.isEmpty());
}

test "pause: shutdownNow overrides a pause and drops the queue" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    pool.pause();
    sleepMsIo(io, 20);
    var c = Counter{};
    for (0..50) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    sleepMsIo(io, settle_ms);

    pool.shutdownNow();
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst)); // never started
    try testing.expect(pool.queue.isEmpty());
    try testing.expectEqual(@as(usize, 0), pool.queuedCount()); // slots freed with the drop
    try testing.expectEqual(@as(u64, 50), pool.dropped.load(.seq_cst));
}

test "pause: a pause racing resume and submit never loses a wakeup (2000 rounds)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    // Sequential: each round pauses, submits behind the pause, resumes and
    // waits. A missed resume wake parks the waiter on a job nobody starts.
    for (0..2000) |i| {
        pool.pause();
        try pool.submit(.{ .func = incr, .ctx = &c });
        pool.@"resume"();
        try testing.expect(pool.wait());
        try testing.expectEqual(@as(u64, i + 1), c.n.load(.seq_cst));
    }

    // Concurrent: a thread flips the flag while this one keeps submitting.
    const Toggler = struct {
        pool: *WorkerPool,
        fn run(self: @This()) void {
            for (0..2000) |_| {
                self.pool.pause();
                std.atomic.spinLoopHint();
                self.pool.@"resume"();
            }
        }
    };
    const t = try std.Thread.spawn(.{}, Toggler.run, .{Toggler{ .pool = pool }});
    for (0..2000) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    t.join();
    pool.@"resume"(); // the toggler ends on resume; make it explicit
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 4000), c.n.load(.seq_cst));
}

/// `pause_seam` body: the worker is parked-to-be inside the pause window;
/// resume the pool right there, from the worker's own thread.
fn resumeInsidePauseWindow() void {
    const ctx = seam_ctx.load(.seq_cst) orelse return;
    if (ctx.used.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    ctx.pool.?.@"resume"();
}

test "TEETH: a resume inside the pause window is not slept through (snapshot precedes the re-check)" {
    // With the generation snapshotted AFTER the flag re-check, the bump made
    // by `resume` here would land before the snapshot: the worker would park on
    // the new generation with the flag already clear and the job queued, and
    // nothing would ever wake it -- the watchdog fires.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var ctx = SeamCtx{ .io = io };
    ctx.used.store(1, .seq_cst); // held off until the pool pointer is set
    seam_ctx.store(&ctx, .seq_cst);
    defer seam_ctx.store(null, .seq_cst);
    pause_seam.store(resumeInsidePauseWindow, .seq_cst);
    defer pause_seam.store(null, .seq_cst);

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    ctx.pool = pool;
    sleepMsIo(io, 20); // the worker is parked on the empty queue
    pool.pause();
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c }); // wakes it; it finds the pause
    sleepMsIo(io, settle_ms);
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
    // Arm: the next trip through the pause window resumes the pool. Kick the
    // worker (spurious wake) so that trip happens.
    ctx.used.store(0, .seq_cst);
    pool.wakeAll();

    while (c.n.load(.seq_cst) == 0) sleepMsIo(io, 1);
    try testing.expectEqual(@as(u32, 1), ctx.used.load(.seq_cst));
    try testing.expect(!pool.isPaused());
}

/// `pause_snapshot_seam` hooks: armed (0) they run once (1), from the worker.
const SnapshotSeam = struct {
    pool: ?*WorkerPool = null,
    armed: std.atomic.Value(u32) = .init(1),
    /// For the drain variant: set by the hook, then the hook waits until the
    /// main thread's `drain` has moved the state and bumped the generation.
    reached: std.atomic.Value(bool) = .init(false),
};
var snapshot_seam_ctx: std.atomic.Value(?*SnapshotSeam) = .init(null);

fn resumeBeforePauseSnapshot() void {
    const ctx = snapshot_seam_ctx.load(.seq_cst) orelse return;
    if (ctx.armed.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    ctx.pool.?.@"resume"();
}

fn drainBeforePauseSnapshot() void {
    const ctx = snapshot_seam_ctx.load(.seq_cst) orelse return;
    if (ctx.armed.cmpxchgStrong(0, 1, .seq_cst, .seq_cst) != null) return;
    const pool = ctx.pool.?;
    const gen = pool.notify.load(.seq_cst);
    ctx.reached.store(true, .seq_cst);
    while (pool.state.load(.seq_cst) == .running or pool.notify.load(.seq_cst) == gen) std.atomic.spinLoopHint();
}

fn drainThread(pool: *WorkerPool) void {
    pool.drain();
}

test "TEETH: a resume before the pause branch's snapshot is seen by its flag re-check" {
    // The resume's generation bump lands before the snapshot: a re-check that
    // ignored the flag would park on the new generation with the job queued,
    // and nothing would wake it -- the watchdog fires.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var ctx: SnapshotSeam = .{};
    snapshot_seam_ctx.store(&ctx, .seq_cst);
    defer snapshot_seam_ctx.store(null, .seq_cst);
    pause_snapshot_seam.store(resumeBeforePauseSnapshot, .seq_cst);
    defer pause_snapshot_seam.store(null, .seq_cst);

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .spin_ns = 0 });
    defer pool.deinit();
    ctx.pool = pool;
    sleepMsIo(io, 20); // the worker is parked on the empty queue
    pool.pause();
    var c = Counter{};
    ctx.armed.store(0, .seq_cst);
    try pool.submit(.{ .func = incr, .ctx = &c }); // wakes it; it finds the pause
    while (c.n.load(.seq_cst) == 0) sleepMsIo(io, 1);
    try testing.expectEqual(@as(u32, 1), ctx.armed.load(.seq_cst));
}

test "TEETH: a drain before the pause branch's snapshot is seen by its state re-check" {
    // `drain`'s bump lands before the snapshot, the flag is still set: a
    // re-check that ignored the state would park for good and `drain` would
    // never join the worker -- the watchdog fires.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var ctx: SnapshotSeam = .{};
    snapshot_seam_ctx.store(&ctx, .seq_cst);
    defer snapshot_seam_ctx.store(null, .seq_cst);
    pause_snapshot_seam.store(drainBeforePauseSnapshot, .seq_cst);
    defer pause_snapshot_seam.store(null, .seq_cst);

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .spin_ns = 0 });
    defer pool.deinit();
    ctx.pool = pool;
    sleepMsIo(io, 20);
    pool.pause();
    ctx.armed.store(0, .seq_cst);
    pool.wakeAll(); // a spurious wake: the worker goes round into the pause branch
    while (!ctx.reached.load(.seq_cst)) std.atomic.spinLoopHint();
    const t = try std.Thread.spawn(.{}, drainThread, .{pool});
    t.join();
    try testing.expect(pool.state.load(.seq_cst) == .stopped);
}

// ── workingCount ─────────────────────────────────────────────────────────────

test "workingCount: N blocking jobs on N workers = N, back to 0 after" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const n = 3;
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = n });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    try testing.expectEqual(@as(usize, 0), pool.workingCount());
    var gates: [n]Gate = undefined;
    for (&gates) |*g| {
        g.* = .{ .io = io };
        try pool.submit(.{ .func = gatedJob, .ctx = g });
    }
    for (&gates) |*g| while (g.entered.load(.seq_cst) == 0) sleepMsIo(io, 1);
    try testing.expectEqual(@as(usize, n), pool.workingCount());
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());

    // A fourth job has no free worker: queued, not working.
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expectEqual(@as(usize, 1), pool.queuedCount());
    try testing.expectEqual(@as(usize, n), pool.workingCount());

    for (&gates) |*g| {
        g.open.store(1, .seq_cst);
        io.futexWake(u32, &g.open.raw, std.math.maxInt(u32));
    }
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(usize, 0), pool.workingCount());
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
}

// ── max_queued ───────────────────────────────────────────────────────────────

test "max_queued: 4 accepted on a paused pool, the 5th is QueueFull and changes nothing" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2, .max_queued = 4, .max_submitters = 1 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    pool.pause();
    sleepMsIo(io, 20);
    var c = Counter{};
    for (0..4) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expectEqual(@as(usize, 4), pool.queuedCount());

    const sub_before = pool.submittedCount();
    const len_before = pool.queue.len();
    try testing.expectError(error.QueueFull, pool.submit(.{ .func = incr, .ctx = &c }));
    var s = try pool.registerSubmitter();
    defer s.deinit();
    try testing.expectError(error.QueueFull, s.submit(.{ .func = incr, .ctx = &c }));
    try testing.expectEqual(sub_before, pool.submittedCount()); // accounting untouched
    try testing.expectEqual(len_before, pool.queue.len()); // nothing pushed
    try testing.expectEqual(@as(usize, 4), pool.queuedCount());

    pool.@"resume"();
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 4), c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), pool.queuedCount()); // released on dequeue
    // Room again: the slots really came back.
    for (0..4) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 8), c.n.load(.seq_cst));
}

test "max_queued = 0 is unbounded: a thousand queued jobs behind a pause are all accepted" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    pool.pause();
    sleepMsIo(io, 20);
    var c = Counter{};
    for (0..1000) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expectEqual(@as(usize, 1000), pool.queuedCount());
    pool.@"resume"();
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, 1000), c.n.load(.seq_cst));
}

test "max_queued: the slot is released on the SubmitFailed rollback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // A bound of exactly one block: after `block_slots - 1` queued jobs and a
    // failed push, a slot leaked by the rollback makes the next submit
    // QueueFull.
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .max_queued = JobQueue.block_slots });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 15_000 };
    try wd.start();
    defer wd.finish();

    var c = Counter{};
    try fillToBlockEdge(pool, &c);
    {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        pool.queue.allocator = failing.allocator();
        defer pool.queue.allocator = testing.allocator;
        try testing.expectError(error.SubmitFailed, pool.submit(.{ .func = incr, .ctx = &c }));
        try testing.expectEqual(JobQueue.block_slots - 1, pool.queuedCount());
    }
    try pool.submit(.{ .func = incr, .ctx = &c });
    pool.@"resume"();
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(u64, JobQueue.block_slots), c.n.load(.seq_cst));
}

const Hammer = struct {
    pool: *WorkerPool,
    max: usize,
    ran: std.atomic.Value(u64) = .init(0),
    over_in_job: std.atomic.Value(u64) = .init(0),
    over_after_submit: std.atomic.Value(u64) = .init(0),
    refused: std.atomic.Value(u64) = .init(0),
};
fn hammerJob(ctx: *anyopaque) void {
    const h: *Hammer = @ptrCast(@alignCast(ctx));
    if (h.pool.queuedCount() > h.max) _ = h.over_in_job.fetchAdd(1, .monotonic);
    var i: u32 = 0;
    while (i < 200) : (i += 1) std.atomic.spinLoopHint();
    _ = h.ran.fetchAdd(1, .monotonic);
}

test "max_queued: 8 producers hammering a bound of 3 never overshoot it; every accepted job runs once" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const n_producers = 8;
    const per_producer: u64 = 3_000;
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2, .max_queued = 3, .max_submitters = n_producers });
    defer pool.deinit();
    var wd = Watchdog{ .io = io, .timeout_ms = 60_000 };
    try wd.start();
    defer wd.finish();

    var h = Hammer{ .pool = pool, .max = 3 };
    const Producer = struct {
        h: *Hammer,
        accepted: u64 = 0,
        fn run(self: *@This()) void {
            var sub = self.h.pool.registerSubmitter() catch @panic("registerSubmitter");
            defer sub.deinit();
            while (self.accepted < per_producer) {
                if (sub.submit(.{ .func = hammerJob, .ctx = self.h })) |_| {
                    self.accepted += 1;
                    if (self.h.pool.queuedCount() > self.h.max) _ = self.h.over_after_submit.fetchAdd(1, .monotonic);
                } else |err| switch (err) {
                    error.QueueFull => {
                        _ = self.h.refused.fetchAdd(1, .monotonic);
                        std.Thread.yield() catch {};
                    },
                    else => @panic("submit"),
                }
            }
        }
    };
    var producers: [n_producers]Producer = undefined;
    var threads: [n_producers]std.Thread = undefined;
    for (&producers, &threads) |*pr, *t| {
        pr.* = .{ .h = &h };
        t.* = try std.Thread.spawn(.{}, Producer.run, .{pr});
    }
    for (&threads) |*t| t.join();
    try testing.expect(pool.wait());

    var accepted: u64 = 0;
    for (producers) |pr| accepted += pr.accepted;
    try testing.expectEqual(@as(u64, n_producers * per_producer), accepted);
    try testing.expectEqual(accepted, h.ran.load(.seq_cst)); // exactly once each
    try testing.expectEqual(accepted, pool.completedCount());
    try testing.expectEqual(@as(u64, 0), h.over_in_job.load(.seq_cst));
    try testing.expectEqual(@as(u64, 0), h.over_after_submit.load(.seq_cst));
    try testing.expect(h.refused.load(.seq_cst) > 0); // the bound was actually hit
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
    try testing.expect(pool.queue.isEmpty());
}

test {
    _ = @import("audit_test.zig");
    _ = @import("model_fuzz_test.zig");
    _ = @import("lead_test.zig");
}
