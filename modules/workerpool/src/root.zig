// SPDX-License-Identifier: MIT

//! workerpool — an in-process, fixed-width worker pool over the lock-free
//! `lockfree.MpmcQueue`. A closed roster of `std.Thread`s pulls type-erased
//! jobs off a shared Michael-Scott queue and runs them; the pool owns its
//! threads and offers a clean lifecycle: `init` → `submit`/`Submitter.submit`
//! → `drain` (graceful) or `shutdownNow` (abrupt) → `deinit`.
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
//! **Backpressure — unbounded, non-blocking.** The MS-queue grows on demand,
//! so `submit` never blocks on a full queue; it fails only with a typed error
//! on allocator exhaustion (`error.SubmitFailed`) or after shutdown
//! (`error.Shutdown`). A bounded/blocking variant is future work (SPEC §5,
//! mirroring `lockfree` SPEC §6's "bounded ring MPMC").
//!
//! See `SPEC.md` for the drain semantics, the wakeup correctness argument, the
//! backpressure policy, and the interaction with `lockfree`'s EBR reclamation.

const std = @import("std");
const lockfree = @import("lockfree");

const QNode = lockfree.Node;
const QNodePool = lockfree.NodePool(QNode);
const Participant = lockfree.Participant;

comptime {
    // A job is carried through the u64 MS-queue payload as `@intFromPtr` of a
    // heap `JobBox`. That round-trips losslessly iff a pointer fits in u64.
    std.debug.assert(@sizeOf(usize) <= @sizeOf(u64));
}

pub const meta = .{
    // std.Thread + std.atomic + the std.Io futex are cross-OS; the pool logic
    // is portable. (The blocking wait needs an `Io`, which the caller supplies.)
    .platform = .any,
    .role = .util,
    // `submit`, `Submitter.submit`, and the job accounting are safe from any
    // thread. The *lifecycle* (`drain`/`shutdownNow`/`deinit`) is single-owner:
    // one thread orchestrates teardown after producers have quiesced.
    .concurrency = .threadsafe,
    .model_after = "std.Thread.Pool / crossbeam worker pool over a Michael-Scott MPMC queue (lockfree)",
    .deps = .{ .lockfree = {} },
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
    /// Extra EBR participant slots for `Submitter` handles beyond the built-in
    /// shared-`submit` slot. Size this ≥ the number of threads that will hold a
    /// `Submitter` concurrently. Default 0 ⇒ only the shared `submit` path.
    max_submitters: usize = 0,
};

pub const InitError = error{
    /// `std.Thread.spawn` failed (resource limit) after some workers were
    /// already running; the partially-built pool is torn down before this
    /// returns, so no threads leak.
    SpawnFailed,
    /// No free EBR participant slot for a worker (should not happen — the
    /// domain is sized to fit; kept for completeness of the propagated set).
    TooManyParticipants,
    /// The queue's node pool tripped its use-after-free canary while building
    /// the dummy sentinel (propagated from `lockfree`; not expected at init).
    CanaryTripped,
} || std.mem.Allocator.Error;

pub const SubmitError = error{
    /// The pool is no longer accepting work (`drain`/`shutdownNow` has begun).
    Shutdown,
    /// Backing storage for the job could not be allocated (queue node or job
    /// box). The job was NOT enqueued and no accounting changed.
    SubmitFailed,
};

pub const RegisterSubmitterError = error{
    /// No free EBR participant slot — raise `Options.max_submitters`.
    TooManySubmitters,
    /// The pool is shutting down; new submitters are refused.
    Shutdown,
};

/// Lifecycle state. Monotonic: `running` → (`draining` | `stopping_now`) →
/// `stopped`. Read by workers on every loop turn; written by the lifecycle
/// calls.
const State = enum(u8) { running, draining, stopping_now, stopped };

// ── internals ────────────────────────────────────────────────────────────────

/// Heap box holding one job's closure while it sits in the queue. Stored in a
/// thread-safe `NodePool` so steady-state submit/run cycles never hit the
/// general allocator. The queue payload is `@intFromPtr(box)`; because the
/// MS-queue delivers each value to exactly one consumer, exactly one worker
/// owns (and releases) each box — no sharing, so no EBR is needed for the box
/// itself (EBR governs only the queue's own nodes).
const JobBox = struct {
    func: *const fn (ctx: *anyopaque) void,
    ctx: *anyopaque,
};
const BoxPool = lockfree.NodePool(JobBox);

const Worker = struct {
    pool: *WorkerPool,
    participant: *Participant,
    thread: std.Thread = undefined,
};

// ── the pool ─────────────────────────────────────────────────────────────────

pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    // lock-free substrate (from `lockfree`)
    domain: lockfree.Domain,
    qnodes: QNodePool,
    queue: lockfree.MpmcQueue,
    boxes: BoxPool,

    workers: []Worker,

    /// The participant + spinlock backing the zero-setup `submit` path. The
    /// lock serializes `submit` against itself so the single shared participant
    /// is never used by two threads at once (EBR's single-owner rule); it does
    /// NOT serialize against `Submitter`s, which enqueue concurrently with
    /// their own participants. Also used single-threaded at teardown to drain
    /// leftover boxes.
    shared_producer: *Participant,
    producer_lock: lockfree.SpinLock = .{},

    /// Idle-worker wakeup generation. Bumped (and a futex wake issued) after
    /// every publish and every state transition; workers park on a snapshot of
    /// it. Monotonic; wraparound is harmless (the futex compares for equality).
    notify: std.atomic.Value(u32) = .init(0),

    state: std.atomic.Value(State) = .init(.running),

    // observability (also lets tests assert exact run counts)
    submitted: std.atomic.Value(u64) = .init(0),
    completed: std.atomic.Value(u64) = .init(0),

    /// Build and start the pool. Returns a heap-owned `*WorkerPool` so worker
    /// threads can hold a stable back-pointer (a by-value pool would move on
    /// return, dangling those pointers). `deinit` frees it.
    ///
    /// On any failure the partially-constructed pool is fully unwound —
    /// spawned workers are stopped and joined, participants unregistered, all
    /// storage freed — so a failed `init` leaks nothing.
    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!*WorkerPool {
        const n_workers = blk: {
            const requested = options.n_workers orelse (std.Thread.getCpuCount() catch 4);
            break :blk @max(@as(usize, 1), requested);
        };
        // slots: one per worker (dequeue) + the shared submit slot + submitters.
        const max_participants = n_workers + 1 + options.max_submitters;

        const self = try allocator.create(WorkerPool);
        errdefer allocator.destroy(self);

        // Construct directly into `self.*` fields (their addresses are final,
        // as the queue holds `*QNodePool`/`*Domain` into them). Each substrate
        // field gets its own errdefer against `self.*` — no locals to move in,
        // so no double-deinit on the unwind path. Unspecified fields take their
        // struct-declaration defaults (locks, counters, state).
        self.* = .{
            .allocator = allocator,
            .io = options.io,
            .domain = undefined,
            .qnodes = undefined,
            .queue = undefined,
            .boxes = undefined,
            .workers = &.{},
            .shared_producer = undefined,
        };

        self.domain = try lockfree.Domain.init(allocator, .{ .max_participants = max_participants });
        errdefer self.domain.deinit();

        self.qnodes = QNodePool.init(allocator);
        errdefer self.qnodes.deinit();

        self.boxes = BoxPool.init(allocator);
        errdefer self.boxes.deinit();

        self.queue = try lockfree.MpmcQueue.init(&self.qnodes, &self.domain);
        errdefer self.queue.deinit();

        self.shared_producer = try self.domain.register();
        errdefer self.domain.unregister(self.shared_producer);

        const workers = try allocator.alloc(Worker, n_workers);
        errdefer allocator.free(workers);
        self.workers = workers;

        // Register every worker's participant BEFORE spawning any thread, so a
        // spawned worker never races a still-registering sibling.
        var registered: usize = 0;
        errdefer for (workers[0..registered]) |*w| self.domain.unregister(w.participant);
        while (registered < n_workers) : (registered += 1) {
            workers[registered] = .{
                .pool = self,
                .participant = try self.domain.register(),
            };
        }

        // Spawn. On a spawn failure, stop + join the workers already running,
        // then let the errdefers above unregister/free everything.
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
    /// their boxes are freed (no leak). Use when queued work is safe to drop
    /// (e.g. process teardown). Precondition + idempotency as `drain`.
    pub fn shutdownNow(self: *WorkerPool) void {
        if (self.state.cmpxchgStrong(.running, .stopping_now, .seq_cst, .seq_cst) != null) return;
        self.wakeAll();
        for (self.workers) |*w| w.thread.join();
        self.freeQueuedBoxes();
        self.state.store(.stopped, .seq_cst);
    }

    /// Stop (gracefully, if still running) and release every resource. Safe to
    /// call after `drain`/`shutdownNow`, or directly (then it drains first).
    pub fn deinit(self: *WorkerPool) void {
        if (self.state.load(.seq_cst) == .running) self.drain();
        // Defensive: free any boxes still queued (none after a graceful drain;
        // possibly some after `shutdownNow` already freed them — this is a
        // second, now-empty pass and is safe).
        self.freeQueuedBoxes();

        const allocator = self.allocator;
        for (self.workers) |*w| self.domain.unregister(w.participant);
        allocator.free(self.workers);
        self.domain.unregister(self.shared_producer);
        self.queue.deinit();
        self.qnodes.deinit();
        self.boxes.deinit();
        self.domain.deinit();
        allocator.destroy(self);
    }

    /// Submit a job from any thread (zero setup). Thread-safe: serialized
    /// against other `submit` callers by an internal spinlock so the shared
    /// producer participant is single-owner at the moment of enqueue. For
    /// high-fan-in lock-free submission, use `registerSubmitter`.
    ///
    /// Non-blocking; the queue is unbounded. Errors: `Shutdown` (pool no longer
    /// accepting) or `SubmitFailed` (allocator exhaustion).
    pub fn submit(self: *WorkerPool, job: Job) SubmitError!void {
        self.producer_lock.lock();
        defer self.producer_lock.unlock();
        return self.enqueueJob(self.shared_producer, job);
    }

    /// Claim a dedicated `Submitter` bound to the calling thread for lock-free
    /// concurrent enqueue (its own EBR participant — genuinely exercises the
    /// MS-queue's multi-producer side). Release it with `Submitter.deinit`.
    /// Bounded by `Options.max_submitters`.
    pub fn registerSubmitter(self: *WorkerPool) RegisterSubmitterError!Submitter {
        if (self.state.load(.seq_cst) != .running) return error.Shutdown;
        const p = self.domain.register() catch return error.TooManySubmitters;
        return .{ .pool = self, .participant = p };
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

    // ── internal machinery ───────────────────────────────────────────────────

    /// The shared enqueue path. `p` must be a participant this call owns
    /// exclusively for its duration (the shared-producer spinlock, or a
    /// `Submitter`'s own participant).
    fn enqueueJob(self: *WorkerPool, p: *Participant, job: Job) SubmitError!void {
        if (self.state.load(.seq_cst) != .running) return error.Shutdown;

        const box = self.boxes.acquire() catch return error.SubmitFailed;
        box.* = .{ .func = job.func, .ctx = job.ctx };

        _ = self.submitted.fetchAdd(1, .monotonic);
        self.queue.enqueue(p, @intFromPtr(box)) catch {
            _ = self.submitted.fetchSub(1, .monotonic);
            self.boxes.release(box);
            return error.SubmitFailed;
        };

        // Wake exactly one worker AFTER the job is published. Bumping `notify`
        // first defeats the lost-wakeup window: a worker that observed the
        // queue empty and snapshotted the old generation will find it changed
        // and skip parking (or, if already parked, be woken here).
        _ = self.notify.fetchAdd(1, .seq_cst);
        self.io.futexWake(u32, &self.notify.raw, 1);
    }

    /// Bump the generation and wake every parked worker. Called after a state
    /// transition so no worker stays parked through a shutdown.
    fn wakeAll(self: *WorkerPool) void {
        _ = self.notify.fetchAdd(1, .seq_cst);
        self.io.futexWake(u32, &self.notify.raw, std.math.maxInt(u32));
    }

    /// Run one dequeued job. The box is released back to the pool BEFORE the
    /// closure runs, so a long job does not pin box storage; `func`/`ctx` are
    /// copied out first.
    fn runBox(self: *WorkerPool, value: u64) void {
        const box: *JobBox = @ptrFromInt(@as(usize, @intCast(value)));
        const func = box.func;
        const ctx = box.ctx;
        self.boxes.release(box);
        func(ctx);
        _ = self.completed.fetchAdd(1, .monotonic);
    }

    /// Drain any jobs still in the queue without running them, freeing their
    /// boxes. Single-threaded caller (all workers joined) — uses the shared
    /// producer participant to dequeue.
    fn freeQueuedBoxes(self: *WorkerPool) void {
        while (self.queue.dequeue(self.shared_producer)) |value| {
            const box: *JobBox = @ptrFromInt(@as(usize, @intCast(value)));
            self.boxes.release(box);
        }
    }
};

/// A per-thread handle for lock-free concurrent submission. Owns its own EBR
/// participant; `submit` enqueues with it directly (no shared lock). Not itself
/// thread-safe — one `Submitter` per submitting thread. Release with `deinit`
/// before the pool is torn down.
pub const Submitter = struct {
    pool: *WorkerPool,
    participant: *Participant,

    pub fn submit(self: *Submitter, job: Job) SubmitError!void {
        return self.pool.enqueueJob(self.participant, job);
    }

    pub fn deinit(self: *Submitter) void {
        self.pool.domain.unregister(self.participant);
        self.* = undefined;
    }
};

// The worker thread body. A free function (not a method) so `std.Thread.spawn`
// can name it; takes the stable `*Worker`.
fn workerRun(w: *Worker) void {
    const self = w.pool;
    const p = w.participant;
    while (true) {
        const st = self.state.load(.seq_cst);
        // Abrupt stop: drop whatever is queued, exit now (in-flight job, if
        // any, already completed before this loop turn).
        if (st == .stopping_now) break;

        if (self.queue.dequeue(p)) |value| {
            self.runBox(value);
            continue;
        }
        // Queue observed empty.
        if (st == .draining) break; // graceful: nothing left ⇒ done.

        // st == .running: park until woken. Snapshot the generation FIRST,
        // then re-check the queue and state, so any submit/shutdown that raced
        // in between bumped the generation and makes the wait return at once.
        const gen = self.notify.load(.seq_cst);
        if (self.queue.dequeue(p)) |value| {
            self.runBox(value);
            continue;
        }
        if (self.state.load(.seq_cst) != .running) continue; // re-handle stop/drain
        self.io.futexWaitUncancelable(u32, &self.notify.raw, gen);
        // Woken (real, or spurious) — loop and re-evaluate.
    }
    // NB: the worker does NOT unregister its own participant here. `deinit`
    // unregisters every worker participant in one place (after joining), so
    // self-unregistering would be a double-unregister of the same slot.
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

    pool.deinit(); // frees everything; DebugAllocator verifies no leak
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
    // Some may have run, but never more than submitted; queued boxes were
    // freed (the deferred deinit + DebugAllocator prove no leak/double-free).
    try testing.expect(ran <= n);
    try testing.expectEqual(ran, pool.completedCount());
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
