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
const builtin = @import("builtin");
const lockfree = @import("lockfree");

const QNode = lockfree.Node;
const QNodePool = lockfree.NodePool(QNode);
const Participant = lockfree.Participant;

comptime {
    // A job is carried through the u64 MS-queue payload as `@intFromPtr` of a
    // heap `JobBox`. That round-trips losslessly iff a pointer fits in u64.
    std.debug.assert(@sizeOf(usize) <= @sizeOf(u64));
}

/// Test-and-test-and-set mutual exclusion for `submit`'s shared-producer
/// path, escalating through `lockfree.Backoff` instead of a bare
/// `spinLoopHint()` spin — the same shape as this repo's `kv` F1 (a
/// preempted lock holder otherwise stalls every other `submit` caller for a
/// full scheduler quantum with no yield/backoff). Not `lockfree.SpinLock`:
/// that type is documented "test-only... never used on a lock-free path",
/// so a real production lock lives here instead of widening that type's
/// contract.
const BackoffSpinLock = struct {
    state: std.atomic.Value(u32) = .init(unlocked),

    const unlocked: u32 = 0;
    const locked: u32 = 1;

    fn lock(self: *BackoffSpinLock) void {
        if (self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
        var backoff: lockfree.Backoff = .{};
        while (true) {
            while (self.state.load(.monotonic) != unlocked) backoff.pause();
            if (self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
            backoff.pause();
        }
    }

    fn unlock(self: *BackoffSpinLock) void {
        self.state.store(unlocked, .release);
    }
};

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "In-process fixed-width worker pool over `lockfree.MpmcQueue` — type-erased closure jobs, Io-futex idle wakeup (no busy-spin, no lost-wakeup), graceful drain / abrupt shutdown",
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
    .model_after = "std.Thread.Pool / crossbeam worker pool over a Michael-Scott MPMC queue (lockfree)",
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
    producer_lock: BackoffSpinLock = .{},

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

    state: std.atomic.Value(State) = .init(.running),

    // observability (also lets tests assert exact run counts)
    submitted: std.atomic.Value(u64) = .init(0),
    completed: std.atomic.Value(u64) = .init(0),

    /// `JobBox`es handed out by `boxes` and not yet returned to it.
    ///
    /// This exists because a leaked box is **invisible to the allocator**:
    /// `lockfree.NodePool.deinit` `destroy`s every slot it ever allocated
    /// regardless of whether that slot was `release`d, so a `DebugAllocator`
    /// reports a clean teardown even when `freeQueuedBoxes` never ran and tens
    /// of thousands of boxes were abandoned. Both of this module's "no leak"
    /// tests were anchored on nothing until this counter existed. It is the
    /// pool's own accounting, so it holds without any change to `lockfree`
    /// (whose `NodePool` exposes no live-slot count).
    boxes_live: std.atomic.Value(i64) = .init(0),

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
    /// `JobBox`es currently checked out of the box pool. Must be 0 once the
    /// workers have joined and the queue has been drained (`drain`) or flushed
    /// (`shutdownNow`); a non-zero value is a leak the allocator cannot see.
    pub fn outstandingBoxes(self: *const WorkerPool) i64 {
        return self.boxes_live.load(.seq_cst);
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

    /// The shared enqueue path. `p` must be a participant this call owns
    /// exclusively for its duration (the shared-producer spinlock, or a
    /// `Submitter`'s own participant).
    fn enqueueJob(self: *WorkerPool, p: *Participant, job: Job) SubmitError!void {
        if (self.state.load(.seq_cst) != .running) return error.Shutdown;

        const box = self.acquireBox() catch return error.SubmitFailed;
        box.* = .{ .func = job.func, .ctx = job.ctx };

        _ = self.submitted.fetchAdd(1, .monotonic);
        self.queue.enqueue(p, @intFromPtr(box)) catch {
            _ = self.submitted.fetchSub(1, .monotonic);
            self.releaseBox(box);
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

    /// Check a box out of the pool, counting it. Every `boxes.acquire` in the
    /// module goes through here, and every `boxes.release` through
    /// `releaseBox`, so `boxes_live` cannot drift.
    fn acquireBox(self: *WorkerPool) !*JobBox {
        const box = try self.boxes.acquire();
        _ = self.boxes_live.fetchAdd(1, .monotonic);
        return box;
    }

    fn releaseBox(self: *WorkerPool, box: *JobBox) void {
        self.boxes.release(box);
        _ = self.boxes_live.fetchSub(1, .monotonic);
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
        self.releaseBox(box);
        func(ctx);
        _ = self.completed.fetchAdd(1, .monotonic);
    }

    /// Drain any jobs still in the queue without running them, freeing their
    /// boxes. Single-threaded caller (all workers joined) — uses the shared
    /// producer participant to dequeue.
    fn freeQueuedBoxes(self: *WorkerPool) void {
        while (self.queue.dequeue(self.shared_producer)) |value| {
            const box: *JobBox = @ptrFromInt(@as(usize, @intCast(value)));
            self.releaseBox(box);
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

    // The allocator alone cannot see an unreturned `JobBox` (see `boxes_live`),
    // so assert the pool's own accounting too — otherwise "no leak" in this
    // test's name is a claim nothing checks.
    try testing.expectEqual(@as(i64, 0), pool.outstandingBoxes());

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
    // Some may have run, but never more than submitted; queued boxes were
    // freed (the deferred deinit + DebugAllocator prove no leak/double-free).
    try testing.expect(ran <= n);
    try testing.expectEqual(ran, pool.completedCount());
    // Same point as above: the DebugAllocator cannot see an abandoned box.
    try testing.expectEqual(@as(i64, 0), pool.outstandingBoxes());
}

// ── F3: the error ladder (audit W2 `workerpool` F3) ─────────────────────────
//
// Every non-happy path below was previously unreached by any test: no
// `FailingAllocator` anywhere in the suite (`rg 'FailingAllocator'
// modules/workerpool/` returned nothing), so a double-decrement, a missing
// `boxes.release`, or a broken `init` unwind could ship silently.

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

    // Sweep every possible allocation-failure point inside `init` (domain,
    // qnodes, boxes, queue's dummy sentinel, shared_producer registration,
    // the workers slice, each worker's participant registration — one
    // `errdefer` per site, per the doc comment on `init`). Deliberately on
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

test "F3: SubmitFailed on box-acquisition failure leaves accounting untouched" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Build a real, healthy pool first (real allocator) so `init`'s own
    // allocations are not in the budget being tested below — only the
    // allocation `submit` itself triggers (`boxes.acquire`'s fresh `JobBox`,
    // the pool's free list starts empty) is exercised.
    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();

    // Swap in a FailingAllocator that fails on the very first allocation —
    // `boxes.acquire` is the first thing `enqueueJob` allocates, so this
    // fails there, before `submitted` is touched and before the queue is
    // touched at all. Only `boxes`' own allocator needs swapping:
    // `acquireBox` routes through `self.boxes.acquire()`, which reads
    // `self.boxes.allocator`, not the pool's top-level `allocator` field.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    pool.boxes.allocator = failing.allocator();
    defer pool.boxes.allocator = testing.allocator;

    const before_submitted = pool.submittedCount();
    const before_outstanding = pool.outstandingBoxes();
    try testing.expectError(error.SubmitFailed, pool.submit(.{ .func = incr, .ctx = undefined }));
    try testing.expectEqual(before_submitted, pool.submittedCount()); // never incremented
    try testing.expectEqual(before_outstanding, pool.outstandingBoxes()); // box never counted

    // The pool is otherwise still healthy: restore a real allocator and
    // prove a normal submit still works (this was a transient allocator
    // failure, not pool corruption).
    pool.boxes.allocator = testing.allocator;
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });
}

test "F3: SubmitFailed on enqueue failure rolls back submitted-count AND releases the box (no leak)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();

    // Let `boxes.acquire` succeed (fail_index high) but make the QUEUE's own
    // node allocation fail — `queue.enqueue` needs a fresh `QNode` from
    // `qnodes`, a separate pool from `boxes`, so failing only `qnodes`'
    // allocator isolates the rollback branch specifically (`enqueueJob`'s
    // `queue.enqueue(...) catch { submitted.fetchSub; boxes.release; ...
    // }`) from the box-acquisition failure the previous test already covers.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    pool.qnodes.allocator = failing.allocator();
    defer pool.qnodes.allocator = testing.allocator;

    const before_submitted = pool.submittedCount();
    const before_outstanding = pool.outstandingBoxes();
    try testing.expectError(error.SubmitFailed, pool.submit(.{ .func = incr, .ctx = undefined }));
    // Rolled back exactly: `submitted` was incremented then decremented back
    // (not left elevated), and the acquired box was released (not leaked —
    // `outstandingBoxes` returns to what it was before this submit).
    try testing.expectEqual(before_submitted, pool.submittedCount());
    try testing.expectEqual(before_outstanding, pool.outstandingBoxes());

    // Healthy afterward: restore and prove a normal submit still runs.
    pool.qnodes.allocator = testing.allocator;
    var c = Counter{};
    try pool.submit(.{ .func = incr, .ctx = &c });
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

// W2-B/workerpool-F5: `producer_lock` (guarding the shared zero-setup
// `submit` path) had no test exercising it under real concurrent contention
// — every other `submit`-path test calls it sequentially from one thread;
// only the `Submitter` stress test above spawns real threads, and each
// `Submitter` has its own participant, entirely bypassing `producer_lock`.
// This spawns several real OS threads all calling the SAME `WorkerPool.submit`
// (the shared-producer path) concurrently — the shape that actually exercises
// mutual exclusion under contention — and checks no job is lost or
// double-counted, which a broken lock (or a bare-spin lock racing a
// descheduled holder) could otherwise silently corrupt.
test "STRESS: many concurrent producers via the SHARED submit path (producer_lock under real contention)" {
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

test "STRESS: submitter register/deinit churn (dynamic EBR slot reuse)" {
    // Area 3: register/deinit a `Submitter` thousands of times so its EBR
    // participant slot is reused over and over WHILE the workers consume and
    // advance epochs. This hammers the dynamic-registration path — the `in_use`
    // CAS + `local_epoch` reset on a recycled slot racing the workers'
    // `tryAdvance` scans. A reclamation bug on slot reuse would surface as a
    // poison-canary trip (propagated as an init/submit error) or a hang.
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
    try testing.expectEqual(@as(i64, 0), pool.outstandingBoxes());
}

// ── TEETH: box reclamation the allocator cannot see ─────────────────────────

test "TEETH: shutdownNow returns every queued JobBox to the pool" {
    // `testing.allocator` is blind here: `lockfree.NodePool.deinit` frees every
    // slot whether or not it was released, so deleting `freeQueuedBoxes`
    // outright leaves 50 000 abandoned boxes and still reports a clean run.
    // `outstandingBoxes` is the anchor the allocator cannot provide.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();

    var wd = Watchdog{ .io = io, .timeout_ms = 30_000 };
    try wd.start();
    defer wd.finish();

    // Slow jobs, so the abrupt stop is guaranteed to leave a real backlog in
    // the queue — otherwise there would be nothing for `freeQueuedBoxes` to do
    // and the test would assert a vacuous truth.
    var c = SpinCounter{ .spins = 2_000 };
    const n: u64 = 50_000;
    for (0..n) |_| try pool.submit(.{ .func = spinIncr, .ctx = &c });

    pool.shutdownNow();
    const ran = c.n.load(.seq_cst);
    try testing.expect(ran < n); // the backlog was real
    try testing.expectEqual(@as(i64, 0), pool.outstandingBoxes());
}

test "TEETH: graceful drain returns every JobBox to the pool" {
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
    try testing.expectEqual(@as(i64, 0), pool.outstandingBoxes());
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
