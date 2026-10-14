# workerpool

An in-process, fixed-width **worker pool** over `lockfree.SegQueue`: a closed
roster of `std.Thread`s pulls type-erased jobs off one shared unbounded
multi-producer/multi-consumer queue and runs them. Jobs travel by value — no
allocation per job, no lock on submit. It is the execution
substrate for the P2 write-behind data-layer coordinator (DL5), which submits
"flush this dirty entry to the sink" jobs to run off the request path.

Clean lifecycle: `init` → `submit` / `Submitter.submit` → `drain` (graceful) or
`shutdownNow` (abrupt) → `deinit`. Idle workers sleep on an `std.Io` futex (no
busy-spin); the pool owns its threads; misuse returns typed errors, never
panics.

```zig
const workerpool = @import("workerpool");

// The futex-backed wait/wake needs an Io (Zig 0.16 has no io-less blocking
// wait — std.Thread.Condition/Futex are gone). Pass the server's Io.
var threaded = std.Io.Threaded.init(allocator, .{});
defer threaded.deinit();

const pool = try workerpool.WorkerPool.init(allocator, .{
    .io = threaded.io(),
    .n_workers = 4,        // null ⇒ cpu-count-derived (min 1)
});
defer pool.deinit();       // graceful drain, then free

// A job is a type-erased closure: fn(*anyopaque) + a context pointer.
try pool.submit(.{ .func = flushEntry, .ctx = @ptrCast(dirty_entry) });

pool.drain();              // stop accepting; run everything queued; join
```

## API

- `WorkerPool.init(allocator, Options) !*WorkerPool` — spawns the workers and
  returns a **heap-owned** pool (so workers can hold a stable back-pointer). A
  failed init unwinds fully (spawned workers stopped + joined, storage freed) —
  no leak. The allocator must be **thread-safe**: the queue takes a block per 63
  jobs from it on the submitting thread and workers give blocks back.
- `WorkerPool.submit(Job) !void` — zero-setup, **lock-free** from any thread,
  concurrently with other `submit`s.
- `WorkerPool.registerSubmitter() !Submitter` — a counted handle whose `submit`
  is the pool's `submit` (it once owned an EBR participant; kept for source
  compatibility). Bounded by `Options.max_submitters`; release with
  `Submitter.deinit`.
- `WorkerPool.wait() bool` — block until every accepted job has run (nothing
  queued, nothing in flight) and **keep the pool running** — the
  batch-then-barrier pattern. `true` once idle, `false` if `shutdownNow` dropped
  jobs instead. Producers must pause for a guaranteed return (as for `drain`);
  never call it from one of the pool's own jobs (it panics rather than
  deadlocks).
- `WorkerPool.pause()` / `resume()` / `isPaused()` — stop workers from **starting** new jobs and
  let them go on again. Idempotent. A job already running when `pause` is called finishes (nothing is
  interrupted); queued and newly submitted jobs stay queued until `resume`. `drain` and `shutdownNow`
  override a pause; `wait` on a paused pool with queued jobs blocks until `resume`.
- `WorkerPool.workingCount()` — workers currently running a job (a snapshot, one atomic inc/dec per
  job). `queuedCount()` — jobs submitted and not yet started (a snapshot).
- `WorkerPool.drain()` — **graceful**: stop accepting, run every already-queued
  and in-flight job, join all workers. After it returns the queue is empty and
  every submitted job has run.
- `WorkerPool.shutdownNow()` — **abrupt**: stop accepting, let each worker
  finish only its current in-flight job, join; jobs still queued are **not run**,
  they are taken off the queue and counted as dropped.
- `WorkerPool.deinit()` — drains gracefully if still running, then frees
  everything. Safe after `drain`/`shutdownNow`.
- `completedCount()` / `submittedCount()` / `workerCount()` — observability.
- `Job` = `{ func: *const fn(*anyopaque) void, ctx: *anyopaque }`.

**Job shape — why the type-erased closure** (over a generic `WorkerPool(Job)`):
a write-behind coordinator submits heterogeneous work whose only common shape is
"a closure to run later". The closure lets one **non-generic** pool carry any
callable (no per-job-type instantiation, smaller binary); a comptime job type
would force one concrete `Job`/`run` per pool. The caller owns `ctx` and keeps
it valid until the job runs.

**Backpressure — unbounded by default, never blocking.** The queue grows on demand, so
`submit` never blocks; it fails with `error.SubmitFailed` (allocator exhaustion) or
`error.Shutdown` (pool no longer accepting). Set `Options.max_queued = N` to bound it: a submit that
would leave more than `N` jobs queued-and-not-started returns `error.QueueFull` (nothing allocated,
nothing counted; the bound is exact under concurrent submitters), the caller retries or sheds. A
blocking submit is deferred.

```zig
const pool = try workerpool.WorkerPool.init(allocator, .{ .io = io, .n_workers = 4, .max_queued = 64 });
pool.submit(job) catch |err| switch (err) {
    error.QueueFull => shed(job), // back-pressure: the 65th queued job is refused
    error.Shutdown, error.SubmitFailed => return err,
};
pool.pause();            // workers finish what they run, start nothing new
pool.@"resume"();        // ... and go on (a Zig keyword, hence the quoting)
const busy = pool.workingCount();
```

**Lifecycle contract.** `submit`/`Submitter.submit` are safe from any thread and
concurrently with each other. The **lifecycle** calls (`drain`, `shutdownNow`,
`deinit`) are single-owner: the caller quiesces its producers (joins submitter
threads) before invoking them — the usual thread-pool discipline. `Submitter`
handles must be `deinit`'d before the pool is torn down.

- **Role:** util. **Platform:** any (`std.Thread` + `std.atomic` + the `Io`
  futex are cross-OS). **Deps:** `lockfree`. **Concurrency:** threadsafe submit;
  single-owner lifecycle.

Provenance: clean-room. Models the shape of `std.Thread.Pool` / a crossbeam
worker pool, built on this workspace's own `lockfree.SegQueue`. The
module's source copies nothing. Pithikos/C-Thread-Pool (MIT) was read for the
behaviour of `pause`/`resume`/`num_threads_working` (2026-10-13), and an
unmodified copy of it (plus an SPDX line) sits in `tools/c_bench/thpool/` as
the benchmark's reference side — attributed in `NOTICE`. Data: none beyond
that benchmark; `tools/c_bench/main.c` is our own tooling.

## Verification

`zig build test-workerpool` — offline, green in Debug **and** ReleaseFast
(`-Doptimize=ReleaseFast`), no leaks (`std.testing.allocator` is a
DebugAllocator; a leak or double-free fails the test). Real threads throughout;
a watchdog turns any wakeup/shutdown deadlock into a loud panic instead of a
silent hang. **All pass, none skipped:**

- **exactly-once:** 20 000 jobs (≫ 4 workers) each increment a shared atomic;
  after `drain`, the count and `completedCount` both equal 20 000.
- **graceful drain + no leak:** full init→submit→drain→deinit; post-drain
  `submit` returns `error.Shutdown`, not a panic.
- **idle → wake:** a submit into a parked pool runs promptly (the worker woke on
  the futex, not by spinning).
- **shutdown while idle / while busy:** both terminate under the watchdog;
  busy-drain runs every queued spin-job before returning.
- **shutdownNow:** in-flight completes, the rest are dropped — ran + dropped =
  submitted, the queue empty (no leak / double-free of its blocks).
- **SubmitFailed:** the push that needs a new block fails its allocation; the
  queue and every count are unchanged, and the next submit runs.
- **STRESS (MP):** 8 producer threads each submit 20 000 jobs (via `Submitter`,
  and again 8 × 5 000 via the shared `submit`) while 6 workers consume — all
  accounted for exactly once.

- **pause / resume:** nothing starts while paused (200 jobs held for 50 ms), a running job
  finishes, `drain` / `shutdownNow` override a pause, 2 000 racing pause/resume/submit rounds, and a
  held-open lost-wakeup window.
- **workingCount / max_queued:** N gated jobs on N workers read N; a bound of 4 refuses the 5th with
  `QueueFull` and accepts again after `resume` + `wait`; 8 producers on a bound of 3 never overshoot it.

See `SPEC.md` for the drain semantics, the wakeup/no-lost-wakeup design and the
backpressure policy.
