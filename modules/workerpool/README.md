# workerpool

An in-process, fixed-width **worker pool** over `lockfree.MpmcQueue`: a closed
roster of `std.Thread`s pulls type-erased jobs off a shared Michael-Scott
multi-producer/multi-consumer queue and runs them. It is the execution
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
  failed init unwinds fully (spawned workers stopped + joined, participants
  unregistered, storage freed) — no leak.
- `WorkerPool.submit(Job) !void` — zero-setup, thread-safe from any thread.
  Serialized against other `submit` callers by an internal spinlock (so its one
  shared EBR participant is single-owner at enqueue); this is the ergonomic
  default for a coordinator that submits from a few threads.
- `WorkerPool.registerSubmitter() !Submitter` — a per-thread handle owning its
  **own** EBR participant, for **lock-free concurrent** enqueue (genuinely
  exercises the MS-queue's multi-producer side). Bounded by
  `Options.max_submitters`; release with `Submitter.deinit`.
- `WorkerPool.drain()` — **graceful**: stop accepting, run every already-queued
  and in-flight job, join all workers. After it returns the queue is empty and
  every submitted job has run.
- `WorkerPool.shutdownNow()` — **abrupt**: stop accepting, let each worker
  finish only its current in-flight job, join; jobs still queued are **not run**
  but their boxes are **freed** (no leak).
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

**Backpressure — unbounded, non-blocking.** The MS-queue grows on demand, so
`submit` never blocks on a full queue; it fails only with `error.SubmitFailed`
(allocator exhaustion) or `error.Shutdown` (pool no longer accepting). A
bounded/blocking variant is future work (see `SPEC.md`).

**Lifecycle contract.** `submit`/`Submitter.submit` are safe from any thread and
concurrently with each other. The **lifecycle** calls (`drain`, `shutdownNow`,
`deinit`) are single-owner: the caller quiesces its producers (joins submitter
threads) before invoking them — the usual thread-pool discipline. `Submitter`
handles must be `deinit`'d before the pool is torn down.

- **Role:** util. **Platform:** any (`std.Thread` + `std.atomic` + the `Io`
  futex are cross-OS). **Deps:** `lockfree`. **Concurrency:** threadsafe submit;
  single-owner lifecycle.

Provenance: clean-room. Models the shape of `std.Thread.Pool` / a crossbeam
worker pool, built on this workspace's own `lockfree` MS-queue + EBR. No
third-party source consulted or copied; no NOTICE entry required.

## Verification

`zig build test-workerpool` — offline, green in Debug **and** ReleaseFast
(`-Doptimize=ReleaseFast`), no leaks (`std.testing.allocator` is a
DebugAllocator; a leak or double-free fails the test). Real threads throughout;
a watchdog turns any wakeup/shutdown deadlock into a loud panic instead of a
silent hang. **9/9, 0 skipped:**

- **exactly-once:** 20 000 jobs (≫ 4 workers) each increment a shared atomic;
  after `drain`, the count and `completedCount` both equal 20 000.
- **graceful drain + no leak:** full init→submit→drain→deinit; post-drain
  `submit` returns `error.Shutdown`, not a panic.
- **idle → wake:** a submit into a parked pool runs promptly (the worker woke on
  the futex, not by spinning).
- **shutdown while idle / while busy:** both terminate under the watchdog;
  busy-drain runs every queued spin-job before returning.
- **shutdownNow:** in-flight completes, queued dropped, boxes freed (no leak /
  double-free).
- **STRESS (MP):** 8 producer threads each submit 20 000 jobs via their own
  `Submitter` (lock-free concurrent enqueue) while 6 workers consume — all
  160 000 accounted for exactly once.

See `SPEC.md` for the drain semantics, the wakeup/no-lost-wakeup design, the
backpressure policy, and the interaction with `lockfree`'s EBR reclamation.
