# workerpool — design & semantics

Module purpose + API: see `README.md` (not restated here — CONVENTIONS §5).
This SPEC covers the lifecycle/drain semantics, the wakeup correctness argument
(no lost wakeup, no shutdown deadlock), the backpressure policy, and the
interaction with `lockfree`'s epoch-based reclamation.

## 1. Dedup / std-gap

Zig 0.16 std has **no** general-purpose thread pool available to this module
set. `std.Thread.Pool` exists in the tree but the blocking primitives it and
any hand-rolled pool would need — `std.Thread.Mutex`, `std.Thread.Condition`,
`std.Thread.Semaphore`, `std.Thread.Futex` — were **removed** in 0.16 (futexes
moved onto the `std.Io` vtable). Building an idle-blocking pool therefore means
(a) a lock-free work queue with safe reclamation, and (b) an `Io`-futex wakeup
protocol. (a) is exactly what `lockfree` provides (its stated immediate
consumer is *this* pool); (b) is what this module adds on top. There is no
existing worker pool in `modules/` to extract from — this is the first.

## 2. Layering on `lockfree`

The pool is a thin lifecycle + wakeup layer over `lockfree`:

- **`lockfree.MpmcQueue`** transports work. Its payload is a `u64`, so a job
  (two pointers) cannot ride inline. Each `submit` allocates a **`JobBox`**
  (`{func, ctx}`) from a `lockfree.NodePool(JobBox)` and enqueues
  `@intFromPtr(box)`; a worker dequeues, recovers the box, copies the closure
  out, **releases the box**, then runs. Because the MS-queue delivers each value
  to exactly one consumer, exactly one worker owns each box — no sharing, so the
  box needs **no** EBR (EBR governs only the queue's own nodes). The box pool is
  `NodePool`, which is internally spinlock-synchronized, so submit/run from many
  threads is safe and steady-state cycles reuse boxes without hitting the
  general allocator.
- **`lockfree.Domain`** (EBR) backs the queue. Every thread that touches the
  queue needs its own `Participant`: each **worker** registers one for
  `dequeue`; the shared `submit` path uses **one** participant guarded by a
  spinlock (so it is single-owner at the instant of enqueue); each `Submitter`
  owns a dedicated participant for lock-free concurrent enqueue. The domain is
  sized `n_workers + 1 + max_submitters`.

**Reclamation interaction we had to handle.** `dequeue` retires the old dummy
node **through EBR** into the retiring worker's limbo bags; those bags are
reclaimed lazily as the global epoch advances. Two consequences drove the
teardown order:

1. **Retire allocates.** `ebr.retire` may grow a limbo `ArrayList` via the
   *domain's* allocator, concurrently from every worker. The supplied allocator
   must be thread-safe — `std.testing.allocator`/`DebugAllocator` qualify (the
   `lockfree` REAL-CORE stress drives 8×8 threads through it). Documented as a
   caller requirement.
2. **`unregister` self-drains, and order matters.** `Domain.unregister` spins
   `tryAdvance` (unpinned) until the participant's bags empty, then frees the
   slot. `deinit` therefore: (i) `freeQueuedBoxes` — dequeue any leftover jobs
   (retiring their nodes into the *shared producer's* bags) and free the boxes;
   (ii) unregister every **worker** participant (draining their bags); (iii)
   unregister the **shared producer** (draining the bags from step i); (iv)
   `queue.deinit` (now quiescent — no pinned threads) returns the sentinel chain
   to the node pool; (v) free the node pool, box pool, domain, and the pool
   struct. Workers deliberately do **not** self-unregister on exit — `deinit`
   unregisters all worker participants in one place, so self-unregistering would
   double-free a slot.

## 3. Lifecycle & drain semantics

State is monotonic: `running` → (`draining` | `stopping_now`) → `stopped`, set
by a single CAS in `drain`/`shutdownNow` (idempotent — a second call no-ops).

- **`drain` (graceful, and the `deinit` default).** CAS `running→draining`, wake
  all workers, join. A worker in `draining` state: if `dequeue` yields a job it
  runs it; only when it observes the queue **empty** does it exit. Since
  producers have quiesced (contract §5), the queue only shrinks, so "empty"
  observed by any worker is permanent — every queued job is dequeued by exactly
  one worker (MS-queue guarantee) and run before that worker exits. Result: all
  submitted work completes.
- **`shutdownNow` (abrupt).** CAS `running→stopping_now`, wake all, join. A
  worker checks `stopping_now` at the **top** of each turn and breaks
  immediately — so a worker mid-job finishes that job (already dequeued), then
  exits without draining. Remaining queued jobs are **not run**; after join,
  `freeQueuedBoxes` dequeues and frees them (no leak). Use when queued work is
  safe to drop (process teardown).
- **`deinit`.** If still `running`, `drain` first; then free everything (§2).

## 4. Wakeup correctness — no busy-spin, no lost wakeup, no shutdown deadlock

Idle workers must sleep (not spin at 100% CPU) yet wake on both a submit **and**
a shutdown, with no missed wakeup and no hang. The mechanism is a **monotonic
generation counter** `notify: u32` and the `std.Io` futex.

**Producer/shutdown side** (after making the event visible):

```
submit:     enqueue(box)          // publish the job (seq_cst MS-queue)
            notify += 1           // bump generation (seq_cst)
            futexWake(&notify, 1) // wake one worker
shutdown:   state = draining/…    // publish the state (seq_cst, CAS)
            notify += 1
            futexWake(&notify, ∞) // wake all
```

**Worker side** (park only on the exact generation last observed):

```
loop:
  st = state.load(seq_cst)
  if st == stopping_now: break
  if dequeue() |v|: run(v); continue        // work drains first
  if st == draining:  break                 // graceful: empty ⇒ done
  gen = notify.load(seq_cst)                // SNAPSHOT before parking
  if dequeue() |v|: run(v); continue        // re-check queue …
  if state.load(seq_cst) != running: continue   // … and state
  futexWaitUncancelable(&notify, gen)       // sleeps iff *notify == gen
```

**No lost wakeup.** The producer bumps `notify` *after* publishing the job, and
the worker snapshots `notify` *before* the final re-check + park. Consider a
submit racing a worker about to park:

- If the enqueue is visible to the worker's re-check `dequeue`, the worker takes
  the job and never parks.
- If it is *not* visible there, then (program order + `seq_cst`) the producer's
  `notify += 1` is not visible either, so `*notify` still equals the worker's
  snapshot `gen`. `futexWaitUncancelable` atomically re-tests `*notify == gen`
  under the futex bucket lock before sleeping; if the producer bumps in between,
  the wait returns immediately, otherwise the producer's later `futexWake`
  unblocks it. Either way the job is served.

The same argument covers shutdown: `drain`/`shutdownNow` bump `notify` after the
state CAS, so a worker cannot park through a shutdown it hasn't observed — it
either sees the new state on re-check (and loops to exit) or is woken from the
wait. Hence **no shutdown deadlock**: `join` always completes.

**No busy-spin.** A worker only spins while it is *finding work*; once it
observes the queue empty (in `running`) it blocks on the futex until a real or
spurious wake. Spurious wakes just re-run the loop (cheap) and re-park.

## 5. Backpressure policy

The MS-queue is **unbounded** (grows via its node pool), so `submit` is
**non-blocking** and never sheds on a "full" queue. The only failure modes are
typed: `error.SubmitFailed` (a box or queue-node allocation failed) and
`error.Shutdown` (state ≠ running). This matches the DL5 consumer, where the
flush *work* — not the enqueue — is the bottleneck, and where losing a queued
flush silently would be worse than growing the queue.

**Producer-quiescence contract.** `submit`/`Submitter.submit` may run from any
threads concurrently; the lifecycle calls (`drain`/`shutdownNow`/`deinit`) may
**not** run concurrently with a `submit`. The owner joins its submitter threads
first. This is the standard executor contract and is what lets `drain` treat a
first observed-empty queue as permanently empty (§3) without a
submitted-vs-completed reconciliation dance.

## 6. Verification — real threads, both opt levels

`zig build test-workerpool` and `… -Doptimize=ReleaseFast`, both green, no
leaks. 9 tests, all on real `std.Thread`s over a real `std.Io.Threaded` futex; a
**watchdog** thread panics if any operation misses its deadline, converting a
(hypothetical) lost-wakeup/deadlock from a silent hang into a loud, bounded
failure. Coverage: exactly-once over 20 000 jobs ≫ workers; graceful-drain
completeness + post-drain `error.Shutdown`; idle→wake promptness;
shutdown-while-idle and shutdown-while-busy termination; `shutdownNow`
in-flight-vs-queued + no-leak; and an 8-producer × 6-worker × 20 000
`Submitter` stress that drives the MS-queue's genuine multi-producer path
(160 000 jobs, each run once). ReleaseFast matters: reordering is real there, so
a green ReleaseFast run corroborates the ordering discipline in §4 (the
underlying `seq_cst` reclamation proof lives in `lockfree`).

## 7. Out of scope — next increments

- **Bounded / blocking submit.** A fixed-capacity queue with `submit` blocking
  (or shedding with `error.QueueFull`) on a full queue, for callers that prefer
  back-pressure to unbounded growth — pairs with `lockfree` SPEC §6's "bounded
  ring MPMC".
- **Result / future handles.** `submit` currently is fire-and-forget; a variant
  returning a completion future (join/await a specific job's result) is a
  mechanical add once `std.Io` async settles.
- **Priority / fairness.** A single FIFO queue today; a multi-queue or
  work-stealing variant (crossbeam-deque style) is deferred until a consumer
  needs it.
- **Panicking jobs.** A job that panics aborts the process (as any thread body
  does). Catching/quarantining a faulty job would need a per-job boundary; not
  attempted — the DL5 flush closures are trusted, non-panicking code.
