# lockfree

Lock-free concurrency primitives for shared-memory worker pools:
**epoch-based reclamation (EBR)**, a **Michael-Scott MPMC queue** built on
it, a **bounded, allocation-free MPMC ring** (Vyukov) for hand-offs where
the producer must never wait, and a **Chase-Lev work-stealing deque** for
schedulers (one owner pushes and pops LIFO, any thread steals FIFO). This is the workspace's first lock-free structure; its immediate consumer
is the in-process worker pool (P2 DL4), which needs a multi-producer /
multi-consumer work queue whose retired nodes are freed safely — the
use-after-free/ABA-notorious kernel of any lock-free data structure.

> **Core implemented.** The mechanical layer + the verification harness were
> complete and green from Phase 1; the irreducible concurrency-correctness
> **core** — EBR's `enterCritical`/`exitCritical`/`retire`/`tryAdvance` and the
> queue's `enqueue`/`dequeue` CAS loops — is now implemented behind
> `gate.fable_core_implemented` (`true`), each function carrying its
> memory-ordering argument in place (the grace-period safety theorem lives at
> `ebr.Domain.tryAdvance`). The whole kernel uses a **`seq_cst` discipline**:
> Zig 0.16 removed `@fence`, so every reclamation-relevant atomic access (pin
> store, epoch loads/CAS, the scan loads, and the queue head/tail/next
> loads/CAS) is `.seq_cst`, placing them in one total order that forbids the
> store-buffering interleaving a UAF would need. See `SPEC.md`.

```zig
const lockfree = @import("lockfree");

// One reclamation domain + a node pool back the queue.
var domain = try lockfree.Domain.init(allocator, .{ .max_participants = 32 });
defer domain.deinit();
var pool = lockfree.NodePool(lockfree.Node).init(allocator);
defer pool.deinit();
var q = try lockfree.MpmcQueue.init(&pool, &domain);
defer q.deinit();

// Each thread registers once, then enqueues/dequeues under its participant.
const me = try domain.register();
defer domain.unregister(me);
try q.enqueue(me, 42);          // lock-free MS-queue producer
const v = q.dequeue(me);         // ?u64 (null when empty)

// Any payload type: `lockfree.Queue(Job)`, with `Queue(Job).Pool` as its pool.

// The bounded ring: no domain, no pool, no allocation after `init`.
const Ring = lockfree.BoundedQueue(Record, 1024, .{ .consumers = .single });
const ring = try allocator.create(Ring); // slots are inline: heap, not stack
ring.init();
if (!ring.push(rec)) {}                 // full: refused, counted in refusedCount()
while (ring.front()) |r| {              // one consumer, in place
    export(r);
    ring.advance();
}

// The work-stealing deque: one per worker. The owner pushes and pops at the
// bottom; idle workers steal from the top. It grows on demand.
var dq = try lockfree.Deque(*Task).init(allocator, 256);
defer dq.deinit();
try dq.push(task);                      // owner only
if (dq.pop()) |t| run(t);               // owner only: newest first
switch (other.steal()) {                // any thread: oldest first
    .success => |t| run(t),
    .retry => {},                       // lost a race: not empty, try again
    .empty => {},
}
```

- `Domain` / `Participant` / `Guard` / `Retired` / `Config` — the **EBR**
  reclamation domain: a global epoch + a fixed registry of per-thread
  participants (each with a pinned local epoch and three epoch-indexed limbo
  bags). `register`/`unregister` are mechanical slot bookkeeping;
  `enterCritical`/`exitCritical`/`retire`/`tryAdvance` are the Fable core (the
  safe-reclaim predicate). `retire` is **infallible**: `Config.bag_reserve` limbo
  entries per bag are pre-allocated at `init` (the one place an allocator failure
  is surfaceable), and if that reserve is exhausted under a failing allocator the
  node is *abandoned* — never freed under live readers, never a panic — and
  counted in `Domain.droppedRetires`. See `SPEC.md` §4.
- `Queue(T)` / `MpmcQueue` / `Node` — the **Michael-Scott** unbounded MPMC
  queue over EBR, generic over its payload (`MpmcQueue` is `Queue(u64)`).
  `init`/`deinit`/`reclaimNode` are mechanical; `enqueue`/`dequeue` (the CAS
  loops) are the Fable core. Because EBR keeps a retired node physically alive
  while any thread is pinned on it, the ABA problem is dissolved — no tagged
  pointer or double-word CAS is needed.
- `BoundedQueue(T, capacity, .{ .consumers })` / `BoundedOptions` / `Consumers`
  — **Vyukov's bounded MPMC ring** (crossbeam's `ArrayQueue`): `capacity` slots
  inline (a power of two, ≥ 2), one CAS per operation, no allocation, no EBR.
  `push`/`pushWith` (fill in place) return false and count the refusal when
  full; `pop`; with `.consumers = .single` a CAS-free `pop` and in-place
  `front`/`advance`; `len`/`isEmpty`/`isFull` snapshots. A producer stalled
  between claiming and publishing a slot makes the queue read empty at that
  slot until it finishes (nothing lost or reordered) — see `SPEC.md` §4b.
- `Deque(T)` / `Steal(T)` — the **Chase-Lev work-stealing deque** (crossbeam's
  `deque`, LIFO worker + stealer): `push`/`pop` from the one owner thread,
  `steal` (`.success` / `.retry` / `.empty`), `len`/`isEmpty` from any thread.
  Grows by doubling; replaced buffers are kept until `deinit` (together smaller
  than the current one), so a thief needs no epoch pin. `T` is at most one
  machine word (a pointer or an index): a thief reads a slot it may then lose,
  so slots are atomic. See `SPEC.md` §4c.
- `NodePool(T)` / `PoolError` — a **poisoning** node pool: freed nodes are
  overwritten with a `0xA5` canary and reused first, so a use-after-free is
  caught by `verifyQuiescent` (or the next `acquire`). This is the in-tree UAF
  detector standing in for a sanitizer (see `SPEC.md`).
- `Backoff` / `SpinLock` / `CachePadded` / `cache_line` — mechanical atomic
  helpers over `std.atomic` (0.16 has no `std.Thread.Mutex`). `SpinLock` is
  test-only, used by the harness oracle; never on a lock-free path.
- `runStress` / `StressConfig` / `Verdict` — the concurrent stress driver: N
  producers push disjoint tagged ranges, M consumers drain, and the merged
  multiset is checked for lost / duplicated / corrupted items, and each
  consumer's list for one producer's items out of order (`reordered`).
- `RefQueue` — a correct coarse-spinlock queue: the driver's no-false-positive
  control **and** the linearizability oracle. `BrokenRing` — a deliberately
  racy queue (non-atomic indices) that proves the driver has teeth.

- **Role:** util. **Platform:** any (`std.Thread` + `std.atomic` are cross-OS).
  **Deps:** none (std only). **Concurrency:** threadsafe (lock-free MPMC; EBR
  makes reclamation safe with no mutex).

Provenance: clean-room from published designs — Michael & Scott's non-blocking
queue (PODC 1996) and Keir Fraser's epoch reclamation (2004) as realized in
crossbeam-epoch. No third-party source consulted or copied; no NOTICE entry
required (see CONVENTIONS §5). Test data: the thirteen files under `litmus/` are
written by this repo — `.litmus` programs in herd7's input syntax, which is a
published notation, plus a `run.sh` that drives an installed `herd7` as a
black-box oracle (root NOTICE §0). No herdtools7 source or shipped test is
reproduced; the axiomatic models the tests run against belong to herd7's own
installation and are not vendored here.

## Verification

`zig build test-lockfree` — offline, green in Debug **and** ReleaseFast, no
leaks, no skips: with the core implemented, the gated "REAL CORE"
stress test (8 producers × 8 consumers × 50 000 ops, then the pool canary) now
runs for real. The harness proves it bites before *and* after the core exists:

- **CHECKER TEETH (deterministic):** the multiset verifier rejects hand-built
  lost / duplicated / corrupted histories.
- **CANARY TEETH (deterministic):** a use-after-free write to a freed pool node
  trips `verifyQuiescent` and the next `acquire` (`pool.zig`). This is the
  load-bearing UAF detector: a sabotage that breaks the grace period (reclaim
  two-behind → zero-behind) is caught deterministically (verified: SIGSEGV /
  canary trip, 6/6 runs).
- **ORACLE IS CLEAN:** the driver returns `clean` over the correct spinlock
  queue under real thread contention — no false positives.
- **DRIVER TEETH (high probability):** the driver catches the racy `BrokenRing`
  under N×M threads in ReleaseFast.
- **REAL CORE (probabilistic):** the driver over the real `MpmcQueue`+`Domain`,
  then the pool canary. A green run is *corroboration, not proof* — a stress run
  on x86-TSO cannot distinguish a `seq_cst` pin store from a `.release` one
  (verified: that demotion passes 60/60 runs here). Correctness therefore rests
  on the memory-ordering argument in `ebr.zig`, not on seed volume.
- **BOUNDED (probabilistic + deterministic):** the same driver over a 64-slot
  `BoundedQueue` (8×8 and 8×1 × 50 000, the full path hit constantly), a
  drop-on-full run with an in-place consumer, a concurrent `len` check, and the
  two stalled-claim corners driven by hand.
- **DEQUE (probabilistic + deterministic):** one owner pushing in random bursts
  and popping against 6 thieves (400 000 items from 64 slots; 8 rounds of
  50 000 growing from 2 slots while thieves steal), the owner's every pop
  checked against a shadow stack (LIFO) and each thief's steals for FIFO, then
  the multiset; a positive control whose `pop` skips the last-item CAS (caught
  as `duplicated` in the first round, 5/5); the stalled-thief, retired-buffer and
  failed-growth corners by hand; herd7 litmus pairs for the pop/steal interlock.

See `SPEC.md` for the EBR-vs-hazard decision, the Fable-core boundary, the
honest deterministic-vs-probabilistic breakdown of each test, why sanitizers
are not wired in, and the out-of-scope next increments.
