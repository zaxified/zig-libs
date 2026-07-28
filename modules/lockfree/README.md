# lockfree

Lock-free concurrency primitives for shared-memory worker pools:
**epoch-based reclamation (EBR)** plus a **Michael-Scott MPMC queue** built on
it. This is the workspace's first lock-free structure; its immediate consumer
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
```

- `Domain` / `Participant` / `Guard` / `Retired` / `Config` — the **EBR**
  reclamation domain: a global epoch + a fixed registry of per-thread
  participants (each with a pinned local epoch and three epoch-indexed limbo
  bags). `register`/`unregister` are mechanical slot bookkeeping;
  `enterCritical`/`exitCritical`/`retire`/`tryAdvance` are the Fable core (the
  safe-reclaim predicate).
- `MpmcQueue` / `Node` — the **Michael-Scott** unbounded MPMC queue over EBR.
  `init`/`deinit`/`reclaimNode` are mechanical; `enqueue`/`dequeue` (the CAS
  loops) are the Fable core. Because EBR keeps a retired node physically alive
  while any thread is pinned on it, the ABA problem is dissolved — no tagged
  pointer or double-word CAS is needed.
- `NodePool(T)` / `PoolError` — a **poisoning** node pool: freed nodes are
  overwritten with a `0xA5` canary and reused first, so a use-after-free is
  caught by `verifyQuiescent` (or the next `acquire`). This is the in-tree UAF
  detector standing in for a sanitizer (see `SPEC.md`).
- `Backoff` / `SpinLock` / `CachePadded` / `cache_line` — mechanical atomic
  helpers over `std.atomic` (0.16 has no `std.Thread.Mutex`). `SpinLock` is
  test-only, used by the harness oracle; never on a lock-free path.
- `runStress` / `StressConfig` / `Verdict` — the concurrent stress driver: N
  producers push disjoint tagged ranges, M consumers drain, and the merged
  multiset is checked for lost / duplicated / corrupted items.
- `RefQueue` — a correct coarse-spinlock queue: the driver's no-false-positive
  control **and** the linearizability oracle. `BrokenRing` — a deliberately
  racy queue (non-atomic indices) that proves the driver has teeth.

- **Role:** util. **Platform:** any (`std.Thread` + `std.atomic` are cross-OS).
  **Deps:** none (std only). **Concurrency:** threadsafe (lock-free MPMC; EBR
  makes reclamation safe with no mutex).

Provenance: clean-room from published designs — Michael & Scott's non-blocking
queue (PODC 1996) and Keir Fraser's epoch reclamation (2004) as realized in
crossbeam-epoch. No third-party source consulted or copied; no NOTICE entry
required (see CONVENTIONS §5).

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

See `SPEC.md` for the EBR-vs-hazard decision, the Fable-core boundary, the
honest deterministic-vs-probabilistic breakdown of each test, why sanitizers
are not wired in, and the out-of-scope next increments.
