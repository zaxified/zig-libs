# lockfree — design & verification

Module purpose + API: see `README.md` (not restated here — CONVENTIONS §5).
This SPEC covers the design decisions, the Fable-core boundary, and the
verification strategy with an honest deterministic-vs-probabilistic breakdown.

## 1. Dedup / std-gap

The workspace has **zero** lock-free data structures before this module. `rg`
for `std.atomic` / lock-free / epoch / hazard / MPMC across `modules/` finds
only *uses* of atomics for counters and coarse spinlocks — `kv` and `resilience`
use a single documented spinlock; nothing implements safe memory reclamation or
a lock-free queue.

Zig 0.16 std provides the *primitives* but no reclamation and no lock-free
container:

- `std.atomic.Value(T)` — `load`/`store`/`swap`/`cmpxchgWeak`/`cmpxchgStrong`/
  `fetchAdd`/…, `spinLoopHint`, `cache_line`. Present and sufficient.
- `std.Thread` — `spawn`/`join`/`getCpuCount`/`yield`. Present.
- **No** `std.Thread.Mutex` / `Condition` / `Pool` in this era (CONVENTIONS §2)
  — the harness oracle therefore uses an `std.atomic` test-and-test-and-set
  spinlock, not a std mutex.
- **No** epoch/hazard reclamation, **no** lock-free queue/stack/map anywhere in
  std.

So the gap is genuine: std gives the atomic bricks; the safe-reclamation kernel
and the lock-free queue on top are what this module adds.

## 2. EBR vs hazard pointers

**Decision: epoch-based reclamation (EBR).** The immediate consumer is the P2
DL4 in-process worker pool: a **fixed, trusted** roster of threads, registered
once at pool construction, running **short** critical sections (grab/return one
work item), none stalling indefinitely inside a critical section.

EBR fits that shape better than hazard pointers:

- **Throughput / overhead.** EBR publishes one epoch per critical section (a
  load of the global epoch + a store to the thread-local epoch). Hazard pointers
  require a store **plus a `seq_cst` fence per protected pointer** on every
  load, then a validation re-read — markedly more per-operation traffic on the
  hot path. For a worker pool churning millions of enqueue/dequeue pairs, EBR's
  lighter pin wins.
- **API surface / simplicity.** EBR needs one pin/unpin around a critical
  section; hazard pointers need per-pointer hazard-slot management and a
  scan-the-hazard-array reclaim. Less core to get memory-ordering-right = less
  Fable surface.

The price of EBR: a thread stalled while pinned stalls global-epoch advance, so
retired garbage accumulates until it unpins (unbounded worst-case memory). That
is a non-issue for a closed pool with bounded, short critical sections — there
is no untrusted or arbitrarily-blocking thread to stall the epoch. **The
disqualifier for EBR would be** untrusted/unbounded thread churn, or long
blocking sections inside a pin; neither applies to DL4. If a future consumer
needs bounded per-node reclamation latency (e.g. a latency-SLO server holding
references across I/O), hazard pointers become the next increment (§6).

Reference design: Keir Fraser's epoch reclamation (PhD thesis, 2004), as
realized in crossbeam-epoch — a global epoch advancing only when every pinned
participant has been observed at the current epoch, with retired nodes freed two
epochs later ("two grace periods").

## 3. Module layout

One module `lockfree`, not a split `ebr` + `queue`, because the two are
co-designed: the queue's `dequeue` retires the old dummy **through** EBR, and
the harness stresses them jointly (the queue is EBR's proving consumer).
Splitting would introduce an artificial dep edge for a Phase-1 scaffold with a
single shared verification story. Files:

- `atomic.zig` — mechanical: `Backoff`, `CachePadded`, oracle `SpinLock`.
- `pool.zig` — mechanical + the UAF canary: `NodePool(T)` (poison-on-free).
- `ebr.zig` — mechanical storage (`Domain`/`Participant`/`register`) + the
  gated EBR core (`enterCritical`/`exitCritical`/`retire`/`tryAdvance`).
- `mpmc.zig` — mechanical node/init/deinit/`reclaimNode` + the gated queue core
  (`enqueue`/`dequeue`).
- `harness.zig` — the stress driver, the correct oracle (`RefQueue`), the broken
  control (`BrokenRing`), the deterministic multiset `verify`, and the tests.
- `gate.zig` — the single `fable_core_implemented` switch.

## 4. The Fable-core boundary

**Fable-irreducible core (6 functions, gated `@panic` stubs):**

1. `Domain.enterCritical` — pin: publish the global epoch into the participant
   with ordering such that a concurrent `tryAdvance` either sees the pin or is
   safe to reclaim past it.
2. `Domain.exitCritical` — unpin: release-store the sentinel so a later advance
   sees it.
3. `Domain.retire` — stage a retired node into the current-epoch limbo bag
   (which bag, read with what ordering against a concurrent advance).
4. `Domain.tryAdvance` — **the safe-reclaim predicate**: only if every pinned
   participant is at the current epoch, advance the epoch and reclaim the
   two-behind bag. One wrong ordering or an off-by-one on the "all observed"
   scan is a use-after-free. This is the hardest function.
5. `MpmcQueue.enqueue` — MS-queue tail CAS + the lagging-tail helping swing.
6. `MpmcQueue.dequeue` — MS-queue head CAS, value read, and retiring the old
   dummy through EBR (never freeing inline).

**Mechanical scaffold (implemented + tested today):** the typed atomic helpers
and backoff; the node pool + its poison/canary; the EBR `Domain`/`Participant`
storage structs and `register`/`unregister` slot bookkeeping; the queue node
type, `init` (dummy sentinel), `deinit`, and `reclaimNode` wiring; the
mutex-oracle `RefQueue`; and the **entire** stress harness + multiset checker +
positive controls.

**Honest tiering.** `enterCritical`/`exitCritical` are, mechanically, a load and
a store — the *code* is tiny. They are still core because the **memory ordering**
is the whole correctness argument (the reason a naive epoch scheme is a UAF).
`retire`'s append is nearly mechanical; it stays core only for the epoch-snapshot
read + its ordering against a concurrent advance. `tryAdvance` and the two CAS
loops are unambiguously core. So the honest picture is: **~2 genuinely hard
functions (`tryAdvance`, `dequeue`), 2 hard-ordering functions (`enqueue`,
`retire`), and 2 small-but-ordering-critical pins.** This is a real Fable kernel
— std gives no safe reclamation, so it is not a "std already does it" case — but
it is a *small* kernel (matching the backlog's "malý-střední" sizing), not a
crypto-scale one.

## 5. Verification strategy — the teeth

Lock-free correctness is probabilistic under naive stress, so detection is
engineered four independent ways, and each is proven to bite **before** the core
exists (the harness runs against controls, not the gated core):

| Test | Mechanism | Nature |
|---|---|---|
| CHECKER TEETH | `verify` rejects hand-built lost/dup/corrupt histories | **deterministic** |
| CANARY TEETH | poison + `verifyQuiescent` catch a UAF write to a freed node | **deterministic** |
| ORACLE IS CLEAN | driver returns `clean` over the correct spinlock queue | real threads, no-false-positive |
| DRIVER TEETH | driver catches the racy `BrokenRing` | **probabilistic** (high) |
| REAL CORE (gated) | driver over `MpmcQueue`+`Domain`, then pool canary | gated SKIP today |

**The multiset invariant.** Each of N producers enqueues a disjoint tagged range
— value = `(pid << 48) | seq`. After the run the merged dequeued multiset must
equal the enqueued set: a missing `(pid,seq)` = **lost** (dropped node), a repeat
= **duplicated** (double-free / ABA / reclaimed-then-reused node aliasing a live
one), an unknown tag = **corrupted** (read of a poisoned reclaimed slot; the pool
poison `0xA5A5…` decodes to `pid = 0xA5A5`, always out of range). This is the
single check that catches all three lock-free failure classes at once.

**Honest note on determinism.** Only the DRIVER TEETH and the REAL CORE stress
are probabilistic — real threads, no controlled interleaving, run in ReleaseFast
where reordering is real. `BrokenRing` corrupts via a **bounded, masked** index
(never a wild dereference), so it loses/duplicates data instead of segfaulting —
that is what makes the teeth *reliable* rather than a crash lottery; and the test
runs several rounds and asserts detection in ≥1, which at 6 producers × 6
consumers × 4000 racing ops is overwhelmingly certain (a single lossy round
essentially never returns `clean`). The CHECKER and CANARY teeth are fully
deterministic and carry the guarantee that the *checkers themselves* are sound
independent of scheduling luck. `RefQueue` is a coarse-locked queue and thus
trivially linearizable, so multiset-equality against it is a sound oracle for the
lock-free queue.

**Sanitizers — investigated, not wired in.** `-fsanitize-thread` (TSan) and
`-fsanitize=address` exist in this toolchain, but:

1. Both **link libc** (a TSan build's `ldd` shows `libc.so.6`), which violates
   the module set's zero-C/zero-libc hard invariant (CONVENTIONS §2) for any
   in-tree build lane.
2. A TSan **smoke probe on this exact toolchain silently failed to report a
   blatant data race** (a plainly-racing non-atomic `counter += 1` across two
   threads produced a lost-update result but **no** ThreadSanitizer warning) —
   so TSan here cannot be relied on as the UAF/race oracle.

Therefore no sanitizer lane is added. The in-tree substitute is the **poisoning
node pool**: a broken reclamation that frees a still-referenced node makes a
reader observe the `0xA5A5…` poison (→ `corrupted` in the multiset) and/or trips
`verifyQuiescent`'s canary — a deterministic, libc-free UAF detector. A future
Fable agent may still run the gated stress under an *out-of-tree* TSan build
manually if a given toolchain's TSan proves functional; that is documented here,
not baked into `build.zig`.

## 6. Out of scope — next increments

- **Lock-free hash map** (the F-LF vein's third structure) — a split-ordered or
  open-addressing lock-free map over the same EBR domain. Deliberately **not**
  scaffolded in Phase 1; it is the next module increment once the queue core
  lands and DL4 needs keyed concurrent state.
- **Hazard-pointer reclamation** — the alternative to EBR for a consumer needing
  bounded per-node reclamation latency (see §2). Would slot in beside `ebr.zig`
  behind the same `Retired` callback shape.
- **Bounded ring MPMC** — a fixed-capacity, allocation-free variant (Vyukov
  style) for back-pressured pools that prefer blocking-on-full to unbounded
  growth. Complements, does not replace, the Michael-Scott queue.
- **Linearizability history check** — the current oracle is multiset-equality
  against a coarse-locked queue (sound for the "no lost/dup/corrupt" properties).
  A full per-op timestamped history + sequential-witness search would additionally
  verify FIFO ordering under concurrency; tractable but deferred.
