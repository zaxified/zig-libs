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

**Fable-irreducible core (6 functions, implemented — `gate.fable_core_implemented = true`):**

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

## 4a. Memory-ordering discipline (the implemented core)

**`seq_cst` everywhere it is reclamation-relevant.** Zig 0.16 removed the
standalone fence (`@fence`), so the classic Fraser/crossbeam recipe — "store the
pin, then a `seq_cst` fence, then read shared pointers" — is not expressible. The
sound substitute is to make every reclamation-relevant atomic access *itself*
`.seq_cst`: the pin store (`enterCritical`), every `global_epoch` load/CAS
(`enterCritical`/`retire`/`tryAdvance`), the scan loads of each participant's
`local_epoch` (`tryAdvance`), and — in `mpmc.zig` — every load/CAS of the
queue's `head`/`tail`/`Node.next`. All then belong to the single total order **S**
that C11/LLVM guarantees over `seq_cst` operations, and it is S that forbids the
store-buffering interleaving ("a scan misses a pin *and* the pinned thread reads
a pre-unlink pointer") that acquire/release alone would permit. The full theorem
lives at `ebr.Domain.tryAdvance`; the Dekker interlock in it is exactly why the
pin store, the scan loads, the epoch accesses **and** the queue pointer accesses
must all be `seq_cst` — demote any one to acquire/release and the contradiction
the theorem relies on evaporates.

Two accesses are deliberately **not** `seq_cst`, each with a proof it is safe:
the unpin store (`exitCritical`) is `.release` — it only needs to establish the
happens-before edge that keeps the pool's poison memset from racing a reader's
last node access; a missed unpin errs only toward *not* advancing (safe). And
`register`'s `in_use` CAS is `.acquire` — which is *why* `tryAdvance` scans every
slot's `local_epoch` (all `seq_cst`) rather than gating on `in_use`: an
`in_use`-gated scan could miss a just-registered-and-pinned slot.

**Portability caveat — x86_64-TSO only, by test coverage.** The module logic is
portable (`meta.platform = .any`; `std.Thread` + `std.atomic` are cross-OS), and
the `seq_cst` argument is an ISA-independent C11/LLVM guarantee. But the stress
test only ever *ran* on x86_64 (a TSO memory model). On x86-TSO a `seq_cst` load
is a plain `MOV` and a `seq_cst` store is an `XCHG`/`MOV+MFENCE`, so the one
reordering the discipline must forbid (store→load) is the *only* one TSO allows —
and the window is so narrow that stress cannot reliably hit it (see §5). On a
weaker model (AArch64, POWER) the same `seq_cst` source is still correct by the
theorem, but far more of the ordering is doing real work at runtime, so the
empirical stress would exercise it harder. Bottom line: correctness is carried by
the argument, not by the ISA; the "verified on" claim is x86_64-TSO only.

What the discipline *costs* is a separate question from what it buys, and it is
now measured rather than estimated — see **§7.0a**. Short version: on x86-64 and
on the aarch64 baseline, demoting every non-interlock `seq_cst` site to
acquire/release changes **not one instruction**; the only x86-64 instruction the
discipline pays for is the `xchg` behind `enterCritical`'s pin store (≈8.7 ns per
pin), which is the Dekker store and cannot be given up. A real barrier gap exists
only on riscv64 and ARMv8.3+.

**Self-draining `unregister`.** The Phase-1 scaffold's contract was "the caller
must have drained its limbo bags before unregistering," asserted in Debug. That
is **not deterministically satisfiable** by a caller: draining needs the global
epoch to move ≥ 2 past the last retire, and any concurrently pinned thread (e.g.
one the OS preempted mid-pin) stalls that arbitrarily — so a finite "drain then
unregister" dance always has a losing schedule (observed as a rare
unregister-assert abort, ~1-in-20, in the gated stress). `unregister` therefore
now **self-drains**: it spins `tryAdvance` *unpinned* (with backoff) until its
bags empty, then flips `in_use`. This terminates under the module's own liveness
contract — no thread stays pinned forever (per-attempt pins in `mpmc`) — and
cannot deadlock: the spinning thread is unpinned, so it never blocks the very
advance it waits on; a lone/last participant self-drains deterministically. A
**non-blocking alternative** — migrating leftover garbage to a domain-global
limbo (crossbeam-style) so `unregister` returns immediately — is the documented
next increment (§6); the self-draining version is accepted for the fixed, trusted
DL4 roster where a brief bounded wait at teardown is a non-issue.

**Allocation on the retire path — the bounded reserve (was: `dequeue`'s OOM
`@panic`).** `retire` is called pinned and *after* the unlink, so by then the node
is out of the structure and its payload is already in the caller's hands: there is
nothing to roll back, and `dequeue`'s `?u64` cannot surface an error anyway. The
first version therefore `@panic`ed on `error.OutOfMemory` from the limbo-bag
append, on the argument that both alternatives (lose the node, or free it under
live readers) were wrong. That argument was half right — freeing under readers is
a use-after-free and is never acceptable — but aborting the process is not the
lesser evil it looks like: it loses *all* the memory rather than one node, and it
turns a recoverable allocator failure into a crash for every consumer of the
module. `retire` is now **infallible**, via two mechanisms, neither of which
touches an ordering or the reclaim predicate:

1. **A bounded reserve.** `Config.bag_reserve` (default 16) limbo entries per bag
   per participant are pre-allocated in `Domain.init` — where a failure is just an
   `error.OutOfMemory` out of a constructor. Bags keep capacity across drains
   (`clearRetainingCapacity`), so once warm, retire never calls the allocator at
   all; the reserve exists to cover the cold start and to bound the window in
   which the remaining path can be reached.
2. **Abandon, never free.** If the reserve is exceeded *and* the grow fails, the
   node is dropped on the floor: not staged, not reclaimed. An abandoned node is
   never returned to the `NodePool`, hence never re-acquired, hence can never
   alias a live node — the same conservative direction the whole module takes, and
   the only one of the three responses that is safe in the reclamation sense. Nor
   is it a heap leak: the node is a pool slot, destroyed by `NodePool.deinit` at
   teardown regardless, so the loss is bounded pool capacity. It is counted
   (`Domain.droppedRetires`, quiescent-read) so a consumer that cares can assert
   zero.

`dequeue` keeps its `?u64` signature and contains no failure handling at all. Note
what did **not** change: the retire tag is still the fresh `.seq_cst`
`global_epoch` read, the drain predicate is still `observed − tag ≥ 2`, and the
abandon path leaves `bag_epoch` untouched (the bag is unchanged, and an empty
bag's tag is meaningless). The §7/§7.1 certifications cover the atomics and are
unaffected — the reserve and the abandon path are plain single-owner memory on a
path where the allocator has already failed. Tested with
`std.testing.FailingAllocator` (alloc *and* remap refused): the reserve carries
`bag_reserve` retires with zero allocations, and past it a `dequeue` still returns
its value, drops nothing else, frees nothing early (`verifyQuiescent` clean), and
does not panic.

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
| REAL CORE | driver over `MpmcQueue`+`Domain` (8×8×50 000), then pool canary | **probabilistic** — runs now (core implemented); green is corroboration, not proof (see below) |

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

**What the stress can and cannot catch (sabotage self-check).** Owner-verify
mutated the real core two ways and re-ran the ReleaseFast suite. A **gross**
error — breaking the grace period (reclaim two-behind → zero-behind, freeing live
nodes) — is caught **6/6 runs** (SIGSEGV at REAL CORE / canary trip), confirming
the teeth bite the implemented core, not just the controls. A **subtle** ordering
error — demoting the `enterCritical` pin store from `.seq_cst` to `.release`
(exactly the Dekker-interlock break the theorem forbids) — is **not caught in 60
runs** on x86_64-TSO, because on TSO the missed reordering window is vanishingly
rare (§4a). This is the empirical proof of the module's central claim:
**correctness of the ordering rests on the argument at `tryAdvance`, not on stress
volume.** A green REAL CORE run is corroboration; the reasoning audit is the
proof.

**Sanitizers — investigated, not wired in.** Of the two, only
`-fsanitize-thread` (TSan) exists for pure-Zig code in this toolchain
(0.16); there is **no** `-fsanitize=address` flag for Zig source (`zig test
-fsanitize=address` fails with *"unrecognized parameter"* — only `-fsanitize-c`,
for C UB, and `-fsanitize-thread` are accepted), so an ASan lane is not available
at all. And TSan is unusable here for two reasons:

1. It **links libc** (a TSan build's `ldd` shows `libc.so.6`), which violates
   the module set's zero-C/zero-libc hard invariant (CONVENTIONS §2) for any
   in-tree build lane.
2. TSan **silently fails to report a blatant data race on this toolchain** —
   re-confirmed during owner-verify: a TSan build of the suite runs the racy
   `BrokenRing` DRIVER-TEETH test (non-atomic `head`/`tail` hammered by 12
   threads) to completion with **zero** ThreadSanitizer diagnostics. So TSan here
   cannot be relied on as the UAF/race oracle.

Therefore no sanitizer lane is added. The in-tree substitute is the **poisoning
node pool**: a broken reclamation that frees a still-referenced node makes a
reader observe the `0xA5A5…` poison (→ `corrupted` in the multiset) and/or trips
`verifyQuiescent`'s canary — a deterministic, libc-free UAF detector. A future
Fable agent may still run the gated stress under an *out-of-tree* TSan build
manually if a given toolchain's TSan proves functional; that is documented here,
not baked into `build.zig`.

## 6. Out of scope — next increments

*(Removed from this list 2026-08-09: "non-blocking `unregister` via a global
limbo". It is implemented — see `ebr.Domain.unregister` / `adoptOrphans`. The
shape landed is orphan-slot adoption rather than a domain-global bag: the
departing thread leaves its garbage in its own slot and publishes an `orphaned`
flag, and the next `tryAdvance` by any participant CASes that flag to take
exclusive ownership. Same effect, and it needs no new shared container and no
new memory ordering.)*

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

## 7. Weak-memory codegen certification (aarch64 + riscv64)

**Result: no too-weak barrier found.** Every load-bearing atomic in the
reclamation core and the MPMC queue lowers to an architecturally correct
instruction sequence on both weak-memory targets. `0` too-weak sites, `0`
gratuitously-too-strong sites.

### Why this audit exists

The whole memory-ordering discipline (§4a) is invisible on x86_64: TSO masks
store→load reordering, so the pin/scan Dekker interlock at `enterCritical` ⇄
`tryAdvance` cannot be violated there regardless of what the compiler emits. The
open question is whether the compiler emits the barriers the ARM/RISC-V models
*require*. A missing barrier is a latent use-after-free that only manifests as
reordering on weak hardware. We have no ARM/RISC-V hardware, and QEMU-TCG honors
barriers but does not *expose* a missing one (it does not model speculative
reordering), so QEMU cannot certify ordering. This section therefore certifies
**statically, from the generated machine code**, and treats the QEMU run below as
functional sanity only.

### Toolchain / method

- Compiler: Zig 0.16.0 (bundled LLVM), targets `aarch64-linux` and
  `riscv64-linux`, both `-O ReleaseFast` and `-O ReleaseSafe`.
- Disassembly: the bundled `zig objdump` is a stub and system `objdump`
  (binutils 2.46) is a single-arch build that cannot decode either target, so the
  audit reads Zig's own `-femit-asm` target assembly directly — this is the
  compiler's final instruction selection, one step *before* object emission, and
  is the authoritative record of what each `@atomic*` site lowers to.
- A throwaway driver referenced `enterCritical`/`exitCritical`/`retire`/
  `tryAdvance`/`register`/`unregister`/`enqueue`/`dequeue` through `export`ed
  wrappers so no site was dead-code-eliminated; the driver was deleted after the
  audit (nothing added to the module source).

### Correct-lowering key

| Zig ordering | aarch64 | riscv64 |
|---|---|---|
| `.acquire` load | `ldar` | `ld` + `fence r,rw` |
| `.seq_cst` load | `ldar` | **`fence rw,rw`** + `ld` + `fence r,rw` |
| `.release` store | `stlr`/`stlrb` | `fence rw,w` + `sd`/`sb` |
| `.seq_cst` store | `stlr` | `fence rw,w` + `sd` |
| `.acquire` CAS | `ldaxr`/`ldaxrb` + `stxr`/`stxrb` | `lr` + `sc` (acq form) |
| `.seq_cst` CAS | `ldaxr` + `stlxr` | **`lr.d.aqrl`** + `sc.d.rl` |
| `.monotonic` load/store | plain `ldr`/`str` | plain `ld`/`sd` |

The two load-bearing observations:

1. **aarch64 needs no `dmb`.** Across both opt levels the entire module emits
   `dmb` **zero** times: seq_cst is carried purely by the RCsc `ldar`/`stlr`/
   `ldaxr`/`stlxr` instructions. This is correct, not a missing barrier — ARMv8's
   `ldar`/`stlr` are *sequentially-consistent* acquire/release: a `stlr` is
   architecturally forbidden from being reordered past a later `ldar`, which is
   exactly the store→load edge the Dekker interlock (pin-store then scan/pointer
   load) depends on. Plain acquire/release (which *does* permit store→load
   reordering) would be too weak here; the compiler does not use it for the
   seq_cst sites.
2. **riscv64 distinguishes seq_cst from acquire by a leading fence.** An
   `.acquire` load emits only the trailing `fence r,rw`; a `.seq_cst` load emits
   an additional **leading `fence rw,rw`**. That leading full fence is the RISC-V
   analog of ARM's RCsc `ldar` — it is precisely the store→load barrier that
   orders a thread's prior seq_cst pin-store before its subsequent seq_cst
   pointer/scan loads. It was observed present on every seq_cst load
   (`global_epoch`, `local_epoch` scan, queue `head`/`tail`/`next`) and absent
   from the lone `.acquire` load (`Domain.epoch`), confirming the compiler is not
   silently collapsing seq_cst to acquire. seq_cst RMW lowers to `lr.d.aqrl` +
   `sc.d.rl`, the ISA-sanctioned sequentially-consistent LR/SC pair.

### Per-site verdict

All sites **CORRECT** on both arches, both opt levels. Grouped by role:

| Site (source) | Zig ordering | Sync role | aarch64 | riscv64 |
|---|---|---|---|---|
| `enterCritical` `global_epoch` load | `.seq_cst` | pin: read epoch | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `enterCritical` `local_epoch` store | `.seq_cst` | pin announce (Dekker store) | `stlr` | `fence rw,w`+`sd` |
| `exitCritical` `local_epoch` store | `.release` | unpin publish | `stlr` | `fence rw,w`+`sd` |
| `retire` `global_epoch` load | `.seq_cst` | retire-tag read (after unlink) | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `tryAdvance` `global_epoch` load | `.seq_cst` | observed epoch | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `tryAdvance` `local_epoch` scan load | `.seq_cst` | straggler scan (Dekker load) | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `tryAdvance` `global_epoch` CAS | `.seq_cst`/`.seq_cst` | advance E→E+1 | `ldaxr`+`stlxr` | `lr.d.aqrl`+`sc.d.rl` |
| `Domain.epoch` `global_epoch` load | `.acquire` | mechanical read | `ldar` | `ld`+`fence r,rw` |
| `register` `in_use` CAS | `.acquire`/`.monotonic` | claim slot | `ldaxrb`+`stxrb` | `lr`/`sc` (acq) |
| `register` `local_epoch` store | `.release` | init slot epoch | `stlr` | `fence rw,w`+`sd` |
| `unregister` `in_use` store | `.release` | free slot | `stlrb` | `fence rw,w`+`sb` |
| `unregister` `orphaned` store | `.release` | publish orphaned bags | `stlrb` | `fence rw,w`+`sb` |
| `adoptOrphans` `orphaned` CAS | `.acquire`/`.monotonic` | claim orphaned bags | `ldaxrb`+`stxrb` | `lr.w.aq`+`sc.w` |
| `adoptOrphans` `global_epoch` load | `.seq_cst` | adopter's observed epoch | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `orphan_count` load / fetchAdd / fetchSub | `.monotonic` | hint only, no hb obligation | plain `ldr` / `ldxr`+`stxr` | plain `ld` / `amoadd.d` |
| `enqueue` `tail` load | `.seq_cst` | MS pointer read | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `enqueue` `t.next` load | `.seq_cst` | MS pointer read | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `enqueue` `t.next` CAS (link) | `.seq_cst`/`.seq_cst` | linearization | `ldaxr`+`stlxr` | `lr.d.aqrl`+`sc.d.rl` |
| `enqueue` `tail` CAS (help/swing) | `.seq_cst`/`.seq_cst` | tail helping | `ldaxr`+`stlxr` | `lr.d.aqrl`+`sc.d.rl` |
| `dequeue` `head`/`tail`/`h.next` loads | `.seq_cst` | MS pointer reads | `ldar` | `fence rw,rw`+`ld`+`fence r,rw` |
| `dequeue` `tail` CAS (help) | `.seq_cst`/`.seq_cst` | tail helping | `ldaxr`+`stlxr` | `lr.d.aqrl`+`sc.d.rl` |
| `dequeue` `head` CAS (unlink) | `.seq_cst`/`.seq_cst` | linearization + retire gate | `ldaxr`+`stlxr` | `lr.d.aqrl`+`sc.d.rl` |
| `SpinLock.lock` `state` CAS (pool) | `.acquire`/`.monotonic` | pool mutual-exclusion | `ldaxr`+`stxr` | `lr`/`sc` (acq) |
| `SpinLock.unlock` `state` store | `.release` | pool release + node handoff | `stlr` | `fence rw,w`+`sd` |
| `SpinLock.lock` TTAS spin load | `.monotonic` | non-locking spin read | plain `ldr` | plain `ld` |
| single-owner assert loads (`enter`/`exit`/`retire`/`unregister`) | `.monotonic` | debug assert, no cross-thread role | plain `ldr` | plain `ld` |
| `deinit` chain-walk loads | `.monotonic` | teardown (quiescent) | plain `ldr` | plain `ld` |

The four `unregister`/`adoptOrphans`/`orphan_count` rows were added by the
non-blocking `unregister` hand-off (finding F4) and originally carried a `†`
marking them **inferred, not re-measured**. That `†` is now **removed**: the
codegen audit was re-run (2026-08-09, same `-femit-asm` method, same two targets,
both opt levels) and every one of those four rows was read off real instructions.
Two of them are now *more* precise than the inference was: on riscv64 the
`orphaned` `bool` CAS lowers to a **word**-width `lr.w.aq`+`sc.w` (RVWMO has no
byte LR/SC, so LLVM emits a masked word CAS — the same shape as `register`'s
`in_use`), and the `orphan_count` RMWs lower to a bare `amoadd.d` with no
`.aq`/`.rl` suffix rather than an `lr`/`sc` pair. Neither changes the verdict:
all four are CORRECT at their site. The re-run also re-confirmed the two
load-bearing observations above — `dmb` still appears **zero** times in the whole
module on aarch64 at both opt levels, and the leading `fence rw,rw` is still
present on every seq_cst load and absent from `Domain.epoch`'s `.acquire` load.
No site's ordering has ever been changed, so §7.1's litmus verdicts stand.

Note on the seq_cst queue-pointer ops: they are stronger than the queue's own
linearizability needs (acquire/release would linearize the queue alone), but that
strength is **required, not gratuitous** — it is the EBR grace-period proof (§4a,
theorem at `tryAdvance`) that pulls the pointer loads/unlink-CAS into the seq_cst
total order S. So they are classified CORRECT, not too-strong: demoting them would
keep the queue correct while silently breaking reclamation. The `.monotonic` sites
(TTAS spin, debug asserts, quiescent teardown) are intentionally plain and safe at
their site — none carries a cross-thread happens-before obligation.

### 7.0a What relaxing the non-interlock atomics would actually buy (measured)

The standing perf question against this discipline is: *how much throughput does
`seq_cst`-everywhere cost, and how much of it could a selective demotion to
acquire/release recover?* It was answered on 2026-08-09 by measurement rather
than by reasoning, and the answer is **nothing on x86-64 and nothing on the
aarch64 baseline**.

**Method.** A *maximally relaxed* probe was built outside the tree: a verbatim
copy of `src/` with **14 of the 15** `seq_cst` sites demoted — every
`global_epoch` load (`enterCritical`/`retire`/`tryAdvance`/`adoptOrphans`) and
the epoch CAS to `.acquire`/`.acq_rel`, and every `mpmc` `head`/`tail`/
`Node.next` load and CAS likewise — keeping `seq_cst` on exactly the two Dekker
interlock sites (`enterCritical`'s `local_epoch` store, `tryAdvance`'s
`local_epoch` scan load). That probe is deliberately **unsound** under the
grace-period theorem — it is the *upper bound* of what any selective relaxation
could ever recover, built to be timed and disassembled, never to be shipped.
Both variants were compiled with the same `-femit-asm` driver as the rest of §7
and their instruction streams compared site by site (labels/anon-symbol indices
normalized).

| Target | Instruction-stream delta, current vs maximally relaxed |
|---|---|
| `x86_64-linux`, ReleaseFast **and** ReleaseSafe | **byte-identical** at every site |
| `aarch64-linux` (default baseline), ReleaseFast | **byte-identical** at every site |
| `aarch64-linux` `-mcpu=generic+rcpc` (ARMv8.3) | differs: 16 loads become `ldapr` instead of `ldar` |
| `riscv64-linux`, ReleaseFast | differs: the leading `fence rw,rw` disappears from every demoted load — `dequeue` 10→2, `enqueue` 4→1, `tryAdvance` 3→1, `retire` 1→0 |

Two of those rows correct the intuition this SPEC previously stated:

1. **On x86-64 a `seq_cst` *load* and a `seq_cst` *CAS* cost exactly nothing.**
   The loads are plain `mov`; every CAS is `lock cmpxchg` at any ordering ≥
   monotonic. The *only* x86-64 instruction in this module that exists because of
   `seq_cst` is the `xchg` that `enterCritical`'s `local_epoch` store lowers to —
   and that is precisely the Dekker store, the one edge TSO does not give for
   free and the one the theorem cannot surrender. Measured on this host
   (8-core x86-64, ReleaseFast, 20 M pin/unpin pairs, best of 3): the `seq_cst`
   pin store costs **9.25 ns/pin** against **0.57 ns/pin** for a `.release` store,
   i.e. the Dekker store costs **≈8.7 ns per pin**. That number is the entire
   x86-64 price of the discipline, it is already at the x86 optimum (`xchg` is
   cheaper than the `mov`+`mfence` form of the classic fence recipe, which Zig
   0.16 cannot express anyway — `@fence` is gone), and buying it back is exactly
   the use-after-free §5's sabotage self-check could not detect in 60 runs.
2. **On the aarch64 baseline an `.acquire` load is also `ldar`.** Without
   `+rcpc` LLVM has no cheaper acquire load to emit, so demoting a `seq_cst`
   load to `.acquire` changes no instruction there either. A real gap opens only
   at ARMv8.3+ (`ldapr`) and on riscv64 (the leading full fence). So the barrier
   cost this discipline pays off-x86 is **riscv64-and-ARMv8.3+ specific**, not
   "every weakly-ordered target".

**End-to-end timing, same binary, same inputs.** Both module copies were linked
into one ReleaseFast binary and run against the same 4-producer × 4-consumer ×
20 000-items-per-producer workload, 7 rounds with the variant order alternated to
cancel drift:

| Variant | min | mean |
|---|---|---|
| current (`seq_cst`) | 29.31 ms | 30.48 ms |
| maximally relaxed | 29.58 ms | 31.03 ms |

Ratio relaxed/current: **1.009× at min, 1.018× at mean** — i.e. the "relaxed"
build measured *marginally slower*, which is the expected reading given the two
builds are the same machine code. The spread is thread-scheduling noise, and
that is the point: **on x86-64 there is no win to recover, not a small one.**

**Conclusion.** The perf-portability reservation is real only on riscv64 and
ARMv8.3+. Recovering it means demoting atomics the grace-period theorem (§4a)
places in the total order S, which §7.1's `-relaxed` litmus controls show
re-admits the bug outcome under both formal models. Unless and until a
weak-memory target is actually deployed *and* someone redoes the reduction with
explicit release-sequence reasoning in place of S, the discipline stays as it is.
Do not re-open this as a portable perf win; on the deployed target it is
measurably zero.

### QEMU functional run (sanity only — does NOT certify weak-memory ordering)

Cross-built `zig test` binaries (`-O ReleaseSafe`, asserts + the poison canary
live) were run under qemu-user:

- `qemu-aarch64`: **all tests pass, exit 0** — including the `REAL CORE: MPMC +
  EBR survive N×M stress` test and the `DRIVER TEETH` positive control (which
  still catches the deliberately-racy `BrokenRing`).
- `qemu-riscv64`: **all tests pass, exit 0** — same suite.

This confirms functional correctness under a non-x86 ABI/instruction set and that
the cross-compiled core is not obviously broken. It is **explicitly
non-certifying for weak memory**: QEMU-TCG serializes and honors barriers but does
not model the speculative store→load reordering that a missing barrier would need
in order to fail, so a passing QEMU run cannot distinguish correct ordering from
absent ordering. The static codegen audit above is what certifies ordering; QEMU
is corroborating sanity only.

### Honest scope — what is and is not certified

- **Certified now:** the compiler emits architecturally-correct barriers for every
  atomic site on aarch64 and riscv64 (static codegen), and the core is
  functionally correct under both non-x86 ISAs (QEMU-user).
- **Not yet done (next tier):** (a) dynamic weak-memory stress on *real* ARM/
  RISC-V hardware (or a reordering-faithful simulator), which is the only way to
  observe a reordering bug rather than infer its absence from the codegen; (b) a
  formal litmus/herd7 model-check of the pin/scan interlock and the grace-period
  argument against the C11/ARMv8/RVWMO axiomatic models — **now DONE, see §7.1.**
  Item (a) remains open; this section does not claim to replace it.

## 7.1 Formal litmus certification (herd7)

**Result: every load-bearing ordering forbids its bug outcome under the formal
models, and every positive control confirms the barrier is load-bearing.** The
static audit above proves the compiler *emits* the right barriers; this
subsection proves — against the AArch64 and RISC-V axiomatic memory models —
that those barriers actually *forbid* the use-after-free / stale-read, and that
weakening them lets the bug back in. Files live in `litmus/` (`run.sh` +
`README.md` + the eight `.litmus` sources).

### Toolchain / models

- `herd7` **7.58** (herdtools7, via opam; `run.sh` sources `opam env`).
- Models: the herd7-shipped **`aarch64.cat`** and **`riscv.cat`** (RVWMO),
  selected by name (`-model aarch64.cat` / `-model riscv.cat`).

### Method — matched pairs with teeth

The full grace-period theorem (§4a, `tryAdvance`) reduces the module's
reclamation safety to two sync shapes over the seq_cst total order S. Each shape
is encoded as an `exists` on the **bug** outcome, in a matched pair per arch:

- **safe** — the ordering the code uses, written with the exact SPEC §7
  lowerings (seq_cst = `STLR`/`LDAR` on aarch64, `fence rw,w;sd` /
  `fence rw,rw;ld;fence r,rw` on riscv; release/acquire for the MP publish).
  herd7 must report the bug as **Never**.
- **positive control** — the same test with the ordering demoted to
  plain/monotonic. herd7 must report the bug as **Sometimes**. This is the
  evidence the encoding is not vacuously safe *and* that the barrier is
  load-bearing (the `-relaxed` EBR control is exactly the Dekker-interlock break
  the §4a theorem forbids: pin store demoted below seq_cst).

**Shape 1 — EBR pin/scan Dekker interlock**, encoded as store-buffering (SB):
P0 = reader (pin store then shared-pointer load), P1 = reclaimer (advance/unlink
store then epoch-scan load). Bug = the SB non-SC outcome `0:X2=0 /\ 1:X2=0`
(reclaimer misses the pin **and** reader misses the unlink → frees a live node).

**Shape 2 — MS-queue publish/consume**, encoded as message-passing (MP): P0 =
enqueue (write `Node.value` plain, then release-publish the `next` link), P1 =
dequeue (acquire-load `next`, then read `value`). Bug = `flag observed but
payload stale` (`1:X0=1 /\ 1:X2=0`, riscv `1:x1=1 /\ 1:x2=0`).

### Verdict table

| Test | Shape | Arch | Ordering | herd7 Observation | Verdict |
|---|---|---|---|---|---|
| `ebr-interlock-aarch64-sc` | SB | aarch64 | seq_cst (STLR/LDAR) | `Never 0 3` | ✅ bug forbidden |
| `ebr-interlock-aarch64-relaxed` | SB | aarch64 | plain (STR/LDR) | `Sometimes 1 3` | ✅ control fires |
| `ebr-interlock-riscv-sc` | SB | riscv | seq_cst (fence rw,rw+ld / fence rw,w+sd) | `Never 0 3` | ✅ bug forbidden |
| `ebr-interlock-riscv-relaxed` | SB | riscv | plain (ld/sd) | `Sometimes 1 3` | ✅ control fires |
| `msqueue-aarch64-rel-acq` | MP | aarch64 | release/acquire (STLR/LDAR) | `Never 0 3` | ✅ bug forbidden |
| `msqueue-aarch64-relaxed` | MP | aarch64 | plain (STR/LDR) | `Sometimes 1 3` | ✅ control fires |
| `msqueue-riscv-rel-acq` | MP | riscv | release/acquire (fence rw,w+sd / ld+fence r,rw) | `Never 0 3` | ✅ bug forbidden |
| `msqueue-riscv-relaxed` | MP | riscv | plain (ld/sd) | `Sometimes 1 3` | ✅ control fires |

Safe/positive-control pairing, read as pairs: on **both** arches, both shapes
forbid the bug under the code's real ordering and **permit** it the instant the
ordering is weakened. The `Never 0 3` / `Sometimes 1 3` split (0 vs 1 witnessing
executions out of 3 final states) is the quantitative signature that the barrier,
not the litmus encoding, is what excludes the bug.

### Honest scope

This certifies the two **extracted** sync shapes — the pin/scan interlock and
the MS-queue publish/consume — under the AArch64 and RVWMO axiomatic models. It
is **not** a whole-program proof: the reduction from full reclamation safety to
these two shapes plus the seq_cst total order S is the reviewed §4a argument
(theorem at `tryAdvance`), not a machine-checked model of the entire algorithm.
What remains beyond this layer is dynamic weak-memory stress on *real* ARM/RISC-V
hardware (§7 item (a)); with the static codegen cert (§7) and this formal cert
(§7.1) both green, that hardware run is now belt-and-suspenders corroboration
rather than the only line of evidence.
