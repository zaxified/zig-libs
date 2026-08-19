# reconcilable — design & threat model

What this module is and how to call it: [README.md](README.md).

## 1. What was consulted, and what was not

Clean-room from **documentation only**:

- the Kubernetes controller-runtime docs (`Reconciler`/`Result` contract,
  `RequeueAfter`, "reconcile must be idempotent", the controller concepts page)
  and the client-go **workqueue** documentation (dedup semantics, `Add` /
  `AddAfter` / `AddRateLimited` / `Forget` / `Done`, the
  `ItemExponentialFailureRateLimiter` + `BucketRateLimiter` description);
- the AWS "Exponential Backoff And Jitter" article, already implemented in the
  `resilience` sibling and reused here rather than re-derived;
- vendor documentation for confirm-or-revert configuration: Juniper
  `commit confirmed`, Cisco IOS-XE `configure replace … commit timeout`,
  `netplan try`.

**No Go source was read or ported.** controller-runtime and client-go are
Apache-2.0; a port would attach a patent grant and a NOTICE-propagation
requirement to a repository whose root `NOTICE` deliberately carries no
third-party condition (CONVENTIONS §5). The root `NOTICE` therefore records
controller-runtime as a **design reference** — a provenance record, not a
licence condition.

## 2. Who owns the loop — caller-driven, with no clock at all

The brief proposed a caller-driven `tick(now)` with an *injected clock*. This
goes one step further: there is **no clock seam**, injected or otherwise.
`tick`, `enqueueAfter`, `finish` and every `RollbackTimer` method take the
instant as a parameter. Reasons, in order of weight:

1. **Both real consumers already own a loop.** An L2VPN control plane and an
   edge shaper each run an existing event loop (`pollworker`, a netlink socket
   loop). A reconciler that owned a thread would be a second scheduler to
   synchronise with, and every apply it performs would have to cross back to
   the loop thread that owns the netlink/WireGuard handles anyway. Owning a
   thread would buy nothing and cost a synchronisation design.
2. **Zig 0.16 has no `std.Thread.Mutex`/`Condition`** (CONVENTIONS §2). An
   internal thread would mean hand-rolling POSIX synchronisation inside a
   module that otherwise has zero platform surface — and would cost the `.any`
   platform tag.
3. **Determinism.** `netsim`, `liveness-hyst` and `df-elect` are built this
   way, and it is why their property tests can be exhaustive. Every test in
   this module is a fixed-seed replay with no wall clock and no sleep.
4. **An injected clock is still a clock.** A `Clock` vtable would give the
   module an opinion about *when* `tick` samples time, and would let two
   consecutive reads inside one tick disagree. Passing `now` makes a tick
   atomic with respect to time by construction: every timer comparison in one
   tick uses one instant.

The cost is one line in the caller's loop and the obligation to pass a
non-decreasing `now`. `nextDue(now)`/`sleepFor(now)` hand the caller the exact
`poll(2)` timeout, which is the integration surface that makes this cheap.

Consequence: `meta.platform = .any` is a real claim, not an aspiration — the
module compiles for `x86_64-windows`, `aarch64-macos` and `wasm32-wasi`
(checked; the `resilience` dep is used only for its pure `Retry` value type,
never for its posix default clock).

## 3. Outcome semantics

Mirrors the documented controller-runtime contract so the semantics are
someone else's well-argued design rather than ours:

| controller-runtime | here | scheduling | failure streak |
|---|---|---|---|
| `return Result{}, nil` | `.done` | `Forget` + drop | reset |
| `return Result{Requeue: true}, nil` | `.requeue` | `AddRateLimited` | +1 |
| `return Result{RequeueAfter: d}, nil` | `.requeue_after = ns` | `Forget` + `AddAfter(d)` | reset |
| `return Result{}, err` | `.failed = err` | `AddRateLimited` | +1 |

The one that surprises people is `.requeue_after` **resetting** the streak.
It is correct and it is upstream's rule: the caller chose that delay
deliberately (a lease TTL, a rollback deadline, a re-observe interval), so the
rate limiter must not also stretch it.

## 4. Rate limiting — what was NOT built, and why

Upstream composes two limiters: a per-item exponential-failure limiter and a
global token bucket (`MaxOfRateLimiter`). Only the first is here.

The global bucket was **deliberately dropped**:

- The caller owns the loop, so global throughput is already
  `budget_per_tick / tick period` — expressed in the caller's own clock, in the
  place that actually knows how much work the process can absorb.
- A bucket would need a clock of its own inside a module built to have none
  (§2), and it would be a *second* opinion about time that could disagree with
  the caller's.
- The obvious "reuse the sibling" move is wrong here: `ratelimit.TokenBucket`
  is excellent, but the `ratelimit` module depends on `router` + `http` +
  `netaddr`. Dragging an HTTP stack into a control-plane convergence loop to
  get 40 lines of token bucket is a bad trade, and copying those 40 lines would
  be duplication. `budget_per_tick` is the honest answer.

Per-key backoff, by contrast, is something a caller *cannot* express as loop
cadence, so it is inside — and it is `resilience.Retry`, the sibling that
already implements exponential growth, a cap, and the AWS jitter taxonomy.
Re-deriving it would have been the third copy in this repo.

## 5. The bound, and what happens at the edge

`capacity` bounds **distinct tracked keys**, which is the right unit because
dedup means the queue length can never exceed the number of distinct keys.
Everything per-key is allocated once in `init`:

- a slot arena of `capacity` entries (stable `u32` addresses);
- a `heap` array of `capacity` `u32`s;
- an `AutoHashMapUnmanaged` pre-sized with `ensureTotalCapacity(capacity)`.

So peak memory is `capacity × (sizeof(Slot) + sizeof(u32) + hash-map entry)`,
fixed at construction. `enqueue`/`tick`/`forget` never allocate — asserted by
running a 20 000-step randomized workload with a `FailingAllocator` swapped in
after `init` and checking `allocations == 0`.

**The load-bearing structural decision is the indexed timer heap.** Each
waiting slot stores its own heap position, so removing or rescheduling a key is
an exact O(log n) operation and `heap_len` equals the number of waiting keys.
The textbook alternative — push a fresh heap node on every reschedule and skip
stale ones on pop — makes the heap grow with the *number of reschedules*, which
is unbounded in exactly the workload a reconciler generates (one key flapping
forever). `queue.zig`'s "BOUND: the timer heap never grows past capacity under
endless rescheduling" runs 40 000 reschedules over 8 keys and asserts
`heap_len ≤ capacity` on every iteration; with lazy deletion it would be
asserting `40 000 ≤ 8`. The bound is proven by a test that fails if the
mechanism is removed, not stated in a comment. (This was verified by actually
removing it — see §9.)

**At capacity:** `error.AtCapacity`, a counter, and a sticky
`Stats.overflowed`. Never eviction. Evicting a desired key leaves the world
permanently diverged with nothing to notice it, which is the one failure mode a
reconciler must not have; rejecting is loud and recoverable, because a
level-triggered controller's caller owns desired state and can always
re-enumerate.

The residual hazard is on the caller and is documented in the README: a resync
that always enumerates from index 0 starves the tail, because the queue is full
exactly when enumeration reaches it. The rotating-cursor recovery is asserted in
a test rather than only described.

## 6. Threat model

This module parses nothing and touches no untrusted bytes, so the usual
"never panic on arbitrary input" harness does not apply. The failure modes that
do apply:

| Hazard | Handling |
|---|---|
| Unbounded memory from an enqueue storm | fixed arena + `capacity`; §5 |
| Unbounded memory from timer churn | indexed heap, no stale nodes; §5 |
| A key silently lost | rejection is loud + sticky; dedup is by identity, never by delta |
| A busy key starving a quiet one | re-announcement goes to the FIFO tail; exact fairness bound asserted |
| One tick spinning forever | budget snapshot taken before draining — a mid-tick self-enqueue lands in the next tick |
| Retry storm against a failing dependency | per-key exponential backoff with a cap and full jitter |
| An unreachable resource retried forever | `max_failures` (opt-in; default is deliberately "never give up") |
| Clock going backwards | only differences are used, and `promoteDue` releases on `due ≤ now`; a backwards step delays a wake, never fires one early |
| Deadline arithmetic overflow | saturating `+|` throughout; tested at `maxInt(u64)` |
| A late confirmation cancelling a rollback in flight | refused — the deadline wins (§7) |
| A rollback executed twice | `poll` returns `.expired` exactly once per arming |

Not threats this module addresses: concurrent access (it is `single_owner` by
construction — share it and you are on your own), and the correctness of the
caller's reconcile function, which must be idempotent. Idempotence cannot be
checked from inside; the README states the contract and the module's own
example test *observes* it (a converged world is re-reconciled 50 times with no
further apply).

## 7. Why `RollbackTimer` lives here, not in its own module

The README roadmap said to "extract a small `RollbackTimer` (arm/confirm/
overdue) first, once a consumer appears". The consumer appeared *as this
module*, which changes the answer: extracting it now would create a module
whose only consumer is its sibling in the same tree, which is exactly the
"module that is not a capability" that CONVENTIONS §3 guards against. It is
~100 lines with a four-state machine.

So it ships **inside `reconcilable`**, in its own file, importing nothing from
the reconciler — its whole integration surface is `remaining(now) -> ?u64`,
which the caller feeds to `Outcome.requeue_after`. If a second, unrelated
consumer ever wants it (a two-phase-commit coordinator, a feature-flag canary),
promoting `rollback.zig` to `modules/rollbacktimer/` is a file move plus a
`build.zig` line, and nothing in this module has to change.

The two semantics that are design decisions rather than mechanics:

- **The deadline wins over a late confirmation.** `confirm` at `now ≥ deadline`
  returns `.too_late` and leaves the timer to fire. The alternative (a late
  confirm cancels the rollback) races an in-flight rollback against a
  confirmation, leaving the device in a state neither side believes it is in.
  Fail closed, toward the known-good config. This is why a remote-edge consumer
  can use it: the
  confirmation channel is the very path the change might have severed, so a
  confirmation *arriving late* is exactly the signal that something is wrong.
- **`.expired` fires exactly once.** A rollback is not generally idempotent —
  a second undo may undo the recovery. `poll` transitions to `.rolled_back` on
  the same call that reports `.expired`.

`generation` exists for the same reason: an out-of-band confirmation
(a probe result arriving over a socket) may belong to an arming that has
already been superseded. `confirmGeneration` refuses it.

## 8. Anchoring — self-anchored, and that is not a debt

**There is no external anchor for this module, and none is invented.** There is
no published test vector for a reconciler, no reference binary to interop with,
and no wire format to diff: controller-runtime's semantics are documented prose.
Following the repo's precedent (`bulletproofs`, `coconut`, `vdf`), that is
stated plainly rather than dressed up.

What the module has instead:

1. **Property tests over a deterministic seeded simulation** (`props.zig`):
   - one reconcile per enqueue burst, over 64 seeds × 400 randomized
     enqueue/tick interleavings, checked against a reference *model* (a per-key
     dirty bit). Asserts `reconciles == bursts` exactly — nothing lost, nothing
     duplicated — plus `reconciles ≤ enqueues` and "every key reconciled after
     its last enqueue";
   - FIFO order and the exact fairness bound `tick(p) == ⌈(p+1)/b⌉ - 1` for
     every budget 1..8;
   - un-jittered backoff non-decreasing, reaching and never exceeding the cap,
     over four base/cap pairs; jittered backoff inside `[0, cap]` over 32
     seeds, with a positive control that jitter is actually varying the value;
   - a success resets the streak from any point in the schedule (10 positions);
   - the bound holds over a 20 000-step storm where nothing ever converges;
   - a brute-force **model of the queue itself**: 32 runs × 300 ops comparing
     membership, per-key state, tracked count and FIFO head against a naive
     array-and-sort implementation of the same semantics.
2. **Bound tests that fail if the mechanism is removed** — §5, verified by
   mutation (§9).
3. **`RollbackTimer` characterisation** over 20 000 randomized
   arm/confirm/poll interleavings: `confirm`'s result is a pure function of
   (was armed, before the deadline), and `.expired` fires exactly once iff no
   confirmation landed strictly before the deadline.

**What an external anchor would have to be**, if one is ever wanted: a
differential harness against a real `kube-controller-manager`/controller-runtime
controller — drive both with the same enqueue/failure schedule under a faked
clock and compare the *sequence of reconcile invocations*. That needs a Go
harness, a fake-clock controller-runtime `Manager`, and agreement on tie-break
order that upstream does not document (its ready set is not FIFO-ordered across
the waiting-loop boundary in the way ours is). It is a real project, not a
test-file addition, and it would anchor scheduling order — not correctness of
convergence, which has no oracle at all.

## 9. Mutation testing

**M1 — remove the bound mechanism.** The indexed-heap `reschedule`
(decrease-key) was replaced with the lazy-deletion form: push a fresh heap node
on every reschedule and leave stale ones to be skipped on pop. Result — 4 tests
go red, and the first symptom is not an assertion at all:

```
BOUND: the timer heap never grows past capacity under endless rescheduling
  → panic: index out of bounds: index 8, len 8
PROPERTY: tracked keys never exceed capacity, and overflow is loud, not silent
  → panic: reached unreachable code
PROPERTY: WorkQueue matches a brute-force model of (ready set, timer map)
  → panic: reached unreachable code
immediate enqueue pulls a waiting key forward; earlier deadline wins
  → heap_len 2, expected 1
```

That is a stronger result than a failed assertion: because the heap array is
allocated at exactly `capacity`, **lazy deletion cannot even be expressed** —
the ninth node for eight keys runs off the end of the array. The fixed-size
allocation *is* the bound, and the tests find it on the 20th of 40 000
iterations. (This also corrects a plausible-sounding claim: the mutation is not
"functionally invisible except for memory growth" — the stale nodes also break
`stateOf`/`tracked` accounting, which is what trips the model comparison.)

**M2 — remove the per-tick fairness snapshot.** `tick` takes the ready count
*before* draining, so a key re-enqueued by a pass runs in the next tick. Making
the budget unbounded-and-live instead (`while ready_len > 0`) is caught by
exactly one test and nothing else:

```
a self-enqueue during a pass runs in the NEXT tick, not this one  → 44/45
```

One test, one property — which is what a mutation is supposed to show.

## 10. Backlog

- A `Reconciler` that owns several key *kinds* (upstream's manager/controller
  split). Today each kind is its own `Reconciler` instance with its own `Ctx`;
  that is sufficient for both consumers and avoids type erasure. Revisit only if a
  consumer needs cross-kind ordering.
- Optional per-key metrics (time-in-queue, reconcile duration). Deliberately
  absent: it would require a clock inside the module (§2). If wanted, the
  caller can time `tick` itself.
- `WorkQueue` is currently only reachable as a generic function; if a consumer
  wants a scheduler that is not a reconciler, its `Finish` API may want a
  friendlier surface.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** in-process reconcile loop modeled after k8s controller-runtime, no wire
