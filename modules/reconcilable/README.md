# reconcilable

A generic **desired-vs-actual reconciler**: take a desired state, observe the
actual state, compute and apply the difference, and keep converging when the
apply fails or the world drifts underneath you. It is the control loop that
every provisioning system re-implements — tenant provisioning and WireGuard
backbone lifecycle in an L2VPN fabric, or "the `tc`/XDP plan I want" versus
"what the kernel actually has" in an edge shaper — extracted once, with the
sharp edges (deduplication, backoff, bounded memory, fairness) already handled.

The shape follows **Kubernetes controller-runtime**, because that is the
best-documented statement of the level-triggered control loop. Three pieces:

- **`Reconciler(Key, Ctx)`** — a bounded, deduplicating work queue plus a
  caller-driven `tick(now)` that runs an **idempotent** reconcile pass per
  ready key and re-schedules whatever did not converge.
- **`WorkQueue(Key)`** — that queue on its own: dedup, an intrusive ready FIFO
  and an indexed timer heap, all in a fixed-size slot arena.
- **`RollbackTimer`** — arm / confirm / overdue, for the change that can sever
  its own control path. Apply, start a timer, and roll back automatically
  unless someone confirms in time (Juniper `commit confirmed` semantics).

What is enqueued is the **identity** of something that may have diverged, never
a delta. That is the whole reason coalescing is safe: two enqueues collapsing
into one reconcile cannot lose a change, because the reconcile re-reads the
world anyway.

- **Platform:** `any` — the module makes no syscall, reads no clock and spawns
  no thread. Verified by compiling it for `x86_64-windows`, `aarch64-macos` and
  `wasm32-wasi`, not just claimed.
- **Role:** util. **Concurrency:** `single_owner` — one owner calls
  `enqueue`/`tick`; nothing is internally locked.
- **Deps:** `resilience` (its pure `Retry`/`Jitter` value types are the
  exponential-backoff-with-jitter policy; this module does not re-derive one).

Provenance: original work of the zig-libs authors (MIT), clean-room from
**documentation**. See the root `NOTICE` entry for `reconcilable` — no
controller-runtime or client-go source was read or ported.

## Use

```zig
const reconcilable = @import("reconcilable");

const Peer = [32]u8; // a WireGuard public key — a plain value, so it hashes

fn reconcilePeer(world: *World, key: Peer, now: u64) reconcilable.Outcome {
    const want = world.desired.get(key) orelse {
        world.removePeer(key) catch |e| return .{ .failed = e };
        return .done;
    };
    const have = world.observePeer(key) catch |e| return .{ .failed = e };
    if (have.equals(want)) return .{ .requeue_after = 30 * std.time.ns_per_s };
    world.applyPeer(want) catch |e| return .{ .failed = e };
    return .requeue; // re-observe before declaring victory
}

var r = try reconcilable.Reconciler(Peer, *World)
    .init(gpa, &world, reconcilePeer, .{ .capacity = 4096 });
defer r.deinit();

// The caller owns the loop and the clock.
while (running) {
    const now = clock.now();                 // e.g. resilience.Clock.monotonic
    _ = r.tick(now);
    const timeout_ms: i32 = if (r.sleepFor(now)) |ns|
        @intCast(ns / std.time.ns_per_ms)
    else
        -1;                                   // idle: block until an event
    try loop.poll(timeout_ms);                // events call r.enqueue(...)
}
```

### The reconcile function

```zig
fn (ctx: Ctx, key: Key, now: u64) Outcome
```

It **must be idempotent**: it is handed a key, not a change, and may be called
any number of times for one edit. It may re-enter the reconciler
(`enqueue`/`enqueueAfter`/`forget`), including for its own key — a self-enqueue
is honoured after the pass returns, never inside the same tick.

| `Outcome` | Meaning | Failure streak |
|---|---|---|
| `.done` | Converged; the key leaves the queue | reset |
| `.requeue` | Not converged; come back as the rate limiter allows | **+1** (backoff) |
| `.requeue_after = ns` | Come back in exactly `ns` (a lease TTL, a re-observe interval, a rollback deadline) | reset |
| `.failed = err` | Same scheduling as `.requeue`, plus `err` goes to `Options.on_error` | **+1** (backoff) |

### Keys

`Key` must be a **plain value** — no pointers, no slices; a `@compileError`
says so with the fix. A queued key outlives the call that enqueued it, so a
slice key would make the queue borrow caller memory of unknown lifetime.
Intern strings to an id, or use `[32]u8` / `struct { ifindex: u32, handle: u32 }`.

### Options

| Field | Default | What it does |
|---|---|---|
| `capacity` | — (required) | Hard bound on distinct tracked keys; **all** per-key memory is allocated at `init` and never grows |
| `budget_per_tick` | `0` (all ready) | Reconcile passes per `tick` — the rate limiter (see below) |
| `backoff` | `resilience.Retry{5ms, ×2, 30s, full jitter}` | Per-key failure backoff |
| `random` | `null` | Jitter source; `null` degrades to the un-jittered schedule |
| `max_failures` | `0` (never give up) | Abandon a key after this many consecutive failures |
| `on_error` | `null` | Where `.failed` errors go |

## Guarantees

- **Dedup.** A key enqueued any number of times while pending is reconciled
  **once**. Re-announcing a key already ready does not move it forward in the
  queue, so a hot key cannot starve a cold one.
- **Ordering.** FIFO by the instant each key became *ready*. Timers are
  released earliest-deadline-first, ties broken by scheduling order — so the
  whole thing is deterministic under a fixed clock.
- **Fairness.** With `budget_per_tick = b`, the key at ready-position `p` is
  reconciled on tick `⌈(p+1)/b⌉ - 1`. No starvation, and it is asserted as an
  exact equality in the tests, not as an inequality.
- **At most once per tick.** A key re-enqueued by a pass runs in the *next*
  tick. One tick cannot spin forever.
- **Bounded.** `tracked ≤ capacity` always, and `ready + waiting + running ==
  tracked`. The timer heap is exactly as long as the number of waiting keys.
- **Allocation-free after `init`.** `enqueue`, `tick` and `forget` never
  allocate — proven with a failing allocator, not asserted in a comment.

## Overflow

`enqueue` on a full queue returns `error.AtCapacity`, counts it, and raises a
**sticky `Stats.overflowed`**. It never evicts: silently dropping a desired key
leaves the world permanently diverged, which is the one failure a reconciler
must not have. Because the loop is level-triggered and the caller owns desired
state, the recovery is a **full resync** — re-enumerate and re-enqueue, then
`clearOverflow()`.

⚠ **Rotate the resync.** A caller that re-enumerates from index 0 every round
re-admits the same head keys and starves the tail forever, because the queue is
full precisely when the enumeration reaches the tail. Resume from where
admission last failed. This is the caller's obligation and there is a test for
it (`props.zig`, "after overflow, a ROTATING resync…").

## Rate limiting

There is no token bucket inside. The caller owns the loop, so throughput is
`budget_per_tick / tick period`, expressed in the caller's own clock — see
SPEC.md §4 for why a second clock inside the module would be worse than useless.
Per-key exponential backoff (the part a caller cannot express in its loop
cadence) *is* inside, via `resilience.Retry`.

## RollbackTimer

```zig
var t: reconcilable.RollbackTimer = .idle;
const gen = t.arm(now, 30 * std.time.ns_per_s);  // stage the change
...
switch (t.poll(now)) {
    .armed    => return .{ .requeue_after = t.remaining(now).? },
    .expired  => { world.rollBack(); return .done; },   // fires exactly once
    else      => return .done,
}
// from the confirmation path (a health probe, an operator):
_ = t.confirmGeneration(now, gen);
```

Two semantics worth knowing before you use it:

- **The deadline wins.** A `confirm` at or after the deadline is refused
  (`.too_late`) and the timer still fires. A late confirmation must not cancel
  a rollback that may already be in flight.
- **It fires once.** `poll` returns `.expired` from exactly one call. A
  rollback applied twice is not idempotent in general.

Note the integration consequence, visible in the tests: `requeue_after` parks
the key *on* the deadline, so a confirmation that arrives earlier has to
`enqueue` the key to be seen. Confirmations are external events; wake the loop.

## Verify

```sh
zig build test-reconcilable --summary all      # 45 tests, Debug + ReleaseFast + ReleaseSafe
scripts/dark-tests.sh reconcilable             # every submodule's tests really run
```

Self-anchored: there is no published vector or reference binary for a
reconciler. The evidence is property tests over a deterministic seeded
simulation plus a brute-force model of the queue — SPEC.md §8 states this
plainly and names what an external anchor would have to be.
