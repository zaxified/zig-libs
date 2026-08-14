# tcplan — spec

Design + invariants for auditors. Usage: see ./README.md. Attribution/provenance:
see /NOTICE.

## Design

tcplan is a **pure compiler**: `Topology` in, `Plan` out, no I/O. It owns none of
the wire encoding — every operation it emits is expressed in the sibling `tc`
module's public request types (`QdiscTarget`/`ClassTarget`/`FilterTarget` +
`QdiscSpec`/`ClassSpec`/`FilterSpec`), so the caller turns a plan into netlink
bytes by feeding each op straight through `tc.message.buildQdiscSet` /
`buildClassSet` / `buildFilterSetWith` (wrapped as `Operation.buildRequest`). The
value tcplan adds is purely *policy*: which operations, in which order, with
which handles, realise a hierarchical shaping topology — and the validation that
a topology which cannot be realised correctly is rejected as a typed error rather
than compiled to a silently-wrong plan.

### File layout

| File | Contents |
|---|---|
| `topology.zig` | the input model — `Topology`, `Node`, `Match`, `mbit` |
| `handles.zig` | the handle-allocation scheme — constants + `HandleSpace` counters |
| `plan.zig` | the output model — `Operation`, `Plan`, `buildRequest`, self-checks |
| `compile.zig` | the two-pass compiler (assign+validate, then emit) |
| `root.zig` | re-exports, `meta`, and the acceptance tests (golden/exec/determinism) |

## The topology model

A tree of shaping nodes on one egress interface. Each direct child of the root (a
*site*) is pinned to a CPU/hardware-TX-queue; every descendant inherits that pin.
Interior nodes (site, access-point) are HTB aggregation classes with a committed
rate (`rate`) and ceil rate (`ceil`); leaf nodes (subscribers) additionally carry
a per-subscriber CAKE qdisc and a `flower` classifier. Rates are **bytes/second**
(matching `tc`'s `HtbClass`/`Cake`), with `mbit(n)` as the megabit/s helper.

## The handle-allocation scheme

All handles are `major:minor` (`tc.Handle`), hexadecimal on the wire.

- **`mq` root** — fixed at `0x7FFF:0` (`mq_root_major`, LibreQoS' convention).
  The kernel auto-creates its per-queue children `0x7FFF:1 … 0x7FFF:queue_count`;
  tcplan never emits those.
- **HTB roots** — CPU `c` (0-based) owns **major `c+1`**. Its per-queue HTB root
  qdisc is `(c+1):0`, attached under `mq` child `0x7FFF:(c+1)`. Folding the queue
  index into the major is what makes the cpumap alignment *structural* (below).
  `queue_count` is therefore capped below `0x7FFF`.
- **HTB classes** — minors are handed out per queue from `1` upward, in the
  compiler's canonical traversal order (queues ascending, DFS pre-order within a
  queue). A parent's minor is always lower than — and emitted before — its
  children's.
- **CAKE leaf qdiscs** — each subscriber's CAKE qdisc needs its own
  globally-unique major (a qdisc major must be unique across the interface).
  These come from one global counter starting at `queue_count+1` (so they never
  collide with an HTB major `1…queue_count`), skipping `mq_root_major`, capped at
  `0xFFFE`.
- **Filter priorities** — per queue from `1` upward. A `flower` filter is keyed
  by `(parent, protocol, prio)`, and all of a queue's steering filters share the
  parent `(c+1):0`, so a per-queue prio counter keeps them distinct.

### Determinism

The assignment pass is a single fixed traversal with no maps, no hashing and no
randomness. Given the same `Topology` and the same interface, `compile` produces
a byte-identical `Plan` every time — asserted by compiling twice and comparing
the built request bytes op-for-op. This is the property a shaper that reconciles
live state against a target depends on.

### "queue == CPU" mapping

CPUs are 0-based (as XDP's cpumap indexes them); the `mq` children are 1-based
(as `sch_mq` numbers them). tcplan bridges the two by mapping CPU `c` to `mq`
child minor `c+1` **and** HTB major `c+1`, keeping the HTB major equal to the
`mq`-child index. A caller whose CPU 0 must land on a specific queue should map
its own indices onto `cpu` accordingly.

## The cpumap → MQ → per-CPU-HTB invariant

A packet that XDP steered to CPU `c` egresses queue `c`, so it can only be shaped
by classes under queue `c`'s HTB tree. A subscriber whose class chain straddled
two queues would be shaped incorrectly (or not at all). tcplan enforces the
alignment two ways:

1. **Structurally** — a subtree is pinned by the `cpu` on its top-level site, and
   every class it produces is a `(cpu+1):…` handle. There is no way to express a
   class in one queue's major that hangs off another queue's tree.
2. **By validation** — a descendant that names a `cpu` different from the subtree
   it lives in is a `CpuStraddle` error. A top-level node must name a `cpu`
   (`RootCpuUnset` otherwise); the `cpu` must be `< queue_count`
   (`CpuOutOfRange`).

## Plan ordering contract

`Plan.ops` is emitted so that every operation's dependency exists first:

```
mq root  →  per-queue HTB roots  →  HTB classes (parents before children)
         →  CAKE leaf qdiscs      →  steering filters
```

- The `mq` root's parent is `TC_H_ROOT`.
- A per-queue HTB root's parent is an `mq` child (`0x7FFF:q`) the kernel
  auto-creates — available once the `mq` qdisc has been emitted.
- Every HTB class's parent is either its queue's HTB root (`(c+1):0`, a top-level
  site) or its parent class (a descendant), both emitted earlier.
- A CAKE leaf's parent is its subscriber's HTB class, emitted in phase 3.
- A steering filter attaches at its queue's HTB root, emitted in phase 2.

`Plan.firstOrderingViolation` walks the plan and confirms this holds for every op.

## Validation / error semantics

`compile` returns a typed error, never a wrong plan, for:

| Error | Condition |
|---|---|
| `NoQueues` | `queue_count == 0` |
| `QueueCountTooLarge` | `queue_count >= 0x7FFF` (HTB majors would hit the `mq` major) |
| `RootCpuUnset` | a top-level node left `cpu` null |
| `CpuOutOfRange` | a node's `cpu >= queue_count` |
| `CpuStraddle` | a descendant named a different `cpu` than its ancestor |
| `CeilExceedsParent` | a child's effective ceil exceeds its parent's |
| `ClassifierOnInterior` | a `match` was set on a non-leaf node |
| `ZeroRate` | a node's `rate_bps == 0` |
| `DuplicateName` | two nodes share a `name` |
| `HandleExhausted` | a per-queue minor/prio or the global CAKE major counter overflowed |

**Empty / degenerate topologies (defined behaviour):** `queue_count == 0` →
`NoQueues`. A topology with **no** `roots` compiles to a plan containing exactly
the `mq` root qdisc (so the interface still gets its multiqueue root) — a valid,
tested outcome, not an error. A leaf with no `match` gets its HTB class and CAKE
qdisc but no steering filter (also tested).

## Positive control

`Plan.findHandleCollision` scans every installed qdisc/class handle for a
duplicate. A compiled plan must return `null`; the permanent positive-control
test forges a `Plan` with two class ops sharing a handle and asserts the check
goes RED, so a regression that breaks handle uniqueness cannot pass silently.

## Deliberately deferred

- **Live-diff / reconcile.** Diffing a target topology against the kernel's
  current state to emit a *minimal* add/change/del sequence is valuable but a
  larger design (it needs a state read-back and a diff engine). tcplan today
  emits a full create-or-replace plan; a reconciling caller replays it
  idempotently with `.replace`.
- **`u32` / fwmark classifiers.** The subscriber classifier is modelled as
  `flower` (value-typed L3 prefix match) to keep every `Operation` free of owned
  key slices. Raw-offset `u32` selectors and fwmark-based steering are not
  modelled here; a caller needing them can build the `tc.FilterSpec` itself.
- **WRR/DRR quantum tuning, HTB burst/cburst/prio knobs.** The compiler emits
  `rate`/`ceil` and lets `tc`/the kernel derive burst and quantum. Exposing the
  full HTB class knob set is a straightforward extension of `Node`, deferred
  until a consumer needs it.
- **Per-queue top-class caps.** Multiple sites on one queue attach as sibling
  top-level HTB classes; a single per-queue ceiling would need a synthetic root
  class per queue. A caller wanting one adds a single top site per queue.
- **IPv6 classifier depth.** `Match.ipv6` covers host/prefix matches; flow-label
  and extension-header matching are out of scope.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** pure Topology->Plan compiler, internal data structure, no wire I/O
