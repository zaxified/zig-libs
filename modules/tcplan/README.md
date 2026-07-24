# tcplan

Compile a hierarchical traffic-shaping topology (site → access-point →
subscriber, each with committed/ceil rates) into a **deterministic, ordered plan
of `tc` operations** — an `mq` root, per-CPU HTB class trees, per-subscriber
CAKE leaf qdiscs, and the steering filters that bind each subscriber to its
class. This is the "brain" of a LibreQoS-style edge shaper.

tcplan is a **pure compiler**. It does no I/O, no netlink and no privileged
operation: it computes *what* `tc` operations realise a topology, expressed in
the sibling [`tc`](../tc/) module's own `QdiscTarget`/`ClassTarget`/
`FilterTarget` + `QdiscSpec`/`ClassSpec`/`FilterSpec` types, and hands the caller
an ordered `Plan`. The caller executes the plan through `tc` + `netlink`.

**Status:** implemented; compile + validate. Live-diff/reconcile against a
running interface is deliberately out of scope (see SPEC.md). No kernel round-trip
of a whole plan is exercised here (the plan is pure data); the sibling `tc`
module owns the live-kernel integration tests, and this module proves a
representative op sample builds valid netlink bytes through tc's real builders.

Provenance: see `/NOTICE` (LibreQoS is a design reference for the
architecture; no source copied).

## Model after

The LibreQoS cpumap→MQ→per-CPU-HTB arrangement with CAKE subscriber leaves — an
`mq` root that fans out to one HTB tree per hardware TX queue (== CPU), each
subscriber a leaf HTB class with a CAKE qdisc, steered by a `flower` filter.

## The topology model

A `Topology` is a forest of `Node`s on one egress interface:

- **Root** spans `queue_count` hardware TX queues (== CPUs). Each direct child of
  the root — a *site* — is pinned to a CPU with `cpu = c`.
- **Interior nodes** (site, access-point) are aggregation tiers with a committed
  rate (`rate_bps`, HTB `rate`) and a ceil rate (`ceil_bps`, HTB `ceil`; `0` ⇒
  same as `rate`). Rates are in **bytes/second** — use `tcplan.mbit(n)` to write
  them in megabit/s.
- **Leaf nodes** (subscribers) carry the same rates plus a per-subscriber `cake`
  qdisc config and a `match` classifier (an IPv4/IPv6 host or prefix, in the
  download `.dst` or upload `.src` direction) that steers the subscriber's
  packets into its class.

```zig
const sub = [_]tcplan.Node{
    .{ .name = "alice", .rate_bps = tcplan.mbit(100), .ceil_bps = tcplan.mbit(500),
       .match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 1 } } } },
};
const ap = [_]tcplan.Node{
    .{ .name = "ap1", .rate_bps = tcplan.mbit(500), .ceil_bps = tcplan.mbit(500),
       .children = &sub },
};
const sites = [_]tcplan.Node{
    .{ .name = "site1", .rate_bps = tcplan.mbit(1000), .ceil_bps = tcplan.mbit(1000),
       .cpu = 0, .children = &ap },
};
const topo: tcplan.Topology = .{ .queue_count = 4, .roots = &sites };
```

## The cpumap → MQ → per-CPU-HTB invariant

XDP's cpumap steers a subscriber's packets to a specific CPU, and that CPU
egresses a specific hardware TX queue. So a subscriber's **entire** HTB class
chain must live under that queue's HTB tree — a packet that egresses queue `c`
can only be shaped by classes under queue `c`. tcplan enforces this
**structurally**: CPU `c` owns HTB major `c+1`, and every class of a CPU-`c`
subtree is a `(c+1):…` handle. A subtree is pinned by the `cpu` on its top-level
site; every descendant inherits it. A descendant that names a *different* `cpu`
is a `CpuStraddle` compile error, never a silently-wrong plan. Other guarded
invariants: a child ceil exceeding its parent's, a `cpu` past `queue_count`, a
top-level node with no `cpu`, a duplicate node name, a zero rate, and handle
exhaustion.

## The plan and its handle scheme

`compile` returns a `Plan` — an ordered `[]Operation`, each a tagged union over
tc's `(target, spec)` pairs — in a kernel-valid order:

1. the `mq` root qdisc (`0x7FFF:0`);
2. one HTB root qdisc per used queue (`(c+1):0` under `mq` child `0x7FFF:(c+1)`);
3. every HTB class, parents before children;
4. every subscriber's CAKE leaf qdisc;
5. every subscriber's steering filter (`flower`, attached at its queue HTB root).

Handles are allocated deterministically (no randomness, no map-iteration order):
class minors run `1,2,3,…` per queue in DFS pre-order; each CAKE leaf qdisc gets
a globally-unique major from one counter starting above the queue majors; filter
priorities run `1,2,3,…` per queue. The same topology always compiles to a
byte-identical plan — the property a reconciling shaper relies on. See SPEC.md
for the full scheme.

## Executing the plan

tcplan does not touch the kernel. Each `Operation` builds its netlink request
through tc's real builders (a reconciling shaper uses `.replace` for
idempotence):

```zig
var plan = try tcplan.compile(gpa, topo, ifindex);
defer plan.deinit(gpa);

var sock = try tc.Socket.open(gpa);
defer sock.close();
for (plan.ops) |op| {
    const seq = sock.nl.nextSeq();
    const bytes = try op.buildRequest(gpa, seq, .replace, sock.psched);
    defer gpa.free(bytes);
    try sock.nl.requestAck(bytes, seq);
}
```

`Plan.findHandleCollision` and `Plan.firstOrderingViolation` are self-checks a
caller (or a test) can assert against before executing.

## Import

```zig
const tcplan = b.dependency("zig_libs", .{}).module("tcplan");
```

## Verify

```
zig build test-tcplan                       # Debug
zig build test-tcplan -Doptimize=ReleaseFast
```

Everything is pure logic, so the tests need no privilege and no network: a
hand-verified golden plan (exact handles, targets, rates, kinds, ordering), an
executability check that feeds the plan through tc's `build*` functions, a
determinism check (two compiles are byte-identical), an ordering walk, the full
set of typed-error invariants, and a permanent positive-control that drives a
forged handle collision RED.
