# isis-sim

A headless **multi-node IS-IS/SPB fabric convergence simulator**: a `netsim`
`Protocol` that runs the P2P IS-IS control-plane stack — `isis-lsdb` (the
link-state database) + `isis-flood` (the flooding transmit scheduler), with
`isis-spf` for the resulting routes — on **every node** of a small simulated
fabric, and asserts the two properties that matter: the fabric **converges**
(every node's LSDB synchronises to the same set of LSPs) and **reconverges**
after a link failure. It is the end-to-end proof that the five-layer stack
(`isis` codec → `isis-lsdb` → `isis-flood` → `isis-spf`, driven over `netsim`)
works **together**, not just per-module.

Status: **integration harness** — flooding + LSDB convergence, SPF route
consistency, one mid-run link-fail **reconvergence**, and **partition** detection,
on a small (≤ 6-node) **static-adjacency P2P** fabric. Deliberately deferred: the
adjacency FSM (`isis-adj`), node crash/restart, LSP purge/aging races during a
run, LAN pseudonodes, the SPB data-plane, scale/perf, and topology fuzzing — see
`SPEC.md`.

Model after: **`netsim`'s `Protocol` seam** (the VOPR-style discrete-event
network simulator) driving the **ISO/IEC 10589** IS-IS control plane already
implemented in the sibling modules.

## The node model — a netsim link *is* an adjacency

There is no adjacency handshake here. A `netsim` bidirectional link between two
nodes **is** an up adjacency; a failed link is a down adjacency. Neighbours are
statically configured by the topology, so `isis-adj` is out of scope (it is the
one layer this capstone omits). Each node's netsim links are its IS-IS circuits;
the circuit index is the `iface` the whole isis stack keys SRM/SSN/`up` on.

netsim node *n* maps deterministically to the 6-octet system-id of `n + 1`
(`00:00:00:00:HH:LL`), and each node originates exactly **one** LSP (LSP-number
0, no pseudonodes).

## How the isis stack plugs into netsim's Protocol vtable

| Hook | What the harness does |
|------|-----------------------|
| **onStart(node)** | Originate the node's own LSP — one Extended IS Reachability (#22) entry per currently-up neighbour, sequence 1 — and `lsdb.insert` it self-originated (`arrival_iface = null` → SRM on every circuit). Arm the first flooding poll; pre-arm one timer per scheduled link failure this node terminates. |
| **onMessage(node, from, payload)** | `isis.decode` the PDU: an **LSP** → `lsdb.insert(bytes, arrival_iface, now)` (sets SRM to flood onward + SSN to ack); a **CSNP/PSNP** → `lsdb.reconcileCsnp`/`reconcilePsnp`. Then arm a flooding poll so the next `poll` drains the freshly-set flags. |
| **onTimer(node, id)** | id 0 = *poll now*: `isis-flood.poll(now, up, lsdb, …)`, `sim.send` every effect (LSP/PSNP/CSNP) to the neighbour on its circuit, re-arm while flooding work remains. id ≥ `fail_base` = *a link you terminate just failed*: mark that circuit down, then **re-originate** this node's LSP without the lost neighbour at a bumped sequence number, and flood. |
| **check** | A safety invariant run after every event: no node's LSDB ever holds more than `node_count` distinct LSP-IDs (a runaway/corruption tripwire). |

## The three proofs

- **Convergence.** A 4-node line `A-B-C-D` and a 5-node cyclic topology run to a
  quiesced steady state within the step cap; **every** node's LSDB then holds all
  N originators' LSPs at the right sequence numbers (`lsdbsAgree`). This is the
  core proof the SRM/SSN flooding + SNP-reconcile stack actually synchronises.
- **SPF consistency.** After convergence every node's `isis-spf` table reaches
  every other node, with exact next-hops (on `A-B-C-D`, D's next-hop toward A is
  C; A's toward D is B) and exact metrics.
- **Reconvergence.** On a square `A-B-C-D-A` (an alternate path exists), failing
  link `A-B` mid-run makes A and B re-originate (sequence 2), the fabric
  re-converges, and A's route to B is now the long way (via D, metric 30) — with
  all LSDBs agreeing on the new topology.
- **Partition.** Failing a leaf's only link makes that leaf **unreachable** in
  every other node's SPF — a partition is *detected*, bounded by the step cap, not
  a hang.

## Termination & quiescence

`runToConvergence(max_steps)` drives `netsim.replay` under a **hard step cap**
(`until` time bound + a fixed `max_events_cap` event bound), so it **always
terminates**. Afterwards it inspects the context: the fabric is **quiescent** when
no node has any SRM (flood) or SSN (ack) flag set on an *up* circuit — flooding
has fully drained and a further poll would send nothing. Quiescence within the cap
⇒ `.converged`; otherwise `.step_cap_exceeded`. A non-quiescing fabric (an endless
re-flood) would blow the cap — the quiescence test asserts the steady state
explicitly.

## API sketch

```zig
const sim = @import("isis-sim");

// A 4-node line A-B-C-D, metric 10 per hop.
const edges = [_]sim.Edge{
    .{ .a = 0, .b = 1, .metric = 10 },
    .{ .a = 1, .b = 2, .metric = 10 },
    .{ .a = 2, .b = 3, .metric = 10 },
};
var fab = try sim.Fabric.init(gpa, .{ .node_count = 4, .edges = &edges }, 0xSEED);
defer fab.deinit();

// Optionally schedule a mid-run link failure (both endpoints re-originate).
try fab.failLink(0, 1);

switch (try fab.runToConvergence(100_000)) {
    .converged => {},                 // quiesced steady state
    .step_cap_exceeded => unreachable, // did not settle within the cap
}

// Inspect the converged state.
_ = fab.lsdbsAgree();                  // every LSDB holds the same originator set
var table = try fab.routes(gpa, 3);    // node D's SPF forwarding table
defer table.deinit();
const nh = try fab.reaches(gpa, 3, 0); // next-hop system-id D→A, or null
```

## Test

```
zig build test-isis-sim
```

Covers: **convergence** (4-node line + 5-node cyclic topology — every LSDB holds
all originators at the right sequence); **SPF consistency** (all-pairs
reachability + exact next-hops/metrics on the line); **reconvergence** (fail `A-B`
on a square → reroute via D, sequences bumped to 2, LSDBs agree); **partition**
(fail a leaf's only link → unreachable everywhere, not a hang); **quiescence** (no
pending SRM/SSN after convergence); **determinism** (identical fabric + fault
schedule → identical final LSDBs); a permanent **positive control** (breaking the
flood-drain wiring leaves far nodes ignorant — convergence goes RED); and
`std.testing.allocator` leak checks. Green in Debug and ReleaseFast; `zig fmt`
clean.

Provenance: composes the sibling modules over `netsim`; pure spec-only
clean-room (ISO/IEC 10589), no third-party source ported — no `/NOTICE` entry.
License: MIT.
