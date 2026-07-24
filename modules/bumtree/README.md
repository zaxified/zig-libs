# bumtree

SPB per-source loop-free BUM (broadcast/unknown-unicast/multicast) distribution
tree + Reverse-Path-Forwarding check, over the `spf-ect` shortest-path engine.

In IEEE 802.1aq SPBM, BUM traffic for an I-SID is delivered on **per-source
shortest-path trees**: for a given source node `S`, the distribution tree is
`S`'s shortest-path tree (SPT), pruned to the branches that lead to a member of
the I-SID. For **one source** and **one member set** this module computes, per
node `N`, the two outputs a forwarder needs:

1. **Replication next-hops** (`replicateTo(N)`) — the neighbours `N` must
   replicate a BUM-from-`S` frame to = `N`'s children in `S`'s SPT (nodes whose
   SPT predecessor is `N`), pruned to only children whose subtree holds at least
   one member, so BUM is never flooded down a member-less branch. Sorted
   ascending, deterministic. If `N` is itself a member (`isMember(N)`) it also
   delivers the frame locally.
2. **RPF ingress** (`rpfIngress(N)` / `rpfCheck(N, ingress)`) — the single
   neighbour a BUM-from-`S` frame may legally arrive on = `N`'s SPT predecessor
   toward `S`. A frame from `S` arriving on any other edge is dropped. This is the
   loop/duplicate backstop.

**Model-after:** IEEE 802.1aq (SPBM) per-source SPT multicast trees + Reverse
Path Forwarding Check (RPFC). Clean-room from the public standard.

**Status:** `any · util · single_owner` · deps: `spf-ect` (which owns Dijkstra +
the ECT tie-break) — canonical metadata is `pub const meta` in `src/root.zig`.
Scope is one source per call (the caller iterates sources); see the deferred list
below.

## Why (the gap this closes)

The data-plane siblings `l2encap` and `l2forward` both stop at split-horizon and
say, in their SPECs' "Honest scope of the loop claim" sections, that split-horizon
prevents only **reflection** (a BUM frame handed back to the PE that
ingress-replicated it) — it does **not** prevent a **transient forwarding loop**
among other nodes during reconvergence, which needs "a loop-free BUM distribution
tree and a reverse-path-forwarding check, which are **control-plane**
computations". This module is that control-plane piece: the pruned per-source tree
supplies the replication set, and RPF is the per-node ingress gate. The
data-plane's TTL remains the always-correct last-resort backstop; this module is
what makes the loop not happen in the first place.

## Loop-freedom & congruency

- **Loop-free / duplicate-free by construction.** An SPT is a tree (acyclic), so
  flooding down `replicate_to` terminates and reaches each node at most once. RPF
  enforces a single valid ingress per node: even while the network is
  mid-reconvergence and some node still holds a stale tree, a frame that took a
  wrong path is dropped at the first node whose RPF predecessor it did not arrive
  from — no loop, no duplicate. (RPF earns its keep only where the graph has
  redundant paths; on a pure tree the two properties coincide.)
- **Congruent across nodes.** `spf-ect`'s ECT tie-break is deterministic, so the
  `S`-rooted SPT is identical at every node that computes it from the same
  topology — all nodes agree on the same tree and therefore on mutually-consistent
  RPF checks (the SPB symmetry property). Equal-cost alternatives resolve to one
  and the same parent everywhere.

## Usage

```zig
const spf = @import("spf-ect");
const bumtree = @import("bumtree");

// The caller builds the topology as an spf-ect graph (see `isis-spf` for the
// LSDB→graph path) and supplies the I-SID's member nodes.
var g = spf.Graph.init(gpa);
defer g.deinit();
// … addEdge(...) …

var tree = try bumtree.build(gpa, &g, source_node, members);
defer tree.deinit();

// At node N, replicate a BUM-from-source frame to these neighbours:
for (tree.replicateTo(n)) |next_hop| { /* … */ }
if (tree.isMember(n)) { /* local delivery */ }

// On receiving a BUM-from-source frame on edge `ingress` at node N:
if (!tree.rpfCheck(n, ingress)) { /* drop — failed RPF */ }
```

`build` uses correct member pruning; `buildWith(..., .{ .prune = false })` disables
it and exists only for the positive-control test.

## Upstream

The `spf-ect.Graph` is built by the caller. The reference producer is `isis-spf`,
which turns a synchronised link-state database (`isis-lsdb`) into an `spf-ect`
graph the same way and consumes the resolved tree; this module never parses an
LSDB itself.

## Deferred (out of scope by design — see `SPEC.md`)

- **All-source trees in one pass** — the caller loops over sources; there is no
  batched multi-source build here.
- **FIB installation** — this returns a plan (per-node replication set + RPF
  ingress), not programmed forwarding state.
- **The 16 SPB ECT algorithm variants / equal-cost multiple trees** — one
  congruent tree from `spf-ect`'s single deterministic tie-break.
- **The replication I/O itself** — encap, TTL, and actually sending copies are
  `l2encap` / `l2forward`.
- **Designated-forwarder election** — the separate `df-elect` module.

## Verify

```
zig build test-bumtree                          # Debug
zig build test-bumtree -Doptimize=ReleaseFast   # ReleaseFast
```

Provenance: clean-room from the IEEE 802.1aq standard; no third-party source or
implementation ported or studied — no `NOTICE` entry (see `/NOTICE` and
`CONVENTIONS.md` §5).
