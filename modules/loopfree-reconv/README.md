# loopfree-reconv

Loop-free reconvergence for a link-state fabric: when a link goes up or down,
the destination's shortest-path tree changes and every node must reprogram its
next-hop toward that destination. Applying those FIB updates in an arbitrary
(purely local, uncoordinated) order transiently points two adjacent nodes at
each other — a forwarding loop, which on an L2 overlay is a broadcast storm.
This module computes an **ordered-FIB** update schedule that is provably
loop-free at *every* intermediate step, not just at the start and end, and
verifies it in `netsim` against the invariant "no frame ever revisits a node"
across a 5000-seed fuzzed sweep of reconvergence schedules.

```zig
const lfr = @import("loopfree-reconv");

// old_tree / new_tree: spf-ect `Tree`s rooted at the destination, before and
// after a topology change (`pred[n]` = node n's next-hop toward the dest).
const order = try lfr.computeUpdateOrder(gpa, &old_tree, &new_tree);
defer gpa.free(order);
// Apply `next_hop[n] = new_tree.pred[n]` for each n in `order`, in order:
// no prefix of this sequence can hold a forwarding loop.
```

- `computeUpdateOrder(gpa, old_tree, new_tree) ![]NodeId` — the ordering core.
  Returns a permutation of the changed nodes: a total order in which applying
  each node's `next_hop[n] = new_tree.pred[n]` update keeps the forwarding
  graph acyclic at every intermediate prefix. Two classes — nodes whose
  distance to the destination **decreased** apply first (ascending new-tree
  distance, parent-before-child on the new tree); nodes whose distance
  **increased or shifted** apply last (descending old-tree distance,
  child-before-parent on the old tree). Caller owns the slice.
- `changedNodes(gpa, old_tree, new_tree) ![]NodeId` — the raw "what changed"
  set (next-hop differs), ascending by node id. Caller owns the slice.
- `naiveBadOrder(gpa, old_tree, new_tree) ![]NodeId` — the deliberately-WRONG
  "apply all FIBs instantly" baseline (changed set, ascending id). Used only
  as the positive control that proves the loop checker has teeth.
- `Fabric` / `Mode` / `scenario` — a `netsim.Protocol` consumer (a 4-node ring
  with a per-node FIB and a hop-by-hop frame forwarder) whose **conductor**
  drives topology changes through the chosen ordering and *serializes*
  overlapping transitions, plus a loop-invariant checker
  (`error.ForwardingLoop`). `Mode.ordered_fable` runs `computeUpdateOrder`;
  `Mode.naive_bad` runs `naiveBadOrder`.
- `run` / `findFailing` / `shrink` — thin wrappers around `netsim`'s seeded
  fuzzer / delta-debugger that add the fault-schedule sync `Fabric` needs
  (see `harness.zig`).

- **Role:** util. **Platform:** any. **Deps:** `netsim` (the seeded
  discrete-event simulator + fault fuzzer that drives the property test) and
  `spf-ect` (the shortest-path trees the ordering is computed over).
  **Concurrency:** single-owner — `Fabric` holds mutable per-run state.

Provenance: clean-room from the ordered-FIB / loop-free-convergence
literature (Francois, Filsfils, Evans & Bonaventure, "Achieving sub-second IGP
convergence in large IP networks", INFOCOM 2005; RFC 6976). No third-party
source consulted or copied.

## Verification

`zig build test-loopfree-reconv` — offline tests, green in Debug + ReleaseFast:
a no-fault smoke test; a positive control proving `naiveBadOrder` DOES loop and
the checker catches it; a `netsim`-fuzzed shrink test that finds a naive loop
across seeds and minimizes it; and the headline **5000-seed sweep over the real
`ordered_fable` ordering** that finds no forwarding loop, no crash, and no leak.
See `SPEC.md` for the loop-freedom proof and the conductor's transition
serialization.
