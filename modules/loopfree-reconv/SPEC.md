# loopfree-reconv — spec

Loop-free reconvergence for a link-state fabric: an ordered-FIB update schedule
that keeps forwarding acyclic at every step of a topology transition, verified
in `netsim`. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## The problem

A destination's shortest-path tree gives every node `n` a single next-hop
`pred[n]` toward that destination. A link up/down event recomputes the tree; a
node whose `pred[n]` changed must reprogram its FIB. In a real distributed IGP
each node reprograms the instant its own SPF finishes — an uncoordinated order.
During that window some nodes forward via the *new* tree and some via the *old*
one, and for the wrong order two adjacent nodes point at each other: a transient
forwarding loop. TTL/hop-limit only bounds the damage (a frame dies after N
hops instead of storming); it does not prevent the loop. This module makes the
loop impossible by choosing the *order* in which the same per-node updates are
applied — no extra protocol messages, no extra round-trip, just a smarter
sequence.

## Design & invariants

**Two-class ordered-FIB schedule (`fib.zig` `computeUpdateOrder`).** Split the
changed nodes by comparing `old_dist[n]` to `new_dist[n]`:

- **Class A ("migrate early")** — distance strictly *decreased*
  (`new_dist < old_dist`; includes newly-reachable nodes, `old_dist = +inf`).
  Applied FIRST, ascending new-distance — parent-before-child on the NEW tree,
  so an A-node switches only after every changed node nearer the destination on
  the new tree (in particular its new next-hop, if that also decreased) has
  already switched.
- **Class B ("migrate late")** — everything else that changed next-hop:
  distance increased, or stayed equal with a different next-hop (an ECT
  tie-break shift), including newly-unreachable nodes. Applied LAST, descending
  old-distance — child-before-parent on the OLD tree, so a B-node keeps its
  stale route until every node that used to route THROUGH it has moved off.

Ties within a class break by ascending node id (deterministic, allocation-free
sort; the proof only needs the non-strict prefix inequalities, which ties
satisfy either way).

**Loop-freedom proof (why no prefix can loop).** Fix any intermediate state:
`U` = the already-applied prefix; a node forwards via `new_tree.pred` if it is
in `U`, via `old_tree.pred` otherwise (an unchanged node forwards via the
identical edge in both). Each tree's pred-graph is acyclic (weights ≥ 1 make
pred chains strictly distance-decreasing), so any cycle must MIX ≥ 1 strict new
edge (from a changed node in `U`) and ≥ 1 strict old edge (from a changed node
not in `U`). Track `old_dist` along old-runs and `new_dist` along new-runs:
every edge strictly decreases the tracked value; every old→new switch happens
at a class-A node (`new_dist < old_dist`, a decrease) and every new→old switch
at a class-B node (`old_dist ≤ new_dist`, no increase). The class ordering
(ascending new_dist within A, descending old_dist within B) is exactly what
forces the endpoint of each run to be the safe class at each phase, so one full
lap of the cycle would strictly decrease a value back onto itself —
impossible. Hence every prefix, empty and full included, yields an acyclic
forwarding graph. This is the Francois/Filsfils/Evans/Bonaventure ordered-FIB
condition, generalized here to arbitrary (old, new) tree pairs rather than only
single-failure/single-recovery deltas.

**The loop invariant (the teeth, `fabric.zig`).** The property is checked
data-plane-side, not asserted from the ordering: `Fabric` forwards real frames
hop-by-hop over a 4-node ring (dest = node 0, origin = node 1), tracking per
in-flight frame the set of nodes it has already left and the node it is most
recently at. An immediate re-delivery to the node a frame already sits at (a
`dup_once` fault) is absorbed as a harmless duplicate; a frame arriving at a
node it visited *earlier* after moving on is a genuine loop →
`error.ForwardingLoop`. The FIB updates dictated by the chosen order are
applied `step_gap` ticks apart in real simulated time, so the
transient-inconsistency window the property depends on is real, and link
up/down are real `netsim` faults that genuinely sever/restore data delivery.

**Conductor transition serialization (`fabric.zig` `applyTopologyChange`).**
The proof above assumes the FIB starts exactly at `old_tree.pred` before the
order applies. When a second topology change arrives before the first's ordered
convergence has finished, a naive conductor overlaps the two update windows and
a stale queued update from the first transition lands *after* the second's
updates — a mixed FIB neither transition's proof covers, i.e. a persistent
loop. Real ordered-FIB deployments (RFC 6976 / Francois–Bonaventure) complete
or abort an in-progress ordered convergence before starting a new one. This
conductor models "complete first" by **serializing**: it tracks
`last_apply_time` (the absolute time of the last-scheduled pending update) and
starts each new transition's ordered window at
`max(now, last_apply_time + step_gap)`. Because the control-plane edge state
`self.up` advances monotonically and every `old_tree`/`new_tree` is a full SPF
over it, a transition's `old_tree` is *exactly* the FIB the previous
transition's serialized window converges to — so concatenating complete,
individually prefix-safe transitions stays loop-free no matter how tightly the
events bunch. (Minimal case: seed 464, `link_down 0-1 @ t=894` superseded 46
ticks later by `link_up 0-1 @ t=940`, which a non-serializing conductor loops.)

**Scaffold simplifications (deliberate, orthogonal to the ordering).** Topology
changes are made instantly and consistently visible to the conductor via a
pre-generated fault schedule (`harness.zig` + `Fabric.setSchedule`) rather than
modeled through hello/keepalive timeouts and LSA floods — the control-plane
propagation model is out of scope; the *ordering* problem is what is under
test. The ring topology and its asymmetric `3-0` weight (10 vs 1) are fixed and
hand-derived (see `fabric.zig`) to force the specific next-hop swap the
positive control exercises.

## Threat model / out of scope

Not a security boundary; the "adversary" is timing. Guarantees no transient
forwarding loop for a single destination across a sequence of link up/down
events on a fixed-topology ring, under the modeling assumptions above. Out of
scope: multi-destination / per-prefix scheduling interactions, the LSA-flood /
hold-timer control-plane propagation model, node crash and network partition
faults (spf-ect's `Graph` has no partition concept), weighted-ECMP load
distribution during transition, and the RPF-acceptance dual (the module returns
an apply *ordering*, not an epoch-tagged acceptance predicate, though the two
are equivalent — see `fib.zig`).

## Verification

`zig build test-loopfree-reconv` — green in Debug + ReleaseFast, no leaks:

- **smoke** — no faults, frames flow origin→dest cleanly.
- **positive control** — `naiveBadOrder` on a single `link_down 1-0 @ t=105`
  DOES bounce a frame between nodes 1 and 2; the checker raises
  `error.ForwardingLoop`. Proves the invariant has teeth independent of the
  real ordering.
- **shrink** — `netsim`'s seeded fuzzer finds a naive-ordering loop across
  seeds and ddmin-minimizes it to a still-reproducing core.
- **teeth-at-scale** — the headline sweep: 5000 seeds × up to 8 fault events ×
  a few hundred forwarded frames each, over the REAL `ordered_fable` ordering
  plus the serializing conductor, finds **no** forwarding loop.
- unit tests for `changedNodes`, `naiveBadOrder`, `buildGraph`/`applyInitialFib`,
  and `applyTopologyChange` scheduling.

## Backlog / deferred

- RPF-acceptance variant (epoch-tagged forwarding predicate) as an alternative
  to the explicit apply ordering.
- Multi-destination scheduling and the control-plane propagation model, if this
  graduates from a property-test jewel into a fabric component.

## Status

`any · util · single_owner` + deps `netsim`, `spf-ect`, model_after
"ordered-FIB / RPF loop-free convergence (IS-IS/SPB), TTL backstop" — canonical
source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** ordered-FIB scheduling algorithm proven via own loop-freedom invariant, no wire messages
