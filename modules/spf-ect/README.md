# spf-ect

Deterministic shortest paths over a **directed** weighted graph, with an
undirected-link convenience constructor: Dijkstra plus a totally-ordered,
direction-independent tie-break, so that on a symmetric graph `path(A→B)` is
always exactly the reverse of `path(B→A)` no matter which end computes it. That
property is what lets independent nodes agree on a forwarding tree without
exchanging the result.
Also provides a disjointness-*minimizing* second tree (PRP mode) — a greedy
equal-cost tie-break that steers onto unused links wherever the graph offers
one; **not** a max-flow disjoint-path guarantee.

Pure graph algorithm, zero I/O. Shared kernel of the SPB simulator (S1) and the
encrypted SCADA L2VPN fabric (S1b).

- **Status:** complete — both tiers implemented and property-tested.
  **Platform:** any.
- **Deps:** none (std only).
- **Model after:** the IEEE 802.1aq / RFC 6329 SPB **ECT** path-vector
  tie-break idea, generalized off VLAN fabrics onto a plain weighted graph.

## Use

```zig
const spf = @import("spf-ect");

var g = spf.Graph.init(gpa);
defer g.deinit();
try g.addEdge(0, 1, 4);   // both directions at weight 4
try g.addEdge(1, 2, 3);
try g.addArc(2, 0, 9);    // one direction only — 0→2 stays absent

const path = try spf.shortestPath(gpa, &g, 0, 2); // [0, 1, 2]
defer gpa.free(path);

var tree = try spf.shortestPathTree(gpa, &g, 0);
defer tree.deinit(gpa);

var pair = try spf.disjointTrees(gpa, &g, 0); // primary + PRP second tree
defer for (&pair) |*t| t.deinit(gpa);
```

`comparePaths` and `comparePathsDisjoint` are public: the ordering is the
reusable part, and a consumer with its own path search can adopt it directly.

## How the tie-break works

A lexicographic composite of three keys: a sorted node multiset (+inf-padded so
it stays extension-consistent), a sorted **undirected** edge multiset, and a
forward-order totality backstop reachable only at identical sequences. The first
two keys are preserved by path reversal — that, and only that, is what makes
`path(a, b) == reverse(path(b, a))`. `comparePathsDisjoint` prepends a
primary-tree overlap key for the second tree.

Adjacency is kept sorted by neighbor id, so relaxation order is deterministic
and a run does not depend on insertion order.

## Node ids are dense, and that is enforced

`Graph` indexes a flat array by `NodeId`, so `ensureNode(id)` materialises every
id from 0 up to `id`. That is right for a topology numbered `0..n` and wrong for
an identity mapped 1:1 out of something wide — a 32-bit router id, a hash —
where `ensureNode(0xDEAD_BEEF)` is not a big graph but a 3.7-billion-element
allocation from one call. Ids at or above `Graph.max_nodes` (2^20) are therefore
refused with `error.NodeIdTooLarge`, from `ensureNode`, `addEdge` and `addArc`
alike, leaving the graph untouched. Hitting it means renumber into a dense
range, not raise the cap.

## Directed arcs

`Graph.addArc(from, to, w)` adds one direction; `addEdge(a, b, w)` is exactly
`addArc(a, b, w)` + `addArc(b, a, w)`. Storage is unchanged either way — the
adjacency was always a per-node list of outgoing arcs, and Dijkstra always
relaxed the list of the node it expanded, so the *engine* was already directed;
only the constructor was not.

This is what a link-state decision process needs: ISO/IEC 10589 Annex C.2.4
Step 1 relaxes `dist(P,N) = d(P) + metric_k(P,N)` where "metric_k(P,N) is the
cost of the link from P to N as reported in P's Link State PDU", and §7.2.8.2
permits the two endpoints of one link to advertise different values ("routes
may be asymmetric"). No per-link weight can stand in for both directions,
because which direction a path uses is decided by the tree being computed —
see `isis-spf`'s FRR anchor for the measured case.

On a graph with an asymmetric arc pair the reversal property above does not
hold, and cannot: the two directions have different costs. That is a property
of the topology, not of the comparator.

## Verify

```
zig build test-spf-ect                          # Debug       — 13 pass
zig build test-spf-ect -Doptimize=ReleaseFast   # ReleaseFast — 13 pass
```

The property harness is the real check: reversal symmetry, strict-total-order
laws on the comparator, an exhaustive brute-force cross-check on every graph up
to 7 nodes, and second-tree validity plus disjointness. A comparator that is
merely *consistent* would pass a round-trip test; only the total-order laws and
the brute-force oracle pin it.

Provenance: clean-room from the public IEEE 802.1aq / RFC 6329 description of
ECT — no third-party source ported or studied, so no `NOTICE` entry is required
(root [`NOTICE`](../../NOTICE) §0).
