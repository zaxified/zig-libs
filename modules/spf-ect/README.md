# spf-ect

Deterministic **symmetric shortest paths**: Dijkstra plus a totally-ordered,
direction-independent tie-break, so that `path(A→B)` is always exactly the
reverse of `path(B→A)` no matter which end computes it. That property is what
lets independent nodes agree on a forwarding tree without exchanging the result.
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
try g.addEdge(0, 1, 4);
try g.addEdge(1, 2, 3);

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

## Verify

```
zig build test-spf-ect                          # Debug       — 10 pass
zig build test-spf-ect -Doptimize=ReleaseFast   # ReleaseFast — 10 pass
```

The property harness is the real check: reversal symmetry, strict-total-order
laws on the comparator, an exhaustive brute-force cross-check on every graph up
to 7 nodes, and second-tree validity plus disjointness. A comparator that is
merely *consistent* would pass a round-trip test; only the total-order laws and
the brute-force oracle pin it.

Provenance: clean-room from the public IEEE 802.1aq / RFC 6329 description of
ECT — no third-party source ported or studied, so no `NOTICE` entry is required
(root [`NOTICE`](../../NOTICE) §0).
