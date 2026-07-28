# bumtree — spec

Design + threat notes for auditors. Usage, API and the per-node output contract:
see [README.md](README.md) and the `src/root.zig` doc comments.
Attribution/provenance: see `/NOTICE` — none needed here (clean-room from the
public IEEE 802.1aq standard; a public spec is not a copyrightable work, and no
third-party source or implementation was ported or studied).

## What it computes

For one source `S`, one member set, and a caller-supplied `spf-ect.Graph`, a
per-node plan `{ rpf_ingress, replicate_to, is_member }` that a forwarder uses to
deliver BUM (broadcast/unknown-unicast/multicast) traffic for an I-SID on `S`'s
pruned shortest-path tree. This is the control-plane half deferred to by the
data-plane `l2encap`/`l2forward` (their "Honest scope of the loop claim"
sections): split-horizon stops reflection; the pruned SPT + RPF stop transient
loops and duplicates.

## Algorithm

1. **SPT.** `spf-ect.shortestPathTree(graph, S)` → the shortest-path tree rooted
   at `S`. The whole module hangs on `Tree.pred: []?NodeId`: `pred[N]` is `N`'s
   next hop *toward the root* `S` (its parent in the SPT), and is `null` for the
   root and for any node unreachable from `S`. `N`'s **children** are therefore
   the inverse relation `{ C : pred[C] == N }`. `spf-ect` owns Dijkstra and the
   ECT tie-break; this module reimplements no shortest-path logic and only reads
   the resolved tree — exactly as the sibling `isis-spf` consumes it.

2. **Member subtree marking (the pruning input).** `has_member[N]` = "`N`'s SPT
   subtree contains a member" (N itself or any descendant). Computed by walking
   **each reachable member up its predecessor chain to `S`**, marking every node
   on the way and short-circuiting the first already-marked ancestor. Each node is
   marked at most once, so the whole pass is `O(nodes)` regardless of member
   count — no recursion, no per-node sort. (Predecessor chains are acyclic because
   `spf-ect` rejects zero-weight edges, so the walk always terminates at `S`.)

3. **Replication next-hops.** `replicate_to[N]` = `{ C : pred[C] == N and (C's
   subtree has a member) }`. Built by a single ascending scan over child ids into
   a prefix-summed contiguous backing array, so each parent's run comes out
   **sorted ascending** and the whole result is independent of graph
   insertion/iteration order. Pruning drops any child whose subtree holds no
   member — BUM is never sent toward a member-less branch.

4. **RPF.** `rpf_ingress[N] = pred[N]` — the one neighbour a BUM-from-`S` frame
   may arrive on. `rpfCheck(N, ingress)` is `ingress == rpf_ingress[N]`; it is
   false at `S` (which originates the frame and never accepts one from the
   network, `pred[S] == null`) and for any unreachable node.

Allocation is bounded by node count: one SPT (owned by `spf-ect`, freed before
return), the `nodes` array (`node_count`), one contiguous `backing` array (total
replication targets ≤ `node_count − 1`), plus `O(node_count)` transient scratch
(`is_member`/`has_member`/`counts`/`offset`/`fill`) all freed on return. Result
arrays are deterministic. `BumTree.deinit` frees `nodes` + `backing`; the
per-node `replicate_to` slices borrow from `backing`.

## Loop-freedom & congruency argument

- **Acyclicity ⇒ terminating, single-touch tree flood.** The SPT is a tree;
  flooding down `replicate_to` (parent→child only) reaches each node at most once
  and cannot cycle. Member pruning removes whole member-less subtrees, so the
  flood also never leaves the member-spanning sub-forest.
- **RPF ⇒ single-ingress even mid-reconvergence.** Where the graph has redundant
  paths, a node may *receive* a BUM-from-`S` copy on more than one edge (a
  neighbour holding a stale tree, a chord, a second home). RPF accepts only the
  copy that arrived from `pred[N]` and drops the rest, so no node re-floods a
  wrong-path copy — the transient loop the data-plane's split-horizon cannot stop
  is stopped here, before TTL has to. (On a pure tree there is only one path to
  each node, so RPF and acyclicity coincide; RPF earns its keep only on a meshed
  graph — which is why the positive-control test uses a cyclic topology.)
- **Congruency.** `spf-ect`'s ECT tie-break is deterministic and
  direction-independent, so the `S`-rooted SPT is byte-identical at every node
  computing it from the same topology. All nodes therefore derive the same tree
  and mutually-consistent RPF ingresses (the SPB symmetry property); an equal-cost
  diamond resolves to the same parent everywhere, so exactly one incoming edge is
  the RPF edge at the join point. This is *determinism of the source-rooted SPF*,
  which is all congruency requires; the ECT reversal-invariance additionally makes
  the unicast paths symmetric, but the multicast tree needs only the determinism.

## Threat / robustness notes

Pure logic, no I/O, no untrusted parsing — the graph is caller-built (validated by
`spf-ect`, which rejects self-loops, duplicate and zero-weight edges). Failure
modes are all bounded and defined, never a panic:

- **Source not a node** (`source >= nodeCount()`) → a defined empty tree
  (`node_count == 0`); every accessor returns its absent/empty/false default.
- **Out-of-range / duplicate member ids** → ignored / idempotent.
- **In-range but unreachable member** → flagged `is_member` (it *is* a member) but
  contributes no subtree marking and simply never receives the frame.
- **Empty member set** → all `replicate_to` empty; RPF ingresses still populated.
- All accessors are bounds-safe; only `Allocator.Error` can be returned.

## Verification

Offline only — pure logic, no live-interop surface. `zig build test-bumtree`
(Debug + `-Doptimize=ReleaseFast`):

- **Golden topology** — a 7-node tree with one deliberately member-less branch
  (node 6); asserts the exact per-node `replicate_to`, `rpf_ingress`, and
  `is_member` against a hand computation.
- **Member pruning** — the member-less branch is absent from the parent's
  `replicate_to`; adding a member on it makes it appear (sorted). The key pruning
  proof.
- **RPF correctness** — for every reachable node, `rpfCheck` is true for exactly
  the predecessor ingress and false for every other neighbour (and false at the
  source).
- **Loop-freedom (tree flood)** — flooding down `replicate_to` delivers to each
  member exactly once, touches no node twice, and never reaches the member-less
  branch.
- **RPF backstop (reconvergence flood) + positive control** — on a *meshed*
  graph, a worst-case flood where every accepting node re-floods to all
  neighbours yields exactly-once acceptance *with* RPF; **without** RPF the same
  flood duplicates over the redundant edges (`max acceptance > 1`). Permanent
  positive control that RPF is load-bearing.
- **Pruning positive control** — `prune = false` puts the member-less branch back
  into `replicate_to` and the tree flood then reaches it; proves the prune flag
  actually gates the branch.
- **Congruency/determinism** — identical result across scrambled edge-insertion
  order and repeated rebuilds; an equal-cost diamond resolves to one stable
  source-rooted parent.
- **Degenerate cases** — source not in graph, no members, single member == source,
  isolated source, unreachable member.
- A `testing.allocator` run leak-checks that `deinit` frees `nodes` + `backing`.

`zig fmt --check` clean; `zig build check-catalog` green.

## Deliberately deferred (out of scope by design, not oversight)

- **All-source trees in one pass** — the caller loops over sources; no batched
  multi-source build.
- **FIB installation** — a plan is returned, not programmed forwarding state.
- **The 16 SPB ECT algorithm variants / equal-cost multiple trees** — one
  congruent tree from `spf-ect`'s single deterministic tie-break.
- **Replication I/O** — encap, TTL, and sending the copies are `l2encap` /
  `l2forward`.
- **Designated-forwarder election** — the separate `df-elect` module.
- **Topology extraction** — building the `spf-ect.Graph` from an LSDB is the
  upstream `isis-spf`'s job.
