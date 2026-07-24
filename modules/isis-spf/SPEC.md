# isis-spf — SPEC

Auditor/design reference. The consumer-facing purpose, API sketch, and verify
steps live in `README.md`; this document is the decision-process pipeline, the
two-way reachability rule (with the ISO cite), the metric handling, the next-hop
resolution, the intern mapping, and the deferred list.

## 1. Scope

The IS-IS **decision process** (ISO/IEC 10589 §7.2) for ONE level: read a
synchronised link-state database (`isis-lsdb`) and produce a forwarding table
`dest system-id → { next-hop system-id, total metric }`. Pure and deterministic;
no I/O, no clock (time is only forwarded to `isis-lsdb` so lifetimes age to the
caller's `now`). Point-to-point topology only this increment. Out of scope: §6.

## 2. What each dependency provides

- **`isis`** (codec) — `Lsp.decode` exposing `lsp_id [8]`, `tlv_bytes`, and
  `tlvIterator()`; the reachability TLV views `ExtIsReachIterator` /
  `ExtIsReachEntry` (#22: 7-octet `neighbour_id`, `u24 metric`) and
  `IsReachIterator` / `IsReachEntry` (#2: `default_metric u8` + 7-octet
  `neighbour_id`). All bounds-checked: a lying length is a typed error, never an
  over-read.
- **`isis-lsdb`** (store) — `iterator(now) → ViewIterator` yielding `EntryView`
  with `lsp_id`, owned PDU `bytes`, and `is_request`. This module only reads it.
- **`spf-ect`** (graph) — the `Graph` builder (`ensureNode`, `addEdge`,
  **undirected**, `Weight = u32 ≥ 1`, `Distance = u64`), `shortestPathTree(gpa,
  graph, root) → Tree` (Dijkstra + the ECT tie-break already applied), and
  `Tree.pred` / `distanceTo` / `reachable`.

This module owns: topology extraction, the two-way check, the system-id ↔ NodeId
intern, graph construction, and next-hop/metric resolution.

## 3. The pipeline

### 3.1 Topology extraction

Iterate the LSDB at `now`. Skip request placeholders (no bytes). Decode each LSP
(a decode failure skips only that LSP). Skip **pseudonode LSPs** (LSP-ID octet 6
≠ 0 — this increment is P2P-only). The origin is `lsp_id[0..6]`. Walk the LSP's
TLVs; from #22 and #2 records collect directed advertisements `(from ⟶
neighbour[0..6], metric)`. A **pseudonode neighbour** (neighbour-id octet 6 ≠ 0)
is skipped. A malformed TLV or reachability record terminates that LSP's walk
(the records parsed before it still count); every other LSP is unaffected.

Directed advertisements are deduped per ordered `(from, to)` pair, keeping the
**minimum** metric (a link advertised via both #2 and #22, or across LSP
fragments, resolves to its best cost).

### 3.2 Two-way reachability (ISO/IEC 10589 §7.2.5)

> "…a designated intermediate system shall only consider an adjacency to a
> neighbour in the SPF computation if that neighbour also reports an adjacency
> back."  (ISO/IEC 10589 §7.2.5, the two-way connectivity check.)

An undirected edge for the unordered pair {A, B} is admitted **only if both A⟶B
and B⟶A were advertised**. This is the reason the model needs *directed*
advertisements collected first and *undirected* edges derived second. It is what
prevents a stale one-directional LSP — a neighbour that has gone away but whose
LSP has not yet aged out, or a half-formed adjacency — from creating a
forwarding path that does not exist.

The **positive control** (`Options.require_two_way = false`) admits a single
directed advertisement as an edge. It is deliberately wrong and exists only so a
permanent test can show that flipping the flag makes the one-way edge appear —
i.e. that the two-way check is the load-bearing part, not an accident of the
topology.

### 3.3 Metric handling and the undirected-engine limitation

`spf-ect` is an **undirected** graph with **one** `u32` weight per edge; real
IS-IS SPF is directed (the arc A→B uses A's advertised metric to B). With a
single weight per edge we cannot represent asymmetric metrics exactly. The
deterministic rule chosen:

- the edge weight for {lo, hi} (lo < hi by system-id) is **lo's advertised
  metric to hi** — the endpoint with the lexicographically-smaller system-id.
  This is iteration-order-independent and, when metrics are **symmetric** (which
  IEEE 802.1aq *requires* for congruent forward/reverse paths — the SPB fabric
  this stack targets), exactly correct.
- a metric of 0 is clamped to **1**: `spf-ect` rejects a zero weight because a
  0-cost edge can produce a predecessor 2-cycle that makes tree walks loop. A
  genuinely 0-cost IS-IS link is treated as cost 1.
- old-style #2 default metric: the **low 6 bits** of the octet are the value;
  the high bits are I/E / supported flags.

A directed IS-IS SPF (per-arc metric) is a candidate for a later increment; it
would require either extending `spf-ect` to a directed graph or a different
engine. Documented, deferred.

### 3.4 Intern mapping (system-id ↔ NodeId)

The node set is every endpoint of an admitted edge, plus the local system-id if
it originated an LSP (so an isolated local system still yields a self route).
Note that every two-way edge endpoint is necessarily an LSP origin (to advertise
back, it must have originated an LSP), so a "dangling neighbour" — advertised but
with no LSP of its own — never advertises back, contributes no edge under the
two-way check, and is simply unreachable.

The system-ids are **sorted ascending** and assigned dense NodeIds `0..n` in that
order. This is deliberate, not incidental:

- **Determinism.** The LSDB is an `AutoHashMap`; its iteration order is not a
  stable contract. A "first-seen" NodeId assignment would leak that order into
  which equal-cost path the ECT tie-break selects. Sorting removes the
  dependency, so identical databases produce byte-identical tables.
- **Canonical tie-break.** `spf-ect`'s ECT tie-break prefers the "low path id".
  With NodeIds assigned in system-id order, that lines up with the standard
  lowest-system-id preference.

Because NodeIds ascend with system-id, iterating nodes `0..n` yields the route
table already sorted by destination.

### 3.5 Next-hop and metric resolution

`Tree.pred` is a parent-pointer chain (child → predecessor toward root). The
first hop toward a reachable destination `d ≠ root` is found by walking that
chain until the node whose predecessor **is** the root — allocation-free (no
`pathTo` slice is built). The total metric is `Tree.distanceTo(d)`. The local
node is `{ self, self, 0 }`; a direct neighbour resolves to itself.

## 4. Degenerate cases (all documented, none panic)

| Case | Result |
|------|--------|
| Empty LSDB | empty table |
| Local has no LSP (not in the graph) | empty table |
| Local present but isolated | one row: the self route `{local, local, 0}` |
| Dangling neighbour (advertised, no LSP) | unreachable, absent from the table |
| Malformed reachability TLV | that record skipped; the rest still routes |

## 5. Memory / determinism

Everything allocated from the caller's `gpa` (directed map, pairs map, id set,
node↔id tables, graph, tree) is freed before returning; the leak check runs under
`std.testing.allocator`. The output `RouteTable` owns its `routes` slice, freed by
`deinit`. Given the same database and `now`, the table is byte-for-byte identical
across runs (a permanent test pins this).

## 6. Deferred (with the reason)

- **LAN pseudonodes.** Pseudonode LSPs (LSP-ID octet 6 ≠ 0) and pseudonode
  neighbours are skipped this increment. Modelling them means treating a
  pseudonode as a transparent transit node (0-cost from the pseudonode to each
  attached IS) so a LAN collapses to a full mesh through it. Cheap to add later;
  needs its own tests.
- **Multi-level (L1/L2) route leaking.** One level per computation here; the
  L1↔L2 attached-bit default route and prefix leaking are a separate layer.
- **IP / prefix reachability leaves.** The SPB fabric this targets forwards on
  system-ids / I-SIDs; #135 (extended IP reachability) and friends as leaves of
  the SPT are future work.
- **Overload bit transit exclusion.** An overloaded node (LSP `overload` flag)
  should not be used for *transit* but remains reachable as a destination.
  `spf-ect` exposes no per-node transit-exclusion hook and must not be modified,
  so this is deferred rather than approximated. The bit is available on the
  decoded LSP for a future increment.
- **Incremental SPF.** Each call is a full recomputation. Incremental / partial
  SPF on an LSDB delta is a performance optimisation, not needed for correctness.
- **Directed (asymmetric) metrics.** See §3.3 — the undirected engine uses the
  lower-system-id endpoint's metric; exact only for symmetric metrics.
