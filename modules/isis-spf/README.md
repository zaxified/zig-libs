# isis-spf

The IS-IS **decision process** (ISO/IEC 10589 §7.2) as a pure function: turn a
synchronised `isis-lsdb` into a forwarding table. It walks every LSP's
IS-reachability TLVs into a topology graph (system-id ↔ node), applies the
**two-way reachability** rule, runs the `spf-ect` Dijkstra + ECT tie-break from
the local system, and emits a route table `dest system-id → { next-hop
system-id, total metric }`. Deterministic — the bridge that turns the
link-state database into forwarding decisions.

Status: **gap** — first increment. Covers **point-to-point** topology → SPF →
next-hop table over the #22 Extended (RFC 5305) and #2 old-style (ISO §9.8)
IS-reachability TLVs. LAN pseudonodes, multi-level (L1/L2) leaking, IP/prefix
reachability leaves, the overload bit's transit exclusion, and incremental SPF
are deferred — see `SPEC.md`.

Model after: **ISO/IEC 10589 §7.2** (the decision process / SPF) with the
equal-cost tie-break delegated to `spf-ect` (**IEEE 802.1aq / RFC 6329 ECT**).

## What it does, and what `spf-ect` does

This module owns **topology extraction, the two-way check, the system-id ↔
NodeId interning, and next-hop/metric resolution**. It does **not** own the
shortest-path algorithm: `spf-ect` owns Dijkstra *and* the symmetric,
reversal-invariant ECT tie-break, so equal-cost path selection is loop-free and
`path(A→B) == reverse(path(B→A))` by construction. This module builds the graph,
calls `shortestPathTree`, and reads the resolved tree — it never picks among
equal-cost paths itself.

## The pipeline

1. **Topology extraction.** Walk every current LSP (via `isis-lsdb`'s
   `iterator(now)`). For each, take the **originating system-id** (the LSP-ID's
   first six octets) and iterate its IS-reachability TLVs — #22 Extended IS
   Reachability and #2 old-style IS Neighbours — into directed `(from ⟶
   neighbour, metric)` advertisements. Malformed TLV records are skipped by the
   bounds-checked `isis` parse; a decode failure skips only that LSP.

2. **Two-way reachability (ISO §7.2.5).** An undirected edge A–B is admitted to
   SPF **only if A advertises B and B advertises A**. A one-way advertisement —
   a half-formed adjacency, or a neighbour that just left whose LSP is still in
   the database — is dropped. This is the classic SPF-stability rule that keeps a
   stale one-directional link from poisoning the tree.

3. **Interning.** Each participating system-id is mapped to a dense `spf-ect`
   `NodeId`. The ids are **sorted ascending** and assigned NodeIds in that order,
   so the mapping is independent of the LSDB's hash-map iteration order (⇒ the
   whole table is deterministic) and the ECT "low path id" tie-break lines up
   with the canonical lowest-system-id rule.

4. **SPF + route table.** `spf-ect.shortestPathTree` from the local node; then,
   for each reachable destination, the **first hop after the root** (walking the
   tree's predecessor chain) and the **total metric** (`distanceTo`). The result
   is sorted by destination system-id. The local node is the "self" route
   (`next_hop == self`, metric 0); a direct neighbour's next-hop is itself.

## Metric handling

`spf-ect` is an **undirected** graph with a single `u32` weight per edge, so an
edge carries one metric in both directions. For a two-way pair the weight is the
advertisement from the endpoint with the **lexicographically-smaller system-id**
— deterministic and iteration-order-independent. SPB requires symmetric metrics,
in which case this is exact; when the two directions differ, the lower-id
endpoint's value is used (documented limitation, see `SPEC.md`). A zero metric is
clamped to 1 (`spf-ect` rejects a zero weight, which could form a predecessor
cycle). Old-style #2 metrics use the low 6 bits of the default-metric octet.

## API sketch

```zig
const isis_spf = @import("isis-spf");

// `db` is a synchronised isis-lsdb.Lsdb; `local` is our 6-octet system-id.
var table = try isis_spf.compute(gpa, &db, local, now);
defer table.deinit();

// table.routes is sorted by destination system-id.
if (table.nextHop(dest)) |nh| { /* forward toward `nh` */ }
if (table.lookup(dest)) |r| { /* r.next_hop, r.metric */ }
```

`computeWith(gpa, db, local, now, .{ .require_two_way = false })` disables the
two-way check — used only by the permanent positive control.

## Test

```
zig build test-isis-spf
```

Covers: a **golden line topology** A-B-C with exact routes/next-hops/metrics; a
**4-node path** proving the first hop to a distance-3 destination is the
immediate neighbour; a **diamond** where the ECT tie-break picks a deterministic,
stable equal-cost next-hop; the **two-way check** (one-way advertisement →
no edge; add the reverse → edge appears) plus a permanent **positive control**
(disabling the check DOES use the one-way edge); **reconvergence** (a failed link
reroutes); **old-style #2** extraction; **robustness** (a malformed reachability
TLV is skipped, the valid rest still routes; a dangling neighbour is unreachable,
not a crash); **empty/degenerate** cases (empty LSDB → empty table, local absent
→ empty, local isolated → self only); **asymmetric metrics**; a **determinism**
check (identical databases → byte-identical, sorted tables); and a
`std.testing.allocator` leak check (graph, tree, intern tables all freed). Green
in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from ISO/IEC 10589 §7.2; the ECT tie-break lives in
`spf-ect`. See `/NOTICE` (no entry required — public spec). License: MIT.
