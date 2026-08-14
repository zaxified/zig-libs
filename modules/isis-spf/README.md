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

2. **Two-way connectivity check (ISO §7.2.8.2).** The link A–B is admitted to
   SPF **only if A advertises B and B advertises A**. A one-way advertisement —
   a half-formed adjacency, or a neighbour that just left whose LSP is still in
   the database — is dropped. This is the classic SPF-stability rule that keeps a
   stale one-directional link from poisoning the tree. The clause admits the
   link; it does not merge the two metrics (see "Metric handling").

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

IS-IS metrics are per-interface and **directional**: ISO/IEC 10589 Annex C.2.4
Step 1 relaxes `dist(P,N) = d(P) + metric_k(P,N)` where "metric_k(P,N) is the
cost of the link from P to N as reported in P's Link State PDU". So each
admitted direction becomes its own `spf-ect` arc (`Graph.addArc`) carrying that
endpoint's own advertised metric — the two directions of one link may differ,
which §7.2.8.2 permits in as many words ("routes may be asymmetric"). Nothing
is merged into a single per-link weight; no such weight exists, because which
direction of a link a path traverses is decided by the tree being computed.
`RouteTable.asymmetric_links` reports how many links differ (relevant to SPB,
which *requires* symmetry), and `Options.reject_asymmetric` (default `false`)
turns that into an error for callers who need it. A zero metric is clamped to 1
(`spf-ect` rejects a zero weight, which could form a predecessor cycle).
Old-style #2 metrics use the low 6 bits of the default-metric octet.

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
check (identical databases → byte-identical, sorted tables); a
`std.testing.allocator` leak check (graph, tree, intern tables all freed); and
an **FRR anchor** — a 5-router topology with an asymmetric metric and an
equal-cost tie, run once through a real `isisd` and frozen (see "Anchored"
below). Green in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from ISO/IEC 10589 §7.2; the ECT tie-break lives in
`spf-ect`. See `/NOTICE` (no entry required — public spec). License: MIT.

## Anchored (2026-08-02) — FRR, capture-and-freeze

Historically every expectation above was **ours**: hand-built topologies,
routes we believed ISO/IEC 10589 §7.2 requires, tests and implementation
sharing one reading of one document. The sibling wire modules (`isis`,
`isis-adj`, `isis-dis`, `isis-flood`, `isis-lsdb`) are checked against
Wireshark's dissector, but a sibling's anchor does not transfer, and a
dissector only grades bytes on a wire — an SPF *result* has no wire form.

The owner's call on 2026-08-02 was **option B**: not vendoring FRR's
GPL-licensed `tests/topotests/isis_topo1` fixtures, but running FRR ourselves
and capturing its own output for a topology this task built from scratch.
`frr` was added to `VM_DEBIAN_PACKAGES` (`scripts/vm/manifest.sh`), the
Debian VM lane (`scripts/vm/`) re-provisioned, and a real `isisd` 10.3 —
five instances, one per network namespace, joined by veth, real p2p
adjacencies, asymmetric per-interface metrics on one link, one deliberate
equal-cost tie — computed SPF once. That output is now frozen into two
permanent tests in `src/root.zig` (`"FRR anchor: …"`), whose shared comment
block quotes the exact `vtysh` commands, FRR's version, and the relevant
printed lines.

**History of the r3 row, because it is the point of the anchor.** FRR reaches
r3 at cost 15 via r5. The original undirected engine answered 30 via the r4
branch — wrong next hop, double the cost — and the transcript first sat above
an assertion of *our* 30, which turned a live external disagreement into a
certificate that the disagreement was intended. `55752d4` stopped that: the
divergence itself became the assertion, and `computeWith` refused such a
database outright. Both are now superseded by the actual fix — `spf-ect` grew
directed arcs, this module adds one per advertised direction, and **all five
rows match FRR**, r3 included (15, next hop r5). The tests assert the
agreement, and additionally assert that the old wrong shape (30 via r4/r2) is
not what comes back.

This is a one-shot capture: the test above asserts against literals and does
not boot a VM, run FRR, or touch the network. Licence note: FRR is
GPL-2.0-or-later and this repo is MIT; nothing here is FRR source or FRR's
own test fixtures, and GPLv2 §0 restricts the covered Program, not a routing
table it computed for a topology we authored — the same reasoning already
applied to goaccess/Wireshark captures elsewhere in this repo. See the test's
own comment for the full citation.

What is still not FRR-anchored: the golden-line/4-node-path/diamond/
two-way-check/reconvergence/old-style-#2/robustness/degenerate/determinism
tests above remain self-authored (SELF in the anchor record in `SPEC.md`) — they were not
individually re-derived against FRR captures, only the one dedicated FRR
topology test was added. LAN pseudonodes and multi-level leaking remain out
of scope (`SPEC.md` §6) and so are not anchored either, by construction
rather than by gap.
