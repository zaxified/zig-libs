# isis-spf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **`fuzzComputeOverLsdb` built both of its LSPs with a ZERO-octet
  TLV region, so the SPF it exists to fuzz ran over a graph with no edges.**

  It opened with `smith.bytes(&input_buf)` followed by an inline
  `smith.valueRangeAtMost(u16, 0, input_buf.len)` slice. `bytes` consumes
  `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as a
  little-endian u64, returning the range minimum when fewer remain — so the region
  length was 0 for every input a seed can carry. Both stages the comment describes
  were nullified at once: the front door got `insert("")`, and the traversal stamped
  an empty region into two well-formed LSPs. Neither the Extended IS Reachability
  extraction nor the two-way check nor the shortest-path search ever saw an edge.
  The harness came back clean every time, which is exactly why nothing noticed.

  One `smith.slice` draw, the buffer raised 256 → 512 to match the region size the
  module's own `insertReachLsp` fixtures build, and a nine-entry corpus of #22 TLV
  regions written as the hex `addExtendedIsReach` emits. ⭐ The corpus had to be
  designed around a property of the harness: it stamps the *same* region into both
  originators (0xA and 0xB), so a region naming only the neighbour is asymmetric by
  construction and yields nothing — only a region naming **both** produces a two-way
  link. That is now stated in the corpus rather than left to be rediscovered.

  Measured 2026-09-07: `driveSpf("")` — the collapsed harness, pinned as an
  executable "before" — returns **1 route**, the local self route, and did so for
  all nine seeds. After: **8 routes across the corpus, 2 seeds producing more than
  the self route**, and the rest exercising refusals (a lying TLV length and a
  metric at `max_link_metric` now reach the paths that reject them). The
  route count is the discriminating number: `compute` over two LSPs with empty
  regions succeeds every time, so "the harness returned cleanly" was never evidence
  of anything.

- **2026-09-03** — Drift re-audit (last audited `d163578`, ~719 lines since). Two fixes,
  two mutations, two red.
  - ⛔ **Expired LSPs were routed over.** `computeInternal` takes `now`, forwards it to
    `isis-lsdb` — whose `EntryView.remaining_lifetime` is aged to exactly that `now` — and
    then never read it. The only filter was `ev.bytes.len == 0`, which catches an entry
    `Lsdb.tick` has already reduced to a header; `tick` is caller-driven and wholly
    independent of `compute`, so between two ticks, or in any caller whose `now` runs ahead
    of its last tick, a dead LSP is still fully present. Measured on a two-router database
    inserted with lifetime 5 and computed at `now = 1000`: the LSDB reported
    `remaining_lifetime = 0` for both entries with 40 bytes each, and SPF returned 2 routes
    over them. Remaining Lifetime is the ONLY mechanism IS-IS has for retiring an LSP whose
    originator can no longer speak — a purge needs the originator or a neighbour to send
    one — so a one-shot injected LSP did not have to be maintained to keep attracting
    traffic. Now excluded per ISO/IEC 10589 §7.3.17, together with `is_purge`.
    ⚠ `isis-sim`, the harness that drives this module, calls `compute(gpa, …, 0)` with `now`
    hardcoded to 0, so every simulated SPF runs where nothing has aged: it could not see this.
  - ⛔ **The pseudonode ORIGIN filter's test had stopped discriminating.** Deleting
    `lsp.lsp_id[6] != 0` left the whole suite GREEN. The fixture's own 25-line justification
    argued from a mechanism the directed rewrite (`6634cbb7`) DELETED — a "canonical
    undirected weight" picked from the lower-to-higher system-id advertisement (`lo_hi`) —
    and under the directed engine the forged arc simply was not on the root's path. Rewritten
    with a third router behind the DIS so the forged advertisement lies on the root's own
    path: the corruption is a silently WRONG metric (200 → 101), not a missing route.
  - The min-merge fixture advertised `{20, 5}` in that order only, so "keep the minimum" and
    "keep the LAST" gave the same answer and a keep-last mutation stayed green — while the
    comment claimed the test excluded "the last or the first value seen". It excluded the
    first. Both orders are now driven.
- **2026-09-03** — Docs, and one of them was a fabricated citation. `max_link_metric`'s doc
  quoted RFC 5305 §3 as *"A value of 'MaxLinkMetric' ... MUST NOT be advertised"*. The RFC
  says no such thing and never uses that token; its actual sentence is *"If a link is
  advertised with the maximum link metric (2^24 - 1), this link MUST NOT be considered
  during the normal SPF computation."* The invented half **inverts** the rule — the whole
  mechanism is that the link stays advertised for traffic engineering, which the very next
  sentence of the same comment already said. `scripts/gen/check-citations.py` had been reporting
  the MISMATCH. Also: the `MAX_PATH_METRIC` deferral was justified by "not a fixture that
  can be driven RED at a defensible size" — a 300-router line reaches 5,016,386,986, past
  the ceiling by 754,974,122, in 22 ms, and is now a test; and the RFC's own rationale for
  the ceiling is a 32-bit accumulator, while `Route.metric` is a `u64`. The deferral stands,
  with a true reason: what is left is a tie-break/conformance difference above 2^32 that
  needs clamping during relaxation, which lives in `spf-ect`.
- **2026-09-03** — Docs, README. It documented `computeWith(…, .{ .require_two_way = false })`
  as the way to disable the two-way check — a call that has not compiled since the field was
  removed (an earlier audit removed it so no production caller could disable the ISO
  §7.2.8.2 guard by accident, and `root.zig` carries a permanent test asserting its absence),
  in the one document a caller reads first. And it promised
  `path(A→B) == reverse(path(B→A))` **"by construction"**, which the directed engine made
  conditional on a symmetric-metric fabric — the module's own frozen FRR anchor test asserts
  the counter-example in the green suite (from r1, r3 costs 15 via r5; from r3, r1 costs 30
  via r4). `Options.reject_asymmetric` defaults to `false`. The consumer `spbfib` states its
  whole design on that congruence and cannot set the option, since it consumes a finished
  `RouteTable`; the requirement is now written where its reader meets it.
- **2026-09-03** — The example's fourteen checks were `std.debug.assert`, compiled OUT in
  ReleaseFast — and `scripts/test.sh` RUNS examples in the lane's own optimize mode, one of
  which is ReleaseFast. Measured with the two-way check disabled in a scratch copy of the
  module: Debug panicked, ReleaseFast printed "E unreachable" for a topology in which E is
  reachable and exited 0. Now a `must()` helper that panics with the failing check's text in
  every mode; verified red in both.
- **2026-08-07** — ⏪ *Backfilled 2026-09-03; this entry was missing, and it is the largest
  behavioural change in the module's history.* **The engine went from UNDIRECTED
  SINGLE-WEIGHT to one directed arc per admitted direction, each at its own advertised
  metric** (`55752d45`, `6634cbb7`, alongside `spf-ect` gaining `addArc`). Computed route
  metrics and next-hops change for any asymmetric database. **Source-breaking:**
  `Options.require_two_way` was removed (the two-way check is no longer switchable from
  outside), and `Options.reject_asymmetric` was added, defaulting to `false`.

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on FRRouting
  `isisd` (`isis_spf.c`) + `spf-ect` (design reference, not a test anchor).
- **2026-07-24** — New module: Compute the IS-IS shortest-path forwarding table from an
  `isis-lsdb`.
