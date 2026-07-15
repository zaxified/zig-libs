# df-elect

Designated-Forwarder election + split-horizon for a link-state L2VPN fabric,
**partition-correct**. A customer site dual-homed to two edge nodes forms an
*edge segment*; for broadcast/unknown-unicast/multicast (BUM) traffic toward
that site exactly one of the two nodes must be the Designated Forwarder (DF),
chosen **deterministically from each node's own flooded link-state view** — no
second election protocol, no side-channel vote. The hard part is staying
correct when the network partitions: the segment must never see a frame
*twice* (dual-DF), never reflect a frame back into the segment it came from
(split-horizon), and never black-hole traffic for longer than a bounded
settling window (zero-DF). Model-checked in `netsim` under partition/heal fault
fuzzing with explicit zero-tolerance invariants and a bounded-badness window.

```zig
const dfe = @import("df-elect");

// A node's own view of its segment, derived purely from its link-state flood:
const view = dfe.SegmentView{
    .self_id = 3,      .self_priority = 10,
    .peer_id = 4,      .peer_priority = 20,
    .peer_alive = false, // deliberately NOT consulted by the election — see SPEC
};
const d = dfe.decide(view, ingress_segment, this_segment);
// d.is_df        — may this node forward BUM to the segment at all?
// d.allow_forward — split-horizon gate for one specific frame
if (d.is_df and d.allow_forward) forwardToSegment(frame);
```

- `decide(view, ingress_segment, this_segment) Decision` — the irreducible
  core. A **pure** function (no state, no clock, no I/O): `is_df` is the static
  total-order winner of the segment (lowest `priority`, ties by lowest node id),
  **independent of `peer_alive`**; `allow_forward` is `ingress_segment !=
  this_segment` (`null` ingress = WAN-side, always forwards). Why the election
  ignores peer liveness — the whole point of the module — is proved in `SPEC.md`
  (a backup that self-promotes on a stale peer provably breaks duplicate-freedom).
- `SegmentView` / `Decision` — the plain-data input/output of `decide`.
- `EdgeSegment` / `SegmentId` / `ElectConfig` — segment topology metadata (two
  members + per-member static priority) and the hold-timer config
  (`hello_period`, `stale_after`, test-traffic `bum_period`).
- `Hello` / `BumFrame` / `no_ingress` — the two wire messages the protocol
  floods (link-state liveness + BUM traffic) and the sentinel ingress tag.
- `DeliveryChecker` / `DfTransition` / `maxBadDfWindow` / `worstBadDfWindow` —
  the invariant machinery: a live zero-tolerance duplicate/split-horizon
  checker, and a post-run analyzer that measures the worst DF-count-!=-1 window
  against the declared bound `2·(stale_after + hello_period)`.
- `DfElect` — the real `netsim.Protocol` consumer (Hello + BUM flood calling
  `decide`). `BrokenAlwaysDf` — the deliberately-wrong positive control that
  proves `DeliveryChecker` has teeth (reuses the exact same checker type).
- `scenario` / `segments` — the shared test topology (a 3-node core triangle +
  two edge segments dual-homed to different core nodes, so a core-internal
  partition can genuinely split a segment's own two edge nodes apart).

- **Role:** util. **Platform:** any. **Deps:** `netsim` (the seeded
  discrete-event simulator + partition/heal fault fuzzer that drives the
  property test). **Concurrency:** single-owner — `DfElect` holds mutable
  per-run state; `decide` itself is pure and re-entrant.

Provenance: clean-room from the EVPN multihoming design (RFC 7432 §8.5 DF
election + §8.3 split-horizon), re-derived for a link-state (Hello-flood)
fabric that has no BGP session to lean on. No third-party source consulted or
copied.

## Verification

`zig build test-df-elect` — offline, green in Debug **and** ReleaseFast, no
leaks, **0 skipped** (the Fable core is implemented, so the two gated tests
below run for real):

- a live zero-tolerance seed sweep (partition/heal fuzzed) that finds **no**
  `DuplicateDelivery` and **no** `SplitHorizonViolation` against the real
  election, and
- a per-seed bounded-badness check that the worst observed DF-count-!=-1 window
  stays within `maxBadDfWindow` (= 440 with the default config);
- plus the positive control (`BrokenAlwaysDf` *does* trip the checker), a
  fuzzed shrink test, and unit tests for the wire codecs, the checker, and the
  window analyzer.

See `SPEC.md` for the partition-correctness argument (why the election must
collapse to the static order) and the bounded-badness accounting.
