# df-elect — spec

Partition-correct Designated-Forwarder election + split-horizon for a
link-state L2VPN fabric, verified in `netsim`. Usage: see ./README.md.
Provenance (clean-room from RFC 7432): see ./README.md; no third-party terms to
restate in /NOTICE.

## The problem

A customer site dual-homed to two edge nodes (an *edge segment*) needs exactly
one of those nodes to be the Designated Forwarder for BUM traffic toward the
site, or the site receives every broadcast frame twice. EVPN gets this "for
free" from BGP: every PE runs iBGP, advertises an Ethernet A-D per-ES route,
and BGP's own session liveness + route-withdrawal machinery *is* the "who is
currently reachable for this ES" view; the DF is then a deterministic ordinal
over the ordered list of PEs with an active advertisement (RFC 7432 §8.5). A
link-state fabric has **no BGP session to lean on** — it floods plain
link-state Hellos (the same primitive SPF uses) and must derive the equivalent
"list of live members for this segment" guarantee, and the partition-correctness
that goes with it, purely from that flood. That derivation is this module's
contribution.

Two failure modes a correct election must bound:

- **Dual DF** — both edge nodes believe they are DF → the segment receives
  every BUM frame twice.
- **Zero DF** — neither believes it → a silent black hole (worse than a
  duplicate: nothing signals the failure).

Neither can be avoided with *zero* settling time (a genuinely partitioned node
cannot instantly learn that fact), so both get a bounded window. What must be
avoided **outright, always** is split-horizon reflection — an unbounded window
there is a live forwarding loop into the customer's own site.

## Design & invariants

### The election rule, and why it is the only safe one (`election.zig`)

`decide` elects, as DF, the winner of the segment's **static total order**:
lowest `priority` value, ties broken by lowest node id. Crucially `is_df` is
**independent of `peer_alive`** — a node's DF status does not change when its
peer looks stale. This is not a simplification; it is forced. Consider the
two-member truth table, whose one free cell is the backup (order-loser) when its
peer looks stale:

|              | owner (order winner) | backup (order loser) |
|--------------|----------------------|----------------------|
| peer alive   | DF (wins)            | not DF (loses)       |
| peer stale   | DF (sole member)     | **?** — the one choice |

The intuitive "I'm the only member I can see, so I'm DF" fill (symmetric,
EVPN-style re-election) is **provably wrong** against the zero-tolerance
duplicate invariant:

- **Startup race.** The first network-side BUM is originated before the first
  Hello round completes (any config where traffic can precede liveness
  convergence — here `bum_period` (40) < `hello_period` (50)). It floods to
  *both* members while both still see `peer_alive = false`; under the symmetric
  fill both self-promote and both deliver → duplicate, on every schedule, no
  partition needed.
- **Heal race.** After a partition heals, a BUM frame and the peer's next Hello
  race across the healed cut on the same links; nothing orders them. A frame
  that beats the Hello reaches the backup while its view still says stale (→
  self-promoted) and the owner while the owner is DF (the owner is DF in *every*
  view) → duplicate. The window is small, but the invariant has **zero**
  tolerance — "small" is still a loop seed.

**Generalizing:** `decide` is a pure function of the *local* view, and around a
heal every (owner-view, backup-view) ∈ {alive, stale}² combination is
simultaneously reachable while one frame reaches both members. Duplicate-freedom
therefore requires: for every such pair, **at most one member answers DF**. The
owner must answer DF even when it sees the peer as stale (otherwise a real peer
death black-holes the segment *forever* — an unbounded zero-DF window). So the
backup may answer DF in **no** reachable view → `is_df` cannot depend on
`peer_alive` → the election collapses to the static total order. This is exactly
what EVPN's BGP-fed DF list provides: the liveness feed only ever *removes* the
dead, it never lets the survivor side invent a second concurrent forwarder for
the same reachable frame. A Hello flood cannot distinguish "peer dead" from
"peer unreachable-from-me", so the only view-derived fact both members can never
disagree about is the static order itself.

**The trade is availability, not correctness.** While the owner is partitioned
from a frame's origin, the segment receives nothing on the backup's side — a
black hole bounded by the partition's own duration. That is the same trade
single-active EVPN multihoming makes, and the only one available without a
second protocol (fencing/consensus) layered on top.

### Split-horizon (`election.zig` `Decision.allow_forward`)

Independent of election state, by design: a frame may be forwarded toward
`this_segment` unless it *ingressed* from `this_segment` (`ingress_segment ==
this_segment`). `null` ingress (WAN-side, no source segment) always forwards.
`types.no_ingress` (`0xFFFF_FFFF`) compares unequal to every real segment id by
construction, so it needs no special case. This must not depend on `is_df` or
liveness — it is the local-bias backstop (RFC 7432 §8.3) that holds even during
a transient dual-DF window, with **zero** tolerance.

### Two invariants, checked two different ways (`checks.zig`)

1. **Zero-tolerance, live** via `netsim`'s `Protocol.checkFn` (a violation halts
   the run and captures the exact reproducer trace). Never allowed, not even for
   one tick: `error.DuplicateDelivery` (same BUM frame delivered twice to the
   same segment) and `error.SplitHorizonViolation` (frame delivered back into
   its ingress segment). See `DeliveryChecker` — the accumulate-in-handler,
   assert-in-`check` pattern netsim's own `LoopyForward` uses; the *same*
   checker type is shared verbatim by the real protocol and the positive
   control, so a violation either trips is provably the same check.
2. **Bounded-badness, post-run** over the full DF-status transition log:
   `worstBadDfWindow` reconstructs each segment's DF-count-over-time step
   function and returns the worst "count != 1" interval; the caller compares it
   to `maxBadDfWindow`. This is a *liveness* property — the transient window is
   legal by design, so flagging it as a live `checkFn` error would be wrong; it
   is measured, not asserted inline.

**The bound.** `maxBadDfWindow(cfg) = 2·(cfg.stale_after + cfg.hello_period)` =
**440** with the default config (`stale_after = 170`, `hello_period = 50`).
Reasoning: the stale side needs up to `stale_after` ticks to notice a severed
peer (by construction a single dropped Hello must not flip liveness); a
just-healed side needs up to one more `hello_period` for the next Hello to land;
a flat 2× multiplier budgets core flood-propagation delay plus one confirmation
round-trip so a multi-hop core doesn't need re-derivation. Under the static-order
rule the *actual* behavior is far tighter — dual-DF never occurs (only the owner
ever answers DF), and zero-DF occurs only from t=0 until the owner's first
`decide` call (at latest one `hello_period` after start), so partitions and
heals cause no DF transitions at all. The bound is the SPEC ceiling the harness
enforces, deliberately looser than the measured behavior.

## Threat model / out of scope

Not a security boundary; the "adversary" is timing and topology (arbitrary
partition/heal schedules under `netsim`'s fault fuzzer). Guarantees, for a
two-member edge segment: zero duplicate delivery, zero split-horizon reflection,
and a DF-count-!=-1 window within `maxBadDfWindow`, under the modeling
assumptions below. Out of scope: segments with >2 members (RFC 7432's general
`DF = list[(ordinal) mod N]`); the LSA-flood/hold-timer control-plane details
beyond the abstract `stale_after` liveness threshold; multi-segment split-horizon
label interactions; and node authentication / Byzantine members (a lying Hello
is out of the threat model — the flood's *content* is trusted).

**Malformed frames are NOT trusted, though** — that is a separate axis from
Byzantine content, and it is enforced. `tagOf` / `Hello.decode` /
`BumFrame.decode` return `DecodeError!T` (`Truncated` / `InvalidEncoding`) and
bounds-check before indexing; a 1-byte frame used to panic (`index out of
bounds: index 5, len 1`) and an undefined tag byte used to panic on
`@enumFromInt`.

Length validity is only half of it. `origin` and `seq` are untrusted *values*,
not just untrusted lengths: `origin` indexes the `node_count*node_count`
`hello_last_seq`/`bum_seen` arrays and `seq` is a shift amount into a u64
bitmask. A **perfectly well-formed** 13-byte frame carrying
`origin = 0xFFFFFFFF` was an out-of-bounds write, and one carrying `seq = 64`
was an `@intCast` panic. A bounds-checked decoder cannot catch either — it does
not know the topology — so both are range-checked in
`DfElect.handleHello`/`handleBum` against the live node count before use.

Policy: drop the frame and increment `DfElect.malformed_dropped`. Dropping is
the correct data-plane response (an edge switch discards a runt, it does not
answer it) and there is no control-plane NAK to send; counting keeps a
sustained fault visible rather than silent. In the harness every frame comes
from our own `encode`, so the count must stay 0 — asserted across a seed sweep.
`BrokenAlwaysDf` is hardened the same way, so that a decode panic can never
masquerade as the checker firing.

**Scaffold simplifications (deliberate, orthogonal to the election).** Liveness
is a boolean `peer_alive` derived from a `stale_after` threshold over the last
Hello time, not a full LSA age/refresh model. BUM traffic is timer-generated by
the harness (`bum_period`), bounded to <64 originations per origin so the
per-origin dedup can be an allocation-free 64-bit bitmask (`bum_seen`); a real
data plane would use a windowed hash set. A node crash→restart re-runs `onStart`
and can stack a second Hello/BUM timer chain — a benign harness artifact
(traffic-generator only, never reaching the `bum_seq < 64` assert across the
sweeps); it is not part of `election.decide` and cannot mask a real invariant
failure (an assert trips loudly in Debug; a real duplicate trips the live
checker first).

## Verification

`zig build test-df-elect` — green in Debug + ReleaseFast, no leaks, **0
skipped** (`gate.fable_core_implemented = true`, so the two gated tests below run
for real, not as `SkipZigTest`):

- **real — zero-tolerance seed sweep** (gated): the real `DfElect`, fuzzed with
  partition/heal faults across seeds 1..300, trips *neither* zero-tolerance
  invariant. Independently sanity-checked by temporarily swapping in the
  symmetric "self-promote on stale peer" fill → this test fails with
  `DuplicateDelivery` at seed 1 (the startup race), confirming the rule is
  load-bearing and the test has teeth.
- **real — bounded-badness** (gated): across seeds 1..100 every run completes
  `.ok` and its worst DF-count-!=-1 window stays ≤ `maxBadDfWindow` (440).
- **positive control** — `BrokenAlwaysDf` ("everyone is DF, no split-horizon")
  *does* trip `DeliveryChecker`, on a single seed and across a 100-seed sweep;
  plus a fuzzed **shrink** test that minimizes a failing schedule to a
  still-reproducing core. Proves the checker has teeth independent of the
  election.
- **units** — `Hello`/`BumFrame` wire round-trips, `EdgeSegment` membership
  helpers, the `DeliveryChecker` state machine (duplicate/split-horizon/sticky/
  reset), and `worstBadDfWindow` against hand-written synthetic transition logs
  (zero/dual/late windows, teeth beyond the bound, per-segment isolation).

## Backlog / deferred

- Segments with more than two members (the general RFC 7432 §8.5 ordinal DF).
- A real LSA age/refresh liveness model in place of the abstract `stale_after`
  threshold, if this graduates from a property-test jewel into a fabric
  component.
- Retune `maxBadDfWindow` against the measured settling behavior once a
  multi-hop-core deployment profile exists (today it is a deliberately loose
  ceiling).

## Status

`any · util · single_owner` + dep `netsim`, model_after "EVPN ESI/DF-election +
split-horizon (RFC 7432), link-state derived" — canonical source is `pub const
meta` in src/root.zig.
