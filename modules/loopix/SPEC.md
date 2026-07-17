# loopix — SPEC

The Loopix mixnet (Piotrowska et al., USENIX Security 2017 — Nym's design), as a
model-checked `netsim` consumer; see [README.md](README.md) for purpose and API.
No NOTICE entry: clean-room from the paper, and the Sphinx packet is this repo's
own `sphinx` module (merger doctrine — implementing a published design is not
derived from anyone's code).

## Design

Loopix decomposes into two utterly different halves, and this module is built
around that seam:

- **The packet (reused, not built here).** Per-hop unlinkability is Sphinx, and
  `sphinx` already ships it. A Sphinx onion is fixed-length, peels one layer per
  hop, reveals to each hop only its successor + an opaque per-hop payload, and is
  bit-unlinkable across hops. `routing.zig`'s `sphinxRoundTrip` test builds a
  *real* onion for a stratified route with `(next_hop, delay)` in each hop's
  opaque payload and peels it end-to-end — the standing proof the substrate
  works as a mix packet. Reuse caveats (both immaterial to anonymity): `sphinx`
  is secp256k1 + 1366-byte + ≤37-hop (Lightning's parameters, vs Loopix/Nym's
  Curve25519), and Loopix's sender metadata rides inside BOLT#4's opaque payload
  unchanged. The netsim hot loop carries a *modeled* fixed-size header
  (`types.MixHeader`) instead of a real onion, because the anonymity metric is
  purely about timing and the adversary is denied content by construction — the
  modeled header is faithful to the onion's *observable* behaviour (constant
  length, one-mix-per-layer route, per-hop unlinkability).

- **The strategy (the actual subject).** A continuous-time **Poisson mix** (each
  mix holds every arrival an independent exponential delay), **Poisson cover
  traffic**, and a **stratified** topology. This is what makes the whole thing
  unlinkable against a global passive adversary, and it is what this module
  builds, gates, and model-checks.

Layout mirrors the repo's scaffold→gate→positive-control→harness pattern
(`df-elect`, `raft`): `types.zig` (config + header codec), `routing.zig`
(stratified routes + the Sphinx proof), `mixing.zig` (**the gated core**),
`adversary.zig` (**the anonymity invariant + measurement — the real content**),
`protocol.zig` (the `netsim.Protocol` consumers + the FIFO positive control),
`gate.zig` (the one switch).

## Threat model — the anonymity invariant, and how it is measured

**Adversary: a global passive adversary (GPA)** — the standard Loopix/Nym model.
It observes the *timing* of every packet on every link, but (i) cannot read
packet contents (Sphinx layer-encryption makes each hop's bytes unlinkable to
the next — the `id` a `Transit` carries is a harness-only oracle label the
adversary is never handed), and (ii) cannot distinguish real from cover traffic
(chaff is bit-indistinguishable and constant-length — the `kind` label is
likewise withheld). What it CAN do, at each mix `M`, is see the multiset of
arrival times and the multiset of departure times and try to match them: *did
output `d` carry the same packet as input `a`?* That is the anonymity game.

**The metric (`adversary.measure`).** The adversary knows the mix's strategy
(Kerckhoffs), so it links using that strategy's own hold distribution as its
likelihood kernel. For a target that arrived at `M` at `a*`, it assigns each
departure `d` a weight `kernel(d − a*)` (causal: `0` for `d < a*`) and
normalizes to a posterior over "which departure is my target". From that
posterior, two INDEPENDENT quantities are measured, because Loopix's guarantee
has two independent parts:

1. **Effective anonymity set** `2^H`, `H = −Σ pⱼ·log₂ pⱼ` — the Serjantov–Danezis
   metric, the effective number of departures the target could equally be. This
   is what **cover traffic** buys: no chaff ⇒ the pool empties ⇒ the crowd
   shrinks to 1. Measured as a **worst-case min** over all real targets.
2. **Linking probability** `p(d*)` — the posterior mass on the target's TRUE
   departure `d*` (ground truth the harness knows, the adversary does not). This
   is what the **memoryless Poisson hold** buys: a smooth exponential spreads the
   posterior across the in-flight pool, so no single departure concentrates
   mass. Measured as a **worst-case max** over all real targets.

**The invariant (`AnonymityBound`)** requires BOTH: `min_effective_set ≥ k_min`
AND `max_link_prob ≤ p_max`. A single pinned message fails it. Cover transits are
never scored as *targets* (anonymity is only defined for real traffic) but they
DO swell each mix's departure pool — so disabling cover shrinks every real
target's crowd, exactly as in Loopix.

**Why the positive controls fail it, deterministically and robustly.** The
adversary links with each mix's OWN law, so the failures are not statistical
flukes:

- **FIFO / constant-delay mix** (`FifoMix`): every packet's hold is exactly `Δ`,
  so scored with the constant (spike) kernel the posterior lands entirely on the
  one departure at `a* + Δ` — the true one. `p(d*) = 1`, effective set `= 1`, on
  *every* target, on *every* seed, no partition needed. It fails BOTH clauses.
  This is the canonical anonymity-breaking mix, and the harness flags it hard.
- **No-cover mix** (a Poisson mix with the cover process disabled): the hold is
  still memoryless, but at a low real-traffic rate a mix often holds a *single*
  packet, so the causal candidate set is `{d*}` — effective set collapses to 1
  even though `p(d*)` looks unremarkable. It fails clause 1. (Demonstrated by
  `adversary.zig`'s synthetic thin-pool test; the running no-cover control needs
  the gated core, so it activates with clause-1 teeth once the flag flips.)

The separation is **1.0 vs ~1/pool, not 0.6 vs 0.4** — there is no seed on which
FIFO "accidentally mixes", so no threshold tuning can make the teeth flaky. The
metric is a pure function of a concrete transcript, itself a pure function of the
netsim seed, so a seed sweep just averages independent draws (LLN). This
robustness is the design's whole point and the reason the harness — not the
gated core — is the Fable-worthy work.

## The Fable boundary — and an honest tier call for the core

**Gated core (`mixing.zig`, three `@panic` stubs):**

- `sampleExpDelay(prng, mean) Time` — a **memoryless integer** delay draw. The
  one real subtlety: netsim time is integer ticks, and a floored *continuous*
  exponential (`@intFromFloat(-mean*ln u)`) is NOT memoryless — the discrete
  memoryless law is the **geometric** distribution. This is the single place a
  filler-in could quietly get the anonymity-relevant detail wrong (flagged in
  the code).
- `scheduleRelease(prng, cfg, arrival) Time` — the Poisson mix's per-arrival
  hold/release decision (`arrival + sampleExpDelay(_, mean_delay)`).
- `nextCover(prng, cfg) CoverEvent` — the Poisson cover process (exponential
  inter-arrival + loop/drop choice).

**Honest tier call: the gated core is Opus-doable, not genuine-Fable.** Having
designed it: all three functions are textbook inverse-CDF exponential sampling +
scheduling. Given this harness — which states *exactly* what "correct" means (a
run that satisfies `AnonymityBound`) — a strong Opus pass would implement them
correctly. The one genuine subtlety (discrete geometric vs floored exponential)
is called out inline; a careful Opus handles it, and even a slightly-wrong hold
distribution would likely still clear a loose threshold. The **Fable-worthy
intellectual content is this scaffold pass**: the anonymity invariant, the GPA
threat model, the spike-vs-smooth-kernel insight that makes FIFO fail
deterministically, and the robust min/max aggregation that keeps the metric from
being flaky. That matches the repo's refined Fable-tier heuristic for
protocol-soundness veins (the scaffold holds the value; the core-impl is Opus).
Dispatch Part 2 (fill the three stubs + retune `AnonymityBound` against the real
mix's measured behaviour + flip the gate) to **Opus**.

## Scoped out of Phase 1 (documented increments)

- **Full clients/providers/PKI.** Real Loopix has clients attach to *providers*
  (store-and-forward mailboxes) and a PKI distributing mix keys/epochs. Phase 1
  uses plain client nodes and deterministic routing.
- **Sender-chosen per-hop delays.** Production Loopix samples all hop delays at
  the *sender* and encodes them in the Sphinx header (the mix is stateless); the
  sim uses the equivalent *mix-chosen* continuous-time variant (each mix samples
  its own hold), identical for anonymity. `routing.HopInstruction` already shows
  the sender-chosen shape in the real-onion test.
- **n−1 active-attack detection.** Loop cover exists here as pool-filling chaff;
  using dropped loops as evidence of an active adversary is not modeled.
- **End-to-end (composed) anonymity.** Phase 1 measures *per-mix* anonymity (the
  quantity the mixing strategy directly controls). Composing the per-hop
  posteriors across all L layers into a single source→destination linking bound
  is a follow-on.
- **Retuning `AnonymityBound`.** The defaults (`min_effective_set = 2`,
  `max_link_prob = 0.5`) are loose Phase-1 placeholders; the real core's Part 2
  pass sets them against measured behaviour (like `df-elect`'s `maxBadDfWindow`).

## Verification

`zig build test-loopix`, green in Debug **and** ReleaseFast, no leaks, 18 tests
(17 run + 1 gated skip):

- **Sphinx substrate:** a real onion for a 3-mix route peels hop-by-hop,
  recovering each hop's `(next_hop, delay)`, final hop flagged.
- **Anonymity harness teeth (no core needed):** synthetic transcripts separate a
  well-mixed pool (holds the invariant) from FIFO order-preservation and
  cover-starved thin pools (both fail); plus cover transits shown to enlarge a
  real target's crowd without being scored.
- **FIFO positive control end-to-end:** run through netsim, its transcript scored
  by `measure` — `max_link_prob > 0.9`, `min_effective_set < 1.5`, invariant
  fails; and a seed sweep under fuzzed faults keeps flagging it.
- **Gated:** the real `Loopix` mix's cross-seed anonymity test SKIPs until
  `gate.fable_core_implemented` flips (its call sites into `mixing.zig` are still
  type-checked).
