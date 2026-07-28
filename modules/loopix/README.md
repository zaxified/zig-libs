# loopix

The **Loopix mixnet** (Piotrowska–Hayes–Elahi–Meiklejohn–Danezis, USENIX
Security 2017 — the design underpinning **Nym**), built and model-checked inside
`netsim`. Loopix gives message-level unlinkability against a **global passive
adversary** that watches every link. Its contribution is *not* cryptography —
its packet is **Sphinx**, which this repo already ships (`sphinx`, reused here);
its contribution is the **anonymity strategy**:

- a continuous-time **Poisson mix** — each mix holds every arriving packet an
  *independent exponential* delay before forwarding. The exponential's
  memorylessness makes a packet's departure time statistically independent of
  its arrival time, so the adversary cannot correlate a mix's outputs back to
  its inputs by timing;
- **Poisson cover traffic** — loop (send-to-self) and drop chaff that keeps
  every mix's anonymity set large and detects active (n−1) attacks;
- a **stratified** L-layer topology — every message traverses exactly one mix
  per layer, so all traffic shares the relay set and is mutually
  indistinguishable at the link level.

**Status: complete.** Everything that *defines and measures* anonymity is
real, and the irreducible *mixing* core itself is now implemented too (Part 2,
`gate.fable_core_implemented = true`) — see "What's real" below and SPEC.md's
"Part 2 result" for the measured anonymity separation.

```zig
const loopix = @import("loopix");

// Run a mixnet in netsim, then measure anonymity against a global passive
// adversary that links with the mix's own delay law (Kerckhoffs):
var mix = try loopix.Loopix.init(gpa, loopix.DEFAULT_CFG, seed);   // real Poisson mix
defer mix.deinit(gpa);
var gr = try netsim.run(gpa, .{ .seed = seed, .scenario = loopix.scenario,
    .protocol = mix.protocol(), .until = 2000 }, .{});
defer gr.trace.deinit();

const anon = try loopix.measure(gpa, mix.transcript(),
    .{ .exponential = 40.0 });        // link with the Poisson hold law
if (!anon.holds(.{})) return error.AnonymityBroken;  // min set large + no target pinned
```

## What's real

- The stratified topology + route selection (`routing.zig`, including a
  **real `sphinx` onion** round-trip that carries `(next_hop, delay)` per hop
  and peels end-to-end — the proof the Sphinx substrate works as a mix
  packet); the fixed-size mix-header codec (`types.zig`); the **entire
  anonymity measurement** (`adversary.zig` — effective anonymity set `2^H` +
  linking probability under the mix's delay law); and a deliberately-broken
  **FIFO positive control** (`FifoMix`) the harness flags hard.
- **The three irreducible mixing functions in `mixing.zig`** —
  `sampleExpDelay` (memoryless integer delay, the discrete geometric law),
  `scheduleRelease` (the Poisson mix's per-arrival hold), `nextCover` (the
  Poisson cover process) — are implemented for real
  (`gate.fable_core_implemented = true`), and the test that drives the real
  `Loopix` mix through netsim now runs (not skipped): the real Poisson mix
  satisfies `AnonymityBound` across a seed sweep while the FIFO and no-cover
  controls fail it. See SPEC.md's "Part 2 result" for the measured numbers.

## API

- `Loopix` — the real `netsim.Protocol`: exponential per-hop holds + Poisson
  cover. `FifoMix` — the constant-delay, no-cover positive control (same
  topology/routing/transcript, order-preserving hold) that the harness flags.
- `measure(gpa, transits, model) AnonymityResult` — the global-passive-adversary
  anonymity metric. `AnonymityResult.holds(AnonymityBound)` — does every real
  target hide in an effective set ≥ `min_effective_set` AND stay below
  `max_link_prob`? `DelayModel` = `.exponential` (Poisson mix) / `.constant`
  (FIFO) — the mix's own hold law, which the adversary links with.
- `Transit` — one completed pass of a packet through one mix (the adversary's
  raw material: timing only; `id`/`kind` are the harness's oracle labels).
- `LoopixConfig` — layers/width/clients + `mean_delay` (1/μ), `cover_mean_interval`
  (1/λ), test-traffic `real_period`, and the control's `fifo_delay`.
  `MsgKind` (`real`/`loop_cover`/`drop_cover`), `MixHeader`, `pickRoute`,
  `pickDestClient`, `HopInstruction`.
- `sampleExpDelay` / `scheduleRelease` / `nextCover` — the mixing core
  (implemented). `Prng` / `CoverEvent` — the seeded randomness they use.

- **Role:** util. **Platform:** any (pure simulation). **Deps:** `netsim` (the
  seeded discrete-event simulator that runs the mixnet + observes link timing)
  and `sphinx` (the mix packet substrate). **Concurrency:** single-owner.

Provenance: clean-room from the Loopix paper (Piotrowska et al., USENIX Security
2017); Sphinx packet reused from this repo's `sphinx` module. No third-party
source consulted or copied.

## Verification

`zig build test-loopix` — offline, green in Debug **and** ReleaseFast, no leaks,
all pass, no skips. Highlights:

- a **real Sphinx onion** built for a 3-mix stratified route and peeled
  hop-by-hop, each hop recovering its `(next_hop, delay)` (the packet-substrate
  proof);
- the **FIFO positive control** run end-to-end through netsim, its transcript
  fed to `measure`: every real target is **pinned** (link probability → 1,
  effective set → 1) and the anonymity invariant **fails** — proving the harness
  has teeth;
- synthetic `measure` unit tests separating a **well-mixed** transcript (passes)
  from the **order-preserving** (FIFO) and **cover-starved** (thin-pool) failure
  modes;
- the **real `Loopix` mix**, driven through netsim across a seed sweep,
  satisfies `AnonymityBound` while the FIFO/no-cover controls fail it under
  identical measurement — see SPEC.md's "Part 2 result" for the numbers.

See `SPEC.md` for the threat model, the anonymity invariant + how the adversary
measures linking advantage, the Fable-vs-mechanical split, and the scoped-out
increments.
