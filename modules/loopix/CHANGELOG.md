# loopix — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `LOOPIX_FUZZ`: `loopix-header` (the existing `MixHeader.decode` harness, generic over its source; what decodes is in route bounds and re-encodes to the same octets) and new `loopix-inject` (24 hostile packets per run -- wild octets, damaged well-formed headers, headers naming the receiving mix, mailbox fetches and fetch answers with a lying count -- into the relay handlers of `FifoMix` and `Loopix`, direct and provider topologies; no panic, every delivery names a sent id). New `src/fuzz_test.zig`. No change in `src/` outside tests.
- **2026-10-04** — **Phase 2: providers, sender-chosen delays, end-to-end anonymity,
  n−1 detection; scope poc → core as a simulator (user decision, reverses 2026-09-30;
  re-surveyed against A. Piotrowska's mix network simulator).**
  `LoopixConfig.providers` / `PROVIDER_CFG` / `providerScenario`: providers forward
  into the first layer and keep mailboxes that clients pull at a fixed period with
  fixed-size answers. `sender_chosen_delays`: holds drawn by the sender and carried in
  the header (`MixHeader.has_delays/delays/recipient`; **wire format grew 39 → 72
  octets**). `measureEndToEnd` + `SenderBound`: sender anonymity composed backward
  through all layers (measured worst over 20 seeds: 5.78 of 8 senders / 0.286; FIFO
  1.00; no cover 2.00). `Attack` + loop watching: an attacker blocking a mix is caught
  during the attack on 10/10 seeds, no false alarm on 20 clean seeds, and nothing is
  caught without sender-chosen delays. `TrafficStats`. `LoopixConfig.validate`
  (`init` now returns `InitError`).
  **Review (Sonnet, adversarial): 2 HIGH fixed** — L-01 (predates today): `measure`
  divided tied departures' mass by k twice (1/k² instead of 1/k), so a batch mix could
  pass `max_link_prob`; L-02: a mix acted on a header that did not name it (an all-zero
  header indexed `route` past its end). MED fixed: fallback count in `SenderResult`,
  the no-false-positive test now proves the detector watched and saw loops return,
  delivery exactly once to the addressed client, mailboxes only from the last layer to
  the recipient's own provider, malformed packets dropped and counted instead of
  failing the run. **Mutation:** 24 mutants, all killed after 6 new tests.

- **2026-09-07** — `fuzzMixHeaderDecode` had only ever decoded the empty slice. It drew its
  bytes with `smith.bytes(&buf)` and then took a length from
  `smith.valueRangeAtMost(u8, 0, 64)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes` had already
  consumed them — so `len` was 0 on every input and `MixHeader.decode` refused on its
  `payload.len < wire_len` line, with the header sitting unread in `buf`. Now one
  `smith.slice(&buf)` call, plus a ten-header corpus built through the module's own `encode`
  (the round-trip header, the `n_hops == max_layers` boundary, two truncations, the invalid
  `MsgKind`, the over-capacity `n_hops`, `hop > n_hops`, an over-long payload, an all-zero
  header and the empty one). Measured: **0 of 10 seeds non-empty and 0 headers decoded
  before; 9 of 10 non-empty, 4 decoded and 12 routed hops after.** The guard pins the hop
  count rather than just `decoded`, because an all-zero header is legally decodable here
  (kind `.real`, `hop = 0`, `n_hops = 0`).

- **2026-08-18** — Portability fix (`check-portable`), two test sites in
  `adversary.zig`: both looped a `u64` index to index the fixed test array `deps[i]`
  (and, in one case, `deps_sorted[i]`), which doesn't fit `usize`'s slice-index
  requirement on a 32-bit target — the `deps.len`/`deps_sorted.len` comparison bound is
  the actual TSV-flagged error. Neither loop var needed `u64` range (`tr`'s `arr`/`dep:
  Time` and `id: u64` params all widen implicitly from `usize`), so narrowed both to
  `usize`, matching the sibling test already written that way. Compile-only, identical
  semantics on every target that already built. Verified: `zig build portable-loopix`
  and `zig build test-loopix --summary all` (27/27) both green.
- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Loopix (Piotrowska et al.,
  USENIX Sec 2017) / Nym — no interop KAT exists for the anonymity metric (design
  reference, not a test anchor).
- **2026-07-17** — New module: Loopix mixnet (Piotrowska et al., USENIX Security 2017 —
  Nym's design) — Poisson mix + cover traffic over Sphinx, model-checked in netsim
  against a global-passive-adversary anonymity invariant.
