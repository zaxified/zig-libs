# isis-adj — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-13** — **BREAKING:** A1 findings F5, F7, F12, F13, F14 (round-2 decision:
  safe default plus a switch). New `RejectReason.holding_time_too_short` and
  `DownReason.circuit_id_changed` break an exhaustive `switch`; no in-repo consumer.
  F7: `start()` over a live adjacency now reports `transition`, and
  `adjacency_down = .stopped` from Up; it used to drop it silently.
  F12: `rxHello` returns `send_hello` on every state change
  (`Config.triggered_hello`, default on), as FRR's triggered IIH.
  F13: a neighbour `holding_time` below `Config.min_neighbor_holding_time` (default 1,
  so only 0) is rejected; 0 used to form and expire the adjacency in one instant.
  F14: the recorded neighbour's IIH with another Local Circuit ID deletes the adjacency
  (`Config.detect_circuit_id_change`, default on).
  F5: `Config.accept_without_neighbor_fields` (default off) runs RFC 5303 §3.2 b)'s
  table for a peer whose TLV 240 carries no neighbour fields; off keeps the
  Initializing ceiling.

- **2026-09-10** — A1 fix campaign, three of the remaining MED/LOW findings (module
  still has zero in-repo consumers, verified against `build.zig`'s `example_apps`
  table too — P1 applies without reservation). Additive only, no `RejectReason` /
  `Effect` shape change. (1) **F4** — RFC 5303 §3.2's table has EVERY "received
  three-way state = Down" cell as action "Initialize": "no event is generated...
  set to Initializing" (verified against the RFC text directly; FRR agrees,
  `adj_state` stays UP on that action). Before the fix, `applyState` fired
  `adjacency_down = .neighbor_restarted` on every Up-losing transition regardless
  of cause, so a peer's ordinary "I restarted, I'm Down" self-report looked
  identical to a genuine loss of echo confirmation. A peer that stops echoing us
  while still reporting Initializing/Up still reports `adjacency_down` — only the
  RFC's silent case is now silent. (2) **F8** — a neighbour may split its
  announced Area Addresses across more than one #1 TLV (FRR compares across all
  instances); `RxHello` gained an additive `neighbor_area_addresses_more: []const
  []const u8 = &.{}` field (default empty, no existing caller affected) and
  `rxHelloBytes` now walks the whole TLV stream once collecting every #1 instance
  (bounded to 8, fail-closed beyond that) instead of taking only the first via
  `findFirst`. A neighbour whose shared area sat behind a non-matching first TLV
  was previously rejected `.area_mismatch`. (3) **F16** — `Config.max_area_addresses
  = 0` (the ISO 10589 §9.6 wire shorthand for 3) rejected every real neighbour,
  because `isis.header.decode` normalizes a received 0 to 3 before `rxHelloBytes`
  ever sees it, but the locally configured value was compared literally
  unnormalized. Normalized at the single comparison site; a genuine (non-shorthand)
  disagreement is still rejected exactly as before.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-07** — A1 security audit, the three HIGH findings fixed. **BREAKING for an
  exhaustive `switch` on `RejectReason`:** two new variants, `.neighbor_mismatch` and
  `.neighbor_up_while_down`. (1) RFC 5303 §3.2 discard: a TLV 240 whose neighbour block
  names another system, or our system on another extended local circuit id, is now
  rejected whole before any mutation — it used to be processed as "not an echo", so one
  frame naming a third system dropped an Up adjacency to Initializing, set the hold to the
  sender's `holding_time` and overwrote the recorded extended circuit id. A hello whose
  block echoes our system-id with a WRONG extended circuit id is therefore now a reject,
  where it previously parked the adjacency at Initializing. (2) The one-neighbour lock
  (`.other_neighbor`) applies only while the adjacency is Up; at Initializing a candidate
  is replaced by the next hello from a different system. The 2026-08 rule locked on the
  first hello heard, so one unauthenticated frame with `holding_time = 65535` kept the real
  neighbour out for 65 535 units. (3) RFC 5303 table cell (local Down, received Up) is
  honoured: a fresh circuit refuses a neighbour that already claims Up
  (`.neighbor_up_while_down`) instead of going Up on one frame — the restart /
  unidirectional-link case the handshake exists for. Also: `rxHelloBytes` walks the whole
  TLV stream (`isis.tlv.count`) so a TLV lying about its length behind the 240 fails the
  PDU (was accepted, raised the adjacency); the fuzz harness draws one `smith.slice` and
  is seeded with the Wireshark-anchored hellos plus the two refused shapes (200 010
  unseeded runs had never produced a TLV 240); regression tests for the hold expiring at
  Initializing and for a missing/malformed Area Addresses TLV being a mismatch (both
  guards could be weakened with the suite green); README's reject-rule list catches up
  with the code; SPEC no longer claims `start` primes `next_hello_due = now`. Note on the
  2026-08-06 entry below: those fixes landed 2026-08-08 and added three `RejectReason`
  variants (`.other_neighbor`, `.max_area_mismatch`, `.area_mismatch`) that were BREAKING
  for exhaustive switches too.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  5303 §3.1.
- **2026-07-24** — New module: IS-IS point-to-point adjacency state machine (ISO 10589
  §8.2 + RFC 5303 three-way handshake).
