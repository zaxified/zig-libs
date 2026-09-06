# isis-adj — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
