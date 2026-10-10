# decaf448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `DECAF448_FUZZ` (testkit) over `Element.decode` (accepted encodings re-encode canonically, a damaged one names another element), the group law on random scalars, and hashToElement/hashToScalar DST bounds. No change to the library code.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, MEDIUM):** the new ReleaseFast stack
  probe (`src/stackprobe_test.zig`) found the scalar and its inverse in dead frames after
  `scalar.invert`, and the result after `scalar.random`; both now burn their stack (`burn.zig`).
  `Element.scalarMul(a, s: *const CompressedScalar)` takes the scalar by pointer and
  `scalar.random(out, io) !void` writes into `out` (zeroed on error) — by value, the caller's frame
  kept a copy. 0 residues after, caller's frame included.
- **2026-10-06** — ADDED: the scalar field — `scalar.sub`, `negate`, `invert`
  (Fermat, constant-time), `reduce(n, bytes)`/`fromWide` (wide reduction mod `l`),
  `random(io)` (`io.randomSecure`, fail-closed) and `scalar.one`; and hashing —
  `hash.expandMessageXof` (RFC 9380, SHAKE256), `hashToElement`
  (`hash_to_decaf448`) and `hashToScalar` (RFC 9497 decaf448-SHAKE256), re-exported
  at the root. Anchored byte-exact to RFC 9380 Appendix K.6 and RFC 9497 Appendix
  A.2. Scope mvp -> core.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: `hash_to_decaf448` in Out of scope now reads "not yet — see Backlog", matching the Backlog item.
- **2026-10-05** — Mutation run: 24 of 24 killed, 0 equivalent; 1 test added
  (MAP's mod-p reduction of an input `>= p`, which no RFC 9496 B.3 vector
  reaches). No code change.

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed. `src/kat_vectors.zig` reproduces RFC 9496 Appendix B's test vectors, which the
  module's `Provenance:` statement never mentioned — it answers for the code. The record
  rests on the IETF Trust's written grant, TLP 5.0 §4.c Revised BSD, reproduced in the new
  file, rather than on the merger doctrine.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9496 Appendix B's
  published test vectors.
- **2026-07-16** — New module: decaf448 prime-order group (RFC 9496, "The ristretto255
  and decaf448 Groups", §5) over `ed448`'s edwards448 curve.
