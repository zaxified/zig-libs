# voprf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Test-only, no production change: `fuzzElementFromBytes` had never
  executed its own byte draw. The mode selector `smith.valueRangeAtMost(u8, 0, 2)` came
  BEFORE `smith.bytes(&buf)`, and a ranged `Smith` draw returns the range MINIMUM unless a
  whole eight-octet word lands inside the range - so with no corpus the mode was 0 on every
  input the ordinary lane ever ran, and the only thing `Element.fromBytes` ever saw was the
  all-zero canonical identity encoding, which it refuses. The `smith.bytes` branch was
  dead. The byte draw now comes first and the mode's `else` leaves the drawn or seeded
  octets alone. Both targets also gained a corpus: a ristretto255 element in the form
  `fromBytes` accepts is not reachable from arbitrary bytes (RFC 9496 Decode rejects most
  32-octet strings), so the accepted frames come from the module's own `toBytes`, and each
  element seed carries the `u64` word the mode knob reads - without it the knob would be
  dead on a corpus replay and would overwrite every element frame with zeroes before
  `fromBytes` saw it. Measured by the new `corpus:` guard: 2 elements accepted, **2 of them
  distinct** (G and 2*G), all three mode branches exercised; 2 proofs accepted. The
  distinct count is pinned rather than `accepted > 0` because a corpus collapsed onto one
  repeated base point would satisfy an acceptance check.

- **2026-08-23** — **Breaking:** `blindEvaluateVerifiableBatch` and
  `blindEvaluatePoprfBatch` gained `error.EmptyBatch` and
  `error.MismatchedLengths` in their respective error sets. Both used to
  guard `blinded.len >= 1 and evaluated_out.len == blinded.len` with
  `std.debug.assert`, then feed both caller-supplied slices to a
  `for (blinded, evaluated_out)` loop. ReleaseFast compiles the assert AND
  the loop's own runtime length-match check out together, so a mismatched
  `evaluated_out` read or wrote past its own bounds in the build that ships.
  Found by an audit sweep for this shape.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9497 Appendix
  A.1's published test vectors.
- **2026-07-12** — New module: (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497),
  ristretto255-SHA-512 ciphersuite, all three modes: OPRF (base), VOPRF (verifiable) +
  POPRF (partially-oblivious).
