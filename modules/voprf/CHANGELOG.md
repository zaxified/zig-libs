# voprf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-13** — **Error-set change:** every `input`/`info` longer than RFC 9497's `2^16 - 1` bytes is now `error.InputTooLong` (added to `DeriveKeyPairError`, `BlindError`, `FinalizeError`, `EvaluateError`, `FinalizeVerifiableError`, `FinalizeBatchError`, `PoprfEvaluateError`, `PoprfDirectEvaluateError`; `poprfInfoScalar` now returns `InputTooLongError![Ns]u8`); it was a `std.debug.assert` + `@intCast`, i.e. a consumer-reachable panic / ReleaseFast UB. New `max_input_length`. Per-role context objects on every suite (`OprfClient`/`VoprfClient`/`PoprfClient`, `OprfServer`/`VoprfServer`/`PoprfServer`, with `wipe`). Constant time on the new suites: NIST `encode` masks the identity verdict instead of branching (the unblinded element is secret), and the h2c select uses its own laundered mask (`p521`'s `Fe.cMov` is a jump at ReleaseFast). ctgrind harness drives all five suites (`<suite>-server|client|keygen`); fuzz harness `voprf-decode-suites`.
- **2026-11-13** — **All five RFC 9497 §4 ciphersuites.** The ciphersuite is now a comptime parameter: `Protocol(G)` (`src/protocol.zig`) over a group backend (`src/groups.zig`), instantiated as `Ristretto255Sha512`, `Decaf448Shake256` (sibling `decaf448`), `P256Sha256`, `P384Sha384`, `P521Sha512` (siblings `p256`/`p384`/`p521`), also via `Suite(.p256_sha256)`; every one in OPRF, VOPRF and POPRF mode. The top-level API is the ristretto255-SHA512 instance re-exported — source-compatible. New `src/h2c.zig`: RFC 9380 `expand_message_xmd` over any SHA-2 (multi-block), `expand_message_xof` (SHAKE256), and the NIST `hash_to_field` + simplified SWU + `hash_to_curve` (constant time: `cMov` only, no branch on the input). New batch API on every suite: `blindEvaluateBatch` (OPRF), `finalizeVerifiableBatch`, `finalizePoprfBatch` (one proof check for the batch). `generateProof` now refuses an empty or mismatched batch with `error.ProofGenerationFailed` instead of asserting. Tests: RFC 9497 Appendix A.1-A.5 (all 40 vectors) byte-exact (`src/suite_kat_test.zig`, generated from the RFC text by `tools/gen_vectors.py`), RFC 9380 Appendix J.1.1/J.2.1/J.3.1 (u, Q0, Q1, P) and K.1/K.3 (`src/h2c_test.zig`). New deps: `decaf448`, `p256`, `p384`, `p521`.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Ported to Zig 0.17.0. Test only: `@typeInfo(ErrorSet).error_set` is now `.error_set.error_names` (optional slice of names).

- **2026-10-10** — tests: deterministic fuzz driver `VOPRF_FUZZ` (`src/fuzz_test.zig`): `voprf-decode` (an accepted Element / Proof / scalar re-encodes to its input), `voprf-oprf`, `voprf-verifiable` and `voprf-poprf` (a genuine exchange equals the direct evaluation; a flipped bit in the blinded/evaluated element, the proof or the key is refused or changes the output; a proof for another blinded element or info string is refused). ReleaseSafe, clean.
- **2026-10-10** — Constant time: three zero checks on secrets used the early-exit `std.mem.allEqual`: the blind scalar in `unblind` (every Finalize) and `t = skS + m` in `blindEvaluatePoprfBatch` and `evaluatePoprf`. They are now `std.crypto.timing_safe.eql` against zero with one verdict. New `src/ctgrind_harness.zig` (targets `server`, `client`, `keygen`, ReleaseFast) taints the server key and proof nonce, the client input and blinds, and the key-derivation seed. What remains is single verdicts only: identity rejections, canonical-scalar and zero checks, itemised in `scripts/checks/ctgrind-expected.tsv`. No API change.
- **2026-10-09** — **Breaking:** dead-stack burn for every secret-handling
  entry point (`stackprobe_test.zig`: every one of the 13 probed calls left
  seed / key / blind / nonce / unblinded-element / output residue before; 0
  after). Secrets in by `*const`, secret outputs through `out`:
  `scalarFromWideBytes(&wide, &out)`, `deriveKeyPair(mode, &seed, info, &out)`,
  `generateProof(mode, &k, a, b, c, d, &r)`, `blind(mode, input, &blind)`,
  `blindEvaluate(&sk, ..)`, `finalize(input, &blind, ev, &out)`,
  `evaluate(mode, &sk, input, &out)`, `blindEvaluateVerifiable[Batch](&sk, ..,
  &proof_r)`, `finalizeVerifiable(.., &out)`, `blindPoprf(.., &blind)`,
  `blindEvaluatePoprf[Batch](&sk, .., &proof_r)`, `finalizePoprf(.., &out)`,
  `finalizePoprfUnverified(.., &out)`, `evaluatePoprf(&sk, input, info, &out)`.
  Migrated: this module's tests (via `src/test_shim.zig`, by-value test
  adapters), example, README; the one consumer, `opaque`, in the same change.

- **2026-10-05** — Mutation run: 21 of 25 killed, 4 equivalent; 3 tests added
  (`verifyProof` refuses `s + L` and a C/D length mismatch, `finalize` refuses
  a non-canonical blind, POPRF `InverseError` and the identity tweaked key).
  No code change.

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
