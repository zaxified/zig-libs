# drand — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-07** — A1 security audit, the four HIGH findings fixed. **BEHAVIOURAL, not
  breaking, plus new error values:** `parseInfo` now refuses a `/info` whose `hash` is not the
  chain hash the document's own contents determine — drand's `chain.Info.Hash()`, exposed as
  `computeChainHash` — with `error.ChainHashMismatch` (a genuine quicknet hash over quicknet-t's
  key was accepted and 5/5 foreign rounds then verified "as quicknet"); refuses `period == 0`
  with `error.InvalidPeriod` (it was a division by zero — SIGFPE in ReleaseFast — in
  `expectedRound`, which is now total as well: period 0 answers 1, the `+1` saturates) and a
  `period` past `u32` with `NumberOutOfRange`. `parseRound` refuses the identity signature
  (`InvalidPoint`). `roundPath`/`latestPath` return `PathError` and refuse a non-hex chain hash
  (`InvalidChainHash`) — the value goes into a URL. `ChainInfo`/`Round` buffers past their
  lengths are zero, not stack leftovers. Tests: a G2 key on the curve but outside the subgroup
  → `PublicKeyNotInSubgroup` (the check could be deleted or weakened to on-curve with the suite
  green); the chain-hash formula against three live chains; randomness compared in full (a
  flip in the last or a middle byte — the check was pinned on one nibble); the fuzz harness
  over the verify path rebuilt around a deterministic `checkFixture` whose empty-input case is
  the positive control, so it runs on every gate run (the audit measured that neither of the
  old harness's assertions was ever reachable). The quicknet-t fixture carried a groupHash that
  was not that chain's; replaced by the live document, in one place.
- **2026-08-06** — Security audit: `verifyRound` accepted a malleated beacon signature
  (a missing subgroup check on the signature itself), which could let two honest
  verifiers derive different "verified" randomness for the same round; fixed, along with
  two further findings.
- **2026-07-24** — New module: drand randomness-beacon client core — chain-info + round
  codec + BLS-verify a round signature against the chain public key (`bls12_381`,
  quicknet/unchained-G1 ciphersuite reused from `tlock`).
