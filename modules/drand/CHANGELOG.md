# drand — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Tests:** `fuzzParseVerify` parsed nothing but the empty
  document. It filled a buffer with `smith.bytes` and then drew the length with
  `valueRangeAtMost(u16, 0, buf.len)`; a ranged `Smith` draw reads eight octets
  as a little-endian u64 and returns the range MINIMUM when fewer remain, so
  the length was 0 on every input and both `parseInfo` and `parseRound` were
  handed `""` for the life of the harness. It also had no corpus, so that empty
  document was the only input it ever ran. Second defect: the buffer was 512
  octets against `quicknet_info_json`'s 504, and `chaininfo.zig`'s own
  `quicknet_info_json ++ " trailing"` negative fixture is 513 — over the
  buffer, which `Smith.slice` reads back as EMPTY rather than as a long seed.
  Now one `smith.slice(&buf)` draw over 2048 octets and a 16-seed corpus of
  whole documents (both genuine chains, the audit-F1 forged chain-hash/key
  pair, an odd-length signature hex, 96 hex octets that are not a G1 point, 200
  levels of nesting). Measured: 0 chain infos, 0 public keys, 0 rounds and 0
  signatures decoded before; 2 / 2 / 4 / 4 after. The corpus guard pins the
  decoded POINTS rather than a parse count, since the two things the verify
  path stands on are the G2 key and the G1 signature.

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
