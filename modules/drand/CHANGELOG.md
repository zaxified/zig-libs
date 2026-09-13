# drand — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-13** — **BEHAVIOURAL:** A1 finding F7, the JSON parsers now agree with
  drand's Go reference (`encoding/json` into `uint64`, `common.Beacon`/`client.RandomData`).
  `parseRound` accepted `{"round":"1000",…}` and verified it as round 1000, and accepted
  `{"round":1e3,…}`; Go refuses both. It refused a duplicate `round` key, which Go accepts
  keeping the last. Integer fields in `parseRound` and `parseInfo` are now read by the new
  `json_uint.Uint64` (integer token only), and both parsers keep the last of two equal keys.
  A string, exponent, fraction or negative number is `MalformedJson`. `null`, a key in
  another case and trailing bytes stay refused, stricter than Go (see `SPEC.md`).
  `scripts/modtest drand`: 61/61 (was 57/57), Debug and ReleaseFast;
  `example-apps/timecapsule` builds against the tree.

- **2026-09-10** — A1 fix campaign, 3 of 6 remaining findings closed (test
  quality only — this module has a real consumer, `example-apps/timecapsule`,
  confirmed against `build.zig`'s `example_apps` table, not only
  `module-graph`'s consumer count; P1's free-hardening license does NOT
  apply here, so nothing that changes observable parse/verify behavior was
  touched this session).

  - **F13.** Both `max_document_bytes` tests (`chaininfo.zig`, `round.zig`)
    allocate `max_document_bytes + 1` — self-referential, so widening the
    constant a thousandfold (measured: 64 KiB → 64 MiB) left both green.
    Added a direct pin (`expectEqual(64 * 1024, max_document_bytes)`) in
    both files. Measured: the new pin is 1/57 red against the widened
    constant (`expected 65536, found 65536000`), 57/57 green against the
    real one, and the old self-referential test stays green throughout —
    reproducing F13's own diagnosis exactly.

  - **F16.** The "each alone must fail too" identity-guard test's own
    comment claimed the guard was pinned per-side; mutating away either
    half (M07/M08) still leaves 42/42 green. Rewrote the comment: neither
    one-sided case is independently reachable through `verifyRoundPoints`'s
    pairing check at all — `e(identity, G2gen) = 1` equals `e(qid, pubkey)`
    only if `pubkey` is ALSO identity (`qid` is never identity for a real
    round), so there is no forged input this half of the guard alone stops
    that the pairing math does not already stop. Genuinely verified
    redundant, not a testing gap a mutation-killing test could close;
    documented as defense-in-depth instead of claiming coverage the suite
    cannot have. `rg -n "Each alone must fail too" verify.zig`: 1 hit
    before, 0 after.

  - **F18.** No test exercised a round number above 2^32 (quicknet's real
    rounds top out around 32 million); a mutation truncating
    `ciphersuite.beaconId`'s input to the lower 32 bits left 42/42 green,
    and `tlock`'s capsule format (which shares `beaconId` with this module
    "so drand and tlock can never drift on the scheme") carries the round
    as a full attacker-supplied u64. Added
    `beaconId(2^32+1000) != beaconId(1000)` directly against the real,
    imported `ciphersuite.beaconId`. Measured the test PATTERN's teeth via
    a standalone local reproduction of `beaconId` (not touching
    `modules/tlock`): the same assertion is 1/2 red against a
    `round & 0xFFFF_FFFF` mutant (the two rounds collide under it) and 2/2
    green against the real, unmutated math.

  **Left open, with reasons (not P1-eligible, no clean additive fix):**

  - **F4** (perf, 5.6x slower than drand's own Go client): the number
    belongs to `bls12_381`'s pairing/subgroup-check performance, not to
    anything in this module's own code — out of scope for a single-module
    session.
  - **F5** (G1 subgroup check paid twice on the parse+verify path):
    **the audit's own suggested fix is UNSOUND, discovered by actually
    trying it.** Implemented a private `verifyRound`-only variant skipping
    the "already checked by `parseRound`" subgroup check; it broke an
    EXISTING regression test (`W2-32: the full public path refuses the
    forged round-1000 document`), which hand-constructs a `Round` with a
    subgroup-invalid `sig_g1` WITHOUT going through `parseRound` at all —
    `Round` is a plain, caller-mutable value type, so `verifyRound`'s
    actual contract does not (and per its own doc comment, cannot) assume
    every `Round` it is handed came from this module's own parser. Reverted
    in full (`git diff` empty before committing). A safe fix needs an
    API-level distinction between a parser-verified and a caller-assembled
    `Round`, which changes public shape — a decision for the user.
  - **F7** (3 parser/reference divergences: string-typed `round` and
    exponent notation accepted here but rejected by drand's Go
    `encoding/json`; duplicate `round` key rejected here but accepted
    there, last-wins): every one of the three fixes changes what
    `parseRound` accepts or rejects for some caller-visible input —
    tightening two, loosening one — and this module has a real consumer
    (`example-apps/timecapsule/src/main.zig` calls `parseRound` directly).
    No subset of the three is purely additive.

  `scripts/modtest drand`: 57/57.

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
