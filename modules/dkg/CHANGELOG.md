# dkg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-01** — ⚠ **Breaking: GJKR step 4 (public reconstruction) and an honest-majority
  check** (review of the 2026-09-30 per-participant layer). A QUAL dealer whose Feldman
  commitments failed a party's share used to make that party abort alone: a dealer bending its
  commitments through fewer than `t` honest shares left those parties `.done` with a key nobody
  can sign for while the others aborted, and withholding the commitments vetoed the run (a
  rushing dealer could redraw `Q` on a restart). Now the failure is a public
  `feldman_complaint` that opens the share (every party verifies it: Pedersen yes, Feldman no),
  every party `reveal`s its share of each exposed dealer, and the polynomial is rebuilt from
  `t` verified shares — the outputs equal a clean run. New `Phase.feldman_complaints` /
  `.reveals`, `wire.Kind.feldman_complaint` (6) / `.reveal` (7), `MessageError.Unverified`,
  `AdvanceError.ReconstructionFailed`, `Participant.exposedDealers()`; `MissingFeldman` and
  `FeldmanCheckFailed` are gone. A clean run takes five rounds (was four). `Participant.init`
  and `Dkg.run` refuse `n < 2t − 1` (`NoHonestMajority`, `Config.honestMajority`): below it one
  dealer can fit Feldman commitments with a free constant term and choose `Q` undetected.
  Any error from `advance` now leaves the party `.aborted` (a half-done transition was
  retriable and queued frames twice), the `x_j` summands and decoded share messages are wiped.
  The oracle transcript is regenerated as 3-of-5 (was 3-of-4). Mutation run: 29 of 31
  killed, 2 equivalent; tests added for a Feldman complaint about a non-QUAL dealer, an
  allocation failure inside `advance`, and both sides of resharing's `t'`-complaints rule.
- **2026-09-30** — **Per-participant API and resharing** (maturity task A12; scope `poc` -> `mvp`).
  New `Participant` (`participant.zig`): one GJKR party as a sans-I/O state machine (`start` /
  `handle(from, bytes)` / `advance` / `takeOutgoing`) with typed wire frames (`wire.zig`), full parsing
  validation (lengths, points on the curve, canonical scalars, ids in range) and typed refusals for a wrong
  round, an unknown/mismatched/duplicate sender and anything after completion. Complaints, defenses and QUAL
  are driven by messages (`core.computeQual`). The same seed gives byte-identical outputs to the lockstep
  `Dkg.run` (tested for n in 2,3,5,7). New `ReshareDealer` / `ReshareReceiver` (`reshare.zig`): proactive
  refresh or redistribution to a new `(n', t')` committee keeping the group public key (Desmedt-Jajodia
  1997 / Wong-Wang-Wing 2002 with Feldman commitments). `commit.zig` gains `randomScalar`, `lagrangeAtZero`,
  `scaleElement`; `types.zig` gains `ScalarShareMsg`. Independent check: `tools/gjkr_oracle.py` (plain-integer
  secp256k1, from the GJKR paper) recomputes every public value of a recorded transcript and a resharing; the
  committed `src/transcript_vectors.zig` is replayed by two Zig tests. Parser fuzz harnesses for both roles.
  Not done: GJKR's public-reconstruction branch (a QUAL dealer failing the Feldman check still aborts, now
  with `culprit()` set), distributed aux generation.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **coeffs 98 / combine 5**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. No constant-time claim exists in `SPEC.md` or `README.md`; none was added — this is evidence looking for a sentence to attach to. ⭐ `combineKeyShare`'s own summation over the accepted shares measures **zero**, which is the concrete answer to the question this was built for. ⚠⚠ **45% of `coeffs`' 98 contexts are an over-taint artifact of simulating every party in one process**: `evalCommitmentAt` and `deriveGroupPublicKey` re-decode commitments that this process built moments earlier from tainted coefficients, whereas in the real protocol those bytes arrive over the wire at a party that never held the secret. That limit applies to every multi-party harness in this campaign and none of their numbers were adjusted for it. ⭐ The author also self-corrected before reporting: a first version tainted a whole `[3]?Scalar` and three of eight contexts turned out to be the OPTIONAL'S PRESENCE DISCRIMINANT, not the payload; narrowing the taint took it 8→5. Taint the payload, not the wrapper.

- **2026-09-07** — Test-only, no production change: both broadcast fuzz targets replayed a
  single input. `fuzzPedersenBroadcastDecode` and `fuzzFeldmanBroadcastDecode` each opened
  `smith.bytes(&buf)` and then drew `smith.valueRangeAtMost(u16, 0, 512)`; a ranged `Smith`
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when fewer
  than eight remain, and `bytes` had already eaten them — so `len` was **0** every round
  the ordinary lane ran, and `fromBytesAlloc` returned `InvalidEncoding` off its
  `bytes.len < 8` check with the broadcast sitting unread in `buf`. Neither had a corpus
  either, so outside `--fuzz` the one input was the zero-length slice. Both now draw with
  one `smith.slice(&buf)`. The corpus is built from the module's own `toBytesAlloc` (a
  `secp256k1` point in the form `Element.fromBytes` accepts is not reachable from arbitrary
  bytes) and includes the attack this decoder's own comment is about: a frame whose `t`
  claims `2^32-1` commitments over 107 octets, which must be refused before the `alloc`.
  Measured by the new `corpus:` guard: 8 non-empty seeds of 9, 3 accepted, **11 commitments
  decoded off the wire**. The commitment count is pinned rather than `accepted > 0` because
  the header-only `t = 0` frame is accepted while decoding no point at all.

- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-17** — New module: Secure Distributed Key Generation (GJKR) for
  `threshold_ecdsa` over secp256k1.
