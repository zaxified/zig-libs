# bbs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **sign 47 / proofgen 134**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. Neither `SPEC.md` nor `README.md` makes a constant-time claim, so this is a first measurement, not evidence for a sentence — stated rather than filled by inventing one. ⭐ Attributing each context to its topmost pattern-matching frame, **zero of the 181 have their leaf inside `bbs.zig`/`ciphersuite.zig`/`keys.zig`** — this module's code only ever appears as a caller. Every real branch is in `bls12_381`'s `scalar.zig`/`fp.zig` or `std.crypto.ff`, all disassembled as real `je`/`jne` rather than assumed. This is where `bls12_381`'s `ctSelect` was first disassembled to `bt`/`jae` — see that module's entry. `proofgen` taints the undisclosed messages, which is the property selective disclosure exists to protect.

- **2026-09-09** — `NOTICE` becomes a third-party attribution instead of a provenance note.
  `src/kat_vectors.zig` reproduces eleven Apache-2.0 fixture files from
  `mattrglobal/pairing_crypto` verbatim, and the old file argued they were "data, not source
  code subject to a nontrivial license obligation beyond attribution" — attribution IS the
  obligation. Sharper than "numbers": six entries carry the upstream suite's own English case
  names ("valid multi-message signature, multiple messages revealed proof"), which are
  authored prose, not a fact with one correct expression. Apache-2.0 is now reproduced in
  full per §4(a), with a §4(b) statement of what changed (JSON values to Zig declarations).
  §4(d) does not fire: the upstream ships no NOTICE.

- **2026-09-07** — Test-only, no production change: all three fuzz targets were
  replaying a single input. `fuzzProofFromBytes` opened `smith.bytes(&buf)` and then
  drew its length with `smith.valueRangeAtMost(u32, 0, 352)`; a ranged `Smith` draw
  reads eight octets as a little-endian `u64` and returns the range MINIMUM when fewer
  than eight remain, and `bytes` had already eaten them — so `len` was **0** on every
  round the ordinary lane ever ran, and `Proof.fromBytes` returned
  `InvalidProofEncoding` off the length check with the proof sitting unread in `buf`.
  Replaced with one `smith.slice(&buf)`. The other half was the corpus: none of the
  three targets had one, so outside `--fuzz` each executed exactly one input for ever
  (the all-zero buffer). A `bls12_381` point in the form these decoders accept is
  structurally unreachable from arbitrary bytes — a compressed G1/G2 string has to land
  on the curve AND in the prime-order subgroup — so the seeds come out of the module's
  own `sign`/`proofGen` with the draft's mocked scalars, plus targeted perturbations.
  Measured by the three new `corpus:` guards: Signature 5 non-zero seeds / 1 accepted,
  PublicKey 4 / 2 accepted / 2 distinct keys (the y-sign flip decodes to -P), Proof 9
  non-empty of 10 / 3 accepted / 4 `m_hat` scalars decoded. The `m_hat` and distinct-key
  counts are pinned deliberately: `accepted > 0` would survive a corpus that collapsed
  onto one frame, those numbers would not.

- **2026-08-18** — Portability fix (`check-portable`): `createGeneratorsWithSeed`'s
  generator-index loop counter `i` was `u64`, used both to index `out[i - 1]` and to
  serialize `I2OSP(i, 8)` into the wire format — the array index fails to compile on a
  32-bit target. `i` only ever ranges over `1..=count`, and `count` is already `usize`
  (it bounds the `allocator.alloc` call), so there was no actual need for `u64`; narrowed
  `i` to `usize` (`writeInt(u64, ...)` still accepts it via ordinary implicit widening).
  Pure type annotation, identical semantics on every target that already built — no new
  test. Verified: `zig build portable-bbs` no longer errors on this site (a separate,
  pre-existing `[wasi-surface]` gap — `clock_gettime`/`Environ.view`, unrelated to this
  fix — still blocks the module) and `zig build test-bbs --summary all` (42/43, 1
  pre-existing skip).
- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL: `bbs.zig` gained a
  seam test proving `calculateRandomScalars`'s `entropy.fill` draw is
  actually read (two draws of the same count from the same `io` must
  differ) and that the production `sign`/`proofGen`/`proofVerify` path
  still round-trips with freshly drawn blinding scalars. Before this, the
  blinding-scalar draw could be replaced by a constant and the suite
  stayed green — confirmed by mutating the draw (`@memset(&buf, 0x42)`)
  and watching the new test fail (41 pass, 1 skip, 1 fail), then reverting
  to green (42/43, 1 skip unchanged). Does not distinguish real entropy
  from a varying-but-weak PRNG; see the test's own comment.
- **2026-08-12** — `ciphersuite.calculateRandomScalars` draws through the new `entropy`
  module (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of
  `io.random`. Not breaking: `fill` returns `void`, so the signature still
  returns a plain `[count]Fr`. `std.Io.random` is a CSPRNG whose contract
  permits a silent fallback to a weaker seed (`std/Io.zig:2462`) and the
  default `Io.Threaded` takes it, seeding from pid + wall clock + an ASLR
  pointer. These are `proofGen`'s blinding scalars `r1,r2,r3,m̃ⱼ`;
  predicting them de-anonymises the proof and links presentations back to
  one credential, which is precisely what the scheme exists to prevent.
  `mockedRandomScalars` — the draft's deterministic mocked RNG — is
  untouched, and the KAT path never went near `io` in the first place.
- **2026-07-18** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: byte-exact
  against `mattrglobal/pairing_crypto`'s official draft-irtf-cfrg-bbs-signatures-04
  fixtures.
