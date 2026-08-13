# bbs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
