# bbs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
