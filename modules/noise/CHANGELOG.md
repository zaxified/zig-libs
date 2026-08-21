# noise — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-21** — **Breaking:** `CipherState.encryptWithAd`/`decryptWithAd` and
  `SymmetricState.encryptAndHash`/`decryptAndHash` gained `error.BufferTooSmall`. The
  output-buffer preconditions were `std.debug.assert`, which compiles out in `ReleaseFast`
  and `ReleaseSmall` — the modes this ships in — leaving a caller-supplied `out` slice to
  be written past in exactly the builds where it matters. The module already published
  `BufferTooSmall` and used a runtime check for the same class elsewhere; these four sites
  were the inconsistency. Callers that only `try` are unaffected; an exhaustive `switch`
  over the error set needs the new tag.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 5869's
  published test vectors.
- **2026-07-10** — New module: The generic Noise Protocol Framework (noiseprotocol.org,
  spec rev 34).
