# minisign — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — `KeyPair.generate`'s Ed25519 seed now comes from `entropy.fill`
  (`std.Io.randomSecure`) instead of `io.random`. **Not breaking:** the
  signature is unchanged and so is the on-disk format. New dep:
  `entropy`.

  This is the long-term signing key for every release the key will ever
  sign, and `generate` returns a `KeyPair` with no error channel, so a
  silent degrade to `std.Io.random`'s fallback seed (a zeroed buffer plus
  an ASLR pointer, the pid and a clock — `std/Io.zig:2462`) would be
  invisible and permanent. The `key_number` draw immediately above it
  deliberately stays on `io.random`: it is published in the clear in every
  `.pub` and `.sig` file, so it is an identifier, not a secret.

- **2026-08-06** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: live against
  the real `minisign` 0.12 binary (`minisign -V`).
- **2026-07-28** — New module: sign/verify in the minisign file format over Ed25519, both
  legacy (`Ed`) and prehashed-BLAKE2b (`ED`), including scrypt-encrypted
  secret keys and the trusted-comment global signature. Byte-exact
  against artifacts produced by the reference `minisign` binary.
