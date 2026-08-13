# minisign — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Licensing record. Not breaking and not behavioural — no code
  changed, only what the module says about one function. `isPrintableComment`
  is a port of `is_printable` from jedisct1/minisign — its own doc comment has
  said so all along ("Faithful port of minisign.c's `is_printable`") while the
  module was recorded as clean-room from format facts. So the module was found
  to carry extracted upstream material and now attributes it: a new
  `modules/minisign/NOTICE` reproduces minisign's ISC terms in full and is
  listed in root NOTICE §1. The condition on a consumer is ISC's only one, keep
  the notice with the code. The `src/root.zig` module-level doc comment that
  had reclassified the same function as "a genuine design reference" — the one
  category that carries no condition — and the README's `Provenance:` line were
  corrected to match. The merger-doctrine argument the module used to
  rest on (a thirty-line control-character predicate has few other reasonable
  expressions) is not disowned; it is recorded in the NOTICE as the argument
  not taken, because a file arguing no-attribution beside code that calls
  itself a port is a contradiction a reader has to resolve.

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
