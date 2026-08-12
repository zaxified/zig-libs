# signal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New `x3dh.generateKeyPair(io)` — the module's single source of private
  keys — and all four production draws now use it: the X3DH ephemeral
  `EKA` (`x3dh.initiateUnverified`), the signed prekey `SPKB`
  (`x3dh.generateSignedPreKey`), and both Double Ratchet DH keys
  (`ratchet.State.initAlice`, `ratchet.dhRatchet`). It is
  `std.crypto.dh.X25519.KeyPair.generate` verbatim with the seed taken
  from `entropy.fill` (`std.Io.randomSecure`) instead of `io.random`.
  **Not breaking:** `fill` returns `void`, so no signature changed. New
  dep: `entropy`.

  `std.Io.random` is a CSPRNG whose contract permits a silent fallback to
  a weaker seed (`std/Io.zig:2462`) and the default `Io.Threaded` takes
  it, seeding from a zeroed buffer plus an ASLR pointer, the pid and a
  clock. For X25519 the seed IS the secret key, so that fallback would
  have produced the identity, prekey, ephemeral and ratchet keys directly.
  The ratchet key is the sharper of the two: its freshness is the entire
  post-compromise-security claim, and a predictable one locks nobody out.

  This does NOT touch the KAT seam `CONVENTIONS.md` §2.2 names. Signal's
  published vectors are reproducible because `xeddsa.sign` takes its
  randomness `z` as a **parameter**, which the tests fill from
  `io.random`; no vector depends on where a keypair's seed came from.
