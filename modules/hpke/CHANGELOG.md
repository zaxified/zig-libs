# hpke — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Provenance corrected: README and `NOTICE` both claimed no
  third-party implementation had been consulted as a design reference, while
  `src/schedule.zig:99`, `:1024` and `SPEC.md` all cite `jedisct1/zig-hpke`
  by name. It was consulted — the 2026-07-21 "I5" diff against it is what
  found the ReleaseFast-stripped `std.debug.assert` behind `Context.seal`/
  `.open` and produced `error.InvalidLength` (`15c6e89`). Recorded now with
  its licence (MIT). Documentation only; no code change, nothing owed —
  a design reference carries no condition.

- **2026-08-13** — Each KEM's `generateKeyPair` now mints its keypair the way RFC 9180 §4
  defines it — `GenerateKeyPair() = DeriveKeyPair(random(Nsk))` — with
  `random` being `entropy.fill` (`std.Io.randomSecure`). **Not breaking:**
  no signature changes, no wire byte changes, and the KAT-driven
  `deriveKeyPair`/`*Deterministic` entry points are untouched. New dep:
  `entropy`.

  Previously `X25519Kem` forwarded to `std.crypto.dh.X25519.KeyPair.
  generate` and the two NIST KEMs called `P{256,384}.scalar.random(io,
  .big)`. All three take their randomness from `std.Io.random`, whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`);
  the default `Io.Threaded` takes it, seeding from a zeroed buffer plus an
  ASLR pointer, the pid and a clock. That is the sender's ephemeral key in
  every `encap`/`setup*S`/`seal*` call, i.e. the key the whole
  `shared_secret` rests on, and `generateKeyPair` returns a `KeyPair` with
  no error channel to report a degraded draw on.

  The X25519 KEM could have kept std's shape and swapped only the draw
  (`KeyPair.generateDeterministic` is public); the NIST KEMs could not,
  because `scalar.random`'s rejection loop is std-internal and takes the
  `io` itself. Rather than re-implement that loop, all three now go
  through this module's own `deriveKeyPair` — which means the keygen path
  is covered by the RFC 9180 A.1.1/A.3.3 vectors for the first time
  (`KeyPair.generate` and `scalar.random` never were). `P384Kem` gains no
  such anchor, since Appendix A publishes no P-384 vector.

  `mls` inherits the change through `S.Kem.generateKeyPair` (its
  `UpdatePath` leaf key) without any edit of its own.

- **2026-08-11** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  9180's published test vectors.
- **2026-07-28** — `mode_psk`, `mode_auth` and `mode_auth_psk` are now anchored to RFC
  9180's own Appendix A vectors (A.1.2/3/4 for X25519, A.3.2/3/4 for
  P-256) instead of only to this module's round-trip; the implementations
  needed no correction. New single-shot wrappers `sealPsk`/`openPsk`,
  `sealAuth`/`openAuth`, `sealAuthPsk`/`openAuthPsk` alongside the
  existing `sealBase`/`openBase`. **BREAKING (behavioral):** a
  psk-bearing mode now rejects a PSK shorter than `Nh` with
  `error.PskTooShort` — deliberately stricter than the RFC's
  `VerifyPSKInputs` pseudocode, on the grounds that §5.1.2's "MUST have
  at least 32 bytes of entropy" cannot hold for a PSK shorter than 32
  bytes, and length is the only checkable projection of that
  requirement. Appendix A's own PSK vectors satisfy the floor.
