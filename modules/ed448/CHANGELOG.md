# ed448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- Both `KeyPair.generate` entry points — `x448.KeyPair.generate` and
  `ed448.KeyPair.generate` — draw their seed through the new `entropy`
  module (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of
  `io.random`. Not breaking: `fill` returns `void`, so both still read
  `generate(io: std.Io) KeyPair` and no caller changed. `std.Io.random` is
  a CSPRNG whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`) and the default `Io.Threaded` takes it, seeding from
  pid + wall clock + an ASLR pointer. The seed *is* the private key in both
  cases (X448's scalar; Ed448's `s` and nonce `prefix` are both derived
  from it), so a degraded draw is a recoverable DH secret or a forgeable
  signature. `generateDeterministic` / `create` are untouched — a
  caller-supplied seed stays a caller-supplied seed.
