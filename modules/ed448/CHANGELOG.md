# ed448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL: both `x448.zig` and
  `ed448.zig` gained a seam test proving their `KeyPair.generate`'s
  `entropy.fill` draw is actually read (two key pairs from the same `io`
  must differ) and that the production path still round-trips end to end
  (X448: a two-sided DH shared-secret agreement; Ed448: sign/verify).
  Before this, either curve's signing/DH key draw could be replaced by a
  constant and the suite stayed green — confirmed by mutating both draws
  simultaneously (`@memset(&seed, 0x42)`) and watching both new tests fail,
  each on its own file's distinctness assertion (`x448.test...`/
  `ed448.test...`, 54 pass, 2 fail), then reverting to green (56/56). Does
  not distinguish real entropy from a varying-but-weak PRNG; see the tests'
  own comments.
- **2026-08-12** — Both `KeyPair.generate` entry points — `x448.KeyPair.generate` and
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
- **2026-07-18** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8032 §7.4's published test vectors.
