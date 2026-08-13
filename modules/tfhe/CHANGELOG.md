# tfhe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- The entropy seam is now typed instead of documented. **BREAKING:** every
  production key-generation and encryption entry point — `lweKeyGen`,
  `glweKeyGen`, `lweEncrypt`, `glweEncrypt`, `glweEncryptZero`,
  `ggswEncryptPoly`, `ggswEncryptScalar`, `bootstrapKeyGen`,
  `keySwitchKeyGen` — takes `io: std.Io` in place of `random: std.Random`
  and draws through `entropy.SecureSource`, the fail-closed adapter over
  `std.Io.randomSecure`. The old
  signatures survive under `…ForTest` names for the draw→value KATs and the
  seeded end-to-end tests; a caller that was passing a real CSPRNG adapts by
  passing its `std.Io`, and a caller that was passing `DefaultPrng` no longer
  compiles, which is the point.

  Why the parameter type and not a doc sentence: `std.Random` is a vtable, so
  `DefaultPrng.init(0).random()` is indistinguishable from a CSPRNG at the call
  site, and a predictable stream does not weaken this scheme — it removes it.
  With `a` and `e` known, `b = ⟨a,s⟩ + μ + e` is a linear equation in `s` and
  `dim` ciphertexts recover the secret key by Gaussian elimination; the
  bootstrap and key-switch keys, which a deployment *publishes* to the
  evaluator, are GGSW/GLWE encryptions of that same key. A `std.Io` cannot be
  handed a `DefaultPrng`, which is what this change bought — but it does **not**
  make a degraded source inexpressible — `std.Io.failing` (`std/Io.zig:2509`)
  is a std-provided `Io` whose `random` returns zeros. That is why the draws now
  go through `entropy.SecureSource`; see `CONVENTIONS.md` §2.2.
  Two tests pin the shape: one reads the signatures at comptime, one shows the
  `std.Io` path actually draws (two keys from one `io` differ) and round-trips.
