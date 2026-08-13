# ibe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-12** — `ciphersuite.randomSigma` draws through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so the signature is unchanged and still
  returns a plain `[block_bytes]u8`. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`)
  and the default `Io.Threaded` takes it, seeding from pid + wall clock +
  an ASLR pointer. `sigma` is the FullIdent transform's only secret input,
  so IND-CCA rests entirely on its unpredictability; it now fails closed.
- **2026-08-12** — `Scheme.setup`'s master secret key is covered by the same change one
  layer down — it comes from `bls12_381`'s `Fr.random`, which moved to
  `entropy.fill` in the same sweep. See that module's changelog.
