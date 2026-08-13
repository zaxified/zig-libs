# ibe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: `kat_test.zig` gained "entropy seam: randomSigma
  really draws, and two encryptions of one message differ". **Neither
  BREAKING nor BEHAVIOURAL** — no production code changed; this adds the
  coverage that was missing for the draw the entry below made fail-closed.
  Until now nothing in the suite looked at a drawn `sigma`: hardcoding
  `randomSigma`'s buffer to a constant left all 42 tests green (the
  master-key draw one layer down, in `bls12_381`, was already caught). The
  new test asserts two draws differ AND that two encryptions of one message
  under one identity differ in `U`/`V`/`W` and still decrypt — verified by
  planting `@memset(&buf, 0x5a)` after the draw: 42/43, exactly this test
  red. Its stated limit: it catches a constant and an ignored `io`, not a
  weak-but-varying PRNG; which vtable slot the bytes come from is pinned in
  `entropy`'s own suite.
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
- **2026-07-18** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against a
  genuine `drand`-produced ciphertext, via the shared `tlock` parameterisation.
