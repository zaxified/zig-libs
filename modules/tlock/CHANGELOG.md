# tlock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: `kat_test.zig` gained "entropy seam: randomSigma
  really draws, and two encryptions of one message differ". **Neither
  BREAKING nor BEHAVIOURAL** — no production code changed; this adds the
  coverage that was missing for the draw the entry below made fail-closed.
  Every other test here feeds `encrypt` a FIXED `sigma` on purpose (that is
  what makes the drand interop vector reproducible), so nothing ever looked
  at a drawn one: hardcoding `randomSigma`'s buffer to a constant left all
  33 tests green. The new test asserts two draws differ AND that two
  encryptions of one message to one round differ in `U`/`V`/`W` and still
  open under the genuine round-1000 signature — verified by planting
  `@memset(&buf, 0x5a)` after the draw: 33/34, exactly this test red. Its
  stated limit: it catches a constant and an ignored `io`, not a
  weak-but-varying PRNG; which vtable slot the bytes come from is pinned in
  `entropy`'s own suite.
- **2026-08-12** — `ciphersuite.randomSigma` draws through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so the signature is unchanged and still
  returns a plain `[block_bytes]u8`. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`)
  and the default `Io.Threaded` takes it, seeding from pid + wall clock +
  an ASLR pointer. A guessable `sigma` opens a timelock ciphertext before
  its round, which is the single property the construction sells, so the
  draw now fails closed. The KAT path is untouched — `encrypt` still takes
  `sigma` as an explicit parameter, and every fixture supplies its own.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact bidirectional
  interop against a genuine `drand/tlock` Go `tle` ciphertext.
