# tlock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **fp12pow 8 / decrypt 11**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ The audit's `tlock` F3 lead is CONFIRMED to exist and then answered in the module's favour: `fp12Pow`'s hand-written 4-bit windowed exponentiation and its `fp12CtSelect` full-table scan produce **ZERO contexts of their own**. Everything non-zero is inherited `bls12_381`/`std.crypto.ff` substrate or this module's own already-documented "fine to leak" comparisons. ⚠ The `decrypt` target is measured but means little: a `round_signature` is drand's published per-round threshold signature, public by the time `decrypt` can run, so this is not a defect — recorded so a reader does not conclude otherwise. Its contexts do show that `bls12_381`'s `pairing.zig` branches on what it is given, and that file carries no constant-time claim anywhere in the repository.

- **2026-09-09** — LICENSE ELECTION stated: MIT. The drand upstreams this module models are
  dual-licensed Apache-2.0 OR MIT and the NOTICE named the dual licensing without ever saying
  which branch this repository takes — so the module formally stood under BOTH, and the
  Apache branch's §4(a)/§4(b) conditions were unmet. The same election `rescue` and `lnwire`
  already make, for the same reason.

- **2026-09-07** — `fuzzDecrypt` is a damage harness that applied no damage. Its flip count
  came from `smith.valueRangeAtMost(u8, 0, 6)`, a ranged draw, which reads eight octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word lands inside the
  range — so it was 0 on every replay, the corruption loop never executed once, and
  `Ciphertext.fromBytes`/`decrypt` were handed the PRISTINE ciphertext every time. The damage
  script now comes out of one `smith.slice` call as the first draw and is read with
  `testkit.fuzz.Cursor` (`NN` flips, then position/value pairs), with an eleven-script corpus
  aimed at the G2 compression flag byte, the far end of `U`, and each of `V` and `W`.
  Measured: **0 flips and exactly 1 distinct ciphertext across the corpus before; 16 flips, 11
  distinct ciphertexts, 8 decoded and 1 decrypted after.**
- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `Ciphertext.fromBytes`/`decrypt` (corrupted ciphertext bytes against a
  fixed, self-consistent beacon-shaped keypair) — `zig build check-fuzz` no
  longer names this module. No panic/OOB found; **neither breaking nor
  behavioural**.
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
