# ibe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Records that the drand upstreams behind section 5's constants are dual
  Apache-2.0/MIT and that this repository elects MIT, pointing at `modules/tlock/NOTICE` as
  the authoritative record. Nothing changed about the constants; a reader of this file no
  longer has to go elsewhere to find out whether a choice was ever made.

- **2026-09-07** — Fuzz reach: `fuzzDecrypt` never corrupted a ciphertext. Its flip loop
  opened `smith.valueRangeAtMost(u8, 0, 6)` as the harness's FIRST draw; a `Smith` ranged
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when
  fewer remain, and the target had no corpus, so outside `--fuzz` the one input it ever
  ran was empty and the flip count was **zero every time**. Every ordinary `zig build
  test` decrypted the pristine ciphertext successfully: not one corrupted octet reached
  the compressed-`U` decode boundary or the Fujisaki-Okamoto consistency check the
  harness's own comment says it is biased toward. Measured 2026-09-07: 1 round, 0 octets
  corrupted, 0 refusals of any kind. The flip loop is gone: a ciphertext is 160 octets off
  the wire, so it is drawn with one `smith.slice`, and the corpus is built at run time
  from this module's own `encrypt` — the pristine ciphertext, `U`'s compression flag
  cleared, its infinity flag set over a non-zero body, one octet of `U`'s x flipped, one
  octet of `V` flipped, the last octet of `W` flipped, 160 zeroes, and the empty input.
  A corpus guard builds from the SAME place the harness does and pins 7 non-empty, 4
  refused by the `U` decode, 4 parsed and 1 decrypted.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `Ciphertext.fromBytes`/`decrypt` (corrupted ciphertext bytes against a fixed
  self-issued PKG keypair) — `zig build check-fuzz` no longer names this
  module. No panic/OOB found; **neither breaking nor behavioural**.
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
