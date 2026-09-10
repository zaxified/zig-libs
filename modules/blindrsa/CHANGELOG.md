# blindrsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, audit findings B1/B2/B3/B4/B7/B8/B10/B11/B14/B15
  closed (13/18 open findings; B6/B9/B16/B18 left open, B13/B19 found already fixed
  elsewhere — see `~/CML/20260901-zig-libs-audit/A1/blindrsa.md`'s Dispozice section
  for the full breakdown). **Breaking:** `blindSign` no longer `catch unreachable`s
  `rsa.rsasp1`'s `error.FaultDetected` (a Debug/ReleaseSafe panic, UB in ReleaseFast,
  on a CRT fault the sibling `rsa` module's own Bellcore/BDL self-check legitimately
  raises) — it now returns the ALREADY-documented `error.SigningFailure` instead
  (B1). `FinalizeError` gains `error.InvalidContext`: a `Context.modulus_len` that
  does not match `pk` (previously `std.debug.assert`, compiled out together with the
  following slice's bounds check in ReleaseFast — an out-of-bounds read) is now a
  typed error (B4). `Context` gains `pub fn deinit()`, wiping the secret `r_inv`
  (B7, previously undocumented how a caller was meant to clear it). Ten new tests
  close B2 (sampleFe's uniformity, not just its range), B3 (the mandatory self-check
  rejects a pk with the wrong e — independent of B1's rsa-level fault), B10
  (prepareRandomize's full 32-byte entropy, not just "differs somewhere"), B11
  (finalize rejects an over-long blind_sig, not just a short one), and B14 (RFC 9474
  Appendix A.2/A.3 wired byte-exact, alongside A.1/A.4). SPEC.md gains an RFC 9474
  §6.2 key-reuse paragraph and `example/main.zig` now signs its PSSZERO-Deterministic
  request under a SEPARATE key pair (B8). NOTICE's test count and its now-stale
  claim of a locally-reimplemented `mgf1Xor`/`bigModInverse` are corrected (B15).
  `scripts/modtest blindrsa`: 45/45 (baseline) -> 56/56, Debug and ReleaseFast.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** two tests pin `maskedInvert`'s masking itself. The module's only existing guard asserted that the masked inverse equals the direct inverse — a VALUE, which is exactly what stays true when the masking disappears — so the audit's mutations both survived 42/42: `m8` (`maskedInvert` replaced by `return feInvert(m, x);`) and `m21b` (the fresh uniform scalar replaced by the constant 3). ⚠ ctgrind cannot see this either: a constant mask is still branch-free, so no context count moves. The property is "a fresh, uniform scalar is drawn per attempt", and the seam that makes it observable was already in the signature — `maskedInvert` takes its `std.Random` as a parameter. The tests script that RNG to return `p` (a factor of the RFC 9474 modulus `n`) on the first draw, so the masked product keeps the shared factor, `feInvert` must fail, and the loop must draw a SECOND, different scalar; the answer is still checked against the RFC's published `inv`. The second test scripts `p` for every draw and pins the four-attempt bound and the fail-closed `NotInvertible`. Verified by deploying both mutations: each is killed by both tests.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **blind 477 / sign 218**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. 457 of the 477 are the extended-Euclid modular inverse, which `SPEC.md:188` already names as "the ONE inherently non-constant-time piece" and defends by masking — so this is the first MEASUREMENT of an admitted caveat, not a new finding. ⭐ The two `Modulus.mul` calls SPEC calls constant-time measured ZERO. ⛔⛔ Instrument defect found here and recorded in `scripts/ctgrind.sh`: `modules/blindrsa/src/root.zig` and `modules/rsa/src/root.zig` are different files with the SAME BASENAME, both appear in every stack, and the classifier matches regex text over the whole paragraph — so `root[.]zig` cannot tell them apart and this row's in-file column is "this module plus rsa". The author's first pass mis-attributed several lines that way and corrected it by reading valgrind's qualified symbol names.

- **2026-09-07** — `fuzzVerify` is a damage harness that applied no damage, and its own
  comment's promise about signature length was never kept. The flip count came from
  `smith.valueRangeAtMost(u8, 0, 8)`, a ranged draw, which returns the range MINIMUM unless
  the eight octets it reads as a little-endian `u64` land inside the range — so it was 0 on
  every replay and `verify` was handed RFC 9474's pristine Appendix A.1 signature, unaltered,
  every time; and the comment's "including lengths that don't match the 512-byte RFC 9474
  modulus" could never happen, because `bytes` was a fixed-size array. The damage script now
  comes out of one `smith.slice` call as the first draw and is read with `testkit.fuzz.Cursor`
  (a truncation octet, a flip count, then position/value pairs), with a nine-script corpus.
  Measured: **0 flips, 1 distinct signature and 1 distinct length before; 17 flips, 9 distinct
  signatures and 3 distinct lengths after, of which 1 still verifies.**
- **2026-08-23** — **Breaking:** `prepareRandomize` returns
  `error{OutputTooSmall}![]const u8` instead of `[]const u8`; `blind`,
  `blindWithFactor`, `blindSign`, and `finalize` each gained an
  `error.OutputTooSmall` variant in their existing error sets. All four used
  to guard a caller-supplied output buffer with `std.debug.assert` before an
  `@memcpy`/`toBytes` write; ReleaseFast compiles the assert (and the bounds
  check on the write that follows) out together, so a buffer undersized
  relative to the RSA modulus in use silently corrupted memory in the build
  that ships. Found by an audit sweep for this shape after
  `sortDestinations` and others were fixed the same day.
- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `verify` (corrupted signature bytes against the fixed RFC 9474 Appendix A key
  and prepared message) — `zig build check-fuzz` no longer names this module.
  No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: `blind`/`blindSign` panicked (a reachable
  denial-of-service) for any RSA modulus narrower than the module's compile-time maximum
  — i.e. the common 2048/3072-bit case; fixed, along with a second finding.
- **2026-07-14** — New module: RSA Blind Signatures (RFC 9474, RSABSSA) over `rsa`.
