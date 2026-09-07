# blindrsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
