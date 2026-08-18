# testkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Added `getEnv`, a portable env read for test gates: it returns `null`
  on Windows rather than calling `std.process.Environ.getPosix`, whose own body does not
  compile there (`Environ.Block` resolves to `GlobalBlock`, which has no `.view()`).
  `verboseSkip` now goes through it. The unguarded `getPosix` call was the single reason
  21 modules claiming `platform = .any` failed to cross-compile their test binaries for
  `x86_64-windows-gnu`.
- **2026-08-06** — Security audit: no findings. Modeled on `std.testing`, extended
  (design reference, not a test anchor).
- **2026-07-31** — New module: Test-only shared harness (`hex` decoding for KAT vectors,
  golden byte-comparison that names the first differing offset, the verbose-skip
  convention).
