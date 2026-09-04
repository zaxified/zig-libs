# testkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-04** — **First audit.** `expectBytes` had become a printf: deleting
  its `return error.TestExpectedEqual` left the suite at 22/22 green while five
  of five unequal pairs passed, because the wiring from `diff` to the returned
  error was held by nothing. Both of `expectHex`'s refusals were unheld too, and
  swallowing the decode error made `expectHex("zz", &.{})` **pass** — a
  malformed golden compared as though it were an empty one. The cause of all
  three was structural: the decision and its diagnostics lived in one function,
  and a self-test of the failing direction would have written to stderr, which
  `scripts/test-lib.sh` fails even for a passing step. The decision is now a
  silent `verdict`/`hexVerdict` that the failing direction can and does assert;
  `expectBytes`/`expectHex` are those plus `report`. `hex.bytes` no longer
  refuses a valid literal outside a comptime context — the
  `catch @compileError` branch was analysed on every runtime call, so
  `hex.bytes(4, "deadbeef")` in a test body failed to compile accusing its own
  correct argument. New gate `scripts/check-skip-as-pass.py`: `zig test` counts
  a bare `return;` as a PASS, and 11 sites across nftables, ebpf and bacnet
  still announced a skip and then returned plainly — the exact pattern
  `testkit.skip`'s doc comment says it was written to replace.

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
