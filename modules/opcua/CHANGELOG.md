# opcua — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: deleted `test "smoke"` in `src/root.zig`, whose
  whole body was `try std.testing.expect(true);`. **Neither BREAKING nor
  BEHAVIOURAL** — no production code changed. It could not fail, and it
  anchored nothing: `root.zig` is this module's test root, and the aggregation
  `test` at the top of that file is what pulls the submodules' tests in. Its
  only effect was to report a test count one larger than the coverage behind
  it. Deleted rather than given an assertion because the spot has no subject
  of its own — the offline-flow test that follows it is the real smoke test.
  Measured: `zig build test-opcua` went 176/176 to 175/175, the difference
  being exactly this test, with every other test still running and passing.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
