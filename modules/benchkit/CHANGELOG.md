# benchkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-14** — **NEW (moved):** the comparison driver that was `testkit.bench` is this module, unchanged apart from its own `meta`. Every `tools/bench.zig` imports `@import("benchkit")` instead of `@import("testkit").bench`; `build.zig` hands it to every bench program. Why: no test imports it, yet as part of `testkit` (a `test_dep` of 221 modules) each edit re-keyed every module's tests in every CI lane.
