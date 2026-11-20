# benchkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-14** — **NO CONSUMER-VISIBLE CHANGE:** the "building the Go side / foreign side" progress lines are not printed inside a test (the mutation run's new tests reach `goBuild` and `buildForeign`, and a passing test must leave stderr clean); test stand-ins renamed so `check-module-purity` does not read them as foreign toolchains. Printing only, which the mutation policy leaves unmutated; the audit is re-recorded over the new source hash.
- **2026-11-14** — **NEW (moved):** the comparison driver that was `testkit.bench` is this module, unchanged apart from its own `meta`. Every `tools/bench.zig` imports `@import("benchkit")` instead of `@import("testkit").bench`; `build.zig` hands it to every bench program. Why: no test imports it, yet as part of `testkit` (a `test_dep` of 221 modules) each edit re-keyed every module's tests in every CI lane.
