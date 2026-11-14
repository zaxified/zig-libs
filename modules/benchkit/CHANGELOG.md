# benchkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-14** — **NO CONSUMER-VISIBLE CHANGE:** tests only (mutation run, second pass). `Summary` tests now pin that a later line never replaces the worst/best/spread of an earlier one and that one line without a counter keeps the whole summary on wall time; the tests that provoke the driver's stderr reports point fd 2 at /dev/null so a passing run writes nothing there; a missing `/bin/sh` skips the stand-in tests instead of masking a spawn failure.
- **2026-11-14** — **NO CONSUMER-VISIBLE CHANGE:** tests only (mutation run, first pass). The foreign-program half of the driver is now exercised with `/bin/sh` stand-ins — `foreign`, `foreignOnce`, `buildForeign`, `goBuild` (environment, arguments, working directory, failure kinds), `runCapped` (argv/environment/cwd reach the child; the output cap is exact on both streams), `drive` (per-round alternation, routing to the right program, banners, info / fast_only lines out of the verdict, filters, zero rounds, count mismatch, the noisy-run flag, wall-time fallback, no descriptor left open), `timeIt` against a scripted clock and counter (the 100 ms doubling threshold, best of five, per-op division), `Cycles` (`read`, `close`, `open`: cycles not instructions, user mode only) and `exeAt`'s own panic message.
- **2026-11-14** — **NEW (moved):** the comparison driver that was `testkit.bench` is this module, unchanged apart from its own `meta`. Every `tools/bench.zig` imports `@import("benchkit")` instead of `@import("testkit").bench`; `build.zig` hands it to every bench program. Why: no test imports it, yet as part of `testkit` (a `test_dep` of 221 modules) each edit re-keyed every module's tests in every CI lane.
