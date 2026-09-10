# netsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, netsim F4 (remainder), F9, F11.

  **F4 remainder** (**NO CONSUMER-VISIBLE CHANGE**): the 5 gaps left open by
  the earlier F4 pass — `loss_permille`, `dup_permille`, `jitter`,
  `reorder_extra`, `bandwidth` — are `LinkConfig` statistical properties
  applied unconditionally in `Sim.send`, not one-shot `FaultKind`s, so each
  got an N-sends-then-check-the-log test instead of a single trace. Each
  verified independently: mutating its mechanism to a no-op (`false and
  ...`) failed exactly that test (5/41), nothing else; reverted, 41/41.

  **F9**: `run()` built the topology TWICE — once via `snapshotTopo` (builds
  a whole `Sim`, runs `case.scenario`, discards it) and once more inside
  `replay` (builds another fresh `Sim`, runs the SAME `case.scenario`
  again). `Scenario`'s own contract (deterministic, no unseeded randomness)
  makes the second build strictly redundant. `run` now builds one `Sim`,
  reads the topology off it directly, then reuses the SAME `Sim` to drive
  the generated trace — `snapshotTopo`/`replay` are unchanged and still
  public on their own. Measured (interleaved A/B, 256-node ring, 60 iters):
  Debug 448.9ms → 239.8ms, ReleaseFast 82.2ms → 47.8ms (~1.7-1.9x,
  consistent with the audit's own ~47-51% at comparable sizes). Verified
  with a mutant (`run` reverted to the two-build shape): the two arms
  collapse to statistically the same cost and the regression-guard test
  fails; reverted.

  **F11** (additive, aditivní pole dle P3): `Sim.send` copies every payload
  into an arena freed only at `deinit` — memory grows with the TOTAL bytes
  ever sent, not the in-flight count, and had no cap (audit measured
  `VmHWM +1251 MiB` for 20 000×64 KiB sends, identically across all four
  optimize modes). Added `Sim.max_live_bytes: ?usize = null` (default `null`
  = today's exact unbounded behaviour) and `Case.max_live_bytes` (threaded
  into `Sim` by `build`, so `replay`/`run` callers get it without touching
  `Sim.init` — whose signature is untouched, so the module's 3 direct
  `Sim.init` callers are unaffected). Exceeding the cap returns
  `Sim.SendError.LiveBytesExceeded` (a new, additive error-set member) loudly
  from `send` instead of continuing to grow. All 7 in-repo consumers
  re-verified (`raft` 61/61, `df-elect` 37/37, `loopfree-reconv` 11/11,
  `liveness-hyst` 16/16, `loopix` 28/28, `fleetsim` 92/100+8 skip,
  `isis-sim` 21/21) — unchanged, since the default preserves exact prior
  behaviour. Verified with a mutant (the cap check short-circuited to
  never trigger): both new tests failed at the exact assertion; reverted.

  `scripts/modtest netsim`: 44/44 (was 37/37 before this entry's three
  items), Debug and ReleaseFast.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** A1 fix campaign, netsim F4
  (partial). The audit's mutate.sh found 14 mutations that survive the suite
  untouched — a fault kind or config bound that has no test observing its
  actual EFFECT, only that it appears in a generated trace. Added 8 new tests
  that each observe a mechanism's effect directly (a `PingPong` 2-node
  fixture for the fault kinds, plus direct `Sim`/`Case` construction for the
  two backstops and the config pin), each independently verified to fail
  when its corresponding mutation is applied: `drop_once`, `link_down`,
  `crash_node`, `restart_node`, `delay_once`, the `until` upper bound, the
  `max_events_cap` backstop, and `Config`'s documented defaults.
  `clock_jump` is covered incidentally by F1's positive control (already
  asserts the offset changes). Still open, deliberately not attempted here
  (time-boxed): `loss_permille`/`dup_permille`/`jitter`/`reorder_extra`/
  `bandwidth` — these are `LinkConfig` statistical properties, not
  `FaultKind`s, and need an N-sends statistical test shape rather than the
  single-trace shape used above.
- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** A1 fix campaign, netsim F10
  + F12. F10: `replay` no longer builds the event `Log` when `log_out ==
  null` (a new internal `Sim.want_log` flag, default `true` — the 3 in-repo
  consumers that call `Sim.init` directly and read `.log` themselves are
  unaffected; only `replay`'s own internal `Sim` ever turns it off). Measured
  ~1.8-2.2x (machine-dependent) over 30 replays of a 5-node flood scenario,
  both Debug and ReleaseFast. Results (`RunResult`, including `fingerprint`)
  are bit-identical either way — the fingerprint folds unconditionally in
  `append`, only the discarded-anyway `log.entries` build is skipped. F12:
  fixed two README `## Use` example bugs (`.loss = 0.01`, a field that never
  existed — real field is `.loss_permille: u16`; `netsim.shrink`, an export
  that doesn't exist — real name is `shrinkTrace`) and the stale "15 pass"
  claim under `## Verify` (now 27). Deferred: the audit also suggested wiring
  `findFailing`/`shrinkTrace` into `example/main.zig` so `check-examples`
  compiles those two entry points too (today only `replay` is exercised
  externally) — left open, since verifying an `example/` change requires the
  `check-examples` gate, which this campaign's fixer role is not permitted
  to run.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, netsim F7 +
  F13 + F14. F7: `findFailing(start, end)` with `start > end` now returns
  `null` immediately instead of walking ~2^64 seeds before it could ever
  reach `end` (its only exit condition was `seed == end`, never true on the
  way up past a `u64` wrap) — confirmed hanging past a 15s bound pre-fix.
  F13: `Sim.addLink`/`addBiLink` now reject a `LinkConfig` `_permille` field
  above 1000 with a new `error.InvalidPermille` (additive to their existing
  `Allocator.Error!void`) — `Prng.permille(rate)` silently saturates to
  "always fires" for any `rate > 1000`, so a caller who mistypes "5%" as
  `loss_permille = 5000` previously got a permanently dead link with no
  config error, not the total-loss-on-purpose the value implies. The
  documented range 0..=1000 (checked: every in-repo consumer stays at or
  under 1000) is unaffected. F14: `fault.generate`'s `repair_t` computation
  now uses saturating addition (`+|`) instead of `+`, so a `horizon` near
  `maxInt(u64)` no longer panics in Debug ("integer overflow") or wraps a
  repair to before its own disruption in ReleaseFast.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, netsim F1 +
  F5. F5: `generate`'s fault-kind draw no longer silently drops a disabled or
  inapplicable kind's share of the schedule — it excludes that kind from the
  weighted draw instead, so `Config.max_events` bounds the number of *emitted*
  disruptions, not the number of draws (previously up to 40% weaker with
  `enable_partition`/`enable_crash`/`enable_clock_jump` all off). The default,
  fully-enabled, linked, multi-node case is unchanged byte-for-byte; any other
  `(seed, topo, cfg)` combination now produces a different schedule — old
  seeds pinned against a non-default config are not guaranteed to reproduce
  the same trace (none of the 7 in-repo consumers were affected; verified by
  running every consumer's test lane, all green). F1: `applyFault` now rejects
  an out-of-range node id in `crash_node`/`restart_node`/`clock_jump` with a
  new `error.UnknownNode` instead of indexing unchecked (Debug panic,
  ReleaseFast out-of-bounds write reporting `outcome = .ok`) — additive, since
  `applyFault`/`replay` were already `anyerror!...`.
- **2026-08-18** — Portability fix: `Prng.below(n: usize) usize` was reused for
  `Time`-typed (`u64`) draws — `cfg.horizon` in `fault.generate` and
  `link.cfg.jitter`/`reorder_extra` in `Sim.send` — which fails to compile on a
  32-bit target (`u64` does not implicitly narrow to `usize`). `Time` is
  netsim's simulated clock and is deliberately `u64` on every host, not an
  accidentally-wide index count, so the fix is a dedicated `Prng.belowWide(n:
  u64) u64` (bound and draw both stay `u64`, no narrowing conversion, nothing
  to truncate) rather than casting `Time` down to `usize`. Fixes 4 modules:
  netsim itself plus `df-elect`, `liveness-hyst`, `raft`, all of which import
  `fault`/`sim` and failed `check-portable` for the identical reason. New test
  pins `belowWide` staying in-range and undivided-by-truncation for a bound
  past `maxInt(u32)`.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on TigerBeetle
  VOPR (design ref only; no throughput competitor — it is a test harness) (design
  reference, not a test anchor).
- **2026-07-15** — New module: Deterministic seeded discrete-event network simulator
  (VOPR-style: nodes/links/latency/loss/partition/clock-skew, failure-schedule fuzzer,
  byte-exact replay, ddmin counterexample minimizer).
