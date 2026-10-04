# workerpool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **Tests:** two test-only seams (`snapshot_seam`, `wait_seam`; comptime-gated
  on `builtin.is_test`, nothing in a release build) and two deterministic TEETH tests that pin
  the worker's final pre-park queue re-check and `shutdownNow` waking a `wait` caller — the two
  race-only mutants the morning's run left alive now die (23/23 killed).

- **2026-10-04** — **Tests:** mutation run (23 schemata mutants, 21 killed, 2 race-only survivors
  documented in SPEC §6). New tests: `n_workers = 0` clamps to one worker, `registerSubmitter`
  after `drain` is `Shutdown`, a job submitted during the spin is taken at once. No code change.

- **2026-09-30** — **New `WorkerPool.wait() bool`: block until the pool is idle without shutting it
  down** (Pithikos `thpool_wait`). Waiters park on their own futex word; a worker wakes them only when
  one is registered, so a pool nobody waits on pays one extra load per job. `false` after a
  `shutdownNow` that dropped jobs; a call from one of the pool's own jobs panics (it would deadlock).
  `completed` is now incremented seq_cst (was monotonic) — the lost-wakeup argument needs it.

- **2026-09-25** — **New `Options.spin_ns`: a worker keeps looking before it parks.** With short
  jobs every job paid a `futexWake` and a park (two futex syscalls per job, measured by an
  embedder). A worker that finds the queue empty now watches for a submit for up to `spin_ns`
  and is not counted idle meanwhile, so such a submit skips the wake. Default 0: unchanged.

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  `std.Thread.Pool` / crossbeam worker pool (design ref), over `lockfree` (design
  reference, not a test anchor).
- **2026-07-22** — New module: in-process fixed-width worker pool over
  `lockfree.MpmcQueue`.
