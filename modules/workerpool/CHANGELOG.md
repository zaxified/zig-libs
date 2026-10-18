# workerpool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements that Zig has no io-less blocking mutex / `std.Thread` primitives re-checked against the 0.17.0 std (still true).

- **2026-10-14** — **The queue is now `lockfree.SegQueue(Job)`** (was `lockfree.MpmcQueue` over EBR
  with a `NodePool` box per job): jobs travel by value, no allocation per job (a block per 63), no
  epoch domain, and `submit` from any thread takes no lock. `bench-workerpool` vs thpool
  (7 rounds): 0.19–0.83× (was 0.64–1.01×; no-op burst 1.01 → 0.83, four producers 0.64 → 0.19).
  **BREAKING:** `outstandingBoxes()` removed (there are no boxes); `InitError.TooManyParticipants`
  and `InitError.CanaryTripped` removed (nothing can return them). **BEHAVIOURAL:** the allocator
  given to `init` must be thread-safe (workers free queue blocks); `SubmitFailed` now means only
  "the queue needed a block and could not get one". `Submitter` / `registerSubmitter` /
  `max_submitters` keep their API and their bound, but a `Submitter` no longer differs from `submit`.
- **2026-10-13** — **Feature (grade 2, parity with Pithikos/C-Thread-Pool):** `pause` / `resume` /
  `isPaused` (workers finish the job they have, then park on the `notify` futex; `drain` and
  `shutdownNow` override a pause; lost-wakeup argument in SPEC §4, test seam `pause_seam`),
  `workingCount`, `queuedCount`, and an opt-in bounded queue — `Options.max_queued` (default 0 =
  unbounded, behaviour unchanged) with `SubmitError.QueueFull`, admission by a CAS counter reserved
  before the box allocation and released on dequeue and on every rollback (SPEC §5). **Breaking
  for exhaustive `switch`es over `SubmitError`** (a new member): `qap/src/offload.zig` has one.
  Adds `tools/bench.zig` + `tools/c_bench/main.c` (comparative benchmark against the pinned
  thpool; `zig build bench-workerpool`). Rejected with reasons: result handle, panic isolation,
  dynamic resizing (SPEC §6b/§7).
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
