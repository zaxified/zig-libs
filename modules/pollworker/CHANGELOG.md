# pollworker — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-13** — Scope S4 -> S3: `Waker` (eventfd, self-pipe fallback) +
  `JobTable.setWaker`/`quiesce` wake the poll on job completion (libuv
  `uv_async_send`); `Timers` min-heap with an injected clock, bounded handle count,
  generation-checked handles, `Loop.timeoutMs`/`runTimers`/`nowMs` (libuv
  `uv_timer_*`); `Env` + `JobTable.spawnDetachedEnv` (`.empty`/`.inherit`/`.list`,
  bounded, validated). `spawnDetached` is unchanged (empty environment).
- **2026-10-18** — Ported to Zig 0.17.0. `dupeZ` -> `dupeSentinel(u8, s, 0)`; `waitpid` status is `i32`.
- **2026-10-05** — Mutation run: 22 of 22 killed, 0 equivalent; 7 tests added
  (`poll` EINTR, `drain` skipping RUNNING, empty argv, `spawnDetached` under
  allocation failure, full argv reaching the child, exit 127 on a failed exec,
  `close_range` in the child). No code change.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on libev/libuv event
  loop + a thread-pool exec; Go `os/exec` on a worker goroutine (design reference, not a
  test anchor).
- **2026-07-09** — New module: Single-owner `poll(2)` loop + a lock-free fork/exec job
  table for offloading blocking work off the loop thread.
