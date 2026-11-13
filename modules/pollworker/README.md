# pollworker

Single-owner `poll(2)` loop plus a fork/detach **job table** for pushing
blocking work off the loop thread: a worker forks/execs an arbitrary argv, and
its result is drained back on the loop's next tick. Two independent building
blocks that only share the "single owner drives the loop" discipline:

- **`Loop`** — a thin, allocation-free wrapper over `poll(2)` (`Loop.poll`) plus
  a per-tick **maintenance callback list** (`addTask` / `tick`). The owner
  composes them: poll the fds, service readiness, `tick()` the callbacks.
- **`JobTable(N, Job)`** — a fixed-size, lock-free `FREE→RUNNING→DONE` slot
  table. The loop `claim()`s a slot, a worker fills it and `finish()`es it, and
  the loop `drain()`s the DONE slots on its next tick. Handoff is per-slot
  atomic (acquire/release) — no mutex. `spawnDetached(argv, report)` runs the
  RUNNING→DONE half on a detached thread that fork/exec/waitpid's an arbitrary
  argv, keeping the between-fork-and-exec window async-signal-safe (raw
  syscalls, no allocation in the child). `spawnDetachedEnv` adds a child
  environment (`Env`: `.empty` / `.inherit` / `.list`).
- **`Waker`** — an eventfd (self-pipe fallback) a worker writes when a job
  finishes, so a `poll` on `waker.fd()` returns at once (libuv `uv_async_send`).
  `JobTable.setWaker` makes `finish` signal it.
- **`Timers`** — one-shot and repeating timers in a min-heap with an injected
  millisecond clock (libuv `uv_timer_*`); `Loop.timeoutMs` folds the next due
  time into the `poll` timeout, `Loop.runTimers` fires what is due.

- A single-owner `poll(2)` loop plus a fork/detach
  job table: the loop drives a unix-socket accept + per-tick reap/publish, and
  the job table offloads cold HTTP fetches to detached curl workers.
- **Model after:** a single-owner event loop + detached-fork worker pool.
- **Platform:** `linux` — raw `std.os.linux` errno-encoded syscalls
  (`poll`/`fork`/`execve`/`waitpid`/`access`), a conscious no-libc ceiling.
  **Role:** util. **Concurrency:** `single_owner` — one thread/loop owns
  `claim`/`drain`/`release`; each worker owns `finish` for its slot; the only
  cross-thread state is each slot's atomic.
- **Deps:** none (std only — `std.Thread`, `std.atomic`, `std.os.linux`).

Provenance: original work of the zig-libs authors (MIT) — a single-owner event
loop (`runController`) plus an HttpJob table
(job-find/kick-fetch/drain/fetch-worker). The curl-specific fetch body was
**not** lifted — `spawnDetached` generalizes it to an arbitrary argv.

## API

```zig
const pollworker = @import("pollworker");
const Loop = pollworker.Loop;

// ── Loop: poll the listen fd, run maintenance every tick ──────────────────
var loop: Loop = .{};
defer loop.deinit(gpa);
try loop.addTask(gpa, .{ .context = self, .run = &reapDeadChildren });

var fds = [_]Loop.pollfd{.{ .fd = listen_fd, .events = Loop.POLL.IN, .revents = 0 }};
while (!quit) {
    const n = Loop.poll(&fds, 250) catch |e| switch (e) {
        error.Interrupted => 0, // a signal — loop to re-check `quit`
        error.PollFailed => break,
    };
    if (n > 0 and fds[0].revents & Loop.POLL.IN != 0) accept(listen_fd);
    loop.tick(); // maintenance callbacks, every iteration (not only on timeout)
}

// ── JobTable: offload blocking work to a detached fork/exec ───────────────
const Job = struct { res: pollworker.ProcResult = undefined };
var jobs: pollworker.JobTable(16, Job) = .{};

// on the loop thread, kick a detached child:
try jobs.spawnDetached(gpa, &.{ "/usr/bin/curl", "-fsSL", url }, &record);
//   fn record(job: *Job, res: pollworker.ProcResult) void { job.res = res; }  // worker thread

// every tick, reap finished jobs:
jobs.drain(&onDone);
//   fn onDone(job: *Job) void { if (job.res.ok) ... }                          // loop thread

// manual worker (own thread, not fork): claim → fill → finish → drain
if (jobs.claim()) |job| { job.* = .{ ... }; jobs.finish(job); }
```

`ProcResult` = `{ ok, exit_code: ?u8, term_signal: ?u8, spawn_failed: bool }`,
decoded from the `wait(2)` status word (no libc `W*` macros). Back-pressure is
the fixed slot count `N`: `claim` returns null and `spawnDetached` returns
`error.TableFull` when every slot is busy.

### Waker, timers, environment

```zig
// Wake the poll when a job completes (no waiting out the poll timeout):
var waker = try pollworker.Waker.init();            // eventfd, pipe fallback
defer waker.deinit();
try jobs.setWaker(&waker);                          // before submitting jobs
var fds = [_]Loop.pollfd{
    .{ .fd = waker.fd(), .events = Loop.POLL.IN, .revents = 0 },
    .{ .fd = listen_fd, .events = Loop.POLL.IN, .revents = 0 },
};
// ... poll ...
if (fds[0].revents != 0) { waker.clear(); jobs.drain(&onDone); }
// teardown: after the last job is DONE, jobs.quiesce(); then waker.deinit().

// Timers (the clock is yours: Loop.nowMs() in production, an integer in tests):
const h = try loop.timers.add(gpa, &onTimer, ctx);  // inactive; at most max_timers
try loop.timers.start(h, now, 500, 1000);           // first at +500 ms, then every 1000
const wait = loop.timeoutMs(now, 250);              // poll timeout, capped by the next timer
// ... poll(wait) ...
_ = loop.runTimers(try Loop.nowMs());               // fire what is due
try loop.timers.stop(h);  try loop.timers.again(h, now);  try loop.timers.close(h);

// Child environment (replaces the whole environment, like uv_process_options env):
try jobs.spawnDetachedEnv(gpa, &.{ "/bin/sh", "-c", "echo $X" }, .{ .list = &.{"X=1"} }, &record);
try jobs.spawnDetachedEnv(gpa, argv, .inherit, &record);   // snapshot of /proc/self/environ
```

## Not in scope (DEFER)

- **The curl-specific fetch** (body read into a buffer, negative-cache on
  failure, stderr capture) stays in the app — this module only spawns + reports
  process completion.
- **epoll / fd registration.** `Loop.poll` is still `poll(2)`: O(n) in the fd
  count, and the caller keeps the `pollfd` array. No signal handles.
- **Back-pressure beyond a fixed slot count** (queueing/retry) — the caller
  handles a full table (e.g. re-try on a later tick).
- **Windows / non-Linux** — Linux-only by design (raw syscalls).
