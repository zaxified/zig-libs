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
  syscalls, no allocation in the child).

- **Status:** `extract` — a single-owner `poll(2)` loop plus a fork/detach
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

## Not in scope (DEFER)

- **The curl-specific fetch** (body read into a buffer, negative-cache on
  failure, stderr capture) stays in the app — this module only spawns + reports
  process completion.
- **eventfd / real completion notification.** Results are observed by the loop
  polling `drain` each tick, not by waking the `poll` on completion. An eventfd
  registered in the pollset would remove the drain latency.
- **Environment inheritance.** Detached children exec with an *empty*
  environment; exec absolute paths (which need no `PATH`). A caller-supplied
  envp is a future option.
- **Back-pressure beyond a fixed slot count** (queueing/retry) — the caller
  handles a full table (e.g. re-try on a later tick).
- **Windows / non-Linux** — Linux-only by design (raw syscalls).
