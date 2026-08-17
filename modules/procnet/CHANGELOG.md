# procnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BREAKING:** `comm_max` 16 → 64. It was documented as `TASK_COMM_LEN`
  (`linux/sched.h`), but that constant bounds a task's `comm` *inside the kernel* — it does
  NOT bound what `/proc/<pid>/stat` prints. The kernel's `fs/proc/array.c` renders `comm`
  via `proc_task_name()` into a local `char tcomm[64]`, and for `PF_WQ_WORKER` kernel
  threads calls `wq_worker_comm()` first, which appends the workqueue description — e.g.
  `kworker/0:0H-kblockd` (20 bytes), observed on a live host at `/proc/10/stat`, which the
  old 16-byte bound silently truncated to `kworker/0:0H-kbl`. Added `task_comm_len` (16) as
  the correctly-named constant for the kernel-internal bound; `comm_max` (now 64, anchored
  on `tcomm[64]`) stays the name callers use for the parse buffer
  (`ProcessEntry.name_buf`), so `comm_max` silently getting the wrong value was the actual
  defect — this is that fix, not a cosmetic rename. Also re-exported `netaddr` as
  `procnet.netaddr` so a consumer importing only `procnet` can format the `Ip`/`Prefix`
  values it gets back without a separate structural-match import.
- **2026-08-15** — Fixed a flaky live smoke test (test-only; no change to the module).
  The `readSockets`/`readArp`/`readRoutes`/`readConntrack` wiring test compared the
  ROW COUNT from a direct `/proc` read against the count the wrapper returned, i.e. two
  samples of live kernel state taken microseconds apart. It failed on CI's ReleaseSafe
  amd64 lane with `expected 96, found 97` — one socket appeared mid-test, in a step
  that runs 211 modules' tests concurrently. It now compares CONTENT: every entry the
  oracle reports both before and after the wrapper ran must appear in the wrapper's
  output, which is a stronger wiring claim than a count and does not depend on the
  table holding still. A tolerance window was rejected — the mutation this guards
  (wrong path, dropped table) moves the count by a whole table, so a window wide
  enough to absorb the churn absorbs the defect too. Verified by mutation (dropping
  `/proc/net/udp6` from the wrapper's loop, and typo'ing the `arp`/`route` paths: red
  on 8 of 8 attempts each) and by 40 consecutive green runs under a loop opening and
  closing listeners, which failed the previous version 4 times in 5.
- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on each of
  the five `/proc` table decode entry points — `parseProcStat`, `parseRoutes`,
  `parseTcp`/`parseUdp`, `parseArp`, `parseConntrack`. Kernel-emitted is not
  trusted-input: a container's `/proc` can be bind-mounted/faked, a process names
  itself (`comm`) with adversarial parens, and every parser also reads from a
  caller-supplied snapshot file. Each harness mutates a real fixture (byte flips over
  a copy of the real `/proc/net/*`/`/proc/<pid>/stat` sample) plus a fifth-of-the-time
  pure arbitrary bytes, since arbitrary bytes essentially never spell the exact
  column/hex-length shapes these formats require; the four allocating parsers run
  under `std.testing.allocator` with the result freed on every path. No panic, hang,
  OOB read or leak found.
- **2026-07-19** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  gopsutil (Go) / procps-ng.
- **2026-07-09** — New module: Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP
  sockets/conntrack/process stats/device health, typed.
