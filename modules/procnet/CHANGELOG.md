# procnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **`readVirtualFile`'s `limit` now truncates instead of returning nothing.**
  It was `allocRemaining(...) catch null`, and `allocRemaining` returns `error.StreamTooLong`
  the moment the limit is reached — so an oversized table returned NULL and every row in it
  disappeared, exactly on the busy machines where the bound matters. `/proc/net/tcp` runs about
  150 bytes per row against a 512 KiB limit, so a host past roughly 3 500 sockets reported ZERO
  sockets; `/proc/net/nf_conntrack` past 4 MiB reported zero flows with `total = 0`, which a
  caller cannot tell from "the conntrack module is not loaded". SPEC.md had promised the
  behaviour that is now implemented ("the caller gets a truncated/capped view instead") — the
  code disagreed with its own spec. The truncated tail's last partial row is skipped as
  malformed, like any other. `sockets.socket_table_read_limit` names the socket-table bound so
  the number is visible rather than inline.
- **2026-08-23** — **`SocketEntry` now carries the columns `parseTable` used to tokenize past.**
  `remote`/`remote_port` (the `rem_address` column — a caller could not reproduce `ss`'s default
  Peer Address:Port at all), `uid` (`ss -e`), `tx_queue`/`rx_queue` (`ss`'s Send-Q/Recv-Q, which
  are in `ss`'s DEFAULT output), and `inode`. `inode` is the structural one: **it is the only key
  that maps a socket to a process**, so without it there was no `ss -p` to build. `port` is
  renamed `local_port` now that the type has a peer port to be symmetric with; there were no
  consumers of the old name outside this module. A row must now carry every column through
  `inode` to be accepted — admitting a short row with a defaulted `inode = 0` would be
  indistinguishable from the kernel's own `0` for an orphaned socket.
- **2026-08-23** — **Added the socket-inode → process join, `process.indexSocketOwners`** — what
  `ss -p` and `lsof -i` do: scan `/proc/<pid>/fd/*` for a symlink whose target is
  `socket:[<inode>]`. Deliberately opt-in; `readSockets` does not call it and there is no combined
  wrapper, because (a) it costs one `readlink` per open descriptor of every visible process —
  measured at 45 ms on an ordinary desktop, 390 processes and ~6 900 descriptors, against well
  under a millisecond for reading all four socket tables — and (b) the result is honestly partial:
  `/proc/<pid>/fd` is `0500`, so an unprivileged sweep is refused every other user's process.
  Verified live that real `ss -p` does exactly the same thing, silently leaving the process column
  blank for another uid's socket in a non-root run. `SocketOwnerIndex` therefore reports
  `scanned`/`denied`/`vanished`/`truncated` next to the owners, and `findAll` returns every holder
  of one inode (a socket survives `fork` and `SCM_RIGHTS`, so "the" owner is not a function) and
  never matches inode `0`. Measured on a real accept queue: two ESTABLISHED sockets waiting to be
  `accept(2)`-ed both carry inode `0`, so without that guard every orphan on the machine would be
  attributed to whichever process sorted first.
- **2026-08-23** — Two more columns that were read and thrown away: `ArpEntry.hw_type` (the
  `ARPHRD_*` word — the field that says whether `mac` is an Ethernet address at all; media with
  wider addresses do not fit the fixed `[6]u8` and are skipped, and nothing else recorded why) and
  `RouteEntry.flags` (the `RTF_*` word `route -n` prints as its `Flags` column — `RTF_UP` is the
  only thing saying whether a row is a live route, and no other field implies it). ⚠
  `/proc/net/route` prints Flags as bare hex with no `0x`, unlike `/proc/net/arp`'s columns, so
  the two are parsed with different bases on purpose: base 0 here reads `0011` as decimal 11
  instead of `0x11`, silently, and drops any row whose flags contain a hex letter.
- **2026-08-23** — Added `example/main.zig`: `procnet-demo`, an `ss(8)`-shaped socket lister
  (`-tulnpe`) plus `-r` routes, `-N` neighbours, `-s` snapshot. Diffed against real `ss` from
  iproute2 6.19.0 — see SPEC.md "Verification" for what that comparison does and does not prove.
  The demo drove the `SocketEntry` doc comment's correction about `tx_queue`: for a LISTENING
  socket `ss` prints the configured backlog in Send-Q and `/proc/net/tcp` prints `0`. Measured
  against a `listen(3)` socket holding two un-accepted connections, `ss` reported `Recv-Q 2
  Send-Q 3` while the file printed `00000000:00000002` — rx 2, agreeing exactly, and tx 0. The
  backlog is not in the text file; `ss` reads it over `NETLINK_SOCK_DIAG`.
- **2026-08-23** — README DEFER list: added `/proc/net/unix`, which was neither implemented nor
  listed. An omission missing from the list of omissions reads as coverage.
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
