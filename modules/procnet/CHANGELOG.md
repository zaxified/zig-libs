# procnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **All five fuzz harnesses parsed the empty string, every iteration,
  for their whole lives — and one earlier audit fix aimed at exactly this bought
  nothing.**

  Each parser had its own copy of a `mutateSample` helper, and all five opened with
  `if (smith.valueRangeAtMost(u8, 0, 4) == 0)`. A `Smith` ranged draw reads eight
  octets as a little-endian u64 and returns the range **minimum** unless that word
  already lies inside the range, and after the first short read `Smith` discards the
  rest of the input. So the test was always 0, the *"one draw in five is pure arbitrary
  bytes"* branch was taken every time, and the length drawn after `smith.bytes(buf)`
  was 0. The real `/proc` fixtures in the corpora — `arp.txt`, `route.txt`,
  `nf_conntrack.txt`, four socket tables — were never parsed once.

  ⛔ **`process.zig`'s sample index was a previous audit's fix, and it bought nothing.**
  The comment beside it read *"Was `proc_stat_corpus[0]`, so the two paren-heavy
  samples this harness exists for — `((sd-pam))` and `my weird) name` — were never
  mutation seeds … (W2 re-audit 2026-09-02, `procnet` F10)."* The replacement,
  `smith.index(proc_stat_corpus.len)`, is a ranged draw too and returned 0 for every
  input a corpus can carry: the index was 0 before the fix and 0 after it, and the two
  samples the fix was written for stayed unreached.

  ⛔ **`sockets.zig` had the same draw**, so four of its five fixtures — **both IPv6
  tables and both big-endian MIPS ones** — were never selected. Every address family
  and byte order `parseLocalAddr` has a separate branch for went unexercised.

  The five copies of `mutateSample` are replaced by one `src/fuzzsample.zig`, driven by
  a byte script read off a single `smith.slice` draw through `testkit.fuzz.Cursor`. A
  knob cannot be drawn after the bytes because there are no draws after the bytes: the
  seed's own octets say which sample, how to damage it and how far to truncate it.
  Each parser has a corpus and a guard test in the ordinary lane.

  Measured before → after (every "before" is 0, because every harness parsed `""`):
  ARP 37 entries decoded / 42 octets mutated · conntrack 30 flows, 37 rows walked /
  36 mutated · routes 37 rows / 42 mutated · `/proc/<pid>/stat` **all 5 samples
  selected**, 9 lines parsed / 25 mutated · sockets **all 5 fixtures selected**, 45 TCP
  and 45 UDP entries / 34 mutated.

  None of the guards uses `accepted > 0`: `parseArp("")`, `parseRoutes("")` and
  `parseConntrack("")` all **succeed** with zero entries, so an acceptance count would
  have read 100% on precisely the input these harnesses were stuck on.

- **2026-09-02** — **Truncation is reported instead of being invisible, and `/proc` is treated as
  untrusted input.** Eight findings from the drift re-audit (`952ec657`), each pinned by a test
  that goes red when the fix is reverted. `readSockets` returned a bare `[]SocketEntry`, which
  has no channel for "this table was cut" — a host with ~3500 sockets in one table got a
  silently short listing, and both siblings in this module already reported truncation, so it
  was an inconsistency inside the module rather than a house style. `readConntrack`'s
  documented "true total row count" was itself computed from a 4 MiB prefix, so past ~20000
  flows the signal that says "this view is partial" was partial too, and short by a plausible
  amount. `snapshot()` converted `/proc/uptime` with a bare `@intFromFloat`, and `parseFloat`
  accepts `nan`, `inf`, `-1.0` and `1e30` — SIGABRT in Debug and ReleaseSafe, an uptime of 584
  billion years in ReleaseFast; SPEC's threat model claimed `/proc` is not attacker-controlled
  while five of this module's own fuzz harnesses said the opposite, and lxcfs bind-mounts
  `/proc/uptime` into every LXC container. **New public surface:** `SocketTable` (with its
  `deinit`) and `readSockets` returning it, `socket_table_read_limit`, `VirtualFile`,
  `readVirtualFileReporting`, `copyClamped`. **BREAKING** for a caller that bound
  `readSockets`' result as a slice.
  ⚠ Entry written 2026-09-06, four days after the commit: `scripts/checks/check-changelog-entry.py`
  landed that day and named this module as the one open case in the whole tree.

- **2026-08-24** — The IPv6 half of the big-endian byte-order rule is measured rather than
  derived. The same guest that produced the `tcp` capture also produced a `tcp6` one
  (`testdata/tcp6-mips-be.txt`): a socket bound to `2001:db8:1:2:3:4:5:6`, asymmetric in all
  four 32-bit words so that both the per-word order and the word order are visible. The
  big-endian kernel wrote it straight through, `20010DB8 00010002 00030004 00050006`, where a
  little-endian kernel writes four swapped words. The earlier note that the guest "had no IPv6"
  was wrong — `/proc/net/tcp6` was there, only the loopback address had not been configured.
  No code change: the derived rule was correct, it is now evidence.

- **2026-08-24** — **Address hex columns are decoded in the PRODUCING KERNEL's byte order; they
  were always read low-byte-first.** `/proc/net/{tcp,udp,tcp6,udp6,route}` print each address word
  with `%08X` of a `u32` variable holding a `__be32` — the kernel never converts, so the eight hex
  characters are that word's memory image and their order follows the kernel that wrote them. Both
  decoders (`sockets.hexWord`, ex-`leHexWord`; `routes.hexToV4`, ex-`leHexToV4`) took the parsed
  integer's LOW byte as the first octet unconditionally, which is right only for a little-endian
  producer. **Measured, not inferred:** a big-endian MIPS kernel (OpenWrt 25.12.4 `malta/be` under
  `qemu-system-mips`) with a socket bound to a chosen `127.0.0.1:12345` printed `7F000001:3039`,
  which the old decode read as **1.0.0.127** — reproduced by an outside consumer built against the
  published module (`local=1.0.0.127:22`). The capture is checked in as
  `src/testdata/tcp-mips-be.txt`; its ground truth is the address the capture script itself bound,
  so no foreign tool has to be trusted. ⚠ On `/proc/net/route` the damage was worse than a wrong
  address: the `Mask` column takes the same path, so a big-endian `FFFFFF00` (/24) became
  0.255.255.255 — not a contiguous CIDR mask — and the row was DROPPED. A big-endian router lost
  routes silently. ⚠ The secondary sources saying "little-endian regardless of architecture" (and
  the one primary report agreeing, Bitcoin #31812, which infers byte order from which tests failed
  and quotes no file contents) are wrong; SPEC.md now records the measurement instead of them.
  **Additive, not breaking:** `parseTcp`/`parseUdp`/`parseRoutes` keep their signatures and now
  mean "written by a kernel of this machine's byte order" — always true for `readSockets`/
  `readRoutes`, which read the running kernel, and for any capture that has not crossed
  architectures. New `parseTcpWithEndian`/`parseUdpWithEndian`/`parseRoutesWithEndian` take the
  producer's byte order for a foreign capture (the argument is the *writer's* order, never the
  parsing machine's). ⚠ A green cross-target run was NOT evidence here and had been read as some:
  the decoders are endian-independent as code (arithmetic on a parsed value), so the whole suite
  passed under `qemu-mips` while carrying this bug — the fixtures were all little-endian captures
  AND the decode ignored the machine. The tests now pin what the endian-less entry points decode
  with a per-target expectation, so hard-coding little-endian passes natively and fails under
  qemu-mips; the suite is run both ways.
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
  defects) — part of the collection-wide audit. ⚠ **This entry used to end "Verified
  against a live capture from gopsutil (Go) / procps-ng". There is no such capture** —
  corrected 2026-09-03. Neither name appears anywhere in this module outside the three
  places that state the design reference; what gopsutil and procps-ng are here is a
  *model*, which is what `root.zig`'s `meta.model_after` says. The sentence was a
  template rendering a C-reference-implementation field as a claim of a verified
  capture, and the same template put the same false sentence in four other modules.
  The module's captures are real and are its own: `src/testdata/` holds `/proc`
  snapshots taken from running kernels, including the big-endian `tcp-mips-be.txt`
  whose image, boot command and capture date SPEC.md §"The hex address decode on a
  big-endian target" states in full, so it can be re-taken. Those anchor the parsers;
  no foreign parser was ever run against them, and none needs to be — the ground truth
  is the address the capture script BOUND, not another implementation's opinion.
- **2026-07-09** — New module: Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP
  sockets/conntrack/process stats/device health, typed.
