# procnet — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
Layout mirrors the `dns`/`http` modules: `root.zig` owns the shared file-reading primitive
(`readVirtualFile`) and the system `snapshot`; each `/proc/net/*` table gets its own pure,
offline-testable parser file (`arp.zig`, `routes.zig`, `sockets.zig`, `conntrack.zig`,
`process.zig`). Every parser follows the same split: `parseX(gpa, text) -> []Entry` is pure and
golden-text-tested (never touches I/O); `readX(gpa, io) -> []Entry` is a thin wrapper that reads
the live file and calls the pure parser. `readVirtualFile` uses a *streaming* reader deliberately —
`/proc`/`/sys` files report size 0 from `stat` (generated on read, not disk-backed), so a
default positional whole-file read would come back empty; streaming to EOF is the only correct
read strategy, bounded by a caller-supplied `limit`. A missing or unreadable file yields an empty
result, not an error — these tables are legitimately absent (module not loaded, feature disabled,
no permission) often enough that "no data" beats "hard failure". Result types use fixed inline
buffers for kernel-bounded strings (`if_name_max` = `IFNAMSIZ` = 16, `comm_max` = 64, anchored on the
kernel's `fs/proc/array.c` — `proc_task_name()` renders `/proc/<pid>/stat`'s `comm` field into a local
`char tcomm[64]`, and for `PF_WQ_WORKER` kernel threads appends the workqueue description via
`wq_worker_comm()`, past the kernel-internal `TASK_COMM_LEN` (16, kept as `task_comm_len` for the
bound it actually names). A parser sized to `TASK_COMM_LEN` truncates every such kernel-thread name —
e.g. `kworker/0:0H-kblockd`, verified on a real host — which is why `comm_max` is 64, not 16), so a
whole result slice frees with one `gpa.free(slice)`, no arena required (same shape as the
`netlink` module's typed results); `copyClamped` truncates rather than fails when copying into
these buffers as a defensive belt-and-braces measure (inputs are already kernel-bounded, so this
is not the expected path). Addresses are returned as typed `netaddr.Ip`/`Prefix`, not allocated
dotted-string IPs — IPv6 socket addresses (`tcp6`/`udp6`) decode as four little-endian 32-bit words
concatenated in address order (verified against real kernel captures under
`src/testdata/`). Malformed rows are skipped, not fatal — one corrupt line never sinks the whole
table. A read past `limit` truncates to the bounded prefix rather than failing (the last partial row
is then skipped as malformed like any other), so an oversized table yields a short listing, never an
empty one. `SocketEntry` returns every row with its `state` (not pre-filtered to
LISTEN/bound) — filtering is now the caller's job — and carries the full row the kernel prints: local
AND peer endpoint, `uid`, `inode`, and the `tx_queue`/`rx_queue` pair (`ss`'s Send-Q/Recv-Q). `inode`
is structural rather than informational: it is the only key joining a socket to a process, and `0` is
the kernel's own value for a socket that has none (a `TIME_WAIT` orphan, or a connection still sitting
in an accept queue), so the join must never match on it. The join itself
(`process.indexSocketOwners`, what `ss -p` does) is a `/proc/<pid>/fd` sweep for `socket:[<inode>]`
symlink targets, deliberately opt-in and never called by `readSockets`: it costs one `readlink` per
open descriptor of every visible process — measured at 45 ms on an ordinary desktop (390 processes,
~6 900 descriptors) against well under a millisecond for reading all four socket tables — and its
result is honestly partial, because `/proc/<pid>/fd` is `0500` and an unprivileged sweep is refused
every other user's process. `SocketOwnerIndex` reports `scanned`/`denied`/`vanished`/`truncated`
alongside the owners so a blank process column is never mistaken for "nothing owns this"; real `ss -p`
behaves identically, verified live. `SockState` reuses the
kernel's `net/tcp_states.h` values for UDP too (`.close` = unconnected/bound, `.established` =
connect()-ed — UDP has no separate state space). Concurrency: reentrant, no shared state — each
call is independent, callers may run them from any thread. Original work of the zig-libs authors
(MIT): typed parsers for `/proc/net/route` (`routesOutcome`/`leHexToV4`), `/proc/net/{tcp,udp}`
(`socketsOutcome`), `/proc/net/nf_conntrack` (`conntrackOutcome`/`kvField`), `/proc/<pid>/stat`
(`parseProcStat`), plus the snapshot/thermal-zone/meminfo helpers; `arp.zig` is clean-room from
`proc(5)`; IPv6 socket-table support extends IPv4-only reads to full dual-stack coverage. Written
clean-room against the documented Linux `/proc` file format (`proc(5)`) and the kernel's own
`/proc` ABI.

## Threat model / out of scope
Not security-sensitive in the traditional sense — the untrusted input is the kernel's own
`/proc`/`/sys` text, not attacker-controlled network bytes, and every parser treats a malformed
line as skip-and-continue rather than a hard failure or panic. Linux-only platform ceiling is
accepted scope (raw `/proc`+`/sys` reads, no portable fallback), grouped with the repo's other
Linux-only members (icmp/rawsock/netlink/wireguard/l2disco). Reads are bounded: `readVirtualFile`
takes an explicit `limit` and `listProcesses`/`readConntrack` take an explicit cap, so an
adversarially huge `/proc` table (e.g. a conntrack-flood scenario) cannot force unbounded
allocation — the caller gets a truncated/capped view instead. Out of scope: writing to any
`/proc`/`/sys` file (read-only by design); anything requiring elevated privileges beyond normal
`/proc` read permissions.

## Verification
51 tests across `arp.zig`/`routes.zig`/`sockets.zig`/`conntrack.zig`/`process.zig` (dark-aggregated
from `root.zig`), golden-text fixtures under `src/testdata/` for each table (including real
`tcp6`/`udp6` kernel captures verifying the little-endian-hex IPv6 decode), malformed-row-skipped
-not-fatal cases, the `readVirtualFile` streaming-vs-`stat`-size-0 behavior and its
truncate-don't-vanish limit, per-column tests for every field decoded out of a socket row, and gated
live smoke tests against the real `/proc` (including one that opens its own listener and asserts the
process join attributes it to this pid under the fd this process holds). Run: `zig build
test-procnet`.

Beyond the suite, `example/main.zig` was diffed against real `ss` from iproute2 6.19.0 on a live
host. Five deliberately-created listening sockets (v4/v6, TCP/UDP, wildcard and loopback) compared
byte-identical on Netid, State, Recv-Q, Local Address:Port, Peer Address:Port and the whole `ss -p`
process column including the fd number. Whole-machine, `ss -tuln` and the demo each returned 47 rows
and every row matched after normalising away two renderings `ss` derives from `sock_diag` and
`/proc/net/*` does not carry (the `%iface` `SO_BINDTODEVICE` suffix, and `*` vs `[::]` for an
`IPV6_V6ONLY` wildcard). Set-equality against a live machine is not claimable in general — sockets
open and close between two reads, and `ss` prefers netlink and can legitimately see what these text
files do not — so the strong claim is the controlled-socket one and the whole-machine figure is a
snapshot, not an invariant.

## Backlog / deferred
Per the module README's "DEFER" list: `/proc/net/unix` (the AF_UNIX table, `ss -x` — a different row
shape entirely: a filesystem path or an abstract NUL-containing name, no address/port pair, so it
wants its own entry type; it was missing from the DEFER list itself until 2026-08-23, which made the
list read as if it were covered); the socket columns past `inode` (`tr:tm->when`, `retrnsmt`,
`timeout`, and the `rto`/`ato`/`snd_cwnd`/`ssthresh` tail — `ss -o`/`ss -i` territory, and the
congestion half is answered better over `sock_diag` than from this file); the conntrack **reply**
tuple and `mark`/`use`/`packets`/`bytes` (where NAT translation is visible; `ConntrackFlow` says it
decodes the original direction only); `/proc/net/dev` interface byte/packet counters (a different
per-iface-throughput shape, needs its own parser); `/proc/diskstats` (disk I/O counters, not yet
covered); `/proc/<pid>/status` (richer per-process fields — VmRSS breakdown, uid/gid, cgroup —
beyond `stat`'s scalars, a planned `status.zig` sibling to `process.zig`); `/proc/net/ipv6_route`
(different column layout from v4's `/proc/net/route`, not just a wider address); `statvfs`/
`/proc/mounts` disk-usage (a different module axis, not a `/proc/net`/per-process concern).

## Status
`extract · linux · util · reentrant` + deps: `netaddr` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** testdata/*.txt captured from real kernel /proc snapshots (README)
