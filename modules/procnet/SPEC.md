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

### The hex address decode on a big-endian target — measured, and what is left

Two different questions hide behind "does this work on big-endian", and they
have different answers. This section separates them because the first has now
been measured and the second cannot be settled from here.

**Question 1 — does OUR code behave differently when compiled big-endian? No.
Measured 2026-08-24, not reasoned about.** The same fixed `/proc/net/tcp` table
was fed through `parseTcp` in two builds and the decoded addresses compared:

    zig build-exe -target mips-linux-musl ...   # ELF 32-bit MSB, MIPS32
    qemu-mips ./probe                           # reports: native endian: big

Both builds printed byte-identical results (`0100007F` -> `127.0.0.1`,
`7F000001` -> `1.0.0.127`), and the module's whole suite was then run the same
way — `zig test -target mips-linux-musl --test-cmd qemu-mips --test-cmd-bin` —
with **51/51 passing**.

The reason matters more than the measurement. `leHexWord` (`src/sockets.zig`)
and `leHexToV4` (`src/routes.zig`) parse a hex STRING into an integer VALUE
with `parseInt(u32, s, 16)`, then take octets out of it with `& 0xff` and
`>> 8`. Shifts and masks are defined on the value, not on its representation in
memory, so no byte-order reinterpretation ever happens and the CPU's endianness
cannot reach the result. An earlier version of this section framed the risk as
"the decoders have never been RUN on `.linux32`" and read a green
`portable-procnet-linux32` row as weak evidence. Running them there proves
nothing either: there was nothing endian-dependent to run.

**Question 2 — what does a big-endian KERNEL print into the file? Unverified,
and it is a property of the kernel, not of this module.** The decode is correct
exactly when the kernel emits the `__be32` as a little-endian host word, which
is what every fixture under `src/testdata/` shows — and all of those captures
come from little-endian hosts, so they confirm that case and say nothing about
the other.

What the field says, with its evidence quality stated rather than borrowed:
secondary sources describe the file as "little-endian regardless of
architecture", which would make this decode correct everywhere, and the one
primary report found — Bitcoin's issue #31812, networking tests failing under
emulated s390x — says the same. But that report *infers* the byte order from
which tests failed: it quotes no file contents, no other participant confirms
it, and no fix accompanies it. The kernel's own `proc_net_tcp` documentation
does not mention endianness at all. That is not enough to write "fine on
big-endian" into a SPEC, so it is not written.

**Neither "broken on big-endian" nor "fine on big-endian" is claimed.** What
would settle it, precisely: capture `/proc/net/tcp` **and** `/proc/net/tcp6` on
a big-endian Linux host (s390x, or a big-endian `qemu-system` guest — note that
`qemu-mips` user-mode emulation can NOT do this, because the `/proc` it exposes
is the host kernel's) together with ground truth for the sockets in them, `ss
-tuln` taken on that host at that moment, then replay the capture through
`parseTcp` as a fixture and compare against that ground truth. One such pair of
files, checked in beside the existing fixtures, turns this into either a passing
test or a bug report. Until then `.linux32` in `meta.targets` means "compiles
there, and decodes identically there"; the open question is the file's content,
not this code.

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
