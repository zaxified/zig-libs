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
dotted-string IPs — IPv6 socket addresses (`tcp6`/`udp6`) decode as four 32-bit words concatenated
in address order (verified against real kernel captures under `src/testdata/`), each word in the
byte order of the KERNEL THAT WROTE the file, which is what the hex columns actually encode (see
"The hex address decode on a big-endian target" below; `parseX` means "this machine's order" and
`parseXWithEndian` states a foreign capture's). Malformed rows are skipped, not fatal — one corrupt
line never sinks the whole table. A read past `limit` truncates to the bounded prefix rather than failing (the last partial row
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
(MIT): typed parsers for `/proc/net/route` (`routesOutcome`/`hexToV4`), `/proc/net/{tcp,udp}`
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
57 tests across `arp.zig`/`routes.zig`/`sockets.zig`/`conntrack.zig`/`process.zig` (dark-aggregated
from `root.zig`), golden-text fixtures under `src/testdata/` for each table (including real
`tcp6`/`udp6` kernel captures verifying the four-word hex IPv6 decode, and a real BIG-ENDIAN
`/proc/net/tcp` capture, `tcp-mips-be.txt`, whose ground truth is the address the capture script
itself bound), malformed-row-skipped-not-fatal cases, the `readVirtualFile` streaming-vs-`stat`-size-0 behavior and its
truncate-don't-vanish limit, per-column tests for every field decoded out of a socket row, and gated
live smoke tests against the real `/proc` (including one that opens its own listener and asserts the
process join attributes it to this pid under the fd this process holds). Run: `zig build
test-procnet`. The suite is also run on a BIG-ENDIAN CPU — `zig test -OReleaseSafe -target
mips-linux-musl --test-cmd qemu-mips --test-cmd-bin --dep netaddr -Mroot=modules/procnet/src/root.zig
-Mnetaddr=modules/netaddr/src/root.zig`, 57/57 — which is load-bearing rather than decorative: the
tests pinning what the *endian-less* `parseTcp`/`parseRoutes` decode expect a DIFFERENT answer per
target, so a decode that quietly hard-coded little-endian would pass natively and fail there.
Verified by mutation, both directions: restoring the old unconditional low-byte-first decode turns
the big-endian-capture tests red in both lanes, and hard-coding the endian-less entry points to
`.little` passes natively and fails only under qemu-mips.

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
have different answers. Both have now been measured; the second turned out the
opposite way from what the secondary sources said, and it was a real bug.

**Question 1 — does OUR code behave differently when compiled big-endian? No.
Measured 2026-08-24, not reasoned about.** The same fixed `/proc/net/tcp` table
was fed through `parseTcp` in two builds and the decoded addresses compared:

    zig build-exe -target mips-linux-musl ...   # ELF 32-bit MSB, MIPS32
    qemu-mips ./probe                           # reports: native endian: big

Both builds printed byte-identical results (`0100007F` -> `127.0.0.1`,
`7F000001` -> `1.0.0.127`), and the module's whole suite was then run the same
way — `zig test -target mips-linux-musl --test-cmd qemu-mips --test-cmd-bin` —
with **51/51 passing**.

The reason matters more than the measurement. `hexWord` (`src/sockets.zig`) and
`hexToV4` (`src/routes.zig`) parse a hex STRING into an integer VALUE with
`parseInt(u32, s, 16)` and then lay that value out in an explicitly requested
byte order with `writeInt`. Neither step consults the CPU's representation, so
no byte-order reinterpretation ever happens and the machine running the decode
cannot reach the result. (Before the fix below, the octets came out with
`& 0xff` and `>> 8` instead — different code, same property.) An earlier
version of this section framed the risk as "the decoders have never been RUN on
`.linux32`" and read a green `portable-procnet-linux32` row as weak evidence.
Running them there proves nothing either: there was nothing endian-dependent to
run — which is exactly why a green cross-target suite was not evidence about
Question 2, and why the bug below survived one.

**Question 2 — what does a big-endian KERNEL print into the file? Its own byte
order. MEASURED 2026-08-24, and the answer was the opposite of what the
secondary sources said.** A big-endian MIPS kernel was booted, a socket bound
to an address chosen in advance, and `/proc/net/tcp` read back:

    OpenWrt 25.12.4, target malta/be, from
      openwrt-25.12.4-malta-be-vmlinux-initramfs.elf
      (sha256 verified against the release's sha256sums)
    booted under qemu-system-mips -M malta
    uname -m = mips; /proc/cpuinfo "system type: MIPS Malta"
    ip link set lo up; dropbear -R -p 127.0.0.1:12345
    captured 2026-08-24 -> src/testdata/tcp-mips-be.txt

       0: 7F000001:3039 00000000:0000 0A ...

`7F000001` is 127.0.0.1 in NATURAL order; a little-endian kernel writes
`0100007F` for the same socket (as every other fixture here does). The ground
truth needs no foreign tool and no `ss`: the address and port were CHOSEN when
the socket was bound. The port half, `3039` = 12345, is identical on both
producers — the kernel prints it as a number.

So the eight hex characters are the native-byte-order memory image of a `u32`
holding the `__be32`, and the address octets are that value written back out
**in the producing kernel's byte order**. The secondary sources describing the
file as "little-endian regardless of architecture" are wrong, and so was the
one primary report that agreed with them (Bitcoin issue #31812, which *inferred*
the byte order from which tests failed under emulated s390x and quoted no file
contents). The kernel's own `proc_net_tcp` documentation does not mention
endianness at all.

**What the module does about it.** Both decoders took the parsed integer's LOW
byte as the first octet unconditionally, so they decoded that capture as
`1.0.0.127` — confirmed by an outside consumer built against the published
module, which printed `local=1.0.0.127:22` for a `7F000001` row. The producing
byte order is now an explicit parameter of the decode:

* `parseTcp`/`parseUdp`/`parseRoutes` keep their signatures and mean "written
  by a kernel of THIS machine's byte order". That is correct for every live
  read by construction — `readSockets`/`readRoutes` read the running kernel's
  own files — and for any capture that has not crossed architectures.
* `parseTcpWithEndian`/`parseUdpWithEndian`/`parseRoutesWithEndian` take the
  producer's byte order for a foreign capture, and are what the little-endian
  fixtures here are now parsed with, so they keep decoding correctly when the
  suite runs on a big-endian target.

⚠ A wrong-endian read of `/proc/net/route` does not merely mis-decode: the
`Mask` column goes through the same path, so a big-endian `FFFFFF00` (/24) read
low-byte-first becomes 0.255.255.255, which is not a contiguous CIDR mask and
the row is DROPPED. A big-endian router would have lost routes silently.

**On qemu.** `qemu-mips` user-mode emulation cannot answer Question 2 at all —
the `/proc` it exposes is the HOST kernel's, so a big-endian process there reads
little-endian files. That is why a full-system `qemu-system-mips` guest was
needed for the capture. User-mode qemu remains the right tool for Question 1,
and the whole suite is run under it (`zig test -OReleaseSafe -target
mips-linux-musl --test-cmd qemu-mips --test-cmd-bin`) precisely so the
native-order tests get evaluated on a big-endian CPU as well as this one.

Closed the same day for `tcp6` as well. The v6 case was briefly covered by a
test DERIVED from the measured v4 rule, on the reasoning that a v6 column is
four of the same `__be32`-as-host-word groups — and on the belief that the
big-endian guest had no IPv6. That belief was simply wrong: `/proc/net/tcp6`
exists on it, and only the loopback address had not been configured. So the
capture was taken too, from the same guest and the same way:
`ip -6 addr add 2001:db8:1:2:3:4:5:6/128 dev lo`, then
`dropbear -R -p [2001:db8:1:2:3:4:5:6]:12345`. The address is asymmetric in
every one of the four words, so a wrong per-word byte order and a wrong WORD
order would both show. The big-endian kernel wrote it straight through —
`20010DB8 00010002 00030004 00050006` — where a little-endian kernel writes
four swapped words, `B80D0120 02000100 04000300 06000500`. The reasoning had
been right; it is now evidence instead of an argument, in
`testdata/tcp6-mips-be.txt`, and the test also asserts that reading those bytes
with the WRONG producer order does not yield the address, so the fixture cannot
pass for the wrong reason.

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
