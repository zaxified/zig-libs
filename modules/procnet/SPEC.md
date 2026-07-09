# procnet — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

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
buffers for kernel-bounded strings (`if_name_max` = `IFNAMSIZ` = 16, `comm_max` = `TASK_COMM_LEN` =
16), so a whole result slice frees with one `gpa.free(slice)`, no arena required (same shape as the
`netlink` module's typed results); `copyClamped` truncates rather than fails when copying into
these buffers as a defensive belt-and-braces measure (inputs are already kernel-bounded, so this
is not the expected path). Addresses are returned as typed `netaddr.Ip`/`Prefix`, not allocated
dotted-string IPs — IPv6 socket addresses (`tcp6`/`udp6`) decode as four little-endian 32-bit words
concatenated in address order (new vs. the axp seed, verified against real kernel captures under
`src/testdata/`). Malformed rows are skipped, not fatal — one corrupt line never sinks the whole
table. `SocketEntry` returns every row with its `state` (not pre-filtered to
LISTEN/bound like the axp seed) — filtering is now the caller's job. `SockState` reuses the
kernel's `net/tcp_states.h` values for UDP too (`.close` = unconnected/bound, `.established` =
connect()-ed — UDP has no separate state space). Concurrency: reentrant, no shared state — each
call is independent, callers may run them from any thread. Extracted and retyped from the authors'
own axp project (`axp-core/src/task.zig` — `routesOutcome`/`leHexToV4`, `socketsOutcome`,
`conntrackOutcome`/`kvField`, `parseProcStat`, the snapshot/thermal-zone/meminfo helpers; MIT, the
authors' own code); `arp.zig` has no direct axp precedent (clean-room from `proc(5)`); IPv6
socket-table support is a new extension beyond the IPv4-only axp seed. Modeled after gopsutil (Go)
/ procps-ng — see NOTICE.

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
27 offline tests across `arp.zig`/`routes.zig`/`sockets.zig`/`conntrack.zig`/`process.zig`
(dark-aggregated from `root.zig`), golden-text fixtures under `src/testdata/` for each table
(including real `tcp6`/`udp6` kernel captures verifying the little-endian-hex IPv6 decode),
malformed-row-skipped-not-fatal cases, and the `readVirtualFile` streaming-vs-`stat`-size-0
behavior. Run: `zig build test-procnet`.

## Backlog / deferred
Per the module README's "DEFER" list: `/proc/net/dev` interface byte/packet counters (a different
per-iface-throughput shape, needs its own parser); `/proc/diskstats` (disk I/O counters, no seed
precedent); `/proc/<pid>/status` (richer per-process fields — VmRSS breakdown, uid/gid, cgroup —
beyond `stat`'s scalars, a planned `status.zig` sibling to `process.zig`); `/proc/net/ipv6_route`
(different column layout from v4's `/proc/net/route`, not just a wider address); `statvfs`/
`/proc/mounts` disk-usage (a different module axis, not a `/proc/net`/per-process concern).

## Status
`extract · linux · util · reentrant` + deps: `netaddr` — canonical source is `pub const meta` in
src/root.zig.
