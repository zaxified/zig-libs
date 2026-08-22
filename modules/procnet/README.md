# procnet

Linux `/proc` + `/sys` parsers — ARP neighbor table, IPv4 routes, TCP/UDP
socket tables (v4 + v6), conntrack flows, per-process `stat`, and a device
health snapshot (uptime/load/memory/thermal/conntrack pressure) — all
returning typed values (`netaddr.Ip`/`Prefix`, not allocated dotted-string
IPs).

Provenance: original work of the zig-libs authors (MIT) — typed parsers for
`/proc/net/route` (`routesOutcome`/`leHexToV4`), `/proc/net/{tcp,udp}`
(`socketsOutcome`), `/proc/net/nf_conntrack` (`conntrackOutcome`/`kvField`),
and `/proc/<pid>/stat` (`parseProcStat`), plus the `snapshot`/thermal-zone/
meminfo helpers. `arp.zig` (`/proc/net/arp`) is clean-room from `proc(5)`.
IPv6 socket-table support (`tcp6`/`udp6`) and the little-endian-hex→
`netaddr.Ip` decode for 16-byte addresses are verified against real kernel
snapshots (see the test fixtures under `src/testdata/`), extending IPv4-only
reads to full dual-stack coverage.

- **Model after:** gopsutil (Go) / procps-ng.
- **Platform:** linux (raw `/proc`+`/sys` reads). **Role:** util.
  **Concurrency:** reentrant (no shared state).
- **Deps:** `netaddr` (`Ip`/`Prefix` — typed addresses instead of allocated
  strings), re-exported as `procnet.netaddr` so a consumer that imports only
  `procnet` can format/inspect the addresses it gets back without a
  separate import.

## API

```zig
const procnet = @import("procnet");

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();

// ARP neighbor table (/proc/net/arp)
const neighbors = try procnet.readArp(gpa, io);
defer gpa.free(neighbors);
for (neighbors) |n| _ = .{ n.ip, n.mac, n.device() };

// IPv4 routes (/proc/net/route) — typed Prefix + optional gateway
const routes = try procnet.readRoutes(gpa, io);
defer gpa.free(routes);
for (routes) |r| _ = .{ r.dest, r.gateway, r.iface(), r.metric };

// TCP + UDP sockets, v4 and v6 (/proc/net/{tcp,tcp6,udp,udp6})
const socks = try procnet.readSockets(gpa, io);
defer gpa.free(socks);
for (socks) |s| _ = .{
    s.proto,  s.local,  s.local_port, s.state,
    s.remote, s.remote_port,          // the peer, as `ss` shows it
    s.uid,    s.inode,                // what `ss -e` shows
    s.tx_queue, s.rx_queue,           // `ss`'s Send-Q / Recv-Q
};

// Who owns a socket (`ss -p`): the join is opt-in and costs an
// O(processes x descriptors) sweep of /proc/<pid>/fd -- build the index
// ONCE, then join every socket against it.
var owners = try procnet.indexSocketOwners(gpa, io, .{});
defer owners.deinit(gpa);
for (socks) |s| for (owners.findAll(s.inode)) |o| _ = .{ o.pid, o.fd, o.name() };
// `owners.denied` counts processes this uid may not look into: their
// sockets are listed, but unattributed. Partial, never an error.

// Conntrack flows, capped sample + true total (/proc/net/nf_conntrack)
var ct = try procnet.readConntrack(gpa, io, 50);
defer ct.deinit(gpa);
for (ct.flows) |f| _ = .{ f.src, f.dst, f.sport, f.dport, f.proto(), f.state() };

// Running processes, capped (/proc/<pid>/stat)
const procs = try procnet.listProcesses(gpa, io, 512);
defer gpa.free(procs);
for (procs) |p| _ = .{ p.pid, p.name(), p.state, p.ppid, p.rss_kb };

// Device health snapshot: uptime, load, memory, thermal, conntrack pressure
var snap = try procnet.snapshot(gpa, io);
defer snap.deinit(gpa);
```

Every table follows the same split: `parseX(gpa, text) → []Entry` is pure
and offline-testable (golden-text fixtures in `src/testdata/`); `readX(gpa,
io)` reads the live file and calls the pure parser. A missing or unreadable
file yields an empty result, not an error.

There is a runnable `ss(8)`-shaped tool built on all of this in
[`example/main.zig`](example/main.zig) — `procnet-demo -tulnpe`, plus `-r`
routes, `-N` neighbours and `-s` snapshot.

## Notes / deviations

- Malformed rows are skipped, not fatal — one corrupt line never sinks the
  whole table.
- `SocketEntry`/`parseTcp`/`parseUdp` return *every* row with its `state`
  (not pre-filtered to `LISTEN`/bound) — filtering is the
  caller's job now that the type carries state.
- A read past its `limit` **truncates**; it does not fail. The tail of a
  very large table is missing and the last partial row is dropped as
  malformed, rather than the whole table coming back empty.
- `SocketEntry.inode` is `0` for a socket that has no inode — a `TIME_WAIT`
  orphan, or a connection sitting in an accept queue that nothing has
  `accept(2)`-ed yet. That is the kernel's own value, and the process join
  never matches on it (many unrelated rows share it).
- The process join sees only what the calling uid may: `/proc/<pid>/fd` is
  `0500`. `ss -p` behaves identically — it leaves the process column blank
  for another user's socket in a non-root run. `SocketOwnerIndex.denied`
  reports how many processes were refused so the gap is visible.
- `ss` shows some things `/proc/net/*` does not carry at all, because it
  prefers the kernel's `sock_diag` netlink interface: a listening socket's
  configured backlog (`ss`'s Send-Q — the text file prints `0` there),
  `IPV6_V6ONLY` (`ss`'s `*:port` vs `[::]:port`), the `SO_BINDTODEVICE`
  `%iface` suffix, cgroup paths. Measured, not assumed: two UDP sockets
  differing only in `IPV6_V6ONLY` produce byte-identical `/proc/net/udp6`
  rows and different `ss` output.
- `SockState` reuses the kernel's `net/tcp_states.h` values for UDP too:
  `.close` (0x07) means "unconnected/bound", `.established` (0x01) means
  "connect()-ed" — there is no separate UDP state space.
- IPv6 socket addresses decode as four little-endian 32-bit words
  concatenated in address order (verified against real `tcp6`/`udp6`
  captures in `src/testdata/`).

## DEFER (beyond this module's current scope)

- `/proc/net/unix` — the AF_UNIX socket table (`ss -x`). Not parsed, and
  until now not even listed here, which is the worst kind of omission: a
  reader checking this list would have concluded it was covered. It is a
  genuinely different row shape — a filesystem path or an abstract
  (`@`-prefixed, NUL-containing) name instead of an address/port pair, and
  no `netaddr.Ip` anywhere in it — so it wants its own parser and its own
  entry type, not a widened `SocketEntry`.
- Per-socket columns past `inode` in `/proc/net/{tcp,udp}`: the
  `tr:tm->when` timer, `retrnsmt`, `timeout`, and the TCP diagnostics tail
  (`rto`, `ato`, `snd_cwnd`, `ssthresh`). These are `ss -o` and `ss -i`
  territory — a per-connection timing/congestion view with its own shape,
  and (`ss -i` in particular) mostly answered better over `sock_diag` than
  from this file.
- The conntrack **reply** tuple, and `mark`/`use`/`packets`/`bytes`.
  `ConntrackFlow` decodes the original-direction tuple only, which the type
  says; the reply tuple is where NAT translation is visible and deserves
  explicit modelling rather than four more fields.
- `/proc/net/dev` interface byte/packet counters — a different shape
  (per-iface throughput, not a neighbor/route/socket table); own parser.
- `/proc/diskstats` — disk I/O counters; not yet covered, needs its own
  design pass.
- `/proc/<pid>/status` — richer per-process fields (VmRSS breakdown, uid/gid,
  cgroup) beyond `stat`'s scalars; a `status.zig` sibling to `process.zig`.
- `/proc/net/ipv6_route` — the IPv6 routing table (different column layout
  from v4's `/proc/net/route`, not just a wider address).
- `statvfs`/`/proc/mounts` disk usage — filesystem space, not a `/proc/net`
  or per-process concern; a different module axis entirely.
