# procnet

Linux `/proc` + `/sys` parsers — ARP neighbor table, IPv4 routes, TCP/UDP
socket tables (v4 + v6), conntrack flows, per-process `stat`, and a device
health snapshot (uptime/load/memory/thermal/conntrack pressure) — all
returning typed values (`netaddr.Ip`/`Prefix`, not allocated dotted-string
IPs).

Provenance: extracted and retyped from the authors' axp project
(`axp-core/src/task.zig` — `routesOutcome`/`leHexToV4` for
`/proc/net/route`, `socketsOutcome` for `/proc/net/{tcp,udp}`,
`conntrackOutcome`/`kvField` for `/proc/net/nf_conntrack`, `parseProcStat`
for `/proc/<pid>/stat`, plus the `snapshot`/thermal-zone/meminfo helpers;
MIT, the authors' own code). `arp.zig` (`/proc/net/arp`) has no direct axp
precedent — clean-room from `proc(5)`. IPv6 socket-table support
(`tcp6`/`udp6`) and the little-endian-hex→`netaddr.Ip` decode for 16-byte
addresses are new (verified against real kernel snapshots — see the test
fixtures under `src/testdata/`), extending the axp seed's IPv4-only reads.

- **Status:** `extract`.
- **Model after:** gopsutil (Go) / procps-ng.
- **Platform:** linux (raw `/proc`+`/sys` reads). **Role:** util.
  **Concurrency:** reentrant (no shared state).
- **Deps:** `netaddr` (`Ip`/`Prefix` — typed addresses instead of allocated
  strings).

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
for (socks) |s| _ = .{ s.proto, s.local, s.port, s.state };

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

## Notes / deviations

- Malformed rows are skipped, not fatal — one corrupt line never sinks the
  whole table.
- `SocketEntry`/`parseTcp`/`parseUdp` return *every* row with its `state`
  (not just `LISTEN`/bound, unlike the axp seed) — filtering is the
  caller's job now that the type carries state.
- `SockState` reuses the kernel's `net/tcp_states.h` values for UDP too:
  `.close` (0x07) means "unconnected/bound", `.established` (0x01) means
  "connect()-ed" — there is no separate UDP state space.
- IPv6 socket addresses decode as four little-endian 32-bit words
  concatenated in address order (verified against real `tcp6`/`udp6`
  captures in `src/testdata/`).

## DEFER (beyond this module's current scope)

- `/proc/net/dev` interface byte/packet counters — a different shape
  (per-iface throughput, not a neighbor/route/socket table); own parser.
- `/proc/diskstats` — disk I/O counters; no seed precedent, needs its own
  design pass.
- `/proc/<pid>/status` — richer per-process fields (VmRSS breakdown, uid/gid,
  cgroup) beyond `stat`'s scalars; a `status.zig` sibling to `process.zig`.
- `/proc/net/ipv6_route` — the IPv6 routing table (different column layout
  from v4's `/proc/net/route`, not just a wider address).
- `statvfs`/`/proc/mounts` disk usage — filesystem space, not a `/proc/net`
  or per-process concern; a different module axis entirely.
