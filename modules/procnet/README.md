# procnet

Linux `/proc` + `/sys` parsers — ARP neighbor table, IPv4 routes, TCP/UDP
socket tables (v4 + v6), AF_UNIX sockets, conntrack flows, per-process
`stat`/`status`/`limits`/`io`/`cmdline`/`cgroup`/fd count, the `snmp`/`netstat`
counters, and a device health snapshot (uptime/load/memory/thermal/conntrack pressure) — all
returning typed values (`netaddr.Ip`/`Prefix`, not allocated dotted-string
IPs).

Provenance: original work of the zig-libs authors (MIT) — typed parsers for
`/proc/net/route` (`routesOutcome`/`hexToV4`), `/proc/net/{tcp,udp}`
(`socketsOutcome`), `/proc/net/nf_conntrack` (`conntrackOutcome`/`kvField`),
and `/proc/<pid>/stat` (`parseProcStat`), plus the `snapshot`/thermal-zone/
meminfo helpers. `arp.zig` (`/proc/net/arp`) is clean-room from `proc(5)`.
IPv6 socket-table support (`tcp6`/`udp6`) and the hex→`netaddr.Ip` address
decode are verified against real kernel snapshots (see the test fixtures
under `src/testdata/`, which now include a big-endian kernel's capture),
extending IPv4-only reads to full dual-stack coverage.

- **Model after:** gopsutil (Go) / procps-ng. **Reference for scope and
  performance:** prometheus/procfs v0.21.1 (the library behind the Prometheus
  `process_*` collector).
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
const table = try procnet.readSockets(gpa, io);
defer table.deinit(gpa);
const socks = table.entries; // `table.truncated`: a table hit its read limit
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

### Host counters (2026-10-04, `src/counters.zig`)

```zig
const devs = try procnet.readNetDev(gpa, io);      // []NetDevEntry: rx/tx bytes, packets, errs, drop, … (16 counters)
const st = try procnet.readStat(gpa, io);          // Stat{ cpu, cpus, ctxt, btime, processes, procs_running, procs_blocked }
defer st.deinit(gpa);
_ = procnet.CpuTimes.busyFraction(prev.cpu, st.cpu); // ?f64 between two samples (iowait counts as idle)
const mem = procnet.readMeminfo(gpa, io);          // MemInfo: typed kB fields, null when the kernel omits the line; mem.used()
const disks = try procnet.readDiskstats(gpa, io);  // []DiskStat per iostats.rst; discard/flush groups null on older kernels
const r6 = try procnet.readIpv6Routes(gpa, io);    // []Ipv6RouteEntry: dest/src Prefix, next_hop, metric, flags, iface
```

Formats are the kernel's documented ones (proc(5), `iostats.rst`); fixtures
are real captures; each parser also runs under the shared fuzz harness and a
3000-script deterministic driver that feeds every parser every damaged sample.

### Per-process readers and network counters (2026-10-17, prometheus/procfs parity)

Every per-process reader takes a `procnet.ProcRef` — `.self` (the calling
process, via `/proc/self`) or `.{ .pid = n }` — and every parser underneath is
pure, taking bytes.

```zig
const st = procnet.readPidStat(io, .self).?;       // PidStat: every field procfs's ProcStat has; no allocation
_ = .{ st.cpuSeconds(), st.startTimeSeconds(btime), st.residentBytesNow(), st.vsize, st.num_threads };
//   cpuSeconds = (utime + stime) / USER_HZ;  startTimeSeconds = btime + starttime / USER_HZ
//   (USER_HZ = 100, `procnet.user_hz`, the kernel ABI constant -- procfs uses it too)
const lim = procnet.readPidLimits(io, .self).?;    // Limits: all 16 rows, soft/hard, `unlimited` = null
_ = .{ lim.maxOpenFiles(), lim.maxAddressSpace(), lim.get(.stack_size) };
const nfds = procnet.countFds(io, .self).?;        // fstat size of /proc/<pid>/fd (Linux >= 6.2), else a directory count
const sts = procnet.readPidStatus(io, .self).?;    // PidStatus: uids/gids, Vm*/Rss* in bytes, ctxt switches, caps, cpus_allowed ranges
const pio = procnet.readPidIo(io, .self);          // ?PidIo: null for another user's process (the file is 0400)
const cl = procnet.readPidCmdline(gpa, io, .self).?; // NUL-separated; `cl.args()` iterates; cl.deinit(gpa)
const cg = (try procnet.readPidCgroups(gpa, io, .self)).?; // entries: hierarchy_id, controllers, path
// Network counters: one header/value-pair parser for all four files.
const ns = try procnet.readPidNetstat(gpa, io, .self);   // /proc/<pid>/net/netstat; readNetstat = /proc/net/netstat
defer ns.deinit(gpa);                                    // readSnmp / readPidSnmp for net/snmp
_ = ns.get("IpExt", "InOctets");                          // ?u64 by (section, name); every counter the kernel prints is kept
const unix = try procnet.readUnix(gpa, io);              // /proc/net/unix: []UnixEntry (path inline, abstract names start with '@')
defer unix.deinit(gpa);
```

`parsePidStat`, `parseLimits`, `parsePidStatus`, `parsePidIo`, `parseCgroups`,
`cmdlineArgs`, `parsePairs` and `parseUnix` are the pure halves. Page size comes
from the running kernel (`std.heap.pageSize()`; `parseProcStatWithPage` for a
capture from another machine) — `rss_kb` used to assume 4 KiB pages, which is
wrong on 16 KiB / 64 KiB arm64 and ppc64 kernels.

⚠ `process_network_receive_bytes_total` / `..._transmit_...` in a Prometheus
process collector come from `/proc/<pid>/net/netstat` `IpExt InOctets` /
`OutOctets`. That file shows the process's NETWORK NAMESPACE, not the
process: every process in one namespace reads the same numbers, and `/proc/net`
is `/proc/self/net`. procfs has the same quirk; this module reproduces it.

A process that exited, or whose file this uid may not read, yields null (or
an empty table) from a `ProcRef` reader, never an error.

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
- IPv6 socket addresses decode as four 32-bit words concatenated in address
  order (verified against real `tcp6`/`udp6` captures in `src/testdata/`),
  each word in the producing kernel's byte order — see the next point.
- **The hex address columns are in the byte order of the KERNEL THAT WROTE
  the file**, because the kernel prints a `u32` holding a `__be32` without
  converting it: the same loopback socket is `0100007F` on a little-endian
  kernel and `7F000001` on a big-endian one. Measured on a big-endian MIPS
  kernel, not inferred (`src/testdata/tcp-mips-be.txt`; SPEC.md has the
  provenance). `parseTcp`/`parseUdp`/`parseRoutes` assume a producer of this
  machine's byte order — always true for `readSockets`/`readRoutes`, and for
  any capture that has not crossed architectures. For a foreign capture say
  so explicitly:

  ```zig
  // A /proc/net/tcp copied off a big-endian box (s390x, a BE MIPS router).
  const rows = try procnet.parseTcpWithEndian(gpa, text, .big);
  defer gpa.free(rows);
  ```

  with `parseUdpWithEndian`/`parseRoutesWithEndian` alongside it. The
  argument is the *producer's* byte order, never the parsing machine's.

## DEFER (beyond this module's current scope)

- ~~`/proc/net/unix`~~ — done 2026-10-17 (`readUnix`, own `UnixEntry` type).
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
- ~~`/proc/<pid>/status`~~ — done 2026-10-17 (`readPidStatus`).
- ~~`/proc/net/snmp` / `/proc/net/netstat`~~ — done 2026-10-17 (`readSnmp`/`readNetstat`, per-pid variants).
- `statvfs`/`/proc/mounts` disk usage — filesystem space, not a `/proc/net`
  or per-process concern; a different module axis entirely.
