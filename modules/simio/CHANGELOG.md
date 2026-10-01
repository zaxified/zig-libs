# `simio` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-01** — First pilots (`src/pilots/`, piloted modules as
  `test_deps`): `sntp` (needed `query` to read time through `std.Io`) and
  `dns` (found `lookupIp` reporting an outage as "no addresses"; fixed there).
- **2026-10-01** — Mutation run over the file system (27 schemata, all
  killed after nine new tests — see SPEC.md).
- **2026-10-01** — M4, the disk: `std.Io.Dir`/`File` on a per-host file
  system with a crash-consistency model (unsynced data survives per sector;
  names are journaled and durable on a directory sync, or any sync with
  `FsOptions.durability = .journal`), one-shot I/O errors, bit rot and a disk
  capacity (`Fault.disk_error`, `Fault.bit_rot`, `HostOptions.disk_bytes`),
  flock-style locks, captured stdout/stderr, and `Host.putFile`/`readFile`/
  `console`. The search draws disk faults (`FaultConfig.disk`) and now uses
  its own `Trace`/`TraceEvent` (network faults from netsim inside), so
  `Failing.trace` and `replay` take simio's type.
- **2026-10-01** — Mutation run (46 schemata, 42 killed, 4 equivalent — see
  SPEC.md): nine new tests, and `Host.liveAllocations()` to observe what a
  crash releases.
- **2026-10-01** — M3, crashes and fault search: `Sim.crash`/`restart` with
  `Host.spawnBoot` and `Host.allocator()` (a crash stops tasks without
  unwinding, drops their sockets silently and releases their memory),
  `setLinkDirUp` (one-way failures), `partition`/`heal`, one-shot `Fault`s via
  `scheduleFault`, `setInvariant` (new `Outcome.violated`), and `Case` with
  `run`/`replay`/`findFailing`/`shrink`/`checkDeterminism` over netsim's fault
  schedules. Events due now fire before the next task step, and the
  fingerprint now covers virtual time (fingerprints from M2 differ).
- **2026-10-01** — M2, the network: hosts get IPv4/IPv6 addresses, `Sim.link`/
  `linkAll`/`setLinkUp` build a topology routed over shortest paths, and
  `std.Io.net` works on it — TCP-like streams (handshake with SYN retry,
  refused/reset/timeout, in-order delivery with loss as retransmission delay,
  partitions with backoff and a user timeout, flow-control window, FIN/RST on
  close, `shutdown`, seeded short reads), UDP-like datagrams (loss,
  duplication, reorder, one-bit corruption), ICMP echo answered by the target
  host, and `operate`/`Batch` so `Socket.receiveTimeout` works. `Sim.runFor`
  runs for a span of virtual time (new `Outcome.time_limit`).
- **2026-10-01** — New module: a deterministic `std.Io` for simulation
  testing, so code written against `std.Io` runs unchanged on simulated hosts
  as a pure function of a seed. This first cut (SPEC milestone M1) is the
  scheduler: tasks as fibers on one thread with seeded or FIFO scheduling and
  preemption at yield points, virtual time (`now`, `sleep`, every `Timeout`,
  per-host clock skew), `async`/`concurrent`/`await`/`cancel`, groups, cancel
  protection and `recancel`, futex (so `Io.Mutex`/`Io.Condition` work),
  seeded `random`/`randomSecure`, deadlock and step-limit outcomes, and a
  schedule fingerprint. Network, file system and fault search follow (M2–M5).
