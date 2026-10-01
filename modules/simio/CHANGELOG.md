# `simio` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
