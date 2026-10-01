# `simio` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-01** — New module: a deterministic `std.Io` for simulation
  testing, so code written against `std.Io` runs unchanged on simulated hosts
  as a pure function of a seed. This first cut (SPEC milestone M1) is the
  scheduler: tasks as fibers on one thread with seeded or FIFO scheduling and
  preemption at yield points, virtual time (`now`, `sleep`, every `Timeout`,
  per-host clock skew), `async`/`concurrent`/`await`/`cancel`, groups, cancel
  protection and `recancel`, futex (so `Io.Mutex`/`Io.Condition` work),
  seeded `random`/`randomSecure`, deadlock and step-limit outcomes, and a
  schedule fingerprint. Network, file system and fault search follow (M2–M5).
