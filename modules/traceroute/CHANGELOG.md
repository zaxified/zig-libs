# traceroute — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BREAKING**: a `sendFn`/`recvFn` transport failure inside `traceWith`/`trace`
  no longer discards the hops already collected. `Trace` gained a `transport_err: ?TransportError`
  field (set when the trace stopped early because the transport itself failed, as opposed to a
  per-probe timeout); `TraceError` narrowed from `error{ InvalidOptions, OutOfMemory } ||
  TransportError` to `error{ InvalidOptions, OutOfMemory }` — `error.SendFailed`/`error.RecvFailed`
  can no longer come out of `traceWith`'s return value at all. A caller that did
  `try traceWith(...)` and separately handled `error.SendFailed`/`error.RecvFailed` needs to check
  `tr.transport_err` on the returned `Trace` instead; a caller that only used `try`/propagated the
  whole error set is unaffected except that a transport failure now yields a (partial) `Trace`
  instead of an error. See SPEC.md "A transport failure returns a partial Trace, not just an error".
- **2026-07-19** — Security audit: no findings. Modeled on `traceroute(8)` / `mtr`
  (design reference, not a test anchor).
- **2026-07-07** — New module: ICMP-echo path discovery — TTL-stepped probes, per-hop
  address + RTT stats, load-balanced-path aware.
