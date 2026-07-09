# probe — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
Pure engine behind a `Connector` seam: all connect I/O goes through `connectFn(target,
timeout_ns) -> ConnectOutcome`, so classification, repetition, aggregation and fan-out are fully
offline-testable against a scripted fake — tests never open a socket. The default `LiveConnector`
uses `std.Io.net` TCP (connect, measure, immediate close). Three layers: `probeTcp` (one attempt,
never allocates/panics), `probeTarget` (N reps aggregated via `latency.Accumulator`, every non-`up`
rep counted as loss), `probeMany` (a target list, order-stable). Bounded concurrency: `probeMany`
deals work via an atomic next-target counter; the calling thread plus up to `max_concurrent - 1`
helper threads each own disjoint `TargetResult` slots, so no locking is needed and in-flight
connects never exceed `max_concurrent`; degrades to inline on one thread if spawning is
unavailable. Counts bounded (`max_repetitions = 4096`, `max_targets`). Error policy: a malformed
`host:port` is a typed `Target.ParseError` (Go `SplitHostPort` semantics via
`netaddr.parseHostPort`, port required, `[v6]:port` supported); a DNS/connect failure is an
`error` `Result`, never a panic. Optional `AppCheck` runs after a handshake and downgrades
`up`→`error` on a failed app-level check. Platform: any — the engine is pure; only the default
connector touches the OS. Clean-room; the TCP-connect reachability technique is a standard,
decades-old approach (nmap's `-sT`, fping's parallel sweep) — behavior modeled only, no
third-party source consulted or copied; there is no `probe` entry in NOTICE (nothing derived
requires attribution). Deps `netaddr` + `latency-stats` are sibling modules.

## Threat model / out of scope
Not a security scanner and not privileged (an ordinary TCP connect; no raw sockets, no SYN/stealth
scan). Does not authenticate the peer — `up` means a handshake completed, not that the intended
service answered (use `AppCheck` for an app-level assertion). Known limitation: `std.Io.Threaded`
in Zig 0.16 panics on a connect timeout, so `timeout_ns` is currently **advisory** — the OS default
connect timeout applies until std implements it. Out of scope: UDP/ICMP probing, banner grabbing,
TLS/protocol handshakes, port-range sweeping.

## Verification
Offline-first: a scripted fake `Connector` on a virtual clock drives every path — per-outcome
classification, N-rep min/avg/max + loss%, `AppCheck` downgrade, `Target.parse` KATs (incl.
`[v6]:port` and typed-error negatives), and a 50-target fan-out asserting order stability, one call
per target, and `max_in_flight <= max_concurrent`. One hermetic live test binds a local listener and
probes it, skipping on any error. Run: `zig build test-probe`.

## Backlog / deferred
`timeout_ns` is advisory pending `std.Io.Threaded` connect-timeout support in Zig 0.16 (currently
panics rather than returning a timeout error) — tracked as a std limitation, not a probe bug.
UDP/ICMP probing, banner grabbing, TLS/protocol handshakes, and port-range sweeping are explicit
out-of-scope items, not planned for this module.

## Status
`gap · any · client · single_owner` + deps: `netaddr`, `latency-stats` — canonical source is
`pub const meta` in src/root.zig.
