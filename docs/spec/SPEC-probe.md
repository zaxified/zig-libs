# SPEC — `probe`

**Purpose** — A TCP-connect service-reachability prober: *is this `host:port` accepting connections,
and how fast?* Fills the third network-tail question alongside `icmp` (host liveness) and `traceroute`
(path). A completed handshake is `up` (with connect RTT), an actively refused connection is `refused`
(fast, definitive negative — host present, port closed), no answer within the timeout is `timeout`, a
DNS/other failure is `error`. Repeat N times per target for min/avg/max/loss, and fan out across a
target list with a bounded worker count.

**Model after / Seed** — clean-room. The TCP-connect reachability probe is a standard, decades-old
technique (nmap's `-sT` connect scan; fping's parallel host sweep); this models behavior only — no
nmap, fping or other third-party source consulted or copied. Greenfield, and there is **no `probe`
entry in `NOTICE`** (nothing derived requires attribution). Deps `netaddr` + `latency-stats` are
sibling modules.

**Design & invariants**
- **Pure engine behind a `Connector` seam:** all connect I/O goes through
  `connectFn(target, timeout_ns) -> ConnectOutcome`, so classification, repetition, aggregation and
  fan-out are fully offline-testable against a scripted fake — the tests never open a socket. The
  default `LiveConnector` uses `std.Io.net` TCP (connect, measure, immediate close).
- **Three layers:** `probeTcp` (one attempt, never allocates/panics), `probeTarget` (N reps aggregated
  via `latency.Accumulator`, every non-`up` rep counted as loss), `probeMany` (a list, order-stable).
- **Bounded concurrency:** `probeMany` deals work out via an atomic next-target counter; the calling
  thread plus up to `max_concurrent - 1` helper threads each own disjoint `TargetResult` slots, so no
  locking is needed and in-flight connects never exceed `max_concurrent`. Degrades to inline on one
  thread if spawning is unavailable. Counts bounded (`max_repetitions = 4096`, `max_targets`).
- **Error policy:** a malformed `host:port` is a typed `Target.ParseError` (Go `SplitHostPort`
  semantics via `netaddr.parseHostPort`, port required, `[v6]:port` supported); a DNS/connect failure
  is an `error` `Result`, never a panic. Optional `AppCheck` runs after a handshake and downgrades
  `up`→`error` on a failed app-level check.
- **Platform:** any — the engine is pure; only the default connector touches the OS.

**Threat model / out of scope** — Not a security scanner and not privileged (an ordinary TCP connect;
no raw sockets, no SYN/stealth scan). It does not authenticate the peer — `up` means a handshake
completed, not that the intended service answered (use `AppCheck` for an app-level assertion). Known
limitation: `std.Io.Threaded` in Zig 0.16 panics on a connect timeout, so `timeout_ns` is currently
**advisory** — the OS default connect timeout applies until std implements it. Out of scope: UDP/ICMP
probing, banner grabbing, TLS/protocol handshakes, port-range sweeping.

**Verification** — Offline-first: a scripted fake `Connector` on a virtual clock drives every path —
per-outcome classification, N-rep min/avg/max + loss%, `AppCheck` downgrade, `Target.parse` KATs
(incl. `[v6]:port` and typed-error negatives), and a 50-target fan-out asserting order stability, one
call per target, and `max_in_flight <= max_concurrent`. One hermetic live test binds a local listener
and probes it, skipping on any error.

**Status** — `gap · any · client · single_owner` · deps: `netaddr`, `latency-stats`.
