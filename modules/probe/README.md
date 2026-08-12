# probe

TCP-connect service-reachability probing: is a `host:port` accepting connections,
and how fast? Complements the sibling `icmp` (host liveness) and `traceroute`
(path) modules with the third network-tail question — service reachability.

The technique is `nmap -sT` / `fping`-style: attempt a TCP connection; a completed
handshake is `up` (with the measured connect RTT), an actively refused connection
is `refused` (a fast, definitive negative — host present, port closed), no answer
within the timeout is `timeout`, and a DNS/other failure is `error`. Repeat N times
per target for min/avg/max/loss, and fan out across a target list with a bounded
worker count.

**Pick the right connector.** `PosixConnector` (recommended, Linux) does a
non-blocking connect and a `poll` bounded by your budget, then reads
`SO_ERROR` — `timeout_ms` is a *real* per-attempt timeout. `LiveConnector` is
the portable `std.Io.net` path, whose `std.Io.Threaded` backend cannot abort a
connect: the attempt blocks for the OS default and only the *outcome* respects
the budget (a connect that succeeds past it is reported `timeout` with the real
RTT). Measured against a black-holed target with a 200 ms budget:
**200.3 ms vs 134 367 ms**.

**Neither bounds DNS.** `poll` bounds the connect; name resolution is a second
place a `host:port` attempt blocks, bounded only by the system resolver's own
timeout (`options timeout:` in `/etc/resolv.conf`, default 5 s). So a 1 s probe
of a name whose nameserver is dark blocks ~5 s. `PosixConnector` says so rather
than hiding it: `.resolve = .literal_only` never calls a resolver (wall clock =
your budget — resolve once up front and probe literals, which is what a health
checker wants), while `.system` charges the lookup against the budget so the
*classification* is honest even though the wall clock is not. An IP literal
never reaches the resolver in either mode.

- No small pure-Zig TCP-connect prober exists.
- **Platform:** the engine is portable — all connection I/O goes through an
  injectable `Connector` seam, so the classify/aggregate/fan-out logic is pure
  and offline-testable; only the connectors touch the OS. `LiveConnector` is
  `std.Io.net`, `PosixConnector` is Linux (Zig 0.16 moved the socket wrappers
  out of `std.posix`, so a libc-free build reaches `socket`/`connect`/`poll`/
  `getsockopt` only through `std.os.linux`).
- **Model after:** `nmap -sT` / `fping`-style fan-out (technique, public knowledge).
- **Deps:** `netaddr` (target address parse/format, incl. `[v6]:port`),
  `latency-stats` (per-target min/avg/max/loss).

Layers: `probeTcp` — one connect attempt → `Result { kind, rtt_ns }`;
`probeTarget` — N reps of one target → aggregated min/avg/max/loss;
`probeMany` — fan out a target list with bounded concurrency, order-stable.
An optional app-level check hook runs after the handshake. `Target.parse`
accepts `host:port` and `[v6]:port`.

```zig
const probe = @import("probe");

var pc: probe.PosixConnector = .{ .resolve = .literal_only };
const r = probe.probeTcp(.{ .host = "10.0.0.7", .port = 443 }, .{
    .connector = pc.connector(),
    .timeout_ms = 1000, // a real wall-clock bound on this attempt
});
switch (r.kind) {
    .up => {}, // r.rtt_ns is the connect latency
    .refused, .timeout, .@"error" => {},
}
```

Tests are offline-first: a scripted fake `Connector` + a virtual clock drive the
classify/aggregate/concurrency-bound paths deterministically (`Target.parse`
including `[v6]:port` covered). The timeout itself cannot be tested that way, so
live tests drive it on loopback — including a **black hole** (a listener whose
one-slot accept queue is full, so Linux drops further SYNs) to assert the wall
clock, and the same black hole through `LiveConnector` to show the old path does
not come back. All hermetic: loopback only, no resolver traffic, no netns.

Provenance: clean-room — implements the standard TCP-connect probing technique
(`nmap -sT` / `fping` fan-out, public knowledge); no third-party source consulted
or copied — behavior only. Deps `netaddr` + `latency-stats` are sibling modules.
