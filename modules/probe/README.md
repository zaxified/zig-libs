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

- **Status:** gap — no small pure-Zig TCP-connect prober exists.
- **Platform:** any — all connection I/O goes through an injectable `Connector`
  seam (default = `std.Io.net`), so the classify/aggregate/fan-out logic is pure
  and offline-testable; only the default connector touches the OS.
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

const r = try probe.probeTcp(gpa, .{ .host = "example.com", .port = 443 }, .{
    .timeout_ms = 1000,
});
switch (r.kind) {
    .up => {}, // r.rtt_ns is the connect latency
    .refused, .timeout, .@"error" => {},
}
```

Tests are offline-first: a scripted fake `Connector` + a virtual clock drive the
classify/aggregate/concurrency-bound paths deterministically (`Target.parse`
including `[v6]:port` covered); one hermetic live test binds a local listener and
probes it, skipping when unavailable.

Provenance: clean-room — implements the standard TCP-connect probing technique
(`nmap -sT` / `fping` fan-out, public knowledge); no third-party source consulted
or copied — behavior only. Deps `netaddr` + `latency-stats` are sibling modules.
