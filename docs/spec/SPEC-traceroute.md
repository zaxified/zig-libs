# SPEC — `traceroute`

**Purpose** — ICMP-echo path discovery: TTL-stepped probes yield per-hop addresses + RTTs. The
classic method — ICMP Echo Requests with increasing IP TTL; each router that expires the TTL answers
Time Exceeded (its source = that hop), the destination answers Echo Reply (path complete), a
Destination Unreachable terminates the trace with its code recorded. Fills a gap — no pure-Zig
traceroute engine exists — and is the path member of the network tail alongside `icmp` (liveness) and
`probe` (service reachability).

**Model after / Seed** — clean-room from the classic traceroute(8)/mtr ICMP method (Van Jacobson's
TTL-stepping applied to ICMP Echo — a public technique) and RFC 792 ICMP formats via the sibling
`icmp.echo` codec. Greenfield — no traceroute, mtr or other third-party source consulted or copied
(behavior only; NOTICE records the clean-room provenance).

**Design & invariants**
- **Pure engine behind a `Transport` seam:** `traceWith` is the hop state machine over an injectable
  transport (`sendFn` with TTL / `recvFn` bytes + source / `nowFn` clock), fully offline-testable from
  canned packet bytes on a virtual clock. `LinuxTransport` + `trace` are the live path.
- **Correlation over a bounded flat slot scheme:** each probe's wire sequence is `seq_base +% slot`
  (slot = hop·probes_per_hop + probe); a response — even one arriving after its probe already timed
  out — maps back to its slot via the ident/seq quoted inside the ICMP error (parsed by
  `icmp.echo.parseV4/parseV6`), so late replies land in the right hop.
- **Sequential:** one probe in flight, like traceroute(8)'s default — the state machine stays simple
  and every RTT is unambiguous. Hop count and probes-per-hop are bounded (`Options.validate`;
  `max_probes_per_hop = 16`, `max_payload = 1024`).
- **Allocation:** the `Trace` owns exactly two slices (`hops`, `probes`), sized to the used prefix and
  freed by `deinit`; per-hop `stats()` uses fixed stack scratch (via `latency-stats`).
- **Live path is Linux + raw only:** DGRAM ("ping") sockets deliver ICMP errors on the error queue,
  not as packets, so raw is required (CAP_NET_RAW); per-probe TTL via setsockopt IP_TTL /
  IPV6_UNICAST_HOPS; ppoll for the timeout.

**Threat model / out of scope** — The live trace needs CAP_NET_RAW (raw ICMP socket). Responses are
**not authenticated**: only ident/seq quoted in the ICMP error are checked, so a spoofed router
response with the right ident/seq would be attributed to a hop (path measurement, not authentication);
a response quoting a slot not yet sent is rejected as a spoof. Malformed/hostile ICMP bytes never
panic — anything unrecognized is `.ignored` and the probe falls through to a clean timeout (`*`). Out
of scope: parallel/all-hops-at-once probing, UDP/TCP trace methods, non-Linux live path, MTU/PMTU
discovery.

**Verification** — Offline-first: the hop state machine runs against a fake transport that builds
canned RFC 792-shaped response bytes (Time Exceeded, Echo Reply, Destination Unreachable, drops, late
replies, load-balanced hops, malformed/hostile input) through the real `icmp.echo` parsers on a
deterministic virtual clock — TTL/ident/seq stamping, terminal-code handling, `*` timeouts,
`distinctAddresses`, per-hop `latency-stats`, IPv4 raw-header shape, IPv6, option validation. One live
test traces `127.0.0.1`, skipped without CAP_NET_RAW.

**Status** — `gap · linux · client · single_owner` · deps: `icmp`, `netaddr`, `latency-stats`.
