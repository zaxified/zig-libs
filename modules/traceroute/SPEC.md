# traceroute — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Pure engine behind a `Transport` seam: `traceWith` is the hop state machine over an injectable
transport (`sendFn` with TTL / `recvFn` bytes + source / `nowFn` clock), fully offline-testable from
canned packet bytes on a virtual clock; `LinuxTransport` + `trace` are the live path. Correlation over
a bounded flat slot scheme: each probe's wire sequence is `seq_base +% slot` (slot =
hop·probes_per_hop + probe); a response — even one arriving after its probe already timed out — maps
back to its slot via the ident/seq quoted inside the ICMP error (parsed by `icmp.echo.parseV4/V6`),
so late replies land in the right hop. Sequential: one probe in flight, like traceroute(8)'s default —
the state machine stays simple and every RTT is unambiguous. Hop count and probes-per-hop are bounded
(`Options.validate`; `max_probes_per_hop = 16`, `max_payload = 1024`). Allocation: `Trace` owns
exactly two slices (`hops`, `probes`), sized to the used prefix and freed by `deinit`; per-hop
`stats()` uses fixed stack scratch (via `latency-stats`). Live path is Linux + raw only: DGRAM
("ping") sockets deliver ICMP errors on the error queue, not as packets, so raw is required
(CAP_NET_RAW); per-probe TTL via setsockopt IP_TTL/IPV6_UNICAST_HOPS; ppoll for the timeout.
Clean-room from the classic traceroute(8)/mtr ICMP method (Van Jacobson's TTL-stepping applied to
ICMP Echo — a public technique) and RFC 792 ICMP formats via the sibling `icmp.echo` codec — see
NOTICE.

### A transport failure returns a partial `Trace`, not just an error

`traceWith` used to propagate a `sendFn`/`recvFn` failure with `try`, which discarded every
hop already collected — for a traceroute, eight good hops then a broken socket is most of the
answer, not a failure to report as opaquely as a caller mistake. Zig has no error payloads, so
carrying the partial result out alongside the error needed a shape decision:

- **Considered and rejected: an out-parameter** (`traceWith(gpa, t, dest, opts, partial: ?*Trace)`).
  Works, but it is a second way to receive a `Trace` bolted onto the existing one, and every
  caller — including every offline test in this file — would need to thread a pointer through
  whether or not it cares.
- **Considered and rejected: split the return into `struct { trace: Trace, err: ?TransportError }`
  with no Zig error at all.** This erases the real distinction between "a partial trace, because
  the transport broke mid-run" and "no trace at all, because `Options` were invalid or the initial
  allocation failed" — `InvalidOptions`/`OutOfMemory` happen before a single probe is sent, so
  there is nothing to hand back for them, and forcing every caller to unwrap a `Trace` value for
  those cases too would manufacture a fake one.
- **Chosen: extend `Trace` with a `transport_err: ?TransportError` field, and narrow `TraceError`
  to `error{ InvalidOptions, OutOfMemory }`.** This follows the module's own existing shape:
  `Trace` already records *how* a trace stopped as data (`reached`, `unreachable_code`), not as a
  distinct error per termination mode — a transport failure is simply a third way to stop early,
  and was the odd one out for using the `!` channel instead of a field. `sendFn`/`recvFn` failures
  are now caught inside `traceWith` (`catch |err| { transport_err = err; break :outer; }`) instead
  of propagated with `try`, so the function falls through to the same hop-packing code every other
  termination path already uses, and returns a `Trace` whose `hops`/`probes` hold whatever was
  collected up to the failure. The genuine no-partial-data cases (`InvalidOptions`, the initial
  `gpa.alloc` before any probe exists) keep the ordinary Zig error channel — nothing to carry
  alongside them either way.

**`hops_used` on a send failure.** A failure on a hop's first probe (`pi == 0`) means nothing
about that hop was ever attempted, so it is excluded from `hops_used` (set to `hi`, not `hi + 1`)
— otherwise the returned `Trace` would contain a hop whose every probe reads `.timeout` despite
none of them having been sent, indistinguishable from a hop that really was probed and got no
answer. A failure on a *later* probe of the same hop (or any `recvFn` failure, which by
definition follows a successful send) leaves `hops_used` as already set — that hop did get at
least one real attempt, the same way an `unreachable_code` stop mid-hop keeps the hop it stopped
in (see `wire.zig`'s sibling test "destination unreachable terminates and records the code").

**BREAKING for a caller that matched `TraceError`/`TransportError` on `traceWith`'s return.** A
`try traceWith(...)` or `catch |err| switch (err) { error.SendFailed, error.RecvFailed => ... }`
no longer compiles/fires for those two — the same failure now arrives as `tr.transport_err` on a
successful return. See CHANGELOG.md.

## Threat model / out of scope
The live trace needs CAP_NET_RAW (raw ICMP socket). Responses are **not authenticated**: only
ident/seq quoted in the ICMP error are checked, so a spoofed router response with the right ident/seq
would be attributed to a hop (path measurement, not authentication); a response quoting a slot not
yet sent is rejected as a spoof. Malformed/hostile ICMP bytes never panic — anything unrecognized is
`.ignored` and the probe falls through to a clean timeout (`*`). Out of scope: parallel/all-hops-at-
once probing, UDP/TCP trace methods, non-Linux live path, MTU/PMTU discovery.

## Verification
Offline-first: the hop state machine runs against a fake transport that builds canned RFC 792-shaped
response bytes (Time Exceeded, Echo Reply, Destination Unreachable, drops, late replies, load-
balanced hops, malformed/hostile input) through the real `icmp.echo` parsers on a deterministic
virtual clock — TTL/ident/seq stamping, terminal-code handling, `*` timeouts, `distinctAddresses`,
per-hop `latency-stats`, IPv4 raw-header shape, IPv6, option validation. One live test traces
`127.0.0.1`, skipped without CAP_NET_RAW. Run: `zig build test-traceroute`.

## Backlog / deferred
None beyond the documented out-of-scope list (parallel probing,
UDP/TCP methods, non-Linux live path, MTU/PMTU discovery).

## Status
`gap · linux · client · single_owner` + deps: `icmp`, `netaddr`, `latency-stats` — canonical source
is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** canned ICMP fixtures (SELF); loopback live test skips without CAP_NET_RAW

**How it got there.** The anchoring work landed. DONE 466cc70: real 2-hop veth router; Time Exceeded from a real TTL decrement
