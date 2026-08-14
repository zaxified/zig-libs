# probe — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
Pure engine behind a `Connector` seam: all connect I/O goes through `connectFn(target,
timeout_ns) -> ConnectOutcome`, so classification, repetition, aggregation and fan-out are fully
offline-testable against a scripted fake — tests never open a socket. Two live connectors:
**`PosixConnector` (recommended)** — non-blocking socket, `connect()` → `EINPROGRESS`,
`poll(POLLOUT)` bounded by the caller's remaining budget, `getsockopt(SO_ERROR)` for the verdict, so
`timeout_ns` is a **real per-attempt timeout** on the wall clock; and `LiveConnector` — the portable
`std.Io.net` path (connect, measure, immediate close), which cannot abort a connect and applies the
budget to the result only. `SO_ERROR` is authoritative, never `POLLOUT` alone: a refusal arrives as
`POLLOUT|POLLERR|POLLHUP` with `SO_ERROR=ECONNREFUSED` (measured `revents=0x1c`, `SO_ERROR=111`), and
`refused` must never be reported as `timeout`. The remaining budget is recomputed from
`CLOCK_MONOTONIC` on every poll iteration, so `EINTR` and short polls cannot multiply the timeout by
the host's signal rate; the socket is closed on every exit path by one `defer` after `socket()`; IPv4
and IPv6 both work (no v6 scope/zone). `PosixConnector` is Linux (Zig 0.16 moved the socket wrappers
out of `std.posix`, so a libc-free build reaches them only through `std.os.linux`); the engine and
`LiveConnector` are portable. Three layers: `probeTcp` (one attempt,
never allocates/panics), `probeTarget` (N reps aggregated via `latency.Accumulator`, every non-`up`
rep counted as loss), `probeMany` (a target list, order-stable). Bounded concurrency: `probeMany`
deals work via an atomic next-target counter; the calling thread plus up to `max_concurrent - 1`
helper threads each own disjoint `TargetResult` slots, so no locking is needed and in-flight
connects never exceed `max_concurrent`; degrades to inline on one thread if spawning is
unavailable, and never spawns more than `max_workers = 256` helpers no matter what `max_concurrent` says — the ceiling is the module's, not the caller's, so an aggressive config over a `max_targets` list cannot ask the OS for tens of thousands of threads (it degraded gracefully when the OS refused, which is a weaker property than never asking). Counts bounded (`max_repetitions = 4096`, `max_workers = 256`, `max_targets`). Error policy: a malformed
`host:port` is a typed `Target.ParseError` (Go `SplitHostPort` semantics via
`netaddr.parseHostPort`, port required, `[v6]:port` supported); a DNS/connect failure is an
`error` `Result`, never a panic. Optional `AppCheck` runs after a handshake and downgrades
`up`→`error` on a failed app-level check. Platform: `any` — the engine is pure and only the
connectors touch the OS; `PosixConnector`'s Linux-only syscalls are analysed only if that connector
is referenced, so a non-Linux consumer using `LiveConnector` still builds. Clean-room; the
TCP-connect reachability technique is a standard,
decades-old approach (nmap's `-sT`, fping's parallel sweep) — behavior modeled only, no
third-party source consulted or copied; there is no `probe` entry in NOTICE (nothing derived
requires attribution). Deps `netaddr` + `latency-stats` are sibling modules.

## Threat model / out of scope
Not a security scanner and not privileged (an ordinary TCP connect; no raw sockets, no SYN/stealth
scan). Does not authenticate the peer — `up` means a handshake completed, not that the intended
service answered (use `AppCheck` for an app-level assertion). **Name resolution is outside the
budget, in both connectors** — `poll` bounds the connect and nothing else. std's Linux resolver is
pure-Zig (it bypasses libc `getaddrinfo`), short-circuits IP literals, then `/etc/hosts`, then RFC
6761 `localhost`, and only then queries DNS, bounded by its own deadline: `options timeout:` from
`/etc/resolv.conf`, **default 5 s** (`attempts` divides that span, it does not multiply it). So a
1 s probe of a name whose nameserver is dark blocks ~5 s. `PosixConnector` states the boundary
rather than hiding it: `Resolve.literal_only` never calls a resolver at all (wall clock = the
budget), `Resolve.system` **charges** the lookup against the budget — measured, subtracted, and a
lookup that alone exceeds the budget returns `.timeout` without connecting — which makes the
*classification* honest but not the wall clock. An IP literal never reaches the resolver in either
mode. `LiveConnector` on `timeout_ns`: **advisory** for a different reason — `std.Io.Threaded`
panics if a connect timeout is passed, so the attempt blocks for the OS default (measured 134 367 ms
for a 200 ms budget) and only the result respects the budget. That is a property of that backend,
not a reason for `probe` to be unbounded; `PosixConnector` is the answer. Out of scope: UDP/ICMP
probing, banner grabbing, TLS/protocol handshakes, port-range sweeping, IPv6 zone/scope ids.

## Verification
Offline-first: a scripted fake `Connector` on a virtual clock drives every path — per-outcome
classification, N-rep min/avg/max + loss%, `AppCheck` downgrade, `Target.parse` KATs (incl.
`[v6]:port` and typed-error negatives), and a 50-target fan-out asserting order stability, one call
per target, and `max_in_flight <= max_concurrent`.

The timeout claim cannot be tested that way, so `PosixConnector` is driven by live tests that stay
on loopback (hermetic, no netns needed — a fresh namespace starts with `lo` down, the same reason
`icmp`/`traceroute` are excluded from `NETNS_MODULES`). The hard case is a **black hole**, a
destination that neither completes nor refuses: `listen(fd, 1)` plus enough never-accepted connects
fills the one-slot accept queue, after which Linux drops the incoming SYN (`sk_acceptq_is_full`) and
the client retries for `tcp_syn_retries` rounds (~127 s). Verified on this kernel before being
relied on — closed port 0.1 ms `revents=0x1c`/`SO_ERROR=111`, empty queue 0.1 ms `revents=0x4`, full
queue hung through both a 200 ms and a 3 000 ms poll — and re-asserted every run, since a one-second
budget that still returns `.timeout` is something neither a listening peer nor a closed port can
produce on loopback. Measured: **200 ms budget → 200.3 ms, 1 000 ms budget → 1 000.9 ms**, refused
0.041 ms under a 5 s budget, up rtt 0.050 ms, 8 black-holed targets fanned out at a 200 ms budget →
202.4 ms total. The contrast is the evidence: the same black hole and the same 200 ms budget through
`LiveConnector` on an abandoned thread is **still blocked after 2 000 ms** (run to completion once
outside the gate: 134 367 ms). A signal-storm test (`tgkill` every 10 ms for 600 ms, no `SA_RESTART`)
pins that `EINTR` recomputes the remainder instead of restarting the budget: 200.7 ms with 20
signals delivered. Run: `zig build test-probe`.

## Backlog / deferred
Name resolution is not bounded by `timeout_ns` and cannot be by a `poll`-based connector — see the
threat-model section for what each `Resolve` mode does and does not promise. `LiveConnector`'s
advisory `timeout_ns` stays advisory: `std.Io.Threaded` panics on a connect timeout, and the fix is
to use `PosixConnector`, not to wait for std. UDP/ICMP probing, banner grabbing, TLS/protocol
handshakes, port-range sweeping and IPv6 zone/scope ids are explicit out-of-scope items.

## Status
`gap · any · client · single_owner` + deps: `netaddr`, `latency-stats` — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** TCP connect timing via std connect(); no wire codec of its own
