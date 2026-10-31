# traceroute — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-31** — **CONSUMER-VISIBLE (additive):** `MtrSet` / `LiveMtrSet`, continuous mode for many destinations of one family over one transport (`Transport.sendToFn`, new and optional; `LinuxTransport` provides it for the ICMP method). Shared path prefixes: TTLs where members do not contradict each other, up to the last router both settled on (`MtrSetOptions.settle_rounds`), get one probe per round from the lowest member and every sharer records its answer; each member probes its whole path itself every `verify_every` rounds. Members are `Mtr`s (`Member.mtr`, `Member.sharedLastRound()`). `Mtr.round`'s bookkeeping is now `Mtr.finishRound` (internal, unchanged behaviour). Tests: offline network with per-destination routes and a router answering once a second, a live test over a ping socket to two loopback addresses, a fourth fuzz harness `traceroute-mtrset` (driver 50k seeds clean, a planted mutant found at seed 0). Fix in the fuzz driver test: a harness left out by `TRACEROUTE_FUZZ_ONLY` used to skip the harnesses after it too.

- **2026-10-31** — **CONSUMER-VISIBLE (fixes, review of the `Mtr` commit):** a round retried after a transport failure gets a fresh sequence window (`Mtr.windows`; it used to reuse the failed round's, so a late answer to an aborted probe could be counted with a too-short RTT); `round` re-validates `opts` (a public field) and fails with `SendFailed` instead of reaching an out-of-range slice. The spurious send failures after a router's ICMP error (a pending socket error, frequent in a round with many probes in flight) are fixed in `icmp.Socket.sendTo`.

- **2026-10-31** — **CONSUMER-VISIBLE (additive):** continuous mode, mtr style. `Mtr` (`init`/`round`/`hops`/`lastRound`/`reached`/`reset`) over any `Transport`, and `LiveMtr` over its own socket (unprivileged on a ping socket). One probe per TTL per round, `gap_ms` apart; per-hop `MtrHop` running statistics (loss, last/avg/best/worst, jitter, responders, unreachable code); answers only within their own round; rounds at least `interval_ms` apart, enforced by `round` itself (floor `min_mtr_interval_ms` = 100, `timeout_ms` ≤ 10 s). See SPEC "Continuous mode".

- **2026-10-31** — **CONSUMER-VISIBLE (additive):** traceroute without privilege. `Options.socket` (`SocketKind`: `.auto` = raw when the process may, else an unprivileged ping socket; `.raw`; `.dgram`) — the ICMP method now works over a ping socket, whose error queue the transport reads and rebuilds into the RFC 792 message the engine already parses (`errQueuePacket`; MPLS labels are not available there). `trace` uses the ping socket's kernel-assigned ident. `validate` refuses `.udp` with `.dgram`. Kernel oracle: 8 more real-router traces (`icmp-dgram`, v4/v6) agree with the topology and traceroute(8); `Scenario` gained `strip_ip_header`. Internal: the ICMP answer rules moved into `classifyIcmp`, shared with the coming continuous mode.

- **2026-10-31** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the § GX sweep — new tests only (error-queue drain bound, readable-datagram return, the receive loop's wakeup count and CPU time), in a test block at the end of `root.zig`.

- **2026-10-31** — **BEHAVIOURAL, not breaking:** no-panic sweep + blind review (§ GX). `LinuxTransport` drains the socket error queue on every wakeup (IP_RECVERR, set by `icmp.Socket.open`, left POLLERR raised after the first ICMP error → `ppoll` returned at once and the receive loop spun on a full CPU until the probe deadline; measured 520k wakeups in 2 s); `Hop.stats` streams through an `Accumulator` (was a 16-entry scratch); `Hop.distinctAddresses` truncates to the caller's buffer (was `assert`); the probe deadline saturates on a clock near maxInt(u64).

- **2026-10-18** — Ported to Zig 0.17.0. `sockaddr.in.addr` <-> `[4]u8` use `std.mem.bytesToValue`/`toBytes` (memory order; an array `@bitCast` is little-endian-logical in 0.17). Examples/tools ported to Zig 0.17.0 (tools/interop.zig: `dupeZ` -> `dupeSentinel`, `Ast.parse` options struct).

- **2026-10-09** — tests: deterministic fuzz driver `TRACEROUTE_FUZZ` over the existing harness (the hop state machine on arbitrary and on damaged ICMP packet streams); `testkit` added to its test deps.

- **2026-10-05** — **Anchoring: real routers judge `trace`, and `traceWith` replays their packets**
  (`tools/kernel_oracle.py`, `tools/interop.zig`, `src/kernel_oracle_test.zig`): 16 live traces through a client ->
  r1 -> r2 -> r3 -> server chain of network namespaces (`unshare -rmn`) -- clean, a router dropping its Time
  Exceeded, a router rejecting with Administratively Prohibited, a server dropping everything -- ICMP and UDP, v4
  and v6. Every hop is what the topology puts at that TTL, and traceroute(8) traced the same. The transport is
  recorded on a virtual clock and replayed offline. Anchor grade MIXED → EXTERNAL.
  - **DEFECT fixed, BEHAVIOURAL:** a Destination Unreachable stopped its hop after the first probe and left the
    rest `.timeout` -- a `*` (and a loss in `Hop.stats`) for probes never sent, where traceroute(8) prints `!X`
    for each. The terminal hop now gets its full probe count, like the destination's hop.
  - **New (Additive):** `Options.source_port` -- the UDP method's source port (traceroute(8)'s `--sport`), instead
    of a kernel-chosen ephemeral one; still the correlation token.

- **2026-10-04** — mvp → core (survey 2026-09-30 items: UDP method, MPLS/ICMP extensions,
  source/interface/TOS). ADDED `Options.method` (`.icmp` default, `.udp` = traceroute(8)'s
  classic UDP-to-33434+ probes, matched on the quoted source port + destination port + quoted
  destination; the destination's own Port Unreachable is the `.reply`), `Options.udp_port_base`,
  live-only `Options.iface`/`.source`/`.tos`/`.fwmark` (`LinuxTransport.openWith`),
  `Transport.sendUdpFn` (optional; a transport without it refuses `.udp`), `Probe.mpls`
  (`MplsStack` of `MplsEntry`) from RFC 4884 extensions (length field, or the 128-byte
  compatibility position only with a verified checksum), `extensionObjects`, `mplsOf`. Anchored
  on real kernel replies from a veth router sandbox and an MPLS extension tcpdump decodes as
  "checksum … (correct)". FIXED (test only): the live ICMP test failed instead of skipping in a
  fresh netns with `lo` down. ⚠ `LinuxTransport.OpenError` (and so `LiveTraceError`) gained
  `UdpSocketFailed` — only an exhaustive `switch` notices (axp's has `else`). Mutation: 29
  mutants, all killed (13 after new, rule-isolating tests).

- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, follow-up closing the
  three findings left open by the same day's earlier fix wave below (F3, F4, F10 — all
  three blocked on the sibling `icmp` module, which gained the needed field and check
  today too; see `icmp.md`/`traceroute.md` dispositions). `traceWith`'s `.icmp_error`
  branch now also requires the quoted destination inside the error to equal `dest`
  before attributing it to a hop — an ICMP error quoting a DIFFERENT destination than
  the one being traced (forged, or a stale reply from an unrelated concurrent trace
  sharing the guessable ident/seq window) is now ignored instead of resolving the hop.
  No public signature changed. `icmp.echo.parseV4` verifying the receive-side checksum
  (icmp F7) also closes this module's own F4 for free, and F10 is closed the same way
  icmp closed its own F15: documented, not coded.
- **2026-09-10** — A1 fix campaign, 6 of 12 open findings closed (3 more documented as
  out-of-scope for this module; see SPEC.md "Threat model"):
  - **F1 (HIGH)**: an Echo Reply now must carry the destination's own source address to
    complete the trace (`reached = true`). Before this, a single spoofed Echo Reply from
    ANY address with the right ident+seq truncated the whole trace to one hop attributed
    to the spoofer.
  - **F2 (HIGH)**: `trace()` now draws a fresh random ident and starting sequence per call
    via `getrandom(2)`, instead of the raw socket's PID-derived identifier (measured:
    ~99.8% of neighboring processes' idents differed by exactly 1) and the fixed
    `seq_base = 1` default (always 1, 2, 3, …). Same posture as the sibling
    `pathmtu.randomStartSeq` (CONVENTIONS.md §2.2): not a secret, so a `getrandom` failure
    falls back to the old fixed values.
  - **F5 (MED)**: two new regression tests isolate the "foreign ident" and "not yet sent
    slot" correlation guards from each other — the previous test suite could not tell a
    mutation that deleted either guard from a passing suite, because both existing tests
    happened to be caught by the OTHER guard instead.
  - **F6 + F8 (MED)**: `Options.validate()` now bounds the worst-case wall-clock time of an
    entire run (`max_run_ms`, 30 minutes), not just each field (`max_hops`,
    `probes_per_hop`, `timeout_ms`) individually — the worst individually-legal combination
    was ~202,817 days and ~4.2 MB toward one address with no rate limit.
  - **F9 (LOW)**: added a corpus-seeded `testing.fuzz` test over the full hop state machine
    (previously zero fuzz harnesses existed for this module).
  - **F12 (LOW)**: a probe slot that already has a real answer now keeps it — the first
    non-timeout write wins, not the last. Before this, a duplicate or spoofed packet for an
    already-resolved slot silently overwrote its recorded address and RTT.
  - **Docs**: SPEC.md "Threat model" documents the destination-validation stance (F7 — no
    validation, by design for a diagnostic tool; callers facing an untrusted destination
    must apply their own `netaddr` checks) and cross-references the two findings whose root
    cause is the sibling `icmp` module's shared parser (F3, F4/F10 — the quoted IP header
    inside an ICMP error is parsed and discarded before this module ever sees it, and the
    receive path never verifies the ICMP checksum). README.md gained the same
    not-authenticated caveat SPEC.md already carried (F11).
  - Still open: F3 (HIGH, quoted-header comparison — blocked on `icmp`), F4 (MED, receive
    checksum — blocked on `icmp`), F10 (LOW, quoted-type / ICMPv6-collision acceptance —
    blocked on `icmp`).
- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-08-22** — Adjusted to `icmp.echo.writeEchoRequest` reporting a short buffer.
  The probe slice cannot be short, and the impossible branch panics rather than using
  `unreachable`, which is undefined behaviour in the release modes — the same fail-open
  shape the new signature exists to remove.
- **2026-08-18** — Portability: `linux32` (`mips-linux-musl`, `mips32,soft_float`)
  compile fix, no behavior change. `FakeTransport.sendImpl` (the offline test
  injector's `.time_exceeded_multi` path) indexed `routers` with a bare
  `probe_index % routers.len`, where `probe_index` was `u64` — narrows without
  an explicit cast, which 0.16 rejects for a 32-bit `usize` target.
  `probe_index` is `(f.sends - 1) % 16`, provably in `[0, 16)` regardless of
  how large `f.sends` (a trace's total probe count, genuinely unbounded) gets,
  so the fix casts `probe_index` itself down to `usize` right after the `% 16`
  with a comment recording the bound — not a blanket `@intCast` at the index
  site, which would have silently truncated `f.sends` instead. Test-injector-only:
  `LinuxTransport` (the real send/recv path) has no such narrowing.
  `zig build portable-traceroute-linux32` now succeeds.
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
