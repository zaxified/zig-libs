# traceroute — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
