# pping — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `PPING_FUZZ`: `pping-tcp-options` (checked against an independent reading of the option grammar; a genuine Timestamps option behind NOPs/MSS is found with its exact values, behind END it is not), `pping-ip-echo` (a genuine IPv4/IPv6 Echo packet decodes to its identifier, sequence, kind and addresses) and a new `pping-estimator` stream harness (bounded tables, first echo consumed once, sample fields and RTT bounds against a send-time model, genuine round trip yields exactly its RTT, a clock stepping backwards never panics, echo/TCP mixing refused). No source change.
- **2026-10-06** — ADDED: ICMP / ICMPv6 Echo RTT. `parseIpEcho` (IPv4 or IPv6
  packet, extension-header walk capped at 8, typed `EchoParseError`) and
  `parseIcmpEcho` decode Echo Request/Reply (types 8/0, 128/129);
  `Estimator.observeEcho` pairs a request with the reply carrying the same
  (identifier, sequence) back the other way, in the same bounded tables with
  the same aging and capacity eviction, consuming on first match so duplicate
  replies yield nothing; `IpEcho.direction` labels an address pair;
  `matchEchoReply` is the bare core. `RttSample` gained `proto: Proto =
  .tcp_timestamps` plus `echoIdentifier()` / `echoSequence()`. An estimator now
  fixes `traffic` on its first call and refuses (returns `null`, counts
  `observations_refused`) the other kind — **BEHAVIOURAL** only for a caller
  mixing the new echo calls into a TCP estimator; TCP-only use is unchanged.
  Anchored on real iputils `ping` captures (IPv4, including a 65535 -> 0
  sequence wrap; `tools/capture_icmp_echo.sh`); ICMPv6 packets are
  SELF-DERIVED and tcpdump-checked (`tools/icmpv6_crosscheck.py`). New
  `testing.fuzz` harness on `parseIpEcho`. Scope mvp -> core. The `root.zig`
  "Status: complete" wording is replaced by the scope it implements.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: README "Status" reworded from "complete" to the mvp scope it implements; Anchoring names the leftover `gate.fable_core_implemented` switch precisely.
- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — **Test-only: neither golden capture in the fuzz corpus ever
  reached the parser.** `fuzz_corpus` held the two real loopback handshakes as
  raw arrays (`&syn_tcp_options`, `&synack_tcp_options`), and
  `buildTcpOptions` opened with `smith.valueRangeAtMost(u8, 0, 5)`. A ranged
  `Smith` draw reads EIGHT octets as a little-endian `u64` and returns the
  range MINIMUM unless that whole word already lies inside the range — the SYN
  capture's first eight octets read as 0x0a080204d7ff0402, so the draw
  returned 0, took the "pure arbitrary bytes" branch, `smith.bytes(buf)` ate
  the remaining twelve octets, and the ranged length after it found nothing
  left and returned 0. **Both captures arrived at `parseTcpTimestamps` as the
  EMPTY option list** — from a corpus whose entire point is that each frame
  contains a Timestamps option. Measured 2026-09-07: **0 of 2 seeds carried an
  octet and 0 Timestamps options were found.** The harness now makes one
  `smith.slice` draw and reads the seed as a script whose first octet selects
  "the rest is the option list verbatim" (so a capture can be a seed at all)
  or "the rest assembles TLV entries" through `testkit.fuzz.Cursor`. Corpus
  2 → 14, including an END ahead of a genuine Timestamps option, a length of
  0 and of 1 (neither can advance the walk), and an option claiming 255 octets
  inside a 43-octet list. Measured after: **13 of 14 seeds non-empty, 309
  octets walked, 6 Timestamps options found.** The guard pins the sum of the
  TSvals recovered, which neither an empty list nor a mis-walked one produces.

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on
  `parse.parseTcpTimestamps` (the TCP-options TLV decode entry point), TLV-shaped so
  most draws are well-formed-ish option sequences (END/NOP/genuine Timestamps/opaque
  options with a possibly-malformed length byte) rather than bytes rejected at the
  first kind byte. The module already had two 20k/5k-trial LCG-based "fuzz-style"
  tests covering the same never-panics/never-reads-OOB property, but they predate
  `std.testing.Smith` and are invisible to the gate (which greps for `testing.fuzz(`)
  and to `--fuzz`'s coverage-guided corpus growth — left in place, not superseded. No
  panic, hang or OOB read found.
- **2026-08-13** — Test-only: `src/match.zig`'s single test — `test "match:
  file is reachable from the build"`, body `try std.testing.expect(true);` —
  was replaced by one that pins step 5a's aging sweep of the SAME-direction
  table. **Neither BREAKING nor BEHAVIOURAL** — no production code changed.
  The old test could not fail, and its stated premise had gone stale: it
  described `matchEcho` as a gated stub, but `gate.fable_core_implemented` is
  `true` and `kat.zig`/`property.zig` drive the real function. Its anchoring
  claim was redundant too — `root.zig` imports `match.zig` for the re-export
  and again in its aggregation `test`. The gap it was hiding, measured before
  the replacement was written: deleting `_ = same_dir.evictOlderThan(...)`
  from `matchEcho` left all 56 tests green, because every `kat.zig` scenario
  observes aging only through a match that no longer happens, and a direction
  whose TSvals are never echoed produces no match to observe. The new test
  feeds a stalled direction well under `capacity` and requires the entries to
  be gone once `max_age` passes, including on a call that neither matches nor
  inserts. Proven by mutation: that same deletion now fails 1 of 56, this
  test, `expected 1, found 4`.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Kathleen Nichols'
  pping (Pollere LLC, C) — RFC 7323 §3 TCP Timestamps (design reference, not a test
  anchor).
- **2026-07-15** — New module: Passive RTT estimation from TCP TSval/TSecr echo matching
  (RFC 7323 / Pollere pping).
