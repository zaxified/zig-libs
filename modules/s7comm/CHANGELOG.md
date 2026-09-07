# s7comm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** every one of this module's 15
  fuzz harnesses was replaying a single empty input. Fourteen drew their frame
  as `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(...)`, and a
  `Smith` ranged draw returns the range MINIMUM unless the eight octets it reads
  as a little-endian u64 already lie inside the range — `bytes` had just eaten
  the seed, so the length was 0 every time. They now draw with
  `smith.slice(&buf)` and each carries a corpus of real wire frames, address
  literals or symbolic paths taken from the tests beside it. Measured over those
  corpora, non-empty inputs / inputs the decoder accepts: TPKT 0 -> 11/4, the
  TPKT framer 0 -> 5 fed and 4 packets out, COTP 0 -> 15/6, S7 0 -> 13/4, items
  0 -> 15/12, the data-item iterator 1 -> 6 distinct (block, count) pairs,
  Read/Write Var parameters 0 -> 9/4, userdata 0 -> 12/5, addresses 0 -> 25/19,
  S7CommPlus frames 0 -> 11/3, objects 0 -> 5/2, values 0 -> 6/4, varints
  0 -> 11/8, symbolic paths 0 -> 13/5.
- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** `server.zig`'s responder
  fuzz harness builds a well-formed S7 envelope and spends its entropy on the
  item descriptors, but every knob it drew was a ranged `Smith` draw and so
  returned its minimum: over eight seeds and four requests each it built **32
  requests, 1 distinct, and `Responder.handle` accepted none of them** — so
  `doRead`, `doWrite`, `applyWrite` and `handleUserdata` had no fuzz coverage at
  all, which is the exact hole that harness's own header says it exists to
  close. The knobs are now `value(u64)` reduced locally (`drawBelow`,
  `drawOdds`, `drawWide`) and the test carries a fixed-PRNG seed corpus: **32
  built, 32 distinct, 25 accepted with a reply.** No responder logic changed.

- **2026-08-22** — `TcpTransport` now surfaces `error.Canceled` (a new
  `TransportError` variant) instead of `error.ReadFailed`/`error.WriteFailed`
  when a blocked read or write is interrupted by `std.Io`'s `Future.cancel`.
  Covers both the direct blocking read and the `read_timeout_ms` poll path,
  which is not itself a `std.Io` cancellation point and needed an explicit
  `checkCancel` after the wait to see the request at all.
- **2026-08-06** — Security audit: an unauthenticated 43-byte Read Var request could
  drive an out-of-bounds read one byte past a registered memory area; fixed, along with
  4 further findings.
- **2026-07-23** — New module: Siemens S7 communication — ISO-on-TCP (RFC 1006 TPKT +
  COTP) plus the S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info
  and cyclic services.
