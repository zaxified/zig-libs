# s7comm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — **Behaviour change (source-breaking for code naming the type):** `TcpTransport` bounds its reads with `io.operateTimeout` through its own `std.Io.Reader` instead of `poll(2)` on the raw descriptor, so a simulated `std.Io` (a deterministic simulation, a test `Io`) sees the wait and a cancel ends it at once. Under `std.Io.Threaded` the results are the same. The header read now also fails with `ReadFailed` when the peer stops mid-header (every underlying read waits at most the timeout). The public field `reader` is now a private `TimedReader` instead of `std.Io.net.Stream.Reader`.
- **2026-11-21** — Block services (userdata group 3): `Client.listBlocks` / `listBlocksOfType` / `getBlockInfo`, `userdata.BlockType`, `BlockCounts`, `BlockEntry`, `BlockInfo` (78-octet record) and the request-payload codecs; multi-PDU Userdata answers: `Client.readSzlAll` and the follow-up exchange (`Client.max_fragments`, `SzlResponse.decodeFirstFragment`); responder `Config.blocks` (plus every bound DB area) and `Config.max_userdata_payload` (answers longer than one PDU go out fragmented). **Source-breaking:** `client.Error` gains `TooManyFragments`, and `userdata.Error` (hence `client.Error` and `server.Error`) gains `BadBlockList` and `BadBlockInfo`; an exhaustive `switch` over them needs the new prongs. **Behaviour change:** `Client.readSzl` on the first PDU of a fragmented list used to fail with `error.BadSzl` (the header promised records that were not there) and now returns the whole records that arrived with `partial = true`; group-3 requests to the responder used to be `error.Unsupported` and are now answered. Interop: python-snap7 3.1.0's client lists blocks and reads block info against the responder (`tools/snap7_client_drive.py`).
- **2026-11-19** — Security services (userdata group 5): `Client.setSessionPassword` / `clearSessionPassword` (new `error.PasswordRejected` for error code `0xD602`), `Client.readProtection` (SZL `0x0232` index 4), `userdata.SecuritySubfunction`, `ErrorCode`, `encodePassword` / `decodePassword`, `Protection` + `protectionFrom`, root `Protection`. Responder: `Config.password` (checked in constant time, `Responder.legitimated`) and `Config.protection`; with neither set nothing changes for existing users except that group-5 requests, previously `error.Unsupported`, are now answered. Request bytes match gos7 (BSD-3) and gos7 was run against the responder (`tools/gos7_client_drive`). Tests: gos7 goldens, malformed and unknown requests, reply-shape checks, protection record bounds; fuzz harnesses extended (200,000 runs clean); independent review (fixes: legitimation per connection, octet-string and request-type checks, full reply sub-header required, stack copies of the encoded password wiped); delta mutation 33/33 killed.
- **2026-11-19** — Delta mutation of the time-of-day code: 57 mutants, 12 survived and were killed by new tests (reply tampering via the paired-transport test hook, request bytes pinned, subfunction 0x04, sequence echo, invalid clock value); 57 of 57 killed. No library code changed.
- **2026-11-19** — Time-of-day services (userdata group 7): `Client.readClock`/`setClock`, `userdata.DateTime` (10-octet BCD, every digit and range validated, `error.BadDateTime`), `userdata.TimeSubfunction`, responder `Config.clock` (`server.Clock`, caller-supplied `now`/optional `set`; no system time). Additive; no behaviour change for existing calls (a Userdata group-7 request used to be `error.Unsupported` from `handle`, now it is answered).
- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** `zig fmt` (0.17) rewrote `@intFromEnum`/`@enumFromInt` to `@backingInt`/`@fromBackingInt` in sources and tests; same values, same behaviour.
- **2026-10-18** — Ported to Zig 0.17.0. Test: `EnumSet(..).empty` for `initEmpty()`.
- **2026-10-10** — tests: deterministic fuzz driver `S7COMM_FUZZ` over the existing harnesses (now generic over their choice source; the driver draws a corpus entry with 0-3 octets damaged, maybe truncated) with an in-suite reach test per harness. Fifteen harnesses (address, cotp, items item/dataItems, s7 decode, s7plus frame/object/path/value/var, server handle, tpkt decode/framer, userdata, vars). Verdict: 200,000 runs each, ReleaseSafe, clean.
- **2026-10-05** — Mutation run: 25 of 43 killed, 1 equivalent; 3 tests added
  and 8 existing tests extended, nearly all at a one-past boundary (TPKT total
  65536 and one octet short, framer overflow and partial packet, a COTP
  parameter and `LI` one long, an 11-octet Ack-Data, a 2^24 element address,
  a short item, a 9-bit bit length, responder writes past the area or shorter
  than their item, an empty V3 integrity part, a connect frame's trailing
  octet, an over-long VLQ with a small value, an `i8` below its minimum). 42
  of 43 killed after. No library code changed.


- **2026-09-10** — **BREAKING** for `s7plus_value.skipValue`/`skipBody` (new
  required `budget: *u32` parameter; `skipValueDefaultBudget` added for the
  old single-call behaviour) — no in-repo caller outside this module, so
  nothing here needed updating. **BEHAVIOURAL, not breaking** for everyone
  else: A1 audit findings F1-F14 closed. Of note for `Responder` (`fleetsim`'s
  consumer): a Read/Write Var request with a known function but a body too
  short to parse now gets the same typed error reply an unknown function code
  already got, instead of no reply at all (F8); a COTP `DT` with `EOT = 0`
  (a fragment) now gets no reply instead of being processed as if it were the
  whole request (F12); a bit-item reply now pads the item before it when
  needed (F3, a wire-format correctness fix). `client.Error` gained
  `ReplyExceedsNegotiatedPdu` and `CotpReferenceMismatch` (additive); a
  hostile S7CommPlus `CreateObject` reply no longer panics or silently
  truncates a session id (F1); `TcpTransport`'s read timeout now bounds a
  packet body, not just its header (F2); `userdata.DataBlock.decode` now
  refuses a bit-counted length that isn't a whole number of octets instead of
  silently floor-dividing it (F9); `tpkt.Framer.feed` no longer recompacts its
  buffer on every call (F10, perf only). Full detail and RED->GREEN.



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
