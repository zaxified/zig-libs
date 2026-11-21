# bacnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — ADDED `WritePropertyMultiple`, `DeviceCommunicationControl`, `ReinitializeDevice`, `TimeSynchronization` and `UTCTimeSynchronization`: codecs in `service` (`WpmRequestBuilder`, `WpmRequestIterator`, `PropertyWrite`, `FirstFailedWrite`, `DeviceCommunicationControl`, `CommunicationState`, `ReinitializeDevice`, `ReinitializedState`, `TimeSynchronization`), `Client.writePropertyMultiple` / `deviceCommunicationControl` / `reinitializeDevice` / `timeSynchronization`, and the matching device handlers with `Config.password`. **Source-breaking:** `device.Event` gains `wrote_multiple`, `communication_control`, `reinitialize` and `time_synchronized` (an exhaustive `switch` over it needs the new prongs). **Behaviour change:** the Error PDU of `write_property_multiple` is encoded with class and code inside `[0]` as the standard's `WritePropertyMultiple-Error` requires (the plain pair still decodes); `client.Event.err` gains `extra`. A device with initiation disabled sends no unsolicited I-Am (`announce`).
- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** `zig fmt` (0.17) rewrote `@intFromEnum`/`@enumFromInt` to `@backingInt`/`@fromBackingInt` in sources and tests; same values, same behaviour.
- **2026-10-18** — Ported to Zig 0.17.0 (`EnumSet.initEmpty()` -> `.empty` in `goldens.zig`).
- **2026-10-11** — build fix for websocket's grown `frame.WriteError` (`CompressedNonDataFrame`, permessage-deflate): `sc_ws.writeMessage`'s exhaustive switch names it as unreachable (always one uncompressed binary frame). No behaviour change.
- **2026-10-10** — tests: deterministic fuzz driver `BACNET_FUZZ` over the existing harnesses (now generic over their choice source; the driver draws a corpus entry with 0-3 octets damaged, maybe truncated) with an in-suite reach test per harness. Fourteen harnesses (apdu, bvll, device, npdu, sc decode/options, sc hub, sc node, service, service integers, tag skip/appValue/openedBlock/headerRoundTrip). Verdict: 200,000 runs each, ReleaseSafe, clean.
- **2026-10-05** — Mutation run: 26 of 43 killed, 0 equivalent; 7 tests added
  and 8 existing tests extended (fixed-size BVLC bodies one octet long, ragged
  Write-BDT and `bdtIterator` bodies, the u16 length on encode, DLEN one past
  the buffer, trailing octets on two network messages and SegmentACK, `skip`
  at a foreign closing bracket, day 0 / second 60, a wide context enumeration,
  the Confirmed-Request reserved bit, `forOctets(206)`, an SC option one octet
  short, `max_options + 1`, invoke-id wrap onto a live transaction). All 43
  killed after. No library code changed.



- **2026-09-04** — **The live device-side test reported PASS when
  `BACNET_TEST_LISTEN` was unset**, announcing a skip and then returning
  plainly, which `zig test` counts as a pass. Now `return testkit.skip(...)`.
  Found by the first audit of `testkit`.

- **2026-08-22** — `UdpTransport`'s send/receive paths were collapsing a
  `std.Io` cancellation (`error.Canceled`, carried directly in
  `Socket.SendError`/`ReceiveError`) into `error.SendFailed`/`RecvFailed`, so a
  caller torn down mid-`recv` (e.g. a poll loop's owning task canceled) could
  not tell "the socket broke" from "someone asked us to stop waiting". Added
  `TransportError.Canceled` and stopped the flattening on both paths; the
  existing `error.Timeout => return null` behavior of a bounded receive is
  unchanged. `LoopTransport` is unaffected — it never blocks.
- **2026-08-11** — Security audit: the service layer converted wire-supplied 64-bit
  integers to narrower types with an unguarded `@intCast` at roughly 15 sites, which a
  crafted request could turn into a crash or a misdecode; fixed, plus one follow-up
  finding (an unbounded default lifetime on an unauthenticated peer's COV subscription,
  also fixed).
- **2026-07-23** — New module: BACnet building automation over BACnet/IP and BACnet/SC.
