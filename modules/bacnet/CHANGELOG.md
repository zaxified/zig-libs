# bacnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** all 14 fuzz harnesses in
  this module were replaying a single empty input. Each drew its frame as
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`,
  and a `Smith` ranged draw returns the range MINIMUM unless the eight bytes it
  reads as a little-endian u64 already lie inside the range — `bytes` had just
  eaten the seed, so the length was 0 every time. They now draw with
  `smith.slice(&buf)` and each carries a seed corpus of real wire frames lifted
  from the tests beside it. Measured over those corpora: BVLC 0 -> 12 non-empty
  (9 decode), APDU 0 -> 13 (11), NPDU 0 -> 11 (6), tag streams 0 -> 13 (11
  whose first tag `skip` accepts), tag headers 0 -> 10 (10), BVLC-SC 0 -> 17
  (12), option lists 0 -> 11 (9), service bodies 0 -> 19 (16 accepted by at
  least one of the ten decoders), service integers 3 -> 19 distinct
  (width, arm) pairs, device datagrams 0 -> 12 (8 past the BVLC header),
  hub 0 -> 24 frames, node 0 -> 32 frames. No `pub` declaration, no decoder and
  no encoder changed; the module's behaviour is identical.

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
