# bacnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
