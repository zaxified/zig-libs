# bacnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: the service layer converted wire-supplied 64-bit
  integers to narrower types with an unguarded `@intCast` at roughly 15 sites, which a
  crafted request could turn into a crash or a misdecode; fixed, plus one follow-up
  finding (an unbounded default lifetime on an unauthenticated peer's COV subscription,
  also fixed).
- **2026-07-23** — New module: BACnet building automation over BACnet/IP and BACnet/SC.
