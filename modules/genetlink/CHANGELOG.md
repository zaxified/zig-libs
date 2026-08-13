# genetlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: no findings. Verified:
  `buildGetFamilyRequest("wireguard")` is anchored by a hand-derived golden 36-byte
  vector matching kernel UAPI (`root.zig:332-348`), incl.
- **2026-07-14** — New module: Generic-netlink (genl) transport: genlmsghdr framing +
  nlctrl family-id resolution — the shared foundation for genetlink-family clients
  (ethtool/devlink/nl80211/wireguard).
