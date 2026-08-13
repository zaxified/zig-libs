# conntrack — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `libnetfilter_conntrack` / conntrack-tools — used in-repo as a
  black-box capture oracle.
- **2026-07-22** — New module: Linux ctnetlink (`NETLINK_NETFILTER` /
  `NFNL_SUBSYS_CTNETLINK`) client — typed conntrack flow dump/get/delete plus event
  subscription, over `netlink`'s write engine.
