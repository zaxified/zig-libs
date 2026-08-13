# netlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libmnl` /
  `libnl` (framing + `mnl_nlmsg_ok`/`mnl_attr_ok`) (design reference, not a test
  anchor).
- **2026-07-04** — New module: rtnetlink read + write: dumps (links / addresses / routes
  / neighbors) and `RTM_NEW*`/`RTM_DEL*` writes.
