# tc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — `codec.nestEnd` became fallible (`netlink`, audit: it used to truncate a nest
  longer than 65535 bytes silently). Its `AttrTooLong` is mapped here onto this module's existing
  "the request cannot be encoded" error at each call site, the way `appendAttr`'s already was.

- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Encode
  anchored by hand-derived golden bytes matching `linux/pkt_sched.h` + a live netns
  round-trip (`root.zig:954`, `unshare -rn`) that writes real netem and reads it.
- **2026-07-11** — New module: Traffic control over rtnetlink — qdiscs (`netem`, `htb`,
  `tbf`, `fq_codel`, `mq`, `cake`, `raw`), htb classes, `u32`/`flower` filters and the
  `gact`/`mirred`/`police`/`skbedit`/`vlan` action families.
