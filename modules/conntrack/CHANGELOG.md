# conntrack — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BEHAVIOURAL, not breaking**: `dump`/`dumpEach`/`flush` now return a new
  `error.SubsystemUnavailable` instead of `error.InvalidRequest` when the kernel's `EINVAL`
  means "`nf_conntrack_netlink` is not registered" (e.g. stock OpenWRT 25.12.4) rather than
  "malformed request" — the two were indistinguishable before, and reporting the wrong one for
  a mutating op like `flush` is an operational hazard. `get`/`delete`/`insert`/`update` are
  unchanged (deliberately: they carry a caller-supplied `Tuple`/`NewSpec`, so `EINVAL` there
  stays genuinely ambiguous with a malformed request). Additive to `DumpError`/`RequestError`/
  `WriteError`, so no existing `catch`/`switch` with an `else` arm needs a change; a caller with
  an *exhaustive* switch over the old error set on `dump`/`flush` specifically needs a new arm.
  See SPEC.md "EINVAL vs subsystem absent".
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `libnetfilter_conntrack` / conntrack-tools — used in-repo as a
  black-box capture oracle.
- **2026-07-22** — New module: Linux ctnetlink (`NETLINK_NETFILTER` /
  `NFNL_SUBSYS_CTNETLINK`) client — typed conntrack flow dump/get/delete plus event
  subscription, over `netlink`'s write engine.
