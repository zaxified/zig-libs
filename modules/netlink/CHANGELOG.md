# netlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libmnl` /
  `libnl` (framing + `mnl_nlmsg_ok`/`mnl_attr_ok`) (design reference, not a test
  anchor).
- **2026-07-22** — rtnetlink **writes**: `RTM_NEW*`/`RTM_DEL*` requests sent with
  `NLM_F_ACK` — `addressAdd`/`addressDel`, `routeAdd`/`routeDel`,
  `linkSet`/`linkUp`/`linkDown`/`linkAdd`/`linkDel`, `neighborAdd`/`neighborDel` — with
  `Create{ exclusive, replace, append }` mapping onto `NLM_F_CREATE`/`EXCL`/`REPLACE`/
  `APPEND`. The reply is matched on (portid, seq) and a non-zero errno becomes a typed
  error; `NETLINK_EXT_ACK` is set at `open` and the kernel's `NLMSGERR_ATTR_MSG` string is
  surfaced through `lastErrorMessage()`. `linkSet` keeps the `ifi_change` mask discipline
  — only the `IFF_*` bits the caller asked for are touched, and a change with nothing in it
  is `error.NothingToChange` rather than a silent no-op. The write engine itself is public
  (`nextSeq` + `requestAck`) so sibling modules can build their own requests on it, and
  `codec` gained `nestBegin`/`nestEnd` plus the `NLM_F_*` write modifiers.
- **2026-07-04** — New module: rtnetlink **dumps** — links / addresses / routes /
  neighbors over a pure-Zig netlink transport (sequence numbers, ACK/`NLMSG_ERROR` errno
  decoding, multi-part assembly) and a bounds-checked NLA/rtattr TLV codec. Read-only at
  this point: the module documented write ops (`RTM_NEW*`/`RTM_DEL*`) and multicast event
  monitoring as deliberately out of scope.
