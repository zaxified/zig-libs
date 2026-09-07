# tc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — All four fuzz targets were replaying an EMPTY payload. Each opened with
  `smith.bytes(&raw)` and then drew its length with `valueRangeAtMost`, which reads eight input
  octets as a little-endian u64 and returns the range minimum when fewer remain — so the length
  was 0 on every seed and the parsers were handed `""` with the reply sitting unread in `raw`.
  Five of the eight option parsers *succeed* on an empty attribute list, so the collapse read as
  health. Each target now draws with one `smith.slice(&buf)`, carries a corpus built by this
  module's own encoders, and is pinned by a guard measuring work done rather than acceptance
  (netem options parsed, kinds copied, wire optionals decoded, list entries walked, statistics
  counters read, dump messages framed). Buffers were raised 256 → 1024/4096/8192: an htb class
  options nest is over 2 KiB of rate tables, and a seed longer than the buffer reads back as the
  EMPTY one. Two knobs that were drawn *after* the byte draw — `parseAction`'s ordinal and
  `parseFilter`'s `tcmsg.info` — were 0 on every seed (ordinal 0 is `TCA_ACT_UNSPEC`, which the
  kernel refuses) and now travel in the seed's tail. Measured: 0 of 14/12/12/10 seeds non-empty
  before, all non-empty after. Nine mutations of kernel-response parser bounds that survived the
  green suite are now caught, three of them by an out-of-bounds panic in the harness itself.
  `root.fuzzParseQdisc` duplicated `qdisc.fuzzParseOptions`; it is now `fuzzDumpParse`, which
  walks a whole reply datagram through the framer, `classifyDumpMessage` and the parsers — the
  half of `Socket.dump` above the syscall, previously untested.

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
