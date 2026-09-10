# tc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking (mop-up pass):** three more `A1/tc.md`
  findings closed (F3, F4, F9); F6/F10/F12
  remain open (F10 deliberately, deferred to the campaign's perf pass; F12 needs a user
  decision — see the file's "Dispozice 2026-09-10 (mop-up)").
  - **F3:** four of the seven fault-injection points the audit named
    (`filter.zig`'s `TCA_U32_SEL` length, `qdisc.zig`'s `TCA_HTB_PARMS` length,
    `action.zig`'s `TCA_MIRRED_PARMS`/`TCA_POLICE_TBF` lengths) had zero coverage even after
    the 2026-09-07 fuzz-harness fix made the corpus reach real payloads — "never crashes" and
    "rejects a too-short attribute" are different claims, and three of these four turned out
    to be reachable out-of-bounds READS once the corpus could reach them (confirmed by
    disabling each guard: 3 of 4 crash the existing fuzz test outright, not just a new
    assertion). Four new permanent boundary tests pin all four; the other three named points
    (`copyKind`, the cookie `@min` clamp, the `keys_len` loop bound) were already either
    pinned or safe by construction.
  - **F4:** captured a real golden (`unshare -rn strace` against stock `iproute2-6.19.0`,
    `tc class add … htb rate 20gbit ceil 20gbit`, 2.5e9 B/s — inside `[2^31, 2^32)`, the band
    no existing golden covered) rather than fabricating bytes. `clampRate`'s
    `rate >= (1 << 32)` threshold and the separate `RATE64`-attach condition are two
    independent checks on the same constant; moving just the former to `(1 << 31)` (the
    audit's own proposed mutant) now fails exactly this one new golden and no other.
  - **F9:** `max_actions = 32` (`error.TooManyActions`) isn't always the real limit — a
    `police` action with `peakrate` set (two 1 KiB rate tables) hits `TCA_ACT_TAB`'s u16
    nest-length limit (`error.OptionsTooLong`) at 31 entries, before `max_actions` would ever
    fire. Already fail-closed either way; pinned the exact boundary as a test and added one
    clarifying sentence to `SPEC.md` — no change to the guard itself.
  - Touches `modules/tc/src/{qdisc,filter,action,goldens}.zig` and `SPEC.md`. No public
    signature changed.

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `Socket.qdiscs`/`classes`/`filters`/`actions`
  could double-free their result buffer and crash the process after four consecutive
  `NLM_F_DUMP_INTR` replies from the kernel (concurrent `tc`/daemon churn on the same
  interface, not a malicious input) — fixed, no API change. `HtbClass`/`Tbf`/`Police`'s
  `cell_log`/`ccell_log`/`pcell_log` now reject values above 23 with the new
  `error.InvalidCellLog` (previously `>= 32` panicked in ReleaseSafe); `deriveCellLog` itself is
  now capped at the same 23 instead of silently overflowing its rate table for `mtu >= 2^31`.
  `buildQdiscSet`/`buildClassSet`/`buildFilterSetWith`/`buildFilterDel` return the existing
  `error.OptionsTooLong` for a `kind` string past netlink's attribute length limit instead of
  panicking; `Psched.calcXmitSize` saturates instead of trapping on an overflowing
  kernel-supplied `rate`/`ticks`/`tick_den` product. See A1/tc.md F1/F2/F5/F7/F8/F11 for the
  measured RED→GREEN of each.

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
