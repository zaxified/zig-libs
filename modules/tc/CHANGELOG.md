# tc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** A1 F10 (performance pass). `htb`'s
  `rate`/`ceil` and `tbf`'s `rate`/`peakrate`, plus `police`'s `rate`/`peakrate`, each built
  two 256-entry rate tables even when both would come out byte-identical (the common
  `tc ... rate X ceil X` invocation, and any `rate`/`ceil` pair that both clamp to the same
  32-bit value). `calcRateTable`'s loop measured at ~98-100% of the whole request's build
  cost (A1 audit), so the second call now copies the first table's bytes and spec fields
  instead of recomputing them whenever the inputs that determine the table match. Same
  output, same public API, ~47% faster to build a request on the reuse path and unchanged
  on the path where `rate != ceil` (measured, see `A1/tc.md`'s F10 disposition).

- **2026-09-14** — **BEHAVIOURAL:** A1 F12 (round-2 decision: safe default plus a switch).
  A dump or request whose reply never came blocked in `recvDatagram` forever: the dump loops end
  only on `NLMSG_DONE`, an error or the restart cap, and nothing set `SO_RCVTIMEO`.
  `Socket.open`/`openWithPsched` now bound each receive by the new `default_recv_timeout_ms`
  (10 s); a timeout fails the request with `error.RecvFailed` (already in `RequestError`, no
  error-set change). Per receive, not per dump, so a long table is never cut off. New
  `Socket.setRecvTimeout(ms)` changes it, 0 blocks forever.

- **2026-09-11** — **NO CONSUMER-VISIBLE CHANGE:** `Socket.dump`'s retry-attempt-cap and
  `reply_type` filter (A1/tc.md F6) now have permanent tests. `dump()` was split into a thin
  wrapper (unchanged, still calls `self.nl`) and a private `dumpVia(transport: anytype, ...)`
  with the identical body, following the same `transport: anytype` idiom `netlink`'s own
  `dumpOver`/`collectDumpPass` already use — this lets a scripted fixture drive the
  `NLM_F_DUMP_INTR` restart path and a foreign-type record without a real socket or root.
  Production path re-verified byte-for-byte unchanged before any test was added.
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
