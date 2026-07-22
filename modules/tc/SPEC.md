# tc — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE.

## Design & invariants

`tc` builds the traffic-control message families (`RTM_*QDISC`, `RTM_*TCLASS`,
`RTM_*TFILTER`) on top of the sibling `netlink` module. **Transport is not duplicated**:
`netlink.Socket` owns the `NETLINK_ROUTE` fd, the sequence counter (`nextSeq`), the
write+ACK engine (`requestAck`), the `NLMSG_ERROR` → typed-error mapping
(`writeErrorFromCode`) and the extended-ACK reason string (`lastErrorMessage`); the wire
codec (`appendHeader`/`appendAttr*`/`nestBegin`/`nestEnd`/`AttrIterator`, and the
`NLM_F_CREATE`/`EXCL`/`REPLACE` constants) comes from `netlink.codec`. This module adds
only what is tc-specific: the `tcmsg` fixed header, the kind-specific `TCA_OPTIONS`
payloads, the psched rate arithmetic, and a multi-part dump loop.

The one piece that is still local is that dump loop (`Socket.dump`, marked
`DRY candidate:` in the source). `netlink`'s dump engine is private and generic over its
own parse/match callbacks, and — unlike the sibling `genetlink.Socket` — it publishes no
raw `send`/`recvDatagram` pair, so tc drives the shared socket's fd directly for
`RTM_GET*`. Everything else about a dump (seq allocation, error mapping) still goes
through `netlink`. If `netlink` ever grows a public `sendRequest`/`recvDatagram` seam,
this loop should collapse into it.

### Module layout

| File | Contents |
|---|---|
| `handle.zig` | `Handle` (`major:minor`), `TC_H_*`, `TC_H_MAKE`, hex parse/format |
| `ratespec.zig` | `Psched` calibration, `tc_ratespec`, the 256-entry rate tables |
| `qdisc.zig` | netem/htb/tbf/fq_codel option encode+decode, `Qdisc`/`Class` parsing |
| `filter.zig` | u32 + flower encode+decode, `tcm_info` packing, `Filter` parsing |
| `message.zig` | `tcmsg` + every request builder (pure: allocator in, bytes out) |
| `goldens.zig` | byte-exact requests captured from real `iproute2` |
| `root.zig` | re-exports, `Socket` (ops + dump engine), live integration tests |

### Handles are hexadecimal

`Handle.parse`/`format` use base 16 in both halves because iproute2 does: `classid 1:10`
is minor **0x10 = 16**. The same applies to htb's `default` argument (`htb default 10` is
`defcls = 0x10`) — `Htb.defcls` is a plain number, so pass `0x10` to match that command
line. Getting this wrong silently builds a *different* class id that the kernel happily
accepts, which is why it is called out here and asserted in `handle.zig`'s tests.

### A filter's prio + protocol live in `tcm_info`

```text
tcm_info = TC_H_MAKE(prio << 16, htons(protocol))
```

The protocol half is an **ethertype in network byte order** — `ETH_P_IP` (0x0800) becomes
0x0008 on a little-endian host. This is the classic tc-over-netlink bug: get it wrong and
the kernel installs a working filter under a protocol nothing matches. `filter.makeInfo`
/ `filter.parseInfo` are the only places this is encoded, and the goldens pin
`0x00010008` (ip, prio 1) and `0x0004dd86` (ipv6, prio 4).

### `TCA_OPTIONS` is nested without `NLA_F_NESTED`

iproute2's `addattr_nest` writes the bare attribute type; the kernel's validators ignore
the bit. v1 of this module set `NLA_F_NESTED`, which made every request differ from
`tc`'s by one bit. It is now cleared, so requests are byte-identical to `tc`'s. Wire
behaviour is unchanged (the kernel masks the bit off before dispatch).

### psched ticks and the rate tables

Shaping qdiscs do not carry a rate alone: `htb` and `tbf` also carry 256-entry lookup
tables mapping a packet size (in `1 << cell_log` byte cells) to its transmit time in
**psched ticks**, plus tick-valued `buffer`/`cbuffer`/`mtu` fields. Kernels since v3.8
(commit 56b765b79, "htb: improved accuracy at high rates") no longer use the tables for
lookups, but `tc` still sends them and the kernel still expects the attribute, so a
byte-compatible client must reproduce them.

The tick↔microsecond ratio comes from `/proc/net/psched` (`t2us us2t clock_res tfsc`),
via iproute2's own derivation:

```text
if (clock_res == 1000000000) t2us = us2t;      /* ns-resolution compat hack */
tick_in_usec = t2us / us2t * (clock_res / 1e6)
hz           = (clock_res == 1000000) ? tfsc : 100     /* only used for default bursts */
```

and the table itself is `rtab[i] = ceil(1e6 * size_i / rate * tick_in_usec)` with
`size_i = adjust((i + 1) << cell_log, mpu, linklayer)`.

**One deliberate deviation.** iproute2 evaluates that expression in `double`. On its
still-common i386 builds the intermediates live in 80-bit x87 registers; on x86-64 they
are 64-bit SSE. The two disagree by one tick wherever `size/rate` is not exactly
representable — e.g. 984 B at 125000 B/s gives 123000 on x87 and 123001 on SSE. This
module therefore evaluates

```text
ticks = ceil(size * 1e6 * tick_num / (rate * tick_den))
```

exactly in `u128`, with the calibration kept as the rational `tick_num/tick_den` instead
of a `f64`. That yields the mathematically correct ceiling, which is what the
higher-precision build produces — and it reproduces all 19 captured iproute2 goldens
(three full rate tables, 768 entries, plus every buffer/burst tick) byte for byte. A
64-bit iproute2 build may differ from both by ±1 tick on such inputs; since the kernel
does not read the tables, this has no behavioural effect.

Other faithfully mirrored iproute2 quirks:

- htb's default burst is `rate / hz + mtu` **bytes**, then converted to ticks; its `mtu`
  default is 1600 ("eth packet len"), not the interface MTU.
- htb computes its rate tables from the **clamped 32-bit** `tc_ratespec.rate` (it calls
  `tc_calc_rtable`, not `tc_calc_rtable_64`) while timing `buffer`/`cbuffer` with the full
  64-bit rate. tbf instead times its `buffer` with the clamped rate. Both are reproduced.
- a rate ≥ 2^32 B/s pins `tc_ratespec.rate` to `~0U` and is carried in
  `TCA_HTB_RATE64`/`CEIL64` (or `TCA_TBF_RATE64`/`PRATE64`).
- attribute emission order per kind matches iproute2's, so a request is byte-identical to
  the equivalent command line (htb class: RATE64, CEIL64, PARMS, RTAB, CTAB; tbf: PARMS,
  BURST, RATE64, RTAB, PRATE64, PBURST, PTAB; fq_codel: LIMIT, FLOWS, QUANTUM, INTERVAL,
  TARGET, …; u32: CLASSID then SEL; flower: keys in a fixed order, then FLAGS, then
  ETH_TYPE).

`Psched.read()` never fails: a missing/unreadable `/proc/net/psched` falls back to
1 tick/µs and `hz = 100`, which still produces a working (if not byte-identical) request.
`Socket.openWithPsched` pins the calibration explicitly — that is how the goldens stay
host-independent.

### The netem encoding (unchanged from v1)

`Netem` is the ergonomic input (nanoseconds, `f64` percent `[0, 100]`); all `*_pct`
fields scale as `u32 = round(percent / 100 * UINT32_MAX)`, the kernel's own probability
scale. `NetemWire` deliberately stores the raw scaled integers rather than reconstructed
percentages: the scale is lossy one-way, so comparing raw integers is exact and is what
the tests do (`nw.loss == try percentToU32(1.0)`).

The legacy `tc_netem_qopt.latency`/`.jitter` fields are psched ticks; this module always
writes 0 into them and sets the exact nanosecond values via `TCA_NETEM_LATENCY64` /
`TCA_NETEM_JITTER64` (kernel ≥ 4.14). The capture of `tc qdisc add … netem delay 100ms
10ms loss 1%` confirms modern `tc` does exactly the same — that golden now guards the v1
encoder byte for byte. A pre-4.14 kernel would see no delay applied; still out of scope.

On dump, a real kernel may report the legacy pair as nonzero (it back-fills them from its
internal nanosecond value for old tools); `NetemWire.legacy_latency`/`.legacy_jitter`
capture that, informational only.

### Dump filtering

The kernel dumps every qdisc/class/filter of an ifindex regardless of the handle/parent
in the request, so scoping is client-side, mirroring iproute2's own printers:

- **classes** — `tc class show … parent 1:` filters on `TC_H_MAJ(tcm_handle ^ qdisc)`,
  *not* on `tcm_parent`, because a classful qdisc reports `TC_H_ROOT` as the parent of its
  top-level classes. `Socket.classes` does the same when given a qdisc handle (minor 0),
  and falls back to an exact `tcm_parent` match when given a class handle.
- **filters** — `tcm_parent` is the real attach point, so it is matched exactly (as
  iproute2 does).
- A filter dump also contains bookkeeping entries with no options: a bare per-(chain,
  protocol, prio) header for every classifier plus u32's auto-created hash table.
  `Filter.classid()` returns null for those; callers that only want real filters should
  skip them (the live test does).

## Threat / permission model

Every `RTM_NEW*`/`RTM_DEL*` needs **CAP_NET_ADMIN**; a non-privileged caller gets
`error.AccessDenied` (mapped from `-EPERM`/`-EACCES` by `netlink.writeErrorFromCode`).
The `RTM_GET*` dumps need no privilege.

Untrusted input is the kernel's reply, walked through `netlink.codec`'s bounds-checked
`MessageIterator`/`AttrIterator` (fuzzed there). This module's own parsers
(`parseQdisc`, `parseClass`, `parseFilter`, and every `parse*Options`) never panic or
over-read on a malformed/truncated payload — they return `error.Truncated`/
`error.BadLength` — and are fuzz-tested here over arbitrary bytes.

Caller input is validated before any allocation: `percentToU32` rejects any `*_pct`
outside `[0, 100]` (including NaN), delay/jitter beyond `i64` is `error.InvalidDelay`, a
shaping spec without a rate is `error.MissingRate`, tbf without burst/limit/mtu is
`error.MissingBurst`/`MissingLimit`/`MissingMtu`, a flower port match without a
port-carrying `ip_proto` is `error.PortWithoutProto`, and more `U32Key`s than
`sel.nkeys` (a `u8`) can hold is `error.TooManyKeys`. The rate-table arithmetic saturates
at `UINT_MAX` instead of wrapping, and `calcXmitTime` guards every `u128` multiply, so no
caller-supplied rate/size can panic in ReleaseSafe or wrap in ReleaseFast.

## Out of scope / deferred

- **Actions** (`TCA_*_ACT`, `tc actions` — mirred, police, bpf, …). Filters can select a
  class (`classid`/`flowid`), not run an action list. This is the single largest missing
  piece and the obvious next increment.
- **Other classifiers**: `bpf`, `matchall`, `basic`, `route`, `fw`, `cgroup`. Only `u32`
  and `flower` are modelled; anything else needs `FilterSpec.raw`.
- **u32 hash tables**: `TCA_U32_DIVISOR`/`HASH`/`LINK` (linked hash tables, `ht 800:`
  bucket routing) and `TCA_U32_MARK`/`FLAGS`/`INDEV`/`POLICE`. The selector's variable
  offset fields (`offshift`/`offmask`/`off`/`offoff`/`hoff`/`hmask`, i.e. `at nexthdr+N`)
  are exposed on `U32` but have no golden and no helper.
- **flower beyond L2–L4 basics**: MAC addresses, VLAN/CVLAN, MPLS, tunnel keys, ARP,
  ICMP type/code, TCP flags, IP TOS/TTL, ct state, port ranges, `TCA_FLOWER_INDEV`. The
  `skip_hw`/`skip_sw` bits are settable via `Flower.flags` but untested against hardware.
- **Other qdiscs**: hfsc, cake, prio, sfq, red, codel, pfifo/bfifo, mq, clsact/ingress
  attachment helpers. `QdiscSpec.raw` covers them if you encode the options yourself.
- **htb offload** (`TCA_HTB_OFFLOAD`) is emitted when asked for but never verified against
  offload-capable hardware.
- **`TCA_STAB`** (size tables / per-packet overhead outside the rate table) and the
  `linklayer atm` path: `LinkLayer.atm` is implemented and unit-tested against the SAR
  formula, but has no iproute2 golden.
- **Statistics**: `TCA_STATS`/`STATS2`/`XSTATS` are ignored on dump — no byte/packet
  counters, no per-class backlog.
- **netem's GI/GE loss models** (`TCA_NETEM_LOSS`), `TCA_NETEM_DELAY_DIST`,
  `TCA_NETEM_SLOT*`, `TCA_NETEM_RATE64`, `TCA_NETEM_ECN` — unchanged from v1.
- **Multicast rtnetlink events** — no notification/monitoring, matching `netlink`'s scope.
- **Non-Linux, and big-endian hosts**: the goldens assert only on little-endian (they are
  captured bytes); the encoders themselves use host byte order like the kernel does.

## Verification

- **Byte-exact goldens from real `iproute2`** (`goldens.zig`, 19 requests). Each was
  recovered from
  `unshare -rn strace -f -e trace=sendmsg -xx -s 8192 -e abbrev=none <cmd>`, re-encoded
  from strace's decode and checked against the message's own `nlmsg_len` so a truncated
  capture cannot slip through. Capture host: iproute2-6.19.0, Linux 7.0,
  `/proc/net/psched = 000003e8 00000040 000f4240 3b9aca00` (pinned as
  `ratespec.golden_psched`, so the tests are host-independent). Each test carries the
  exact command in a comment. Coverage:

  | Golden | Command |
  |---|---|
  | htb qdisc | `tc qdisc add dev lo root handle 1: htb default 10` |
  | htb qdisc (tuned) | `… htb default 0 r2q 5 direct_qlen 100` |
  | htb class | `tc class add dev lo parent 1: classid 1:10 htb rate 1mbit ceil 2mbit` |
  | htb class (RATE64) | `… classid 1:30 htb rate 40gbit ceil 80gbit` |
  | htb class (tuned) | `… classid 1:40 htb prio 3 quantum 3000 burst 15k mtu 1500 rate 5mbit ceil 5mbit` |
  | tbf | `tc qdisc add dev lo root handle 5: tbf rate 1mbit burst 32kbit latency 400ms` |
  | tbf (peak) | `… handle 2: tbf rate 10mbit burst 10kb latency 50ms peakrate 20mbit mtu 1540` |
  | fq_codel | `… handle 6: fq_codel limit 1200 flows 1024 target 5ms interval 100ms quantum 1514` |
  | netem | `… handle 3: netem delay 100ms 10ms loss 1%` |
  | u32 filter | `tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip dst 10.0.0.1/32 flowid 1:10` |
  | u32 filter (2 keys) | `… u32 match ip src 192.168.1.0/24 match ip dst 10.0.0.1/32 flowid 1:10` |
  | flower filter | `… protocol ip prio 2 flower ip_proto tcp dst_ip 10.0.0.0/24 dst_port 80 classid 1:10` |
  | flower filter (full) | `… prio 3 flower ip_proto tcp src_ip 192.168.0.0/16 dst_ip 10.0.0.0/24 src_port 1234 dst_port 80 classid 1:10` |
  | flower filter (IPv6) | `… protocol ipv6 prio 4 flower ip_proto udp src_ip 2001:db8::/32 dst_ip 2001:db8:1::1/128 dst_port 53 classid 1:30` |
  | qdisc del / class del / filter del | `tc qdisc del dev lo root`, `tc class del dev lo classid 1:20`, `tc filter del dev lo parent 1: protocol ip prio 2` |
  | qdisc dump / filter dump | `tc qdisc show dev lo`, `tc filter show dev lo parent 1:` |

  The two 2 KiB class goldens and the two tbf goldens include the full 1024-byte rate
  tables, so the psched arithmetic is verified entry by entry, not just structurally.

- **Golden re-parse**: several goldens are fed back through `parseQdisc`/`parseClass`/
  `parseFilter` and asserted field by field, so the decoders are checked against real
  kernel-shaped bytes rather than only against this module's own encoder.
- **Encode/decode round-trip** per kind: htb class (incl. RATE64/CEIL64 clamping), tbf
  with a peak bucket, fq_codel's "omit what is unset", u32 with two keys, flower over
  IPv6, and netem with every optional attribute populated.
- **Unit**: handle packing/parse/format (incl. the hex gotcha and overflow), `tcm_info`
  packing both ways, `Psched` derivation (incl. the ns-resolution compat hack and a
  degenerate divisor), `calcXmitTime` ceiling + saturation, `deriveCellLog`, ATM size
  adjustment, `RateSpec` byte layout, `Create` flag combinations, and every
  spec-validation error path.
- **Fuzz** (`std.testing.fuzz`): `parseQdisc`, `parseClass`, `parseFilter` and all seven
  `parse*Options` over arbitrary bytes — never panic, never over-read.
- **Live netns round-trip** (env-gated; prints `SKIPPED: …` and passes when unprivileged):
  `unshare -rn zig build test-tc`. Four integration tests exercise an unprivileged qdisc
  dump, the v1 netem add/show/change/del cycle, an htb tree (qdisc → two classes, one of
  them needing RATE64 → an fq_codel leaf under a class → u32 + flower filters → dumps of
  all three families → filter del → class del), a tbf round-trip, and an extended-ACK
  probe with a bogus qdisc kind. Every assertion is against what the kernel echoed back,
  including the 64-bit rates surviving `TCA_HTB_RATE64`.

  This was run in the development environment: **71/71 pass under `unshare -rn` in both
  Debug and `--release=fast`**; unprivileged, 67 pass and the 4 privileged tests skip.
  `zig build test-netlink` and `zig build test-wireguard` stay green.

  Two kernel behaviours the live run pinned down (both now encoded in the module): a
  **down** interface has no qdisc at all (a fresh `unshare -rn` starts with `lo` DOWN, so
  the tests admin-up first), and htb dumps `HTB_VER` (0x30011) in `tc_htb_glob.version`,
  of which only the high half is the protocol version `tc` sends.

## Provenance

Kernel UAPI headers (`linux/rtnetlink.h` — struct tcmsg, TCA_*; `linux/pkt_sched.h` —
tc_netem_qopt/tc_htb_glob/tc_htb_opt/tc_tbf_qopt/tc_ratespec, TCA_NETEM_*/TCA_HTB_*/
TCA_TBF_*/TCA_FQ_CODEL_*; `linux/pkt_cls.h` — tc_u32_sel/tc_u32_key, TCA_U32_*/
TCA_FLOWER_*), all GPL-2.0 WITH Linux-syscall-note. No GPL header source is copied — only
the uncopyrightable ABI facts they document (struct layouts, numeric constants); the
Linux-syscall-note exception is what keeps this module cleanly MIT, exactly as already
established for `netlink`/`wireguard`.

**iproute2 (GPL-2.0-or-later) was consulted as a behaviour/design reference** for v2 —
`tc/tc_core.c` (`tc_calc_xmittime`, `tc_calc_rtable`, `tc_core_init`), `tc/q_htb.c`,
`tc/q_tbf.c`, `tc/q_fq_codel.c`, `tc/f_u32.c`, `tc/tc_class.c`, `tc/tc_filter.c` and
`lib/utils.c` (`__get_hz`) — to learn the rate-table arithmetic, the default-burst
formulas, the attribute emission order and the client-side dump-filter rules. No source
was copied; the algorithms are re-derived and re-expressed here, and the goldens are the
independent check that the behaviour matches. The v1 statement that no third-party
implementation was consulted no longer holds; `/NOTICE`'s `tc` entry carries the matching
`design ref: iproute2` declaration required by CONVENTIONS §5.

## Status

`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const
meta` in `src/root.zig`.
