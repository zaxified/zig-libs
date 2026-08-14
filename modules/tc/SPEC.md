# tc — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE.

## Design & invariants

`tc` builds the traffic-control message families (`RTM_*QDISC`, `RTM_*TCLASS`,
`RTM_*TFILTER`, `RTM_*ACTION`) on top of the sibling `netlink` module. **No transport is
duplicated — not even the receive path**: `netlink.Socket` owns the `NETLINK_ROUTE` fd,
its receive buffer, the sequence counter (`nextSeq`), the raw seam (`send`,
`recvDatagram`), the write+ACK engine (`requestAck`), the `NLMSG_ERROR` → typed-error
mapping (`writeErrorFromCode`) and the extended-ACK reason string (`lastErrorMessage`);
the wire codec (`appendHeader`/`appendAttr*`/`nestBegin`/`nestEnd`/`AttrIterator`, and
the `NLM_F_CREATE`/`EXCL`/`REPLACE` constants) comes from `netlink.codec`. This module
adds only what is tc-specific: the `tcmsg` fixed header, the kind-specific `TCA_OPTIONS`
payloads, the psched rate arithmetic, and the *policy* of a dump.

`tc.Socket` is therefore `struct { gpa, nl: netlink.Socket, psched }` — it has no fd, no
buffer and no sequence counter of its own. The multi-part dump loops (`Socket.dump`,
`Socket.actions`) used to drive the shared socket's fd directly, with a hand-rolled
`sendto`/`MSG_PEEK|MSG_TRUNC` pair and a hand-rolled reply triage, because that seam did
not exist when they were written; they now sit on `netlink.Socket.send` +
`recvDatagram` + `netlink.classifyDumpMessage`, which is byte-for-byte the same triage
they open-coded (stale (portid, seq) → skip, `NLM_F_DUMP_INTR` → restart up to 4
attempts, `NLMSG_DONE`/bare-ACK → done, `NLMSG_ERROR` → `writeErrorFromCode`,
`NLMSG_NOOP` → skip, `NLMSG_OVERRUN` → `SystemResources`). What stays local is only the
policy: which request, which reply type, which parser, and the client-side
`ifindex`/`parent` filtering (`ParentMatch`).

`Socket.actionGet` deliberately keeps an explicit triage rather than using
`classifyDumpMessage`: it is a single-reply `RTM_GETACTION`, not a multi-part dump, so
`NLM_F_DUMP_INTR` must not be read as a restart there.

### Module layout

| File | Contents |
|---|---|
| `handle.zig` | `Handle` (`major:minor`), `TC_H_*`, `TC_H_MAKE`, hex parse/format |
| `ratespec.zig` | `Psched` calibration, `tc_ratespec`, the 256-entry rate tables |
| `qdisc.zig` | netem/htb/tbf/fq_codel/mq/cake option encode+decode, `Qdisc`/`Class` parsing |
| `filter.zig` | u32 + flower encode+decode, `tcm_info` packing, `Filter` parsing |
| `action.zig` | the `TCA_ACT_*` list, `tc_gen`/`TC_ACT_*`, gact/mirred/police/skbedit/vlan |
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

### Actions: a 1-based ordinal list

An action list is one nested attribute — `TCA_U32_ACT` (7) on a u32 filter,
`TCA_FLOWER_ACT` (3) on a flower filter, `TCA_ACT_TAB` (1) on a standalone
`RTM_*ACTION` message. All three are the same shape, and their children are **ordinal
nests numbered from 1**:

```text
TCA_U32_ACT
  [1]  TCA_ACT_KIND "gact"
       TCA_ACT_OPTIONS | NLA_F_NESTED { TCA_GACT_PARMS { tc_gen } }
       TCA_ACT_COOKIE (optional, <= 16 bytes)
  [2]  …
```

Numbering from 0 is the classic mistake: attribute type 0 is `TCA_ACT_UNSPEC` and the
kernel's `tcf_action_init` rejects it, so the list silently fails to install.
`action.appendActionList` is the only place this module numbers entries, and the
two-action goldens pin `1` and `2` on the wire. The cap is `TCA_ACT_MAX_PRIO` = 32
(`error.TooManyActions` above it).

Two nesting details are deliberately asymmetric, both copied from iproute2 and both
pinned by goldens:

- the outer list nest and each ordinal nest are written **without** `NLA_F_NESTED`
  (like `TCA_OPTIONS`);
- `TCA_ACT_OPTIONS` **is** written with `NLA_F_NESTED` (0x8002 on the wire).

The kernel masks the bit off either way, but a byte-exact client has to match.

### The generic prologue and the `TC_ACT_*` verdicts

Every action kind's options struct begins with `struct tc_gen` — `index`, `capab`,
`action`, `refcnt`, `bindcnt` (20 bytes) — where `action` is the verdict the action
returns to the classifier. `refcnt`/`bindcnt`/`capab` are kernel bookkeeping and a
request always sends zero.

`TC_ACT_PIPE` (3) is the verdict that **chains**: an action returning it lets the list
continue into the next ordinal, while `OK`/`SHOT`/`STOLEN` end it and `RECLASSIFY`
restarts classification. That is why `skbedit`, `vlan` and a *mirroring* `mirred` default
to `.pipe` while a *redirecting* `mirred` defaults to `.stolen` and a bare `gact` to the
verdict you asked for — the same defaults `tc` picks, each with its own golden.
`TC_ACT_UNSPEC` is **-1** (`tc`'s `continue`, "fall through to the next filter"), so the
field is signed; `Verdict` is a non-exhaustive `enum(i32)` so a newer kernel's verdict —
or a `TC_ACT_GOTO_CHAIN` composite — decodes instead of panicking.

**`police` is the one exception to the prologue.** `struct tc_police` is
`index, action, limit, burst, mtu, rate, peakrate, refcnt, bindcnt, capab` (56 bytes):
`action` sits where `capab` would be and the bucket parameters are interleaved before
`refcnt`. `Action.gen` is still populated for a decoded police action, reassembled from
the equivalent fields, so callers can treat every kind uniformly.

### `police` reuses the rate tables — but not the way htb does

`police` carries the same `tc_ratespec` + 256-entry psched rate table as htb and tbf, so
`ratespec.zig` is reused unchanged (`calcRateTable`, `encodeRateTable`,
`Psched.calcXmitTime`). Two behaviours differ from the shaping qdiscs and both are pinned
by the `rate 40gbit` goldens:

- **the tables are computed from the full 64-bit rate.** iproute2's `m_police.c` calls
  `tc_calc_rtable_64`, whereas `q_htb.c`/`q_tbf.c` call the 32-bit `tc_calc_rtable` and so
  bake the `~0U` clamp into their tables. A 40 Gbit/s police table therefore ends at 7
  ticks, not the 8 the clamped rate would give. `calcRateTable`'s `rate_override`
  parameter — added for exactly this — carries the real rate.
- **`mtu` stays in bytes.** tbf converts its `mtu` to psched ticks; police writes the byte
  value straight into `tc_police.mtu` and only uses it to derive the tables' cell shift.

The burst is `tc_calc_xmittime(rate, bytes)` with the **full** rate (10 KiB at 5 GB/s is
32 ticks, not the 38 the clamp would give), the same split htb makes for `buffer`.
`conform-exceed A/B` puts the **exceed** verdict A in `tc_police.action` and the
notexceed verdict B in `TCA_POLICE_RESULT`; with no `conform-exceed` at all `tc` sends
`TC_ACT_RECLASSIFY`, which is `Police.exceed`'s default here.

### Standalone actions use `tcamsg`, not `tcmsg`

`RTM_NEWACTION`/`DELACTION`/`GETACTION` (48/49/50) address the **shared action table**,
not an interface. Their fixed header is `struct tcamsg` — family plus two pads, **4
bytes** — where every other tc family carries the 20-byte `tcmsg`. Sending a `tcmsg`
here shifts every attribute by 16 bytes and the kernel rejects the message; `tcamsg_len`
and `appendTcamsg` exist so the two cannot be confused.

The three request shapes, each goldened:

| Form | Flags | Body |
|---|---|---|
| `tc actions add` | `REQUEST\|ACK\|CREATE\|EXCL` | `TCA_ACT_TAB` of full actions (kind + options) |
| `tc actions del` | `REQUEST\|ACK` | `TCA_ACT_TAB` of references (kind + `TCA_ACT_INDEX`) |
| `tc actions get` | `REQUEST` | same body as del; the reply is one `RTM_NEWACTION`, not a dump |
| `tc actions ls` | `REQUEST\|DUMP` | `TCA_ACT_TAB` with just a kind, plus `TCA_ROOT_FLAGS` |

`tc` always sets `TCA_ACT_FLAG_LARGE_DUMP_ON` in that `nla_bitfield32`, without which the
kernel truncates the table at one message; `buildActionDump` does the same.

**Permissions differ from the rest of the module.** Qdiscs, classes and filters are
network-namespaced (`netlink_net_capable`), so an unprivileged `unshare -rn` namespace
can drive them. `act_api.c`'s `tc_ctl_action` uses `netlink_capable` instead, i.e. it
checks `CAP_NET_ADMIN` against the **initial** user namespace — so `tc actions add|del`
needs real root even inside a namespace. The `RTM_GETACTION` dump is unrestricted.

### Decoding actions off a dump

`Filter.actions()` returns the decoded list attached to a dumped filter. `Action` is a
fixed-size value type (no allocation, safe to copy out of the receive buffer), which is
why the per-filter decode is capped at `action.max_actions_decoded` = 4 entries —
`Filter.act_list.total` still reports the true count. The standalone `Socket.actions()`
dump is **not** capped: it walks `ActionIterator` directly and flattens every table entry
of every message into one slice.

`TCA_ACT_STATS` (byte/packet counters from `TCA_STATS_BASIC`/`PKT64`, drops and
overlimits from `TCA_STATS_QUEUE`) and each kind's `*_TM` `struct tcf_t` timestamps are
decoded when present. The rate estimator (`TCA_STATS_RATE_EST*`) is not.

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

### mq carries no options, cake is a flat attribute list

Two qdisc kinds were added after the v2 batch, both with captured goldens.

**`mq`** (`sch_mq`) is a pure pivot: attaching it to a multiqueue device makes the kernel
auto-create one child class per hardware TX queue, onto which per-CPU qdisc trees hang.
Its request is `TCA_KIND = "mq"` and **nothing else** — not even an empty `TCA_OPTIONS`
nest (the `tc qdisc replace … mq` capture is 44 bytes: header + `tcmsg` + the padded kind
attribute). `QdiscSpec.carriesOptions` returns false for `mq`, and `buildQdiscSet` gates
the whole `nestBegin`/`appendOptions`/`nestEnd` block on it, so an `mq` request omits the
attribute entirely while every other kind still writes a nest (empty when it has no knobs,
exactly like `tc`). The per-queue child classes are the kernel's to create, never this
call's.

**`cake`** (`sch_cake`, the LibreQoS per-subscriber leaf) is a flat list of `TCA_CAKE_*`
TLVs inside `TCA_OPTIONS` — no fixed struct, unlike the shaping qdiscs. `Cake` models it
the way `FqCodel` models fq_codel: every field is optional, `null` omits its attribute and
keeps the kernel default. Only `TCA_CAKE_BASE_RATE64` is a u64; everything else is a u32
(`TCA_CAKE_OVERHEAD` is a *signed* s32, round-tripped through `@bitCast`). The enum-valued
knobs (`CakeDiffservMode`/`CakeFlowMode`/`CakeAtmMode`/`CakeAckFilter`) carry the kernel's
own `sch_cake.c` numeric values and are non-exhaustive so a newer value still decodes.

The **emission order** mirrors iproute2's `q_cake.c` so a request is byte-identical to the
command line: BASE_RATE64, DIFFSERV_MODE, ATM, FLOW_MODE, OVERHEAD, RAW, MPU, RTT, TARGET,
AUTORATE, MEMORY, FWMARK, NAT, WASH, SPLIT_GSO, ACK_FILTER, INGRESS. Five captured goldens
pin every position except RAW's and INGRESS-vs-ACK_FILTER's relative order (see the
deferred list). A few `tc` words expand to more than one attribute, and `Cake` exposes each
attribute directly rather than reproducing the CLI's coupling: `bandwidth`/`unlimited` also
emit `AUTORATE = 0`; `rtt T` also emits `TARGET = rtt/20` (confirmed by the `rtt 100ms`
golden: RTT 100000 µs, TARGET 5000 µs); `raw` also sets `atm = noatm` and `overhead = 0`.
`unlimited` is `bandwidth = 0` (an explicit `BASE_RATE64` of 0); a `null` bandwidth omits
the attribute (also unlimited, but zero bytes on the wire). Callers reproduce a given `tc`
line by setting exactly the fields that line sets — the goldens do precisely that.

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
The `RTM_GET*` dumps need no privilege. The action family is stricter: `RTM_NEWACTION`/
`RTM_DELACTION` need `CAP_NET_ADMIN` in the **initial** user namespace (see the
`tcamsg` section), so an unprivileged `unshare -rn` cannot drive them even though it can
drive qdiscs, classes and filters.

Untrusted input is the kernel's reply, walked through `netlink.codec`'s bounds-checked
`MessageIterator`/`AttrIterator` (fuzzed there). This module's own parsers
(`parseQdisc`, `parseClass`, `parseFilter`, `parseAction`/`parseActionList`, and every
`parse*Options`) never panic or over-read on a malformed/truncated payload — they return
`error.Truncated`/`error.BadLength` — and are fuzz-tested here over arbitrary bytes. A
decoded `Verdict` is a non-exhaustive enum, so an unknown kernel verdict is a value, not
illegal behaviour; a `TCA_ACT_COOKIE` longer than `TC_COOKIE_MAX_SIZE` is truncated on
decode rather than overflowing its buffer.

Caller input is validated before any allocation: `percentToU32` rejects any `*_pct`
outside `[0, 100]` (including NaN), delay/jitter beyond `i64` is `error.InvalidDelay`, a
shaping spec without a rate is `error.MissingRate`, tbf without burst/limit/mtu is
`error.MissingBurst`/`MissingLimit`/`MissingMtu`, a flower port match without a
port-carrying `ip_proto` is `error.PortWithoutProto`, more `U32Key`s than `sel.nkeys`
(a `u8`) can hold is `error.TooManyKeys`, an action list longer than `TCA_ACT_MAX_PRIO`
is `error.TooManyActions`, a cookie over 16 bytes is `error.CookieTooLong`, and a
`police` without a rate/burst — or with a `peakrate` but no `mtu` — is
`error.MissingRate`/`MissingBurst`/`MissingMtu`. Every one of those is checked before a
single byte is appended, so a rejected list leaves the output buffer untouched. The rate-table arithmetic saturates
at `UINT_MAX` instead of wrapping, and `calcXmitTime` guards every `u128` multiply, so no
caller-supplied rate/size can panic in ReleaseSafe or wrap in ReleaseFast.

## Out of scope / deferred

- **Other action kinds**: `bpf`, `connmark`, `csum`, `ct`, `ctinfo`, `gate`, `ife`,
  `mpls`, `nat`, `pedit`, `sample`, `simple`, `tunnel_key`. `ActionSpec.raw` takes a kind
  string plus a pre-encoded options payload for all of them.
- **Action extras**: `TCA_ACT_FLAGS` (`no_percpu`, `skip_hw`/`skip_sw`),
  `TCA_ACT_HW_STATS`/`USED_HW_STATS`/`IN_HW_COUNT`, and `tc actions flush`. `skbedit`'s
  `mask` decodes but is never emitted (this iproute2 build rejected the `mask` keyword in
  the capture harness, so it has no golden); its `flags`/`queue_mapping_max` and `vlan`'s
  `push_eth`/`pop_eth` + `PUSH_ETH_DST`/`SRC` are neither emitted nor decoded.
- **The legacy `TCA_U32_POLICE`** attribute — the pre-action-API way of hanging a policer
  off a u32 filter. Use a `police` entry in `U32.actions` instead, which is what modern
  `tc` emits.
- **police extras**: `TCA_POLICE_AVRATE` (iproute2 6.19 rejects `avrate` in the position
  the capture harness could reach, so it has no golden and is not emitted) and the
  packet-rate policer `TCA_POLICE_PKTRATE64`/`PKTBURST64`.
- **`TC_ACT_GOTO_CHAIN`** and the chain machinery (`TCA_CHAIN`, `tc chain add`). The
  composite verdict decodes (`Verdict` is non-exhaustive) but there is no helper to build
  one and no chain API.
- **Per-filter action decode is capped** at `action.max_actions_decoded` = 4 entries
  because `Filter` is a fixed-size value type; `Filter.act_list.total` reports the true
  count, and `Socket.actions()` (the standalone dump) is uncapped.
- **The rate estimator** (`TCA_STATS_RATE_EST`/`RATE_EST64`) and `TCA_STATS_APP` are
  ignored; only basic counters, queue drops/overlimits and the `tcf_t` timestamps decode.
- **Other classifiers**: `bpf`, `matchall`, `basic`, `route`, `fw`, `cgroup`. Only `u32`
  and `flower` are modelled; anything else needs `FilterSpec.raw`.
- **u32 hash tables**: `TCA_U32_DIVISOR`/`HASH`/`LINK` (linked hash tables, `ht 800:`
  bucket routing) and `TCA_U32_MARK`/`FLAGS`/`INDEV`/`POLICE`. The selector's variable
  offset fields (`offshift`/`offmask`/`off`/`offoff`/`hoff`/`hmask`, i.e. `at nexthdr+N`)
  are exposed on `U32` but have no golden and no helper.
- **flower beyond L2–L4 basics**: MAC addresses, VLAN/CVLAN, MPLS, tunnel keys, ARP,
  ICMP type/code, TCP flags, IP TOS/TTL, ct state, port ranges, `TCA_FLOWER_INDEV`. The
  `skip_hw`/`skip_sw` bits are settable via `Flower.flags` but untested against hardware.
- **Other qdiscs**: hfsc, prio, sfq, red, codel, pfifo/bfifo, clsact/ingress attachment
  helpers. `QdiscSpec.raw` covers them if you encode the options yourself. (`mq` and `cake`
  are now modelled — see the "mq carries no options" section.)
- **CAKE knobs not modelled**: the built-in RTT/bandwidth *presets* (`datacentre`, `lan`,
  `metro`, `regional`, `internet`, `oceanic`, `satellite`) — these are just CLI shorthands
  that resolve to an `rtt`/`bandwidth` pair on iproute2's side, so set `rtt_us`/`bandwidth`
  directly instead. The read-only `TCA_CAKE_STATS`/`TIN_STATS` sub-attributes (tin
  occupancy, drop/mark counters, capacity estimate) are not decoded on a dump — `CakeWire`
  carries the configuration attributes only, matching the module-wide "stats are ignored on
  qdisc dumps" stance. The exact emission position of `TCA_CAKE_RAW` (only ever seen in
  isolation, where it follows `OVERHEAD`) is placed right after `OVERHEAD`/before `MPU`; no
  capture combines `raw` with `mpu`/`rtt` to pin it further, and the kernel is order-agnostic
  within `TCA_OPTIONS`, so this has no behavioural effect.
- **htb offload** (`TCA_HTB_OFFLOAD`) is emitted when asked for but never verified against
  offload-capable hardware.
- **`TCA_STAB`** (size tables / per-packet overhead outside the rate table) and the
  `linklayer atm` path: `LinkLayer.atm` is implemented and unit-tested against the SAR
  formula, but has no iproute2 golden.
- **Statistics**: `TCA_STATS`/`STATS2`/`XSTATS` are ignored on **qdisc/class/filter**
  dumps — no byte/packet counters, no per-class backlog. (Per-*action* `TCA_ACT_STATS`
  *is* decoded.)
- **netem's GI/GE loss models** (`TCA_NETEM_LOSS`), `TCA_NETEM_DELAY_DIST`,
  `TCA_NETEM_SLOT*`, `TCA_NETEM_RATE64`, `TCA_NETEM_ECN` — unchanged from v1.
- **Multicast rtnetlink events** — no notification/monitoring, matching `netlink`'s scope.
- **Non-Linux, and big-endian hosts**: the goldens assert only on little-endian (they are
  captured bytes); the encoders themselves use host byte order like the kernel does.

## Verification

- **Byte-exact goldens from real `iproute2`** (`goldens.zig`, 50 requests). The v2 batch
  was recovered from
  `unshare -rn strace -f -e trace=sendmsg -xx -s 8192 -e abbrev=none <cmd>` and re-encoded
  from strace's decode; the action batch adds `-e write=all`, which prints the exact
  bytes handed to `sendmsg` so there is no re-encoding step at all. Either way the
  reconstruction is checked against the message's own `nlmsg_len`, so a truncated capture
  cannot slip through. Capture host: iproute2-6.19.0, Linux 7.0,
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
  | mq | `tc qdisc replace dev lo root handle 1: mq` (kind only, no `TCA_OPTIONS`) |
  | cake (bare) | `… handle 8: cake` (an empty options nest) |
  | cake (bandwidth) | `… cake bandwidth 100mbit` |
  | cake (full) | `… cake bandwidth 1gbit diffserv4 dual-srchost nat wash ack-filter overhead 18 mpu 64 memlimit 4194304 split-gso fwmark 0xff` |
  | cake (overhead/mpu/rtt) | `… cake bandwidth 50mbit overhead 10 mpu 84 rtt 100ms ingress split-gso` |
  | cake (unlimited/modes) | `… cake unlimited besteffort flowblind ptm no-ack-filter nowash nonat` |
  | cake (raw) | `… cake raw` |
  | u32 filter | `tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip dst 10.0.0.1/32 flowid 1:10` |
  | u32 filter (2 keys) | `… u32 match ip src 192.168.1.0/24 match ip dst 10.0.0.1/32 flowid 1:10` |
  | flower filter | `… protocol ip prio 2 flower ip_proto tcp dst_ip 10.0.0.0/24 dst_port 80 classid 1:10` |
  | flower filter (full) | `… prio 3 flower ip_proto tcp src_ip 192.168.0.0/16 dst_ip 10.0.0.0/24 src_port 1234 dst_port 80 classid 1:10` |
  | flower filter (IPv6) | `… protocol ipv6 prio 4 flower ip_proto udp src_ip 2001:db8::/32 dst_ip 2001:db8:1::1/128 dst_port 53 classid 1:30` |
  | qdisc del / class del / filter del | `tc qdisc del dev lo root`, `tc class del dev lo classid 1:20`, `tc filter del dev lo parent 1: protocol ip prio 2` |
  | qdisc dump / filter dump | `tc qdisc show dev lo`, `tc filter show dev lo parent 1:` |

  The two 2 KiB class goldens and the two tbf goldens include the full 1024-byte rate
  tables, so the psched arithmetic is verified entry by entry, not just structurally.

  The 24 **action** goldens (every filter one is `tc filter add dev lo parent 1: protocol
  ip prio N u32 match ip src A/32 flowid 1:10 <ACTION…>` unless noted):

  | Golden | Action clause |
  |---|---|
  | gact drop | `action drop` |
  | gact pass + index | `action pass index 7` |
  | gact continue | `action continue` (`TC_ACT_UNSPEC` = -1) |
  | gact probabilistic | `action gact drop random determ pass 2` (`tc_gact_p`) |
  | gact + cookie | `action drop cookie a1b2c3d4` |
  | mirred egress redirect | `action mirred egress redirect dev lo` (verdict STOLEN) |
  | mirred ingress mirror | `action mirred ingress mirror dev lo` (verdict PIPE) |
  | police | `action police rate 1mbit burst 10k conform-exceed drop` |
  | police + peak | `action police rate 1mbit burst 10k mtu 1500 peakrate 2mbit conform-exceed pipe/drop` |
  | police 64-bit | `action police rate 40gbit burst 10k mtu 1500 peakrate 80gbit conform-exceed pipe/drop` |
  | skbedit | `action skbedit priority 1:10 mark 5 queue_mapping 2 ptype host` |
  | vlan push / pop / modify | `action vlan push id 100 protocol 802.1Q priority 3`, `action vlan pop`, `action vlan modify id 200` |
  | two-action PIPE chain | `action skbedit mark 7 pipe action mirred egress redirect dev lo` |
  | two-action vlan chain | `action vlan push id 100 protocol 802.1ad priority 7 pipe action vlan pop` |
  | flower + action | `tc filter add … prio 20 flower ip_proto tcp dst_port 80 action drop` |
  | flower + classid + action | `… prio 31 flower ip_proto tcp dst_port 80 classid 1:10 action drop` |
  | actions add | `tc actions add action drop index 1` |
  | actions add ×2 | `tc actions add action drop index 1 action pass index 2` |
  | actions add mirred | `tc actions add action mirred egress redirect dev lo index 3` |
  | actions ls / del / get | `tc actions ls action gact`, `tc actions del action gact index 1`, `tc actions get action gact index 1` |

  The three police goldens carry their full 1024-byte rate (and peak) tables, so the
  `tc_calc_rtable_64` behaviour is verified entry by entry. The two chain goldens are what
  pin the 1-based ordinals; the `tc actions` goldens are what pin the 4-byte `tcamsg`.

- **Golden re-parse**: several goldens are fed back through `parseQdisc`/`parseClass`/
  `parseFilter`/`parseAction` and asserted field by field, so the decoders are checked
  against real kernel-shaped bytes rather than only against this module's own encoder —
  including the pipe chain's two ordinals, police's 64-bit rates and tick burst, the vlan
  chain's 802.1ad protocol, and the standalone table's `tcamsg` bodies.
- **Encode/decode round-trip** per kind: htb class (incl. RATE64/CEIL64 clamping), tbf
  with a peak bucket, fq_codel's "omit what is unset", u32 with two keys, flower over
  IPv6, netem with every optional attribute populated, and a six-entry action list
  covering all five modelled kinds plus `raw` (which also exercises the decode cap).
- **Unit**: handle packing/parse/format (incl. the hex gotcha and overflow), `tcm_info`
  packing both ways, `Psched` derivation (incl. the ns-resolution compat hack and a
  degenerate divisor), `calcXmitTime` ceiling + saturation, `deriveCellLog`, ATM size
  adjustment, `RateSpec` byte layout, `Create` flag combinations, and every
  spec-validation error path.
- **Fuzz** (`std.testing.fuzz`): `parseQdisc`, `parseClass`, `parseFilter`,
  `parseAction`/`parseActionList`/`parseStats`/`actionsOf` and all `parse*Options` over
  arbitrary bytes — never panic, never over-read.
- **Live netns round-trip** (env-gated; prints `SKIPPED: …` and passes when unprivileged):
  `unshare -rn zig build test-tc`. Integration tests exercise an unprivileged qdisc
  dump, the v1 netem add/show/change/del cycle, an htb tree (qdisc → two classes, one of
  them needing RATE64 → an fq_codel leaf under a class → u32 + flower filters → dumps of
  all three families → filter del → class del), a tbf round-trip, an extended-ACK probe
  with a bogus qdisc kind, an **action round-trip** (a u32 filter carrying a
  `skbedit`→`police` PIPE chain and a flower filter carrying `mirred`, both dumped back
  and decoded ordinal by ordinal, with police's tick burst converted back to the 10 KiB
  requested and the kernel's own `refcnt`/`TCA_ACT_STATS` asserted), and an unprivileged
  `RTM_GETACTION` dump. Every assertion is against what the kernel echoed back.

  This was run in the development environment: green under `unshare -rn` in
  both Debug and `--release=fast`, with only the shared-action-table write skipping; run
  fully unprivileged, the privileged-only tests skip cleanly instead. `zig build test-netlink`
  stays green. The mq/cake batch was captured
  on the same host and recipe as the action goldens (`-e write=all`, exact `sendmsg` bytes
  checked against each message's own `nlmsg_len`); `lo` is single-queue so the kernel
  rejects the attach, but the request bytes are what the golden pins.

  The one test that still skips inside `unshare -rn` is the shared-action-table write
  (`tc actions add|del`), which needs `CAP_NET_ADMIN` in the initial user namespace — see
  the `tcamsg` section. Its read half (`RTM_GETACTION` dump + decode) runs unprivileged
  and is covered.

  Kernel behaviours the live runs pinned down (all now encoded in the module): a **down**
  interface has no qdisc at all (a fresh `unshare -rn` starts with `lo` DOWN, so the tests
  admin-up first); htb dumps `HTB_VER` (0x30011) in `tc_htb_glob.version`, of which only
  the high half is the protocol version `tc` sends; and an **empty** shared action table
  answers a dump with `-ENOENT` rather than an empty `NLMSG_DONE`.

## Provenance

Kernel UAPI headers (`linux/rtnetlink.h` — struct tcmsg, TCA_*; `linux/pkt_sched.h` —
tc_netem_qopt/tc_htb_glob/tc_htb_opt/tc_tbf_qopt/tc_ratespec/tc_police, TCA_NETEM_*/
TCA_HTB_*/TCA_TBF_*/TCA_FQ_CODEL_*; `linux/pkt_cls.h` — tc_u32_sel/tc_u32_key/tcamsg,
TCA_U32_*/TCA_FLOWER_*/TCA_ACT_*/TCA_ROOT_*/TC_ACT_*/TCA_POLICE_*; `linux/tc_act/*.h` —
tc_gen/tc_gact/tc_gact_p/tc_mirred/tc_skbedit/tc_vlan and their attribute enums;
`linux/gen_stats.h` — TCA_STATS_*, gnet_stats_basic/queue, tcf_t), all GPL-2.0 WITH
Linux-syscall-note. No GPL header source is copied — only
the uncopyrightable ABI facts they document (struct layouts, numeric constants); the
Linux-syscall-note exception is what keeps this module cleanly MIT, exactly as already
established for `netlink`/`wireguard`.

**iproute2 (GPL-2.0-or-later) was consulted as a behaviour/design reference** for v2 and
the action work —
`tc/tc_core.c` (`tc_calc_xmittime`, `tc_calc_rtable`, `tc_core_init`), `tc/q_htb.c`,
`tc/q_tbf.c`, `tc/q_fq_codel.c`, `tc/f_u32.c`, `tc/f_flower.c`, `tc/tc_class.c`,
`tc/tc_filter.c`, `tc/m_action.c`, `tc/m_gact.c`, `tc/m_mirred.c`, `tc/m_police.c`,
`tc/m_skbedit.c`, `tc/m_vlan.c` and `lib/utils.c` (`__get_hz`) — to learn the rate-table arithmetic, the default-burst
formulas, the attribute emission order (including the per-action-kind order and the
1-based ordinal numbering) and the client-side dump-filter rules. No source
was copied; the algorithms are re-derived and re-expressed here, and the goldens are the
independent check that the behaviour matches. The v1 statement that no third-party
implementation was consulted no longer holds; `/NOTICE`'s `tc` entry carries the matching
`design ref: iproute2` declaration required by CONVENTIONS §5.

## Status

`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const
meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** netlink datagrams captured from real iproute2 tc via strace, goldens.zig
