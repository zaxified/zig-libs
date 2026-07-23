# conntrack — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE.

## Design & invariants

`conntrack` is a ctnetlink client split in two:

- `src/wire.zig` — pure, I/O-free: the `nfgenmsg` header, every CTA_*/IPS_*/TCP-state
  constant, the typed `Flow`/`Tuple`/`Counters` model, `decodeFlow`, and the request
  builders. No syscalls, no allocator beyond the caller's, testable on any OS.
- `src/root.zig` — the `NETLINK_NETFILTER` socket, the dump engine, the ACK/GET await loops
  and the event seam. Linux-only by construction (`@compileError` on other targets).
- `src/goldens.zig` — raw netlink frames captured off a live kernel, with the exact capture
  command in the file header.

Framing is reused from the sibling `netlink` module's codec: `codec.MessageIterator`,
`codec.AttrIterator`, `appendHeader`/`finishHeader`, `appendAttr`, `nestBegin`/`nestEnd`,
`NLM_F_*`, `errorFromCode`/`writeErrorFromCode` (typed errno mapping) and the extended-ACK
string extraction. Nothing under `modules/netlink` was modified.

### The two things a ctnetlink client gets wrong

**1. Byte order.** netlink itself is host-endian, but every ctnetlink *integer* attribute is
big-endian: `CTA_STATUS`, `CTA_TIMEOUT`, `CTA_MARK`, `CTA_ID`, `CTA_USE`, `CTA_ZONE`, the
ports, the ICMP id, the 64-bit counters, the timestamps and `nfgenmsg.res_id`. The kernel does
**not** set `NLA_F_NET_BYTEORDER` on them, so nothing on the wire distinguishes them from a
host-endian attribute — only the attribute *type* does. `netlink.codec.Attr.asU16/asU32` are
therefore deliberately unused for payload values; `wire.zig` has `asBe16/asBe32/asBe64` and
their append twins, and a dedicated test pins the trap:

```
CTA_TIMEOUT = 08 00 07 00 | 00 06 97 75
  big-endian:  431989 s   (what the kernel meant, and what `conntrack -L` printed)
  host-endian: 0x75970600 (what a copy-pasted rtnetlink decoder would report)
```

**2. Nesting flags.** ctnetlink *does* set `NLA_F_NESTED` on `CTA_TUPLE_ORIG/_REPLY`,
`CTA_TUPLE_IP`, `CTA_TUPLE_PROTO`, `CTA_PROTOINFO`, `CTA_PROTOINFO_TCP`, `CTA_COUNTERS_*` and
`CTA_TIMESTAMP` — unlike rtnetlink, where iproute2 conventionally omits it. The builders OR it
in explicitly; the golden request tests would fail by four bytes' worth of type field if they
did not.

### Kernel behaviours the API is shaped around

Both were found by running against a real kernel, and both are asserted by the live test:

- **`CTA_STATUS` is a diff, not an assignment.** `ctnetlink_change_status` XORs the requested
  status against the entry's current one and returns `-EBUSY` if the difference would clear
  `IPS_EXPECTED`, `IPS_CONFIRMED`, `IPS_DYING`, `IPS_SEEN_REPLY` or `IPS_ASSURED` — those bits
  can only be set. A newly created entry is already `IPS_CONFIRMED` when the status is applied,
  so an insert that sends `IPS_SEEN_REPLY` alone is rejected. (`conntrack -I -u SEEN_REPLY`
  sends `SEEN_REPLY|ASSURED|CONFIRMED`, which is why it works.) Documented on `NewSpec.status`.
- **`CTA_ID` is not a lookup key.** `ctnetlink_del_conntrack` finds the entry by
  `CTA_TUPLE_ORIG` or `CTA_TUPLE_REPLY` and only then compares `CTA_ID`, returning `-ENOENT` on
  a mismatch. Consequently: a delete needs a tuple, `expect_id` is a compare-and-delete guard,
  and **a delete with no tuple at all flushes the whole table**. That last one is a footgun by
  construction, so flushing is a separately named entry point (`Socket.flush` /
  `wire.buildFlushRequest`) that a mis-built tuple can never reach.

A third, smaller one: the kernel sets `NLM_F_MULTI` even on the single-message answer to a
non-dump `IPCTNL_MSG_CT_GET`, so that flag cannot be used to tell a GET reply from a dump. The
module matches replies on `(portid, seq)` instead; a golden test pins the observed flag word.

### Decoder safety

The decoder is the module's whole attack surface: it consumes kernel-supplied bytes that a
container-neighbour's traffic can influence in content (never in framing). Invariants:

- Every length is validated by `netlink.codec`'s walkers before a slice is formed; iteration
  always advances ≥ 4 bytes, so a walk over N bytes is capped at N/4 steps and cannot loop.
- Every scalar accessor demands the exact payload size (`asBe32` on a 2-byte `CTA_STATUS` is
  `error.BadLength`, not a truncated read).
- Nesting is walked at a fixed, compile-time depth (flow → tuple → ip/proto), so an
  attacker-chosen nesting depth costs a constant, not a stack frame per level.
- Unknown attribute *types* are skipped, never rejected — a future kernel adding a CTA_* must
  not break a dump — while malformed *lengths* always error out.
- `Flow` is fixed-size and pointer-free, so `dump` returns a slice that frees with one
  `gpa.free` and a decoded flow can never dangle into the receive buffer.

Coverage: hostile/truncated/misaligned attribute streams, wrong-sized scalars, a 64-deep
self-nested tuple, and a `std.testing.fuzz` target over `decodeFlow` + the message walker.

### Transport

**All of it is `netlink.Socket`'s** — `Socket` here is a one-field wrapper
(`nl: netlink.Socket`) opened with `netlink.Socket.openProtocolGroups(gpa, linux.NETLINK.NETFILTER,
groups)`. That gives: one blocking `NETLINK_NETFILTER` socket per thread/loop; kernel-assigned
portid; datagrams whose sender pid ≠ 0 dropped; receive buffer grown by a `MSG_PEEK|MSG_TRUNC`
probe (capped at 16 MiB); `NETLINK_EXT_ACK` enabled best-effort so a rejected request carries the
kernel's reason string; the sequence counter; the write+ACK engine
(`netlink.Socket.awaitAckStrict`). This module adds only ctnetlink policy on top: replies matched
on `(portid, seq)` through `netlink.classifyDumpMessage`, `NLM_F_DUMP_INTR` restarting the dump up
to 4 times before `error.InconsistentDump`, the reply-type/decoder choice, and the errno mapping.

`ENOBUFS` is surfaced as `error.Overrun` rather than folded into `SystemResources`, because on an
event socket it means events were **lost** and the caller must re-dump to resynchronise. `EAGAIN`
is `error.WouldBlock`, so a caller can set `O_NONBLOCK` on `Socket.handle()` or a receive timeout
and drive the socket from poll/epoll. Both come from `netlink.Socket.recvDatagramStrict` /
`awaitAckStrict` — the *strict* half of the shared engine, which the rtnetlink path narrows away
because it has no multicast groups and no receive timeout. `Socket.send`, `Socket.recvDatagram`,
`Socket.handle`, `Socket.setRecvTimeout`, `Socket.nextSeq` and `Socket.lastErrorMessage` are
unchanged in signature and behaviour; they are now one-line forwards.

The event API is deliberately a seam rather than a callback: `Socket.nextEvents()` performs
exactly one blocking `recv` and hands back an `EventIterator` over that datagram. The iterator
is pure — it can also be fed a replayed capture, which is how the offline event tests work.

### DRY candidates

Two were filed when this module was written (`modules/netlink` was owned by another workstream
at the time), and a third — the transport itself — was filed after them. **All three are now
paid off:**

1. ~~**`asBe16/32/64` + `appendAttrBe16/32/64`** (`wire.zig`)~~ — **done.** They live in
   `netlink.codec` beside their host-order twins (`Attr.asBe16/32/64`,
   `codec.appendAttrBe16/32/64`) and this module uses them from there; `nftables` had written
   the same eight independently, and nfqueue, nflog, cttimeout and nf_acct will want them too.
   Only the *writers'* error set changed on the way: this module's copies propagated
   `AttrTooLong` from `appendAttr`, `nftables`' asserted it away. The shared ones assert
   (`unreachable`) — the payload is a fixed 2/4/8 bytes, so the error is unreachable by
   construction, and it matches the existing `appendAttrU16/U32/U8`. `BuildError` still lists
   `AttrTooLong` because the string/raw builders here can still raise it.
2. ~~**The dump loop**~~ — **done.** `Socket.dump`'s multi-part triage (the (portid, seq)
   match, the `NLM_F_DUMP_INTR` restart, the `NLMSG_DONE`/`NLMSG_ERROR`/`NLMSG_NOOP`/
   `NLMSG_OVERRUN` dispatch) is `netlink.classifyDumpMessage`, shared with `netlink`'s own
   dumps and with `nftables`. It is a pure verdict function, not a driver: the policy above it
   — which request, which reply type, which parser, which errno mapping, how items are
   allocated — stays here, which is what lets three different netlink protocols share it.
3. ~~**The socket transport**~~ — **done.** `netlink.Socket.open` no longer hardcodes
   `linux.NETLINK.ROUTE`: `openProtocol`/`openProtocolGroups` take the protocol (and a multicast
   bind mask), and `netlink.Socket` now *is* the shared transport — bind, portid capture,
   `NETLINK_EXT_ACK`, sequence allocation, `send`, the `MSG_PEEK|MSG_TRUNC` growth loop,
   `SO_RCVTIMEO`, the extended-ACK capture and the ACK engine. This module's private copies of
   all of it are gone; `Socket` is `struct { nl: netlink.Socket }` and its transport methods are
   forwards. Behaviour is bit-for-bit what it was — the strict `Overrun`/`WouldBlock` mapping
   this module needed became the shared implementation, and `netlink`'s coarser rtnetlink mapping
   became a narrowing wrapper over it, so neither side moved. **`genetlink` is the remaining
   candidate** (it still carries its own copy, and `nl80211`/`ethtool`/`wireguard` ride on it).

**Not folded in, deliberately: `nfgenmsg` framing.** `nftables` and this module both define
`nfgenmsg_len`/`NFNETLINK_V0`/`msgType`/`Nfgenmsg`/`parseNfgenmsg`/`appendNfgenmsg`. `struct
nfgenmsg` is a *per-protocol fixed payload header*, the same layer as `ifinfomsg` (which lives in
`netlink`, with rtnetlink), `tcmsg` (in `tc`) and `genlmsghdr` (in `genetlink`) — so it belongs
with its family, not in `netlink`, whose remit is netlink-generic mechanism. The argument in full
is in `modules/netlink/SPEC.md`; the trigger to revisit is a third nfnetlink family (nfqueue,
nflog, ipset), at which point a sibling `nfnetlink` module is the right home.

## Verification

### Byte-exact goldens (all from real captures)

Every golden in `src/goldens.zig` is a **raw netlink frame captured off the wire**, not a
hand-written layout. The capture used an `nlmon` device, which hands the kernel a verbatim copy
of every netlink frame in the namespace:

```sh
unshare -rn bash -c '
  sysctl -w net.netfilter.nf_conntrack_acct=1        # capture set 2 only
  sysctl -w net.netfilter.nf_conntrack_timestamp=1   # capture set 2 only
  ip link add nlmon0 type nlmon && ip link set nlmon0 up
  tcpdump -i nlmon0 -s 0 -c 400 -U -w nl.pcap -Z root &
  sleep 2
  conntrack -I -s 192.168.1.10 -d 93.184.216.34 -p tcp --sport 51000 \
            --dport 443 --state ESTABLISHED -t 431990 -u SEEN_REPLY,ASSURED
  conntrack -I -s 10.0.0.1 -d 10.0.0.2 -p udp --sport 5353 --dport 53 -t 30
  conntrack -I -s fd00::1 -d fd00::2 -p tcp --sport 40000 --dport 80 \
            --state ESTABLISHED -t 300 -u SEEN_REPLY
  conntrack -L; conntrack -L -f ipv6
  conntrack -G -s 10.0.0.1 -d 10.0.0.2 -p udp --sport 5353 --dport 53
  conntrack -D -s 10.0.0.1 -d 10.0.0.2 -p udp --sport 5353 --dport 53
  wait'
```

(Set 2 also passed `-m 42 -w 7` to the first insert and added an ICMP flow with
`-p icmp --icmp-type 8 --icmp-code 0 --icmp-id 1234`.) In a `DLT_NETLINK` pcap each record
carries a 16-byte cooked header whose last two bytes are the netlink family (`0x000c` =
`NETLINK_NETFILTER`); the goldens are the bytes after it. The same traffic was independently
captured with `unshare -rn strace -f -e trace=sendmsg,recvmsg,sendto,recvfrom -xx -s 8192
conntrack …` and agrees attribute for attribute — that decode is what the layout comments were
cross-checked against. Tools: conntrack-tools v1.4.9, kernel 7.0.0 x86_64.

**Encoder goldens** — the module's request bytes are compared to conntrack-tools' byte for byte:

| golden | request | assertion |
|---|---|---|
| `dump_request_unspec` / `dump_request_inet6` | `conntrack -L`, `-L -f ipv6` | full 20-byte equality |
| `get_request_udp4` | `conntrack -G` (udp/v4) | full 72-byte equality |
| `new_request_udp4` | `conntrack -I` udp/v4 | full 132-byte equality |
| `new_request_tcp4` | `conntrack -I` tcp/v4 + `-m 42 -w 7` | full 188-byte equality (status, timeout, mark, TCP protoinfo, zone) |
| `new_request_tcp6` | `conntrack -I` tcp/v6 | full 220-byte equality |
| `new_request_icmp4` | `conntrack -I` icmp/v4 | full 148-byte equality (id/type/code, and `Tuple.invert()`'s echo 8→0 mapping) |
| `delete_request_udp4` | `conntrack -D` | header + `nfgenmsg` + the whole `CTA_TUPLE_ORIG` nest byte-identical; see below |

The delete golden is a **prefix** comparison, and that is a real difference, not a hedge:
conntrack-tools dumps the entry first and then echoes everything it read back
(`CTA_TUPLE_REPLY`, `CTA_STATUS`, `CTA_TIMEOUT`, `CTA_MARK`, `CTA_SYNPROXY`), while the kernel
matches on `CTA_TUPLE_ORIG` alone. This module sends the minimum, so the two agree on every byte
both emit (nlmsghdr type/flags, nfgenmsg, the 52-byte tuple TLV) and differ only in what
conntrack-tools adds. The delete path is additionally proven end-to-end by the live test.

**Decoder goldens** — real kernel replies, decoded and checked field by field:

| golden | contents |
|---|---|
| `dump_reply_three_flows` (720 B) | one datagram, three `NLM_F_MULTI` messages: IPv4/UDP unreplied, IPv4/TCP assured, IPv6/TCP established — ports, both directions, status bits, timeout, mark, id, use, TCP state/wscale/flags |
| `dump_reply_with_counters` (600 B) | `nf_conntrack_acct=1` + `nf_conntrack_timestamp=1`: 64-bit `CTA_COUNTERS_ORIG/_REPLY`, `CTA_TIMESTAMP_START`, `CTA_ZONE`, `CTA_MARK`, and an ICMP tuple (id/type/code, no ports) |
| `get_reply_udp4` (192 B) | the single-entry `conntrack -G` answer, incl. the surprising `NLM_F_MULTI` |
| `delete_request_udp4` (176 B) | doubles as a decoder fixture — a genuine `IPCTNL_MSG_CT_DELETE` message, i.e. exactly the shape of a destroy *event* |

### Live proof

`unshare -rn zig build test-conntrack` (real kernel, real netns, CAP_NET_ADMIN inside the user
namespace) runs three live tests, all of which passed in Debug and in `--release=fast`:

1. **dump** — open the socket, `IPCTNL_MSG_CT_GET|NLM_F_DUMP`, decode; every returned flow must
   have complete `orig`/`reply` tuples, a family matching its addresses, and ports for TCP/UDP.
2. **round-trip** — insert a synthetic UDP flow on RFC 5737 documentation addresses, `get` it
   back by the original tuple, `get` it again by the reply tuple and assert both name the same
   `CTA_ID`, find it exactly once in a `dump(.ipv4)` (this is the path that decodes a genuine
   kernel dump reply, not a replayed one), attempt a compare-and-delete with a **wrong** id and
   assert `error.NotFound` *and* that the entry survived, then delete with the right id and
   assert it is gone and that a second delete answers `NotFound`.
3. **events** — bind `NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY` on a second socket, insert a flow
   from the first, and observe the `new` event decoded through the same `decodeFlow`.

Without the namespace (plain `zig build test-conntrack` as an ordinary user) the kernel answers
`EPERM` to everything, and each live test prints `SKIPPED: …` and passes.

Test totals: **28 tests, all passing** in Debug and `--release=fast`; unprivileged, 25 offline
tests run and 3 live tests skip-and-pass; under `unshare -rn`, all 28 run for real. One fuzz
target (`decodeFlow` + message walker).

## Deferred (honest list)

Scope choices, not oversights. None of them is load-bearing for a dump/get/delete/event client:

- **Expectations** (`NFNL_SUBSYS_CTNETLINK_EXP`, `IPCTNL_MSG_EXP_*`) — a separate subsystem with
  its own message types; the `Group.CONNTRACK_EXP_*` masks are defined but nothing decodes
  expectation messages.
- **NAT attributes** (`CTA_NAT_SRC`/`_DST`, `CTA_SEQ_ADJ_*`, `CTA_SYNPROXY`) — skipped by the
  decoder and never built. Reading a NAT'd flow's *tuples* works (they are ordinary tuples,
  and the reply tuple already shows the translation); the explicit NAT range attributes do not.
- **DCCP/SCTP protoinfo** — `CTA_PROTOINFO_DCCP`/`_SCTP` are skipped; only the TCP sub-tree is
  decoded. The constants are present.
- **`CTA_HELP` / `CTA_SECCTX` / `CTA_LABELS`** — helper name, security context and connlabels
  are neither decoded nor built.
- **Filtered dumps** (`CTA_MARK`+`CTA_MARK_MASK`, `CTA_FILTER`, `CTA_STATUS_MASK`) — the kernel
  can filter a dump server-side; this module always dumps and lets the caller filter, which is
  correct but not the cheapest.
- **Statistics** (`IPCTNL_MSG_CT_GET_STATS`, `_STATS_CPU`) and the dying/unconfirmed dumps
  (`IPCTNL_MSG_CT_GET_DYING`, `_GET_UNCONFIRMED`) — message types defined, no typed API.
- **`nf_conntrack_timeout` / `cthelper` subsystems** — out of scope entirely.
- **Event socket tuning** — no `SO_RCVBUF` bump and no `NETLINK_BROADCAST_ERROR`/
  `NETLINK_NO_ENOBUFS`; a busy event socket will report `error.Overrun` rather than silently
  dropping, and the caller is told to re-dump. A future consumer that needs lossless events
  should raise the receive buffer first.
- **`Tuple.invert()`** maps only the paired ICMP types (echo/timestamp/information/address-mask,
  and ICMPv6 echo). Any other type is copied unchanged — the kernel would not track it as a
  request/reply pair either — but a caller that knows the exact reply tuple should build it
  explicitly rather than rely on the helper.
