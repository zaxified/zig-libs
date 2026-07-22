# netlink — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
The attr/message walker is the security boundary and lives in `codec.zig` — pure, no I/O, no
platform dependency, unit- and fuzz-tested on any OS. Every `nlmsg_len`/`rta_len` is
bounds-checked against the enclosing buffer before any slice is formed; each step advances ≥4
bytes, so a walk over N bytes is capped at N/4 steps. Malformed/hostile/bit-flipped input →
`error.Truncated`/`error.BadLength`, never a panic or OOB read. Typed results are plain data (fixed
inline buffers, no pointers into the receive buffer) — an owned slice frees with a single
`gpa.free(slice)`; deliberately no `netaddr` dependency (addresses are raw `{family, bytes,
prefixlen, ...}`) to keep `netlink` a dep-free foundation. Transport discipline: raw
`std.os.linux` errno-encoded syscalls (Linux-only by design); kernel-assigned portid + per-request
sequence number match replies (stale messages from an aborted earlier dump are skipped,
self-healing the queue); multi-part dumps assemble until `NLMSG_DONE`; `NLM_F_DUMP_INTR` restarts
up to 4 attempts (libnl's `NLE_DUMP_INTR`). Receive buffer grows via a `MSG_PEEK|MSG_TRUNC` size
probe so nothing is lost to truncation; non-kernel datagrams (sender pid ≠ 0) are dropped. One
`Socket` per thread/loop; no globals. Scoping: `Filter.family` is applied kernel-side (fixed-header
family byte) *and* re-checked client-side; `Filter.ifindex` is client-side only. Dump requests
carry the full fixed header (not the legacy 1-byte rtgenmsg) for strict-check compatibility, like
modern iproute2. IPv4 prefers `IFA_LOCAL` over `IFA_ADDRESS`. Clean-room from the kernel UAPI
headers (`linux/netlink.h`, `linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`,
`linux/neighbour.h`, `linux/if.h`) + RFC 3549; libmnl and Go `vishvananda/netlink` are design
references only (framing/validation discipline, typed-query shape) — constants/struct layouts are
the OS ABI, see NOTICE.

## Shared codec surface (what other netlink families reuse)
`codec.zig` is not just this module's private wire layer — it is the codec every netlink-family
module in the tree sits on (`genetlink`, `nl80211`, `ethtool`, `tc`, `wireguard`, `ebpf`,
`conntrack`, `nftables`). Three parts of it exist specifically to be shared:

**Big-endian attribute accessors.** rtnetlink puts its integers on the wire in *host* order
(`Attr.asU16`/`asU32`, `appendAttrU16`/`appendAttrU32`). Every **netfilter** family — ctnetlink,
nftables, nfqueue, nflog, cttimeout, nf_acct — does the opposite: network order, and the kernel
does **not** set `NLA_F_NET_BYTEORDER`, so nothing on the wire distinguishes the two and the
reader has to know its family. `Attr.asBe16/asBe32/asBe64` and
`appendAttrBe16/appendAttrBe32/appendAttrBe64` are the net-order twins, with the same exact-width
guards (`error.BadLength` on any other length — never a truncating read). The writers take a
fixed 2/4/8-byte payload, so like their host-order twins they assert `AttrTooLong` away
(`unreachable`) instead of propagating it. `conntrack` and `nftables` had each written these
eight independently before they landed here.

**Multi-part dump triage — `DumpStep` + `classifyDumpMessage(m, portid, seq)`.** The per-message
verdict every dump loop needs, in the order the kernel's framing requires: match on
(portid, seq) first — anything stale or foreign is skipped, self-healing the queue after an
aborted earlier dump — then honour `NLM_F_DUMP_INTR` (`.restart`), then dispatch the control
types (`.done` for `NLMSG_DONE` *and* for an `NLMSG_ERROR` carrying code 0, i.e. the bare ACK
that ends an empty dump; `.failed = errno`; `.overrun`; `.malformed` for an errno payload too
short to read; `.skip` for `NLMSG_NOOP`), and hand everything else back as `.record`.

It is a **verdict function, not a driver** — deliberately. A driver would have to own the
allocation strategy, the error set and the recv call, and those are exactly what differs between
families: `netlink` collects into an `ArrayList(T)` and maps errno through `errorFromCode`,
`conntrack` adds `error.Overrun` and captures the extended ACK first, `nftables` collects into a
caller-supplied arena and maps through its own `errorFromErrno`. Keeping the verdict pure means
sockets on *other netlink protocols* (`NETLINK_NETFILTER`, `NETLINK_GENERIC`) can share it
without this module having to model their transports. `Socket.dump` and `Socket.dumpCollect`
here are themselves written on it, so it cannot drift from the behaviour it describes.

**Raw transport seam — `Socket.send` + `Socket.recvDatagram` (public).** For callers that need a
message this module does not model. `tc` drives `RTM_GET*` dumps this way (today it goes through
`handle()` and re-implements the syscall loops — it can now collapse onto this pair plus
`classifyDumpMessage`; that rewire is a later wave, `tc` was read-only when this seam landed).
The returned datagram borrows the socket's receive buffer and is valid until the next call on
the socket. Sequence numbers come from `nextSeq`.

## Write ops (RTM_NEW\*/RTM_DEL\*)
Supported, and **not** "read/dump only" any more (that scope statement was retired when the write
path landed). Implemented: **addresses** (`addressAdd`/`addressDel` — `IFA_LOCAL`+`IFA_ADDRESS`,
prefixlen/scope/flags, optional broadcast/label/`IFA_FLAGS`), **routes** (`routeAdd`/`routeDel` —
`RTA_DST`/`RTA_GATEWAY`/`RTA_OIF`/`RTA_PREFSRC`/`RTA_PRIORITY`, table/scope/protocol/type, tables
>255 promoted to `RTA_TABLE` like iproute2), **links** (`linkSet`/`linkUp`/`linkDown` — admin
state, MTU, rename, MAC, txqlen; `linkAdd`/`linkDel` — virtual devices via
`IFLA_LINKINFO`/`IFLA_INFO_KIND`), **neighbours** (`neighborAdd`/`neighborDel` — `NDA_DST`,
`NDA_LLADDR`, NUD state, NTF flags). Message construction reuses the existing codec
(`appendHeader`/`appendAttr*`/`finishHeader`, plus new `nestBegin`/`nestEnd`), so `NLMSG_ALIGN`/
`NLA_ALIGN` handling is shared with the read path; a nest's length covers the inner attributes'
padding exactly like the kernel's `nla_nest_end`, and rtnetlink nests are sent without
`NLA_F_NESTED` (iproute2 convention; the kernel's validator ignores the bit).

**`ifi_change` discipline (the classic footgun).** The kernel computes
`new = (old & ~ifi_change) | (ifi_flags & ifi_change)`, so a lazy `ifi_change = ~0` silently applies
*every* IFF_\* bit. This encoder never sets a mask bit the caller did not ask for: `LinkChange.up`
contributes exactly `IFF_UP` (value set for up, cleared for down), `flags`/`flags_mask` are the raw
escape hatch for anything else, attribute-only changes (MTU/name/MAC) send `ifi_change = 0`, and a
change that would touch nothing at all is rejected with `error.NothingToChange` instead of being
sent as a silent no-op.

**Privileges.** Every write needs `CAP_NET_ADMIN` (`error.AccessDenied` otherwise); all `RTM_GET*`
dumps stay unprivileged.

**ACK/error model.** Every write carries `NLM_F_REQUEST|NLM_F_ACK` plus
`NLM_F_CREATE`+`NLM_F_EXCL` (add), `NLM_F_CREATE`+`NLM_F_REPLACE` (replace) or `NLM_F_APPEND`, per
the `Create` option struct; deletes carry `NLM_F_REQUEST|NLM_F_ACK` only. The call blocks for the
matching `NLMSG_ERROR` reply (matched on portid+seq; foreign/stale messages and `NLM_F_ECHO` copies
are skipped): errno 0 = success, otherwise `writeErrorFromCode` maps it to a typed error — EPERM/
EACCES → `AccessDenied`, EEXIST → `Exists`, ENOENT/ESRCH → `NotFound`, ENODEV → `NoSuchDevice`,
EADDRNOTAVAIL → `AddressNotAvailable`, ENETUNREACH/EHOSTUNREACH → `NetworkUnreachable`, EBUSY →
`Busy`, EINVAL → `InvalidRequest`, EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT → `NotSupported`,
ENOBUFS/ENOMEM → `SystemResources`, anything else → `Unexpected`. A silent write failure is
impossible: there is no fire-and-forget path. **Extended ACK** is enabled per socket
(`NETLINK_EXT_ACK`, best-effort — pre-4.12 kernels just answer ENOPROTOOPT) and the kernel's reason
string (`NLMSGERR_ATTR_MSG`) is surfaced via `Socket.lastErrorMessage()`. Its offset is derived the
same way `netlink_ack()` writes it — TLVs start after `struct nlmsgerr` when `NLM_F_CAPPED` is set,
otherwise after the fully echoed request — with every offset bounds-checked, so a hostile ext-ack
yields an empty message, never an over-read. Requests are validated *before* any syscall
(`BuildError`: bad address length, mixed families, missing family, bad name/link address).

The write+ACK engine is public (`Socket.nextSeq` + `Socket.requestAck`) so sibling modules can send
their own hand-built rtnetlink messages through the same socket discipline.

## Bridges (AF_BRIDGE) — `src/bridge.zig`
Bridge support is a pure builder/parser layer on the existing engine: nothing about sending, ACK
handling, extended ACKs or dump assembly is duplicated. Three message shapes, each with its own
family discipline — the usual source of `EINVAL` when hand-rolled:

**Device lifecycle.** `bridgeAdd` sends `RTM_NEWLINK` with
`IFLA_LINKINFO{ IFLA_INFO_KIND = "bridge", IFLA_INFO_DATA{ IFLA_BR_* } }`; the encoded options are
`FORWARD_DELAY`(u32), `AGEING_TIME`(u32), `STP_STATE`(u32), `PRIORITY`(u16), `VLAN_FILTERING`(u8)
and `VLAN_PROTOCOL`(**big-endian** u16), emitted in ascending attribute order — the order
`ip link add … type bridge` produces when its arguments are given in that order. With no option set
at all, `IFLA_INFO_DATA` is omitted entirely. Deletion is the existing `linkDel`. Enslaving is
`IFLA_MASTER` on the ordinary (AF_UNSPEC) `RTM_NEWLINK` link-set path — `LinkChange.master`, exposed
as `portEnslave`/`portRelease`; `master = 0` is `nomaster` and deliberately does *not* trip the
`NothingToChange` guard.

**FDB.** `RTM_NEWNEIGH`/`RTM_DELNEIGH`/`RTM_GETNEIGH` with `ndm_family = AF_BRIDGE`.
`FdbSpec` carries `NDA_LLADDR`, `NDA_DST`, `NDA_VLAN`, `NDA_PORT` (big-endian, VXLAN UDP),
`NDA_VNI` and `NDA_MASTER`, emitted in iproute2's `fdb_modify` order; `ndm_state` (NUD_\*) and
`ndm_flags` (`NTF_SELF` = the device's own FDB vs `NTF_MASTER` = the bridge's, `| NTF_EXT_LEARNED`
for controller-installed entries) are explicit. The defaults reproduce
`bridge fdb add <mac> dev <port> master` (`NUD_PERMANENT|NUD_NOARP`, `NTF_MASTER`); iproute2's
`static` keyword is `NUD_REACHABLE|NUD_NOARP`. The dump is a plain 12-byte `ndmsg` with the family
byte set — *not* the legacy `ifinfomsg` form (the kernel's `rtnl_fdb_dump` accepts both; modern
iproute2 sends `ndmsg`, and so does this module). Both `ndm_ifindex` and `NDA_MASTER` filter
kernel-side. `parseFdb` returns `null` for a non-AF_BRIDGE entry, so an ordinary ARP/NDP neighbour
in the same buffer is never mistaken for an FDB entry.

**VLAN filtering.** `RTM_SETLINK` (add) / `RTM_DELLINK` (remove) with `ifi_family = AF_BRIDGE` and a
nested `IFLA_AF_SPEC` containing an optional `IFLA_BRIDGE_FLAGS` (u16 `SELF`/`MASTER`) plus one or
two `IFLA_BRIDGE_VLAN_INFO` = `struct bridge_vlan_info { u16 flags; u16 vid; }`. Neither `self` nor
`master` set ⇒ **no** `IFLA_BRIDGE_FLAGS` attribute at all, which is the kernel default and exactly
what `bridge vlan add dev <port>` sends. A VID **range** is two entries flagged
`RANGE_BEGIN`/`RANGE_END`; the decoder collapses the pair back into a single `VlanEntry`
(`vid..vid_end`) with the range bookkeeping bits stripped. Specs are validated before any syscall:
VID ∈ 1..4094 (`InvalidVlanId`), ascending range and never a PVID range, `self`+`master` mutually
exclusive (`InvalidVlanRange`). The dump is `RTM_GETLINK` + `ifinfomsg{AF_BRIDGE}` +
`IFLA_EXT_MASK = RTEXT_FILTER_BRVLAN`; `Filter.ifindex` scopes it client-side.

**Bridge-port options.** `RTM_SETLINK` with `ifi_family = AF_BRIDGE` and `IFLA_PROTINFO` — the one
rtnetlink nest iproute2 *does* set `NLA_F_NESTED` on, and the encoder matches it byte-for-byte.
`BrportChange` covers `STATE`, `LEARNING`, `UNICAST_FLOOD`, `ISOLATED` plus `GUARD`, `FAST_LEAVE`,
`PROTECT`, `MODE` (hairpin), `PRIORITY`, `COST`, `MCAST_FLOOD`, `BCAST_FLOOD` and
`NEIGH_SUPPRESS`; attributes are emitted in iproute2's `bridge link set` order (flood → learning →
state → isolated for the golden-covered subset), and an empty change is `NothingToChange`. Reading
port state back needs `RTM_GETLINK` with `ifi_family = AF_BRIDGE`: a plain AF_UNSPEC link dump
(`ip link show`) carries no `IFLA_PROTINFO`, which was verified on a live kernel.

**Error mapping** is unchanged and shared — the bridge ops add only `InvalidVlanId`/
`InvalidVlanRange` to the *build* side, in a separate `bridge.BuildError`/`bridge.WriteError` so the
existing `BuildError`/`WriteError` sets stay byte-for-byte compatible for sibling modules. One
kernel errno is deliberately left unmapped: `ENETDOWN` (moving a carrier-down port to
`BR_STATE_FORWARDING`) surfaces as `error.Unexpected`, because widening the shared
`writeErrorFromCode` table would change a public error set other modules compose with.

## Provenance / licensing
The kernel UAPI headers this module cites are GPL-2.0, but that does not make the module a GPL
derivative: only uncopyrightable ABI facts are taken from them (numeric constants, struct layouts),
and separately, those headers carry the **Linux-syscall-note** exception, which explicitly permits
userspace of any license to use them to interface with the kernel. No kernel or libmnl (LGPL-2.1)
source was consulted or copied; the codec is an original pure-Zig implementation. Full attribution
in /NOTICE. The golden request bytes in the tests were captured from iproute2's own traffic with
`strace` and with an `nlmon` + `tcpdump` netlink tap (observed wire bytes = ABI facts, no iproute2
code involved).

## Threat model / out of scope
The untrusted input is the kernel's reply bytes; the codec treats them as hostile and is fuzzed
accordingly. Unprivileged: RTM_GET\* dumps need no root; writes need CAP_NET_ADMIN. Out of scope
(deliberate, additive extension points): multicast event monitoring (RTNLGRP_\* subscription —
still unbuilt), qdiscs/classes/filters (the sibling `tc` module; classful qdiscs = a separate
task), conntrack (`NETLINK_NETFILTER`, separate module), policy routing (`RTM_*RULE`, `RTA_SRC`,
tos), `IFLA_INFO_DATA` payloads for kind-specific link parameters *other than* bridge (veth peers,
VLAN ids, VXLAN) and multipath routes (`RTA_MULTIPATH`).

**Deferred inside the bridge surface** (honest list — all reachable through the public codec +
`nextSeq`/`requestAck` if needed before they are built): MDB / IGMP-MLD multicast snooping
(`RTM_NEWMDB`/`DELMDB`/`GETMDB`, `MDBA_*`) and the bridge's own multicast options
(`IFLA_BR_MCAST_*`); VXLAN link creation and its `IFLA_VXLAN_*` `IFLA_INFO_DATA` (FDB entries
*pointing at* a VXLAN remote are supported — `NDA_DST`/`NDA_VNI`/`NDA_PORT` — but creating the
device is not); VLAN tunnel mapping (`IFLA_BRIDGE_VLAN_TUNNEL_INFO`); per-VLAN options and stats
(`BRIDGE_VLANDB_*`, `IFLA_BR_VLAN_STATS_ENABLED`, `RTEXT_FILTER_BRVLAN_COMPRESSED` — the dump
decoder *handles* compressed ranges, but the request always asks for the uncompressed form);
MRP, CFM and MST (`IFLA_BRIDGE_MRP`/`_CFM`/`_MST`); bridge-port backup port
(`IFLA_BRPORT_BACKUP_PORT`), `IFLA_BRPORT_FLUSH` and the read-only STP timers/ids; and reading the
bridge device's own `IFLA_BR_*` options back out of a link dump (only the port-side
`IFLA_PROTINFO` block is decoded). `ENETDOWN` is unmapped, see above.

## Verification
Offline unit tests over canned payloads built by the codec's own encoders: per-type parse
(link/address/route/neighbor), IFA_LOCAL-vs-ADDRESS preference, default-route + RTA_TABLE
override, truncated/bad-length/overrunning attrs → typed error, `errorFromCode`/`writeErrorFromCode`
errno mapping, `codec` constants cross-checked against `std.os.linux`, `std.testing.fuzz` harnesses
over the four typed parsers, the message/attribute/ext-ack walkers, and the request builders.
**Byte-exact construction tests** assert the encoded request equals the bytes iproute2 puts on the
wire for the same operation, captured with
`unshare -rn strace -f -e trace=sendmsg -xx -s 300 ip <cmd>` and cross-checked field-by-field
against the UAPI structs: `ip addr add 10.11.12.1/24 dev lo` (40 B), `ip route add 10.99.0.0/24 dev
lo scope link` (44 B), `ip route add 10.98.0.0/24 via 10.11.12.9 dev lo` (52 B), `ip link set lo up`
(32 B, `ifi_change = IFF_UP`), `ip link add name zdum0 type dummy` (60 B, nested LINKINFO), `ip link
del zdum0` (32 B), `ip neigh add 10.11.12.55 lladdr de:ad:be:ef:00:01 dev lo nud permanent` (48 B),
plus the delete forms and the `ifi_change`-mask cases.

**Bridge goldens** were captured the more direct way — an `nlmon` tap inside the namespace
(`unshare -rn bash -c 'ip link add nlmon0 type nlmon; ip link set nlmon0 up; tcpdump -i nlmon0
-Z root -w cap.pcap -U -s0 & …'`), which records the raw datagrams rather than strace's decoded
rendering (`DLT_NETLINK`: a 16-byte Linux cooked header, then the `nlmsghdr`); the
`strace -f -e trace=sendmsg -xx -s 400` form yields the same fields. Every builder's output was
diffed byte-for-byte (nlmsg_seq masked) against the capture — **23/23 identical**. Commands
covered, each cited in its test: `ip link add name br0 type bridge forward_delay 100 ageing_time
20000 stp_state 1 priority 4096 vlan_filtering 1` (100 B) and its minimal `vlan_filtering 1` form
(68 B) and bare form (56 B, no `IFLA_INFO_DATA`); `ip link set dev veth0 master br0` (40 B) and
`… nomaster`; `bridge fdb add 02:00:00:00:00:01 dev veth0 master static vlan 10` (48 B),
`bridge fdb del …` (48 B, `NUD_PERMANENT|NUD_NOARP`), `bridge fdb add … self static` (40 B),
`… master extern_learn` (40 B, `NTF_MASTER|NTF_EXT_LEARNED`), `bridge fdb append …` (40 B,
`NLM_F_CREATE|NLM_F_APPEND`); `bridge fdb show` (28 B), `bridge fdb show dev veth0` (28 B,
`ndm_ifindex`), `bridge fdb show br br0` (36 B, `NDA_MASTER`); `bridge vlan add dev veth0 vid 10
pvid untagged` (44 B), `… vid 30 untagged` (44 B), `… vid 100-200` (52 B, RANGE_BEGIN/END),
`bridge vlan add dev br0 vid 20 self` (52 B, `IFLA_BRIDGE_FLAGS`) and the three matching
`bridge vlan del` forms; `bridge vlan show` (40 B, `IFLA_EXT_MASK`); `bridge link show` (32 B,
`ifi_family = AF_BRIDGE`); `bridge link set dev veth0 state 3 learning off flood off isolated on`
(68 B, `IFLA_PROTINFO|NLA_F_NESTED`) and the two-attribute subset (52 B). Bridge **decoder** tests
run over real captured reply payloads (an FDB entry with `NDA_MASTER`/`NDA_VLAN`/`NDA_CACHEINFO`/
`NDA_FLAGS_EXT`, an `NTF_SELF` entry, a VXLAN-style entry, a `bridge vlan show` reply, a link-dump
`IFLA_PROTINFO` block) plus hostile nested streams: dangling `RANGE_BEGIN`, an inverted
`RANGE_END`, a bad-length `bridge_vlan_info`, an `IFLA_AF_SPEC` overrunning the buffer and a
zero-length nest — each yields a typed error or a defensively degraded entry, never a panic,
inversion or over-read. Both bridge builders and parsers are fuzzed.

Linux integration tests (skipped only if the
socket won't open, no root): `lo` present, a loopback address on `lo`, family/ifindex scoping,
routes & neighbors structurally valid, sequential dumps in sync, a write to a nonexistent ifindex
surfacing a mapped typed error, spec validation firing before any syscall. **Live write→read
round-trip:** a forked child isolates itself with `unshare(CLONE_NEWUSER|CLONE_NEWNET)` (the
programmatic `unshare -rn`, no privilege needed on a stock kernel; falls back to a plain netns
unshare when already root), creates a `dummy` device (falling back to `lo` if the driver is
missing), brings it up, sets the MTU, adds an address, a route and a neighbour, reads each one back
through this module's *own* dump path, checks EXCL/ENODEV/EOPNOTSUPP/EADDRNOTAVAIL error mapping,
then deletes everything and verifies the removals. A **second live round-trip** covers the bridge
surface in its own namespace: create a VLAN-filtering bridge and a veth pair, bring both ends up
(a carrier-down port cannot be moved to `FORWARDING`), enslave and verify `IFLA_MASTER` through
`brportInfo`, set state/learning/flood/isolated and read every one back from `IFLA_PROTINFO`, add a
PVID+untagged VLAN and a 101-VID range and verify both through the `RTEXT_FILTER_BRVLAN` dump
(including that the decoded range covers exactly 101 VIDs and no entry is inverted), add an FDB
entry and find it through both the per-port and the per-bridge kernel-side filter, check
`NLM_F_EXCL` → `Exists` and that build-time VLAN validation fires before any syscall, then delete
the entry, the VLANs, release the port and delete both devices (checking the veth peer disappears
with its partner). Nothing touches the host: the namespace dies with the child. Where namespaces or
the bridge/veth drivers are unavailable the child reports a skip code and the test prints
`SKIPPED` and passes — the suite never fails for lack of privilege. Run: `zig build test-netlink`
(and `--release=fast`): **81/81 pass, 0 skipped** on a stock Linux 7.0 with user namespaces
enabled, i.e. both live round-trips really execute there.

## Backlog / deferred
Multicast event monitoring (RTNLGRP subscription) is the remaining deliberate extension point on
the transport. **Protocol-parameterised transport:** `Socket.open` hardcodes
`linux.NETLINK.ROUTE`, which is why `genetlink`, `conntrack` and `nftables` each carry their own
copy of bind + portid capture + `NETLINK_EXT_ACK` + the `MSG_PEEK|MSG_TRUNC` growth loop. The
codec and the dump triage are now shared; lifting the socket itself into a
`netlink.Transport(open(protocol, groups), send, recvDatagram, awaitAck)` is the remaining piece,
and is tracked in `conntrack`'s and `nftables`' specs as well. Write-path gaps listed under "Threat model / out of scope" above:
`IFLA_INFO_DATA` for non-bridge kinds / veth peers, multipath routes, policy rules, and the bridge
sub-list (MDB/multicast snooping, VXLAN device creation, VLAN tunnels, per-VLAN options, MRP/CFM/
MST, backup port). Linux-only platform
ceiling is an accepted design choice (raw-syscall nature, no portable fallback), grouped with
icmp/rawsock/wireguard/l2disco/procnet.

## Status
`gap · linux · client · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
