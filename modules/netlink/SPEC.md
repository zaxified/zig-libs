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

## Provenance / licensing
The kernel UAPI headers this module cites are GPL-2.0, but that does not make the module a GPL
derivative: only uncopyrightable ABI facts are taken from them (numeric constants, struct layouts),
and separately, those headers carry the **Linux-syscall-note** exception, which explicitly permits
userspace of any license to use them to interface with the kernel. No kernel or libmnl (LGPL-2.1)
source was consulted or copied; the codec is an original pure-Zig implementation. Full attribution
in /NOTICE. The golden request bytes in the tests were captured from iproute2's own traffic with
`strace` (observed wire bytes = ABI facts, no iproute2 code involved).

## Threat model / out of scope
The untrusted input is the kernel's reply bytes; the codec treats them as hostile and is fuzzed
accordingly. Unprivileged: RTM_GET\* dumps need no root; writes need CAP_NET_ADMIN. Out of scope
(deliberate, additive extension points): multicast event monitoring (RTNLGRP_\* subscription —
still unbuilt), qdiscs/classes/filters (the sibling `tc` module; classful qdiscs = a separate
task), conntrack (`NETLINK_NETFILTER`, separate module), bridge/FDB and VLAN filtering
(`RTM_*NEIGH` with `NTF_SELF`/`AF_BRIDGE`, `RTM_*VLAN`), policy routing (`RTM_*RULE`, `RTA_SRC`,
tos), `IFLA_INFO_DATA` payloads for kind-specific link parameters (veth peers, VLAN ids, bridge
options) and multipath routes (`RTA_MULTIPATH`).

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
plus the delete forms and the `ifi_change`-mask cases. Linux integration tests (skipped only if the
socket won't open, no root): `lo` present, a loopback address on `lo`, family/ifindex scoping,
routes & neighbors structurally valid, sequential dumps in sync, a write to a nonexistent ifindex
surfacing a mapped typed error, spec validation firing before any syscall. **Live write→read
round-trip:** a forked child isolates itself with `unshare(CLONE_NEWUSER|CLONE_NEWNET)` (the
programmatic `unshare -rn`, no privilege needed on a stock kernel; falls back to a plain netns
unshare when already root), creates a `dummy` device (falling back to `lo` if the driver is
missing), brings it up, sets the MTU, adds an address, a route and a neighbour, reads each one back
through this module's *own* dump path, checks EXCL/ENODEV/EOPNOTSUPP/EADDRNOTAVAIL error mapping,
then deletes everything and verifies the removals. Nothing touches the host: the namespace dies
with the child. Where namespaces are unavailable the child reports a skip code and the test prints
`SKIPPED` and passes — the suite never fails for lack of privilege. Run: `zig build test-netlink`
(and `-Doptimize=ReleaseFast`).

## Backlog / deferred
Multicast event monitoring (RTNLGRP subscription) is the remaining deliberate extension point on
the transport. Write-path gaps listed under "Threat model / out of scope" above:
`IFLA_INFO_DATA`/veth peers, multipath routes, policy rules, bridge/FDB. Linux-only platform
ceiling is an accepted design choice (raw-syscall nature, no portable fallback), grouped with
icmp/rawsock/wireguard/l2disco/procnet.

## Status
`gap · linux · client · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
