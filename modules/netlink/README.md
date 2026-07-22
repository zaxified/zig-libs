# netlink

Pure-Zig **rtnetlink** transport + control API over `NETLINK_ROUTE`: enumerate
*and* configure links, addresses, routes, neighbors and Linux **bridges**
(FDB + VLAN filtering + port options) straight from the kernel control plane —
no `ip`/`bridge` shell-outs, no `/proc/net` parsing, no libc.

- No maintained pure-Zig netlink library exists.
- **Model after:** libmnl (minimal framing + validation discipline) and
  vishvananda/netlink (Go; typed dump queries). Wire format from the kernel
  UAPI headers and RFC 3549.
- **Platform:** linux (raw `std.os.linux` errno-encoded syscalls — a
  conscious ceiling). **Role:** client. **Concurrency:** reentrant (no
  globals; one `Socket` per thread/loop).
- **Deps:** none (std only) — a clean foundation for a future `wireguard`
  (genetlink) module and for retiring `/proc/net` parsers.
- **Privileges:** RTM_GET* dumps are unprivileged; the write ops
  (`RTM_NEW*`/`RTM_DEL*`) need **CAP_NET_ADMIN**.

Provenance: clean-room from the kernel UAPI headers (`linux/netlink.h`,
`linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`,
`linux/neighbour.h`, `linux/if_bridge.h`, `linux/if.h`) and RFC 3549; design
references libmnl
(LGPL-2.1) and vishvananda/netlink (Apache-2.0) — behavior/wire semantics
only, no source consulted or copied. See `NOTICE`.

## API

```zig
const netlink = @import("netlink");

var nl = try netlink.Socket.open(gpa);
defer nl.close();

// Typed dumps — owned slices of plain structs; free with gpa.free(slice).
const ls = try nl.links();                                  // []Link
const as = try nl.addresses(.{ .family = netlink.AF.INET }); // []Address
const rs = try nl.routes(.{});                               // []Route
const ns = try nl.neighbors(.{ .ifindex = 2 });              // []Neighbor

for (ls) |l| _ = .{ l.index, l.name(), l.mtu, l.flags & netlink.IFF.UP, l.mac };
for (as) |a| _ = .{ a.family, a.bytes(), a.prefixlen, a.ifindex, a.label() };
for (rs) |r| _ = .{ r.table, r.dstBytes(), r.dst_prefixlen, r.gatewayBytes(), r.oif, r.priority };
for (ns) |n| _ = .{ n.dstBytes(), n.lladdrBytes(), n.state & netlink.NUD.REACHABLE };

// Write ops (RTM_NEW*/RTM_DEL*) — need CAP_NET_ADMIN. Every request carries
// NLM_F_ACK; the NLMSG_ERROR reply becomes a typed error, so a write never
// fails silently.
try nl.linkAdd(.{ .name = "dummy0", .kind = "dummy" }, .{});   // RTM_NEWLINK + LINKINFO
try nl.linkUp(ifindex);                                        // ifi_change = IFF_UP only
try nl.linkSet(ifindex, .{ .mtu = 1400, .name = "lab0" });     // attrs, ifi_change = 0
try nl.addressAdd(.{ .ifindex = ifindex, .local = &.{ 10, 11, 12, 1 },
                     .prefixlen = 24 }, .{});                  // .{} = CREATE|EXCL
try nl.routeAdd(.{ .dst = &.{ 10, 99, 0, 0 }, .dst_prefixlen = 24,
                   .oif = ifindex, .scope = netlink.RT_SCOPE.LINK }, .{});
try nl.neighborAdd(.{ .ifindex = ifindex, .dst = &.{ 10, 11, 12, 55 },
                      .lladdr = &.{ 0xde, 0xad, 0xbe, 0xef, 0, 1 } }, .{});
// …and the RTM_DEL* mirrors: addressDel / routeDel / neighborDel / linkDel.

nl.routeAdd(bad_spec, .{}) catch |err| switch (err) {
    error.Exists, error.NoSuchDevice, error.NetworkUnreachable => {
        std.log.err("kernel said: {s}", .{nl.lastErrorMessage()}); // extended ACK
    },
    else => return err,
};
```

### Bridges (AF_BRIDGE)

Everything `ip link … type bridge`, `bridge fdb`, `bridge vlan` and
`bridge link set` do — same socket, same ACK/ext-ACK discipline:

```zig
// 1. The bridge device itself (IFLA_LINKINFO/IFLA_INFO_DATA → IFLA_BR_*).
try nl.bridgeAdd(.{ .name = "br0", .vlan_filtering = true,
                    .stp_state = 1, .forward_delay = 100,
                    .ageing_time = 20000, .priority = 4096, .up = true }, .{});
try nl.portEnslave(veth_index, br_index);  // IFLA_MASTER
try nl.portRelease(veth_index);            // …nomaster

// 2. FDB — `bridge fdb add/del/show`, ndm_family = AF_BRIDGE.
try nl.fdbAdd(.{ .ifindex = veth_index, .lladdr = &mac, .vlan = 10,
                 .state = netlink.NUD.REACHABLE | netlink.NUD.NOARP,
                 .flags = netlink.NTF.MASTER }, .{});
const fdb = try nl.fdbEntries(.{ .master = br_index }); // []FdbEntry, kernel-filtered
for (fdb) |e| _ = .{ e.lladdrBytes(), e.vlan, e.master, e.isSelf(), e.isPermanent() };
try nl.fdbDel(.{ .ifindex = veth_index, .lladdr = &mac, .vlan = 10 });

// 3. VLAN filtering — IFLA_AF_SPEC/IFLA_BRIDGE_VLAN_INFO, ranges included.
try nl.bridgeVlanAdd(veth_index, .{ .vid = 10, .pvid = true, .untagged = true });
try nl.bridgeVlanAdd(veth_index, .{ .vid = 100, .vid_end = 200 });  // RANGE_BEGIN/END
try nl.bridgeVlanAdd(br_index,   .{ .vid = 20, .self = true });     // on the bridge itself
const vlans = try nl.bridgeVlans(.{ .ifindex = veth_index });       // []VlanEntry
for (vlans) |v| _ = .{ v.vid, v.vid_end, v.isPvid(), v.isUntagged(), v.count() };
try nl.bridgeVlanDel(veth_index, .{ .vid = 100, .vid_end = 200 });

// 4. Bridge-port options — IFLA_PROTINFO/IFLA_BRPORT_*.
try nl.brportSet(veth_index, .{ .state = netlink.BR_STATE.FORWARDING,
                                .learning = false, .unicast_flood = false,
                                .isolated = true });
const port = try nl.brportInfo(veth_index); // ?BrportInfo (state/learning/flood/…)
```

The builders and parsers behind these live in `netlink.bridge`
(`buildBridgeAddRequest`, `buildFdbRequest`, `buildFdbDumpRequest`,
`buildVlanRequest`, `buildVlanDumpRequest`, `buildBrportRequest`,
`buildBrportDumpRequest`, `parseFdb`, `parseVlans`, `parseBrport`) together
with the UAPI tables `IFLA_BR`, `IFLA_BRPORT`, `IFLA_BRIDGE`,
`BRIDGE_VLAN_INFO`, `BRIDGE_FLAGS`, `BR_STATE`, `RTEXT_FILTER` — all usable
standalone, without a socket.

Low-level, for custom queries and hand-built requests (all `pub`):
`netlink.codec` — bounds-checked `MessageIterator`/`AttrIterator`,
`Message.errorCode()` (NLMSG_ERROR → errno), `Message.errorMessage()`
(extended-ACK string), `Message.errorRequestSeq()` (which request of a batch
the kernel rejected), `appendHeader`/`appendAttr*`/`nestBegin`/`nestEnd`
encoders — plus `Socket.nextSeq()`/`Socket.requestAck()` (the write+ACK engine
sibling modules reuse), the typed payload parsers (`parseLink`,
`parseAddress`, `parseRoute`, `parseNeighbor`) and the UAPI constant tables
(`AF`, `IFF`, `RTA`, `NDA`, `NUD`, `RTN`, `RTPROT`, `NTF`, `IFA_F`,
`IFLA_INFO`, `RT_TABLE`, `RT_SCOPE`) and the `netlink.bridge` namespace.

Shared with the other netlink families (see SPEC.md § "Shared codec surface"):

- **Big-endian attribute accessors** — `Attr.asBe16/asBe32/asBe64` and
  `appendAttrBe16/appendAttrBe32/appendAttrBe64`, the network-byte-order twins
  of the host-order `asU16`/`asU32`/`appendAttrU*`. Every netfilter family
  (ctnetlink, nftables, nfqueue, nflog, cttimeout) needs them, because its
  integer attributes are network order *and* the kernel does not set
  `NLA_F_NET_BYTEORDER` on them.
- **`classifyDumpMessage(msg, portid, seq) DumpStep`** — the multi-part dump
  triage (stale/foreign reply, `NLM_F_DUMP_INTR` restart, `NLMSG_DONE`/`ERROR`/
  `NOOP`/`OVERRUN`, record). Pure and I/O-free, so a socket on another netlink
  protocol can share it; this module's own dumps are written on it.
- **`Socket.send` / `Socket.recvDatagram`** — the raw transport seam, for
  driving a message type this module does not model over the same bound
  socket. The received slice borrows the socket's buffer until the next call.

## Design notes

- **The attr walker is the security boundary.** Every `rta_len`/`nlmsg_len`
  is validated against the enclosing buffer before any slice is formed
  (mirroring `mnl_attr_ok`/`mnl_nlmsg_ok`); each step advances ≥ 4 bytes, so
  iteration is capped by construction. Malformed input → `error.Truncated` /
  `error.BadLength`, never a panic or OOB read. The walkers and the typed
  parsers are fuzzed (`std.testing.fuzz`).
- **Multi-part dumps:** `NLM_F_REQUEST|NLM_F_DUMP`, replies matched on
  (kernel-assigned portid, sequence number) and assembled until `NLMSG_DONE`;
  stale messages from an aborted earlier dump are skipped by the seq check.
  `NLM_F_DUMP_INTR` restarts the dump (up to 4 attempts), mirroring libnl.
- **Receive buffer** grows via a `MSG_PEEK|MSG_TRUNC` size probe (nothing is
  lost to truncation); datagrams whose sender pid != 0 (not the kernel) are
  dropped.
- **Scoping:** `Filter.family` is applied kernel-side (family byte of the
  request's fixed header) and re-checked client-side; `Filter.ifindex` is
  client-side only — kernel-side ifindex scoping would require
  `NETLINK_GET_STRICT_CHK` (Linux ≥ 4.20 opt-in). Dump requests carry the
  full fixed header (ifinfomsg/ifaddrmsg/rtmsg/ndmsg), not the legacy 1-byte
  rtgenmsg, for strict-check compatibility — same as modern iproute2.
- **IPv4 addresses** prefer `IFA_LOCAL` over `IFA_ADDRESS` (the peer on
  point-to-point links), matching iproute2's display semantics.
- **Writes are ACKed, never fire-and-forget.** Each `RTM_NEW*`/`RTM_DEL*`
  carries `NLM_F_REQUEST|NLM_F_ACK` (+ `NLM_F_CREATE`/`EXCL`/`REPLACE`/
  `APPEND` per the `Create` options) and blocks for the `NLMSG_ERROR` reply:
  errno 0 = success, otherwise a typed error (`Exists`, `NotFound`,
  `NoSuchDevice`, `AddressNotAvailable`, `NetworkUnreachable`, `AccessDenied`,
  `InvalidRequest`, `NotSupported`, `Busy`…). `NETLINK_EXT_ACK` is enabled per
  socket, so the kernel's reason string is available from
  `lastErrorMessage()`. Specs are validated before any syscall
  (`InvalidAddressLength`, `MixedFamilies`, `FamilyRequired`, `InvalidName`).
- **`ifi_change` is never over-broad.** For link changes the kernel applies
  `new = (old & ~change) | (flags & change)`; `LinkChange.up` therefore puts
  *only* `IFF_UP` in the mask, attribute-only changes (MTU/name/MAC) send
  `ifi_change = 0`, and `flags`/`flags_mask` is the explicit escape hatch. An
  empty change is rejected (`error.NothingToChange`) rather than sent.
- **AF_BRIDGE has three different message shapes**, and getting them wrong is
  the usual source of `EINVAL`. FDB entries are `RTM_*NEIGH` with
  `ndm_family = AF_BRIDGE` (`NDA_LLADDR`/`NDA_VLAN`/`NDA_MASTER`, and
  `NTF_SELF` vs `NTF_MASTER` picking the device's own FDB or the bridge's).
  VLANs are `RTM_SETLINK`/`RTM_DELLINK` with `ifi_family = AF_BRIDGE` and a
  nested `IFLA_AF_SPEC`; a range is *two* `IFLA_BRIDGE_VLAN_INFO` attributes
  flagged `RANGE_BEGIN`/`RANGE_END`, which `VlanEntry` collapses back into one
  `vid..vid_end` on decode. Port options are `RTM_SETLINK` with
  `IFLA_PROTINFO` — the one rtnetlink nest iproute2 *does* mark
  `NLA_F_NESTED`, and this encoder matches it. The dumps differ too: FDB uses
  `RTM_GETNEIGH` + `ndmsg{AF_BRIDGE}` (with `ndm_ifindex`/`NDA_MASTER` filtered
  kernel-side), VLANs use `RTM_GETLINK` + `IFLA_EXT_MASK = RTEXT_FILTER_BRVLAN`,
  and port state needs `RTM_GETLINK` with `ifi_family = AF_BRIDGE` — a plain
  `ip link show`-style dump carries no `IFLA_PROTINFO` at all.
- **VLAN specs are validated before the syscall:** VID must be 1..4094
  (`error.InvalidVlanId`), a range must be ascending and can never be a PVID
  (`error.InvalidVlanRange`), and `self`+`master` together is rejected.
- **Known unmapped errno:** setting a port to `FORWARDING` while its carrier is
  down answers `ENETDOWN`, which `writeErrorFromCode` reports as
  `error.Unexpected` (the mapping table is shared with the other write ops and
  was left untouched). Bring both ends of a veth pair up first.
- **Out of scope (deliberate extension points):** multicast event monitoring,
  qdiscs/filters (sibling `tc` module), conntrack, policy rules, multipath
  routes, and — within the bridge surface — MDB/multicast snooping
  (`RTM_*MDB`), VXLAN link creation, VLAN tunnel mapping, MRP/CFM/MST and
  per-VLAN options. See SPEC.md.
