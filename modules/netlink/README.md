# netlink

Pure-Zig **rtnetlink** transport + control API over `NETLINK_ROUTE`: enumerate
*and* configure links, addresses, routes and neighbors straight from the kernel
control plane — no `ip`/`ss` shell-outs, no `/proc/net` parsing, no libc.

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
`linux/neighbour.h`, `linux/if.h`) and RFC 3549; design references libmnl
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

Low-level, for custom queries and hand-built requests (all `pub`):
`netlink.codec` — bounds-checked `MessageIterator`/`AttrIterator`,
`Message.errorCode()` (NLMSG_ERROR → errno), `Message.errorMessage()`
(extended-ACK string), `appendHeader`/`appendAttr*`/`nestBegin`/`nestEnd`
encoders — plus `Socket.nextSeq()`/`Socket.requestAck()` (the write+ACK engine
sibling modules reuse), the typed payload parsers (`parseLink`,
`parseAddress`, `parseRoute`, `parseNeighbor`) and the UAPI constant tables
(`AF`, `IFF`, `RTA`, `NDA`, `NUD`, `RTN`, `RTPROT`, `NTF`, `IFA_F`,
`IFLA_INFO`, `RT_TABLE`, `RT_SCOPE`).

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
- **Out of scope (deliberate extension points):** multicast event monitoring,
  qdiscs/filters (sibling `tc` module), conntrack, bridge/FDB, policy rules,
  `IFLA_INFO_DATA` link parameters and multipath routes — see SPEC.md.
