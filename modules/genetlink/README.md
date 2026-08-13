# genetlink

Pure-Zig **generic-netlink (genl) transport**: `genlmsghdr` framing, nlctrl
family-id resolution (`CTRL_CMD_GETFAMILY`), multicast group-id resolution
(`CTRL_ATTR_MCAST_GROUPS`), and a blocking `NETLINK_GENERIC` socket — the
shared foundation any genetlink-family client builds on (`ethtool`,
`devlink`, `nl80211`, the `wireguard` family, …).

- No maintained pure-Zig genetlink library exists.
- **Model after:** the `netlink` module's shared transport (this module opens
  it with `openProtocol(gpa, NETLINK_GENERIC)` rather than re-implementing
  it) and the kernel UAPI (`linux/genetlink.h`).
- **Platform:** linux (raw `std.os.linux` errno-encoded syscalls — a
  conscious ceiling). **Role:** client. **Concurrency:** reentrant (no
  globals; one `Socket` per thread/loop).
- **Deps:** `netlink` — both its bounds-checked wire codec (nlmsghdr +
  nlattr TLV build/parse, the dump triage) and its socket transport are
  reused; this module adds only the genetlink-specific 4-byte `genlmsghdr`
  and the nlctrl protocol on top.
- **Privileges:** none — family resolution via nlctrl is unprivileged.
  Whatever a specific family's commands need (e.g. WireGuard's
  `CAP_NET_ADMIN`) is that family module's concern, not this one's.

Provenance: clean-room from the kernel UAPI (`linux/genetlink.h`,
GPL-2.0 WITH Linux-syscall-note — `genlmsghdr` + `nlctrl` `CTRL_CMD_GETFAMILY`
family resolution; the command/attribute constants and their layouts are the
kernel's OS ABI, not copyrightable interface code). No GPL header source is
copied; the operative mechanism is the same Linux-syscall-note exception relied
on by `netlink`/`wireguard`/`tc`, which permits userspace of ANY license to use
these headers to interface with the kernel. Extracted from the `wireguard`
module (its first consumer, where this layer originally lived as a private
`genl.zig`) so other genetlink families can reuse it without depending on
`wireguard`; no third-party design reference beyond the kernel header.

## API

```zig
const genetlink = @import("genetlink");

var sock = try genetlink.Socket.open(gpa);
defer sock.close();

// Resolve a family name to its dynamic message-type id.
const family_id = try sock.resolveFamily("wireguard");

// Resolve one of a family's multicast group ids, then join it on `sock.fd`
// (NETLINK_ADD_MEMBERSHIP) to receive that family's events.
const scan_group = try sock.resolveMcastGroup("nl80211", "scan");

// From here, encode/send the family's own commands over `sock` using
// netlink's codec (netlink.codec.appendHeader/appendAttr*) plus this
// module's genlmsghdr helpers:
try genetlink.appendHeader(gpa, &list, my_cmd, my_version); // after the nlmsghdr
```

Socket: `open`/`close`, `handle` (= the `fd` field, for poll/epoll and
`setsockopt`), `setRecvTimeout`, `nextSeq`, `send`, `recvDatagram` /
`recvDatagramStrict`, `lastErrorMessage`, `resolveFamily`,
`resolveMcastGroup`.

Low-level, for building custom family requests (all `pub`): `header_len`
(sizeof `genlmsghdr`), `GENL_ID_CTRL`/`CTRL_CMD_GETFAMILY`/
`CTRL_ATTR_FAMILY_ID`/`CTRL_ATTR_FAMILY_NAME`/`CTRL_ATTR_MCAST_GROUPS`/
`CTRL_ATTR_MCAST_GRP_NAME`/`CTRL_ATTR_MCAST_GRP_ID`/`GENL_NAMSIZ` (the
nlctrl constants), `appendHeader` (encode a `genlmsghdr`), `splitPayload`
(split a message payload into its `genlmsghdr` command byte + attribute
bytes), `buildGetFamilyRequest` (the raw `CTRL_CMD_GETFAMILY` request bytes,
useful for callers that want to drive the socket themselves) and
`findMcastGroupId` (the pure group-id walk over a `CTRL_CMD_NEWFAMILY`
reply's attribute bytes).

## Design notes

- **The socket _is_ `netlink.Socket`**, opened with `openProtocol(gpa,
  NETLINK_GENERIC)`. Socket creation, bind, kernel-assigned portid (bind
  with pid 0, read back via getsockname), `NETLINK_EXT_ACK`, the sequence
  counter that never lands on 0, `MSG_PEEK|MSG_TRUNC` receive-buffer growth
  so nothing is lost to truncation, non-kernel datagram (sender pid != 0)
  filtering and the extended-ACK capture are the `netlink` module's, carried
  once for every netlink protocol. This module holds the socket state in its
  own public fields (`fd`, `portid`, `seq`, `gpa`, `buf` — consumers read
  them, and `wireguard` sets `seq` when it batches requests) and borrows a
  transport view over them for the duration of each call.
- **Two receive flavours, the transport's.** `recvDatagram` keeps genetlink's
  historical mapping (`ENOBUFS`/`EAGAIN` → `SystemResources`/`RecvFailed`);
  `recvDatagramStrict` reports them as `Overrun`/`WouldBlock`, which is what
  an event-subscribing caller needs — an overrun on a multicast socket means
  *events were lost*, and `WouldBlock` is the normal end of a
  `setRecvTimeout`-bounded wait.
- **Family and group resolution** are the two high-level operations this
  module ships (`CTRL_CMD_GETFAMILY` → `CTRL_ATTR_FAMILY_ID` /
  `CTRL_ATTR_MCAST_GROUPS`), over one shared nlctrl round trip. Everything
  past that (a family's own commands, attributes, request/reply shapes) is
  family-specific and belongs in that family's own module — exactly how the
  `wireguard`, `nl80211` and `ethtool` modules consume this one.
- **The pure halves are pure** — `buildGetFamilyRequest` (byte slice out) and
  `findMcastGroupId` (byte slice in) are golden-tested offline; the socket
  only ferries buffers.
- **Joining a group is the caller's**, deliberately: `NETLINK_ADD_MEMBERSHIP`
  on `sock.fd` is one `setsockopt`, and each family module already maps its
  errno onto its own error set.
