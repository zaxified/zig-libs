# genetlink

Pure-Zig **generic-netlink (genl) transport**: `genlmsghdr` framing, nlctrl
family-id resolution (`CTRL_CMD_GETFAMILY`), and a blocking `NETLINK_GENERIC`
socket — the shared foundation any genetlink-family client builds on
(`ethtool`, `devlink`, `nl80211`, the `wireguard` family, …).

- No maintained pure-Zig genetlink library exists.
- **Model after:** the `netlink` module's transport discipline (same
  portid/seq/MSG_PEEK-MSG_TRUNC socket shape, applied to `NETLINK_GENERIC`
  instead of `NETLINK_ROUTE`) and the kernel UAPI (`linux/genetlink.h`).
- **Platform:** linux (raw `std.os.linux` errno-encoded syscalls — a
  conscious ceiling). **Role:** client. **Concurrency:** reentrant (no
  globals; one `Socket` per thread/loop).
- **Deps:** `netlink` — its bounds-checked wire codec (nlmsghdr + nlattr TLV
  build/parse) is reused; this module adds only the genetlink-specific
  4-byte `genlmsghdr` and the nlctrl family-resolve protocol on top.
- **Privileges:** none — family resolution via nlctrl is unprivileged.
  Whatever a specific family's commands need (e.g. WireGuard's
  `CAP_NET_ADMIN`) is that family module's concern, not this one's.

Provenance: clean-room from the kernel UAPI (`linux/genetlink.h`,
GPL-2.0 WITH Linux-syscall-note — the command/attribute constants and their
layouts are the kernel's OS ABI, not copyrightable interface code).
Extracted from the `wireguard` module (its first consumer, where this layer
originally lived as a private `genl.zig`) so other genetlink families can
reuse it without depending on `wireguard`. See `NOTICE`.

## API

```zig
const genetlink = @import("genetlink");

var sock = try genetlink.Socket.open(gpa);
defer sock.close();

// Resolve a family name to its dynamic message-type id.
const family_id = try sock.resolveFamily("wireguard");

// From here, encode/send the family's own commands over `sock` using
// netlink's codec (netlink.codec.appendHeader/appendAttr*) plus this
// module's genlmsghdr helpers:
try genetlink.appendHeader(gpa, &list, my_cmd, my_version); // after the nlmsghdr
```

Low-level, for building custom family requests (all `pub`): `header_len`
(sizeof `genlmsghdr`), `GENL_ID_CTRL`/`CTRL_CMD_GETFAMILY`/
`CTRL_ATTR_FAMILY_ID`/`CTRL_ATTR_FAMILY_NAME`/`GENL_NAMSIZ` (the nlctrl
constants), `appendHeader` (encode a `genlmsghdr`), `splitPayload` (split a
message payload into its `genlmsghdr` command byte + attribute bytes), and
`buildGetFamilyRequest` (the raw `CTRL_CMD_GETFAMILY` request bytes, useful
for callers that want to drive the socket themselves).

## Design notes

- **Socket transport mirrors `netlink.Socket`** byte-for-byte in discipline:
  kernel-assigned portid (bind with pid 0, read back via getsockname),
  `MSG_PEEK|MSG_TRUNC` receive-buffer growth so nothing is lost to
  truncation, non-kernel datagrams (sender pid != 0) dropped, per-request
  sequence numbers that never land on 0. The only difference is the netlink
  protocol family passed to `socket()`: `NETLINK_GENERIC` instead of
  `NETLINK_ROUTE`.
- **Family resolution only** — `resolveFamily` is the one high-level
  operation this module ships (`CTRL_CMD_GETFAMILY` → `CTRL_ATTR_FAMILY_ID`).
  Everything past that (a family's own commands, attributes, request/reply
  shapes) is family-specific and belongs in that family's own module —
  exactly how the `wireguard` module now consumes this one.
- **`buildGetFamilyRequest` is pure** (byte slice in, byte slice out), so
  it's golden-byte-tested offline; the socket only ferries buffers.
- **Out of scope (deliberate extension point):** multicast group id
  resolution (`CTRL_ATTR_MCAST_GROUPS`) — needed by event-subscribing
  families (e.g. `nl80211` scan/MLME events) but not by the current
  consumer (`wireguard`, which only needs the family id). `resolveFamily`'s
  reply-walking loop already has everywhere a `CTRL_ATTR_MCAST_GROUPS`
  branch would go; adding it is additive, not a redesign.
