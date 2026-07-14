# genetlink — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
`genetlink` is the generic-netlink counterpart to the `netlink` module's rtnetlink transport: same
socket discipline (kernel-assigned portid from bind-with-pid-0 + getsockname, `MSG_PEEK|MSG_TRUNC`
receive-buffer growth, non-kernel datagrams dropped, per-request sequence numbers that never land on
0), applied to `NETLINK_GENERIC` instead of `NETLINK_ROUTE`. It reuses `netlink.codec` for the
message/attribute wire format (`nlmsghdr` + `nlattr` TLV — genl payloads use the same TLV shape as
rtnetlink) and adds only what genetlink puts on top: the 4-byte `genlmsghdr` (cmd/version/reserved)
and the nlctrl `CTRL_CMD_GETFAMILY` family-resolve protocol. `resolveFamily` is the one high-level
operation shipped; everything past family resolution (a family's own commands/attributes/request
shapes) is intentionally left to the caller — `wireguard` is the reference consumer, and future
families (ethtool, devlink, nl80211, …) are expected to depend on this module the same way. One
`Socket` per thread/loop; no globals.

## Provenance / licensing
The kernel UAPI header this module cites (`linux/genetlink.h`) is GPL-2.0, but that does not make the
module a GPL derivative: only uncopyrightable ABI facts are taken from it (numeric constants,
`genlmsghdr` layout), and separately, that header carries the **Linux-syscall-note** exception, which
explicitly permits userspace of any license to use it to interface with the kernel. No kernel source
was consulted or copied. Full attribution in /NOTICE.

## Threat model / out of scope
The untrusted input is the kernel's reply bytes; wire-format validation (bounds/length checks) is
delegated to the fuzzed `netlink.codec` walkers, so a malformed or hostile datagram yields a typed
error, never a panic or OOB read. Unprivileged: `CTRL_CMD_GETFAMILY` resolution needs no root — a
specific family's own commands may be privileged (e.g. WireGuard's `CAP_NET_ADMIN`), but that
requirement lives in the family module, not here. Out of scope (deliberate, additive extension
point): multicast group id resolution (`CTRL_ATTR_MCAST_GROUPS`) — not needed by the current
consumer (`wireguard`), but the reply-walking loop in `resolveFamily` already has the shape a
`CTRL_ATTR_MCAST_GROUPS` branch would slot into.

## Verification
Offline unit tests over the pure, testable half: golden `CTRL_CMD_GETFAMILY` request bytes
(byte-exact, LE-only), a name-too-long rejection (`GENL_NAMSIZ`), `appendHeader`'s genlmsghdr
encoding, and `splitPayload` truncation handling. Linux integration test (unprivileged, skipped only
if the socket won't open): nlctrl resolves to itself (`GENL_ID_CTRL`), a nonexistent family name
yields `error.FamilyNotFound`, an over-length name yields `error.NameTooLong`. Run:
`zig build test-genetlink`.

## Backlog / deferred
Multicast group id resolution (`CTRL_ATTR_MCAST_GROUPS`) — see README "Out of scope". No other
deferred items; this module is a narrow, complete extraction of what `wireguard` needed plus the
`GENL_ID_CTRL` reply-walking flexibility already present.

## Status
`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const meta` in
src/root.zig.
