# genetlink — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
`genetlink` is the generic-netlink counterpart to the `netlink` module's rtnetlink client, and it
sits **on** that module's shared transport rather than beside it: `Socket.open` is
`netlink.Socket.openProtocol(gpa, NETLINK_GENERIC)`, so socket creation, bind, kernel-assigned
portid (bind-with-pid-0 + `getsockname`), `NETLINK_EXT_ACK`, the sequence counter that never lands
on 0, the `MSG_PEEK|MSG_TRUNC` receive-buffer growth loop, the non-kernel-datagram filter and the
extended-ACK capture are carried once, for every netlink protocol. It also reuses `netlink.codec`
for the message/attribute wire format (`nlmsghdr` + `nlattr` TLV — genl payloads use the same TLV
shape as rtnetlink) and `codec.classifyDumpMessage` for reply triage. What is genuinely genl and
stays here: the 4-byte `genlmsghdr` (cmd/version/reserved), the nlctrl `CTRL_CMD_GETFAMILY`
protocol, and the two resolvers built on it (family id, multicast group id). One `Socket` per
thread/loop; no globals.

**Why the socket state stays in this struct's own fields.** `Socket` keeps `gpa`/`fd`/`portid`/
`seq`/`buf` as public fields and materialises a `netlink.Socket` view over them per operation
(`transport()`), writing the mutated half back afterwards (`sync()`). That is not decoration: the
fields are load-bearing public API for the three consumers — `nl80211` and `ethtool` `setsockopt`
multicast membership on `fd` and poll it, all three match replies against `portid` themselves, and
`wireguard` *assigns* `seq` when it sends a batch of requests under one sequence window. A
`nl: netlink.Socket` composition (the shape `conntrack`/`nftables`/`tc` use, none of which expose
socket internals) would have broken every one of those. The view is a struct copy, scoped to a
single call, and `gpa`/`fd`/`portid` are immutable for the socket's lifetime, so the only state
written back is `seq`, `buf` (the receive path may reallocate it) and the extended-ACK slot.

## Behavioural differences found between the two transport copies
The consolidation wave's rule — where the copies disagree, take the stricter/safer reading — applied
to genetlink's private copy vs. `netlink`'s shared one:

| # | Difference | Reading chosen |
|---|---|---|
| 1 | genetlink never set `NETLINK_EXT_ACK`; the shared transport sets it best-effort (a pre-4.12 `ENOPROTOOPT` is not fatal) | **Shared.** Errors now carry the kernel's reason string, reachable via `lastErrorMessage`. It only adds attributes *after* the errno in an `NLMSG_ERROR`, which every reply walk here and in the consumers reads by offset, and `ethtool` already set the same option on its genetlink socket by hand — so the reply shape was already in production. |
| 2 | genetlink's `bind` mapped `EACCES`/`EPERM` to `Unexpected` (its `else` arm); the shared one maps them to `AccessDenied` | **Shared.** Unreachable with `groups = 0`, but the honest mapping, and already inside `OpenError`. |
| 3 | Receive errno mapping: genetlink folded `ENOBUFS`+`ENOMEM` onto `SystemResources` and everything else (including `EAGAIN`) onto `RecvFailed`; the shared engine splits `ENOBUFS` → `Overrun`, `EAGAIN` → `WouldBlock`, `ENOMEM` → `SystemResources` | **Both, explicitly.** `recvDatagram` stays the narrowing wrapper and reproduces genetlink's historical mapping *exactly* (`Overrun` → `SystemResources`, `WouldBlock` → `RecvFailed`); `recvDatagramStrict` is added for callers that need the distinction. See "Which face genetlink presents" below. |
| 4 | Receive-buffer growth (8 KiB initial, `alignForward` to that granularity, 16 MiB cap, re-probe after growth) | Identical in both copies; the shared one is now the only one. |
| 5 | Kernel-sender filter (`slen >= sizeof(sockaddr_nl) and src.pid != 0` → drop) | Identical; shared. |
| 6 | `send` (INTR retry, `ENOBUFS`/`ENOMEM` → `SystemResources`, `EACCES`/`EPERM` → `AccessDenied`, else `SendFailed`) | Identical; shared. |
| 7 | `nextSeq` (`+%= 1`, skip 0) | Identical; shared. |
| 8 | `resolveFamily`'s reply loop ignored `NLMSG_DONE` and `NLMSG_OVERRUN` (both fell into its `else => {}` arm) — either would have made it block forever on the next `recvfrom` | **Stricter:** the loop is now `codec.classifyDumpMessage`, so `NLMSG_DONE` terminates like a bare ACK and `NLMSG_OVERRUN` is an error (`SystemResources`, matching the narrowed face). |
| 9 | `NLM_F_DUMP_INTR` was ignored (the flag was never inspected) | **Stricter:** a flagged reply is dropped (`.restart` is treated as `.skip`) rather than trusted. It cannot occur — a `CTRL_CMD_GETFAMILY` *by name* is the kernel's `doit` path, not a dump — but an interrupted reply is not something to parse. |
| 10 | `NLMSG_NOOP` was ignored by falling through `else`; the shared triage skips it explicitly | Same outcome; shared. |
| 11 | Neither copy had `handle()` / `setRecvTimeout()` | **Added** (they come free with the transport). A bounded receive on a genl event socket previously required reaching for the raw `fd`. |
| 12 | A short `NLMSG_ERROR` payload: genetlink's `m.errorCode() catch → MalformedReply`, the triage's `.malformed` | Same outcome; shared. |

**Which face genetlink presents to its callers.** `recvDatagram` keeps the *narrow* error set
(`OutOfMemory`/`RecvFailed`/`MalformedReply`/`SystemResources`) and `recvDatagramStrict` is
additive — the opposite of a free choice. `nl80211` and `ethtool` each contain
`fn recvErr(e: genl.RecvError)` with an **exhaustive** switch over exactly those four members;
widening `RecvError` would not have deprecated anything, it would have failed to compile in two
read-only modules. Beyond that compile-level fact the split is right on the merits: the historical
face is what a *command* socket wants (a resolve that hits `ENOBUFS` has simply failed), while the
strict face is what an *event* socket wants, and both consumers run separate command and event
sockets. `resolveFamily`'s and `resolveMcastGroup`'s own error sets are unchanged/additive: nothing
in `ResolveError` moved, and `McastGroupError = ResolveError || error{GroupNotFound}`.

## Multicast group resolution — promoted, not deferred
Previously "out of scope (deliberate extension point)". `nl80211` documented that it implemented
`findMcastGroupId` locally *"as the first family that needs group ids — if a second family ever
needs it, this is the code to promote"*; `ethtool` then became that second family and copied it
verbatim (same nest walk, same `error.BadLength` on a named group with no id). Two independent
copies of a UAPI walk is exactly the duplication this wave exists to delete, so the trigger the
`nl80211` comment named has fired and the API now lives here:

- `findMcastGroupId(attr_bytes, want) codec.Error!?u32` — pure, byte slices in, id out, identical
  in behaviour to both existing copies (including the sticky-`null` and `BadLength` cases).
- `Socket.resolveMcastGroup(family, group) McastGroupError!u32` — the round trip, sharing one
  `CTRL_CMD_GETFAMILY` engine with `resolveFamily`.
- The three nlctrl constants (`CTRL_ATTR_MCAST_GROUPS`, `CTRL_ATTR_MCAST_GRP_NAME`,
  `CTRL_ATTR_MCAST_GRP_ID`), which both consumers also re-declare privately.

`nl80211` and `ethtool` were read-only in this wave and still carry their own copies; adopting the
shared one (deleting ~25 lines each, keeping their own `SubscribeError` mapping) is a later,
purely-mechanical wave. **Joining** a group deliberately stays with the caller: it is one
`setsockopt(NETLINK_ADD_MEMBERSHIP)` on `sock.fd`, and each family maps its errno onto its own
request-error set — hoisting it would force a translation layer that is longer than the call.

One deliberate hardening over the copies: a `CTRL_CMD_NEWFAMILY` reply spread over several messages
cannot erase an id already found (`found = find(…) orelse found`), where `nl80211`'s copy assigns
unconditionally. Unreachable for a by-name lookup, which the kernel answers in one message.

## Provenance / licensing
The kernel UAPI header this module cites (`linux/genetlink.h`) is GPL-2.0, but that does not make the
module a GPL derivative: only uncopyrightable ABI facts are taken from it (numeric constants,
`genlmsghdr` layout), and separately, that header carries the **Linux-syscall-note** exception, which
explicitly permits userspace of any license to use it to interface with the kernel. No kernel source
was consulted or copied. Full attribution in /NOTICE.

## Threat model / out of scope
The untrusted input is the kernel's reply bytes; wire-format validation (bounds/length checks) is
delegated to the fuzzed `netlink.codec` walkers, so a malformed or hostile datagram yields a typed
error, never a panic or OOB read. `findMcastGroupId` walks three nest levels through those same
checked iterators and propagates their errors. Unprivileged: `CTRL_CMD_GETFAMILY` resolution needs
no root, and neither does group *resolution* — a specific family's own commands, or joining some
groups, may be privileged (e.g. WireGuard's `CAP_NET_ADMIN`), but that requirement lives in the
family module, not here. Out of scope: everything past the generic layer (a family's commands,
attributes and request/reply shapes) and multicast *membership* (see above).

## Verification
Offline unit tests over the pure half: golden `CTRL_CMD_GETFAMILY` request bytes (byte-exact,
LE-only), a name-too-long rejection (`GENL_NAMSIZ`), `appendHeader`'s genlmsghdr encoding,
`splitPayload` truncation handling, and `findMcastGroupId` over a synthesised
`CTRL_ATTR_MCAST_GROUPS` nest (hit/miss/prefix-miss/empty, a named group with no id →
`error.BadLength`, a chopped nest → `error.Truncated`). One golden is genuinely captured rather
than self-built: `Socket.send`/`recvDatagram` against this machine's real nlctrl, both the request
and the `CTRL_CMD_NEWFAMILY` reply frozen byte-for-byte, offline-parsed with `codec.MessageIterator`
+ `splitPayload` + `findMcastGroupId` — every other offline test here round-trips this module's own
encoder against its own decoder (or hand-typed bytes matching its own constants), so a
`CTRL_ATTR_MCAST_GRP_NAME`/`_ID` swap made consistently in both directions passes them all; this one
came out of a kernel that was never told this module's constant values, so it does not. Linux
integration tests (unprivileged,
skipped only if the socket won't open): nlctrl resolves to itself (`GENL_ID_CTRL`), a nonexistent
family name yields `error.FamilyNotFound`, an over-length name yields `error.NameTooLong`; nlctrl's
own `notify` group resolves to a nonzero dynamic id while an unknown group on a known family yields
`error.GroupNotFound` and an unknown family yields `error.FamilyNotFound`; and the transport seam is
exercised end-to-end (`handle()` agrees with `fd`, a nonzero `portid`, a `setRecvTimeout`-bounded
receive on an idle socket returning `WouldBlock` from the strict path and `RecvFailed` from the
narrow one, and `seq` still advancing afterwards). Run: `zig build test-genetlink`.

The three reverse dependents (`nl80211`, `ethtool`, `wireguard`) are the real regression net — the
first two run live tests against a Wi-Fi radio and an e1000e NIC. All three must keep identical
pass/skip counts in Debug and `--release=fast`, and source compatibility is proven mechanically
(a comptime-reflection dump of every public decl/field/error, diffed against a worktree of the
previous commit), not by inspection.

## Backlog / deferred
- `nl80211` and `ethtool` still carry their private `findMcastGroupId` + `CTRL_ATTR_MCAST_GRP_*`
  copies; they can adopt the shared ones in a later wave (mechanical, module-local).
- `ethtool` sets `NETLINK_EXT_ACK` itself and keeps its own `err_buf`; the transport now does both,
  so that copy can go the same way.

## Status
`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const meta` in
src/root.zig.

**Repo-wide netlink transport consolidation: complete.** Every module that speaks netlink now shares
one implementation of the socket discipline — `netlink` (rtnetlink, and the transport's home),
`conntrack`, `nftables`, `tc` and, with this change, `genetlink` (and through it `nl80211`,
`ethtool` and `wireguard`). No private copy of socket/bind/portid/`EXT_ACK`/`MSG_PEEK|MSG_TRUNC`
remains in the repo.
