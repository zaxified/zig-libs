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
| 9 | `NLM_F_DUMP_INTR` was ignored (the flag was never inspected) | **Stricter:** a flagged reply is dropped (`.restart` is treated as `.skip`) rather than trusted. It cannot occur — a `CTRL_CMD_GETFAMILY` *by name* is the kernel's `doit` path, not a dump — but an interrupted reply is not something to parse. ⚠ **Correction, 2026-09-10 (audit finding F1):** "cannot occur" turned out to be a claim about *this* kernel, not a bound the loop enforced — nothing capped how many `.skip`/`.restart` messages it would wait through, so a peer that never reaches `NLMSG_DONE` (missing terminator, an endless `NLM_F_DUMP_INTR` stream, or a flood of foreign-`seq` datagrams) spun `resolveFamily`/`resolveMcastGroup` forever. Fixed with a `max_reply_messages` budget (65536, same value and rationale as `netlink`'s `max_await_messages`/`max_dump_messages`) — `error.TooManyMessages`, additive to `ResolveError`. The budget does not depend on row 9's claim holding. |
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

## Reply identity verification (audit finding F2, closed 2026-09-10)
A `CTRL_CMD_GETFAMILY` reply's data record used to be accepted on the strength of matching
`(portid, seq)` alone — nothing checked that the record actually *was* an answer about the
requested family. Live against a real kernel, `resolveFamily("nlctrl\x00zz")` resolved (the kernel
reads `CTRL_ATTR_FAMILY_NAME` as a C string and stops at the embedded NUL; this module sent the
raw Zig slice and never looked at what came back), and three more identity axes were provably
unchecked (a reply named for a different family, a `CTRL_CMD_DELFAMILY` payload, a family id outside
the kernel's own dynamic range). The four consumers had each independently noticed this gap and
worked around it — `ethtool/src/goldens.zig:1387-1389` and `devlink/src/goldens.zig:699-700` both
hand-assert `family_name == requested` and `family_id > GENL_ID_CTRL` after calling the resolver —
which is the invariant this module now enforces itself instead of leaving to callers that remember to.

`ctrlGetFamilyOver`'s `.family_id` branch now requires all three to hold before accepting a record:
`CTRL_CMD_NEWFAMILY` (not `DELFAMILY` or any other control command), `CTRL_ATTR_FAMILY_NAME` present
and byte-equal to the requested name (this closes the NUL-truncation confusion too: a name with an
embedded NUL can never equal what the kernel echoes back, which it reads only up to its own NUL),
and `CTRL_ATTR_FAMILY_ID` inside `[GENL_ID_CTRL, GENL_MAX_ID]` — the kernel's own dynamic-id range
(`GENL_MIN_ID`/`GENL_MAX_ID` in `linux/genetlink.h`; `GENL_MIN_ID == GENL_ID_CTRL` by the kernel's own
`#define`). Any other shape is `error.MalformedReply`, the vocabulary already used for a hostile or
malformed datagram — no new error, no signature change. `findMcastGroupId`'s group-name path gained
the matching hardening for its own two axes (F8): a matching group entry whose id is 0 is now
`error.BadLength` (every id this module has observed from a real kernel is dynamically assigned and
nonzero), and an empty `want` never matches an empty group name.

## Reply loop message budget (audit finding F1, closed 2026-09-10)
See row 9's correction above. `ctrlGetFamilyOver` now bounds its receive loop at
`max_reply_messages` (65536) datagrams, returning `error.TooManyMessages` — additive to
`ResolveError` — instead of spinning forever. Same constant value and the same rationale as
`netlink`'s `max_await_messages`/`max_dump_messages`.

## `lastErrorMessage` freshness (audit finding F3, closed 2026-09-10)
Its own doc comment promises the extended-ACK reason is "valid until the next request on this
socket", but `ctrlGetFamily` never cleared it — a caller that inspected `lastErrorMessage()` after a
*successful* request, or after a *different* failure than the one that set it, could read stale text
describing an earlier, unrelated error. `ctrlGetFamily` now clears `ext_ack_len` unconditionally
before the request is even built, matching how `netlink.Socket.awaitAckStrict` clears its own
`ext_ack_len`/`last_errno` before each bounded-engine call.

## Sequence-number spend on a client-rejected request (audit finding F7, closed 2026-09-10)
`ctrlGetFamily` called `t.nextSeq()` before `buildGetFamilyRequest`'s own `GENL_NAMSIZ` guard could
run, so a name too long to ever be sent still advanced the socket's sequence counter — visible in a
`strace` of the socket as a gap (`seq` 1, 3, with 2 missing). The `GENL_NAMSIZ` check now runs first,
in `ctrlGetFamily` itself, before a transport view is even taken; `buildGetFamilyRequest`'s own check
stays as defense in depth.

## `resolveMcastGroups` — batch group resolution (audit finding F6, closed 2026-09-10)
`resolveMcastGroup` costs one full `CTRL_CMD_GETFAMILY` round trip *per group name*, even though a
single reply already carries every group the family publishes and `findMcastGroupId` is a pure walk
over bytes already in hand. Measured against a real kernel: 1 name = 1 request + 4 receives (5
syscalls); 6 names = 6 requests + 24 receives (30 syscalls) — `nl80211/src/client.zig:779` calls
`resolveMcastGroup` once per group in a loop, and `nl80211` publishes 6+ groups (`config`, `scan`,
`regulatory`, `mlme`, `vendor`, `nan`). `Socket.resolveMcastGroups(family, names, out)` resolves all of
`names` over one round trip: `ctrlGetFamilyOver` gained a third `FamilyQuery` variant (`many_groups`)
that calls `findMcastGroupId` once per name against each reply record instead of once total,
leaving `out[i]` `null` for a name the family does not publish rather than failing the batch.
Purely additive — `resolveFamily`/`resolveMcastGroup`'s signatures are unchanged. `nl80211` and the
other three consumers still call the single-name resolver in a loop; adopting the batch entry point
is the same later, purely-mechanical wave already on the backlog for `findMcastGroupId` itself (see
below) — this only makes that adoption possible without a protocol change.

## UAPI constant coverage (audit finding F9, closed 2026-09-10)
`scripts/check-uapi-consts.py` diffed `ethtool`/`nl80211`/`devlink`/`conntrack`/`netlink` against
this host's kernel headers but not `genetlink` itself — the only automatic check of `GENL_ID_CTRL`,
`CTRL_CMD_GETFAMILY`, `CTRL_ATTR_FAMILY_ID`/`NAME`, `CTRL_ATTR_MCAST_GROUPS` and
`CTRL_ATTR_MCAST_GRP_*` ran through `nl80211`'s own private copy of them, which the backlog below
plans to delete once `nl80211`/`ethtool` adopt the shared resolver — at which point the check would
have silently stopped covering these constants entirely. `genetlink` is now its own entry in
`MODULES`, `zig_files: ["modules/genetlink/src/root.zig"]` (no separate `uapi.zig` — this module's
constants live next to the resolver). `9 matched, 0 MISMATCH, 2 unresolved` (`header_len`, a
repo-local sizing constant, and `GENL_ID_CTRL`, whose kernel spelling `NLMSG_MIN_TYPE` lives in a
different header than the one it's `#define`d relative to, which this script's single-header
evaluator does not cross-reference — both within the declared `unresolved_budget: 2`).

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

**Scripted-transport tests over the reply loop itself (added 2026-09-10, audit findings F1/F2/F4).**
Until this wave, `ctrlGetFamily`'s receive loop made real syscalls through `netlink.Socket`, so
nothing in `zig build test-genetlink` could drive a mutation of it deterministically — the audit
measured 10 of 23 mutations to the loop passing 16/16 green, including deleting the `(portid, seq)`
match outright. `ctrlGetFamilyOver` is the same loop factored out over an `anytype` transport (the
same shape `netlink`'s own `awaitAckOver`/`dumpOver` already use, for the same reason), so it now
runs in-process against `GenlScripted`, a scripted fixture with no socket, no namespace, no
privilege: the no-terminator hang, an endless `NLM_F_DUMP_INTR` stream, a foreign-portid reply, and
all four identity-check rejections from F2, each with the positive control that must still resolve.
Two more targeted regression tests cover F3 (`lastErrorMessage` does not survive into the next
request) and F7 (a rejected request does not advance `seq`) against a real socket. Independently,
`.zig-cache/probe/genetlink_{f2,f7,f8}_red_green.zig` hold RED/GREEN reproductions run once during
the fix (pre-fix logic genuinely exhibits the bug; post-fix logic does not) — supplementary evidence,
not part of the gate.

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

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** offline goldens self-built; live nlctrl test vs real Linux kernel is external

**How it got there.** The anchoring work landed. DONE 5938bfc: real nlctrl exchange frozen; CLOSES the audit blind spot, measured
