# SPEC — `netlink`

**Purpose** — Read the Linux control plane straight from the kernel over `NETLINK_ROUTE`:
enumerate links, addresses, routes and neighbors as typed structs — no `ip`/`ss` shell-outs, no
`/proc/net` parsing, no libc. It is also the transport foundation the `wireguard` (genetlink) module
builds on, and the substrate for retiring ad-hoc `/proc/net` readers elsewhere.

**Model after / Seed** — clean-room from the kernel UAPI headers (`linux/netlink.h`,
`linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`, `linux/neighbour.h`, `linux/if.h`) +
RFC 3549. Design references only (no source consulted or copied): libmnl for framing/validation
discipline (`mnl_nlmsg_ok`/`mnl_attr_ok` semantics) and Go `vishvananda/netlink` for the typed-query
shape. Constants and struct layouts are the OS ABI; see `NOTICE`.

**Design & invariants**
- **The attr/message walker is the security boundary** and lives in `codec.zig` — pure, no I/O, no
  platform dependency, unit- and fuzz-tested on any OS. Every `nlmsg_len`/`rta_len` is bounds-checked
  against the enclosing buffer before any slice is formed; each step advances ≥ 4 bytes, so a walk
  over N bytes is capped at N/4 steps. Malformed/hostile/bit-flipped input → `error.Truncated` /
  `error.BadLength`, never a panic or an OOB read.
- **Typed results are plain data** — fixed inline buffers, no pointers into the receive buffer — so
  an owned slice frees with a single `gpa.free(slice)`. Deliberately no `netaddr` dependency
  (addresses are raw `{family, bytes, prefixlen, …}`) to keep `netlink` a dep-free foundation.
- **Transport discipline:** raw `std.os.linux` errno-encoded syscalls (Linux-only by design);
  kernel-assigned portid + per-request sequence number match replies (stale messages from an aborted
  earlier dump are skipped, self-healing the queue); multi-part dumps assemble until `NLMSG_DONE`;
  `NLM_F_DUMP_INTR` restarts up to 4 attempts (libnl's `NLE_DUMP_INTR`). Receive buffer grows via a
  `MSG_PEEK|MSG_TRUNC` size probe so nothing is lost to truncation; non-kernel datagrams (sender pid
  ≠ 0) are dropped. One `Socket` per thread/loop; no globals.
- **Scoping:** `Filter.family` is applied kernel-side (fixed-header family byte) *and* re-checked
  client-side; `Filter.ifindex` is client-side only (kernel-side would need the `NETLINK_GET_STRICT_CHK`
  opt-in). Dump requests carry the full fixed header (not the legacy 1-byte rtgenmsg) for
  strict-check compatibility, like modern iproute2. IPv4 prefers `IFA_LOCAL` over `IFA_ADDRESS`.

**Threat model / out of scope** — The untrusted input is the kernel's reply bytes; the codec treats
them as hostile and is fuzzed accordingly. Unprivileged: RTM_GET* dumps need no root. Out of scope
(deliberate, additive extension points — the transport already speaks seq/ACK/errno + multi-part):
write ops (`RTM_NEW*`/`RTM_DEL*`) and multicast event monitoring.

**Verification** — Offline unit tests over canned payloads built by the codec's own encoders:
per-type parse (link/address/route/neighbor), IFA_LOCAL-vs-ADDRESS preference, default-route +
RTA_TABLE override, truncated/bad-length/overrunning attrs → typed error, `errorFromCode` errno
mapping, `codec` constants cross-checked against `std.os.linux`, and a `std.testing.fuzz` harness
over the four typed parsers. Linux integration tests (skipped only if the socket won't open, no
root): `lo` present (index 1, LOOPBACK), a loopback address on `lo`, family/ifindex scoping, routes
& neighbors structurally valid, and sequential dumps on one socket staying in sync.

**Status** — `gap · linux · client · reentrant` · deps: none (std only).
