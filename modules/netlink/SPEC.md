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

## Threat model / out of scope
The untrusted input is the kernel's reply bytes; the codec treats them as hostile and is fuzzed
accordingly. Unprivileged: RTM_GET* dumps need no root. Out of scope (deliberate, additive
extension points — the transport already speaks seq/ACK/errno + multi-part): write ops
(`RTM_NEW*`/`RTM_DEL*`) and multicast event monitoring.

## Verification
Offline unit tests over canned payloads built by the codec's own encoders: per-type parse
(link/address/route/neighbor), IFA_LOCAL-vs-ADDRESS preference, default-route + RTA_TABLE
override, truncated/bad-length/overrunning attrs → typed error, `errorFromCode` errno mapping,
`codec` constants cross-checked against `std.os.linux`, a `std.testing.fuzz` harness over the four
typed parsers. Linux integration tests (skipped only if the socket won't open, no root): `lo`
present (index 1, LOOPBACK), a loopback address on `lo`, family/ifindex scoping, routes & neighbors
structurally valid, sequential dumps on one socket staying in sync. Run: `zig build test-netlink`.

## Backlog / deferred
Write ops (`RTM_NEW*`/`RTM_DEL*`) and multicast event monitoring are deliberate, additive
out-of-scope extension points — the transport already speaks the seq/ACK/errno + multi-part
protocol needed for them, not yet built. Linux-only platform ceiling is an accepted design choice
(raw-syscall nature, no portable fallback), grouped with icmp/rawsock/wireguard/l2disco/procnet.

## Status
`gap · linux · client · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
