# SPEC — `netlink`

Pure-Zig **rtnetlink** transport + query API over `NETLINK_ROUTE`: enumerate links, addresses,
routes, and neighbors without shelling out to `ip` or parsing `/proc/net`. Task T4.
`gap · linux · client · reentrant`. Model after: `libmnl` (minimal netlink framing) + `libnl` /
`vishvananda/netlink` (Go) + iproute2; **clean-room from the kernel UAPI** headers
(`linux/netlink.h`, `linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`, `linux/neighbour.h`)
and the wire format — no GPL source consulted. Deps: **none (std only)**. New `build.zig` entry
`.{ .name = "netlink" }`.

## Why

Netlink is the real Linux control-plane API. A native reader retires a pile of `/proc/net/*`
parsing and `ip`/`ss` shell-outs (cf. axp), is faster and race-free, and is the substrate a future
`wireguard` module (genetlink) builds on. This task = the **read/dump** surface + the transport
that write ops would later use. Reads need **no root** (RTM_GET* dumps are unprivileged).

## Scope

1. **Socket transport:** open `AF_NETLINK`/`NETLINK_ROUTE` via `std.os.linux` (errno-encoded, like
   the ICMP path — no libc), bind, send/recv. Sequence numbers + PID matching, `NLMSG_ERROR`/ACK
   handling (errno), **multi-part dump** assembly (`NLM_F_REQUEST|NLM_F_DUMP` → messages until
   `NLMSG_DONE`), receive-buffer growth for large dumps. Never panic on a malformed reply.
2. **Message + attribute codec (the bulletproof core, separable + golden-tested):** `nlmsghdr`
   build/parse; **rtattr (TLV)** iterate/encode with correct `NLMSG_ALIGN`/`RTA_ALIGN` (4-byte);
   nested-attr walking; bounds-checked (a truncated/hostile attr returns an error, no OOB).
3. **Typed dump queries** returning owned slices of typed structs:
   - **Links** (`RTM_GETLINK` → `ifinfomsg` + `IFLA_IFNAME`/`IFLA_MTU`/`IFLA_ADDRESS`/flags/index).
   - **Addresses** (`RTM_GETADDR` → `ifaddrmsg` + `IFA_ADDRESS`/`IFA_LOCAL`/prefixlen/scope/label);
     surface as an `Ip`-ish `{family, bytes, prefix, ifindex}` (don't depend on `netaddr` — keep
     `netlink` dep-free; a plain address struct is fine).
   - **Routes** (`RTM_GETROUTE` → `rtmsg` + `RTA_DST`/`RTA_GATEWAY`/`RTA_OIF`/`RTA_PRIORITY`/table).
   - **Neighbors** (`RTM_GETNEIGH` → `ndmsg` + `NDA_DST`/`NDA_LLADDR`/state) — the ARP/ND table.
4. **Filtering:** allow a dump to be scoped (e.g. by family AF_INET/AF_INET6, by ifindex) where the
   kernel supports it; otherwise filter client-side and note it.
5. **(Out of scope this task, note as extension points):** write ops (`RTM_NEWROUTE`/`NEWADDR`/
   `NEWNEIGH`/`DELROUTE`…) and event monitoring (`NLM_F_ACK`, multicast groups) — the transport
   should be shaped so these are a small future addition, but do NOT implement them now.

## Public API sketch (final shape your call; allocator-explicit)

```zig
pub const Socket = struct {
    pub fn open(gpa) !Socket;   pub fn close(*Socket) void;
    pub fn links(self) ![]Link;         // owned; caller frees
    pub fn addresses(self, family: ?u8) ![]Address;
    pub fn routes(self, family: ?u8) ![]Route;
    pub fn neighbors(self, family: ?u8) ![]Neighbor;
};
pub const Link = struct { index: u32, name: []const u8, mtu: u32, flags: u32, mac: ?[6]u8 };
pub const Address = struct { family: u8, ifindex: u32, prefixlen: u8, addr: [16]u8, len: u8 };
// Route, Neighbor similarly. Low-level: Message + Attr iterators are pub for custom queries.
```

## Acceptance / verification

- **Offline unit tests (the core must be perfect):** rtattr encode → **golden bytes**; parse of
  canned dump buffers (single + multi-part with `NLMSG_DONE`), nested attrs, `NLMSG_ERROR` → the
  right errno, truncated / bad-length / OOB-pointer attrs → error (no panic, no OOB read — fuzz the
  attr walker), alignment edge cases. `zig build test-netlink` green.
- **Integration (real kernel, NO root needed — RTM_GET* dumps are unprivileged; gate via
  `error.SkipZigTest` only if the netlink socket can't open):** open `NETLINK_ROUTE`, dump links →
  assert **`lo` is present** (index 1, LOOPBACK flag); dump addresses → assert a loopback address
  (127.0.0.1 and/or ::1) on `lo`; dump routes and neighbors → parse without error and return a
  slice (contents environment-dependent — assert structural validity, not specific rows).
- `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean. Registered with no deps.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 raw syscalls (`std.os.linux.socket/bind/sendto/recvfrom` are
  errno-encoded usizes — same discipline as the repo's ICMP/`http` raw paths; NO libc, NO
  `std.posix` wrappers that panic). Const names come from `std.os.linux` where present, else define
  them from the UAPI (document the header + value).
- The attr walker is the security-critical part (untrusted kernel bytes in theory, but be strict):
  bounds-check every `rta_len`, cap iteration, never index past the buffer.
- Keep `netlink` dependency-free (plain address structs, not `netaddr.Ip`) so it stays a clean
  foundation.
- SPDX header + a `Provenance:` line (clean-room from kernel UAPI + wire; design refs libmnl
  LGPL / vishvananda-netlink Apache-2.0 — behavior/wire only, no source copied). Add the NOTICE entry.
