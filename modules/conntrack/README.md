# conntrack

Linux **ctnetlink** client (`NETLINK_NETFILTER` / `NFNL_SUBSYS_CTNETLINK`) — the real netlink
API of the kernel connection tracker, the one `conntrack -L/-G/-I/-D/-E` speaks. Dump the flow
table, look a flow up by tuple, insert, delete, flush, and subscribe to the conntrack event
multicast groups. Pure Zig raw syscalls: no libc, no `conntrack` shell-out, no
libnetfilter_conntrack.

The sibling `procnet` module only *reads* `/proc/net/nf_conntrack`, a lossy text view that many
kernels no longer build at all (`CONFIG_NF_CONNTRACK_PROCFS=n`). ctnetlink is the supported
interface and carries what the text file cannot: 64-bit counters, connmark, zone, entry id,
TCP state, timestamps — and it is writable and event-driven.

Wire framing, TLV walking **and the socket transport** are the `netlink` module's: `nlmsghdr`,
the `nlattr` walkers, `nestBegin`/`nestEnd`, the big-endian attribute accessors every netfilter
family needs, the multi-part dump triage, the typed errno mapping and extended-ACK strings — plus
the socket itself, opened with `netlink.Socket.openProtocolGroups(gpa, NETLINK.NETFILTER, groups)`,
which carries bind, port-id capture, `NETLINK_EXT_ACK`, sequence allocation, the
`MSG_PEEK|MSG_TRUNC` receive-sizing loop and the ACK engine. This module adds the `nfgenmsg`
header, the CTA_* attribute tree and the ctnetlink policy on top. Addresses are `netaddr.Ip`.

## Import

```zig
const conntrack = @import("conntrack");
```

## Usage

```zig
var sock = try conntrack.Socket.open(gpa);
defer sock.close();

// Dump every tracked flow (needs CAP_NET_ADMIN in the netns).
const flows = try sock.dump(.unspec);   // or .ipv4 / .ipv6
defer gpa.free(flows);                  // Flow is pointer-free: one free()
for (flows) |f| {
    if (f.hasStatus(conntrack.IPS.ASSURED)) {
        std.debug.print("{d} -> {d} timeout={d}s\n", .{
            f.orig.src_port.?, f.orig.dst_port.?, f.timeout.?,
        });
    }
}

// Look one flow up by its original tuple.
const key: conntrack.Tuple = .{
    .src = .{ .v4 = .{ 10, 0, 0, 1 } },
    .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
    .proto = conntrack.IPPROTO.UDP,
    .src_port = 5353,
    .dst_port = 53,
};
if (try sock.get(.ipv4, .orig, key)) |f| {
    // …and delete exactly that entry (compare-and-delete on its id).
    try sock.delete(.ipv4, .orig, key, f.id);
}

// Insert a synthetic flow (what `conntrack -I` does).
try sock.insert(.ipv4, .{
    .orig = key,
    .reply = key.invert(),
    .timeout = 120,
    .mark = 0x5a5a,
});

// Events: the blocking read is one call, so the caller owns the loop.
var evs = try conntrack.Socket.openEvents(gpa, conntrack.Group.all_conntrack);
defer evs.close();
while (true) {
    var it = try evs.nextEvents();          // blocks; or poll evs.handle() first
    while (try it.next()) |ev| switch (ev.kind) {
        .new, .update, .destroy => { … ev.flow … },
    };
}
```

## API

- `Socket.open(gpa)` / `.close()` — one `NETLINK_NETFILTER` socket per thread/loop.
- `Socket.openEvents(gpa, groups)` — the same socket bound to conntrack multicast groups
  (`Group.CONNTRACK_NEW/_UPDATE/_DESTROY`, or `Group.all_conntrack`). Needs `CAP_NET_ADMIN`.
- `Socket.dump(family) DumpError![]Flow` — `IPCTNL_MSG_CT_GET` + `NLM_F_DUMP`, restarted on
  `NLM_F_DUMP_INTR`. Free with one `gpa.free`.
- `Socket.get(family, dir, tuple) WriteError!?Flow` — one entry by tuple, `null` if untracked.
- `Socket.delete(family, dir, tuple, expect_id) WriteError!void` — delete by tuple;
  `expect_id` (from a previous dump/get) makes it a compare-and-delete.
- `Socket.flush(family) WriteError!void` — drop the whole table. Deliberately a separate name:
  in the kernel a *tuple-less* delete **is** a flush, and no caller should reach that by accident.
- `Socket.insert(family, NewSpec)` / `.update(family, NewSpec)` — `IPCTNL_MSG_CT_NEW` with and
  without `NLM_F_CREATE|NLM_F_EXCL`.
- `Socket.nextEvents() RecvError!EventIterator` — the **only** blocking call in the event path;
  `Socket.handle()` and `Socket.setRecvTimeout(ms)` let a caller drive it from poll/epoll.
- `Socket.lastErrorMessage()` — the kernel's extended-ACK reason for the last failure.
- `Flow` — `orig`/`reply` tuples plus `status`, `timeout`, `mark`, `id`, `use`, `zone`,
  `counters_orig`/`_reply` (64-bit), `tcp_state`, `tcp_wscale_*`, `tcp_flags_*`,
  `timestamp_start`/`_stop`. Every field optional: present iff the kernel sent it.
- `Tuple` — `src`/`dst` (`netaddr.Ip`), `proto`, `src_port`/`dst_port` **or**
  `icmp_id`/`icmp_type`/`icmp_code`, plus `isComplete()` and `invert()`.
- `wire` — the whole I/O-free layer (`decodeFlow`, `buildDumpRequest`, `buildGetRequest`,
  `buildDeleteRequest`, `buildNewRequest`, every CTA_*/IPS_* constant), usable without a socket.

Two kernel behaviours worth knowing, both verified live and covered by tests:

- **`CTA_STATUS` on a write is a diff, not an assignment.** The kernel refuses (`EBUSY` →
  `error.Busy`) any request whose status would clear `IPS_CONFIRMED`, `IPS_SEEN_REPLY`,
  `IPS_ASSURED`, `IPS_EXPECTED` or `IPS_DYING`. An insert that sends a status at all must
  therefore include `IPS.CONFIRMED`; sending no status is always safe.
- **`CTA_ID` is not a lookup key.** The kernel finds the entry by tuple and only then compares
  the id — so a delete still needs a tuple, and the id turns it into a compare-and-delete.

## Verify

```sh
zig build test-conntrack                       # goldens + decoder + fuzz; live tests skip
unshare -rn zig build test-conntrack           # + live insert/get/dump/delete + event round-trip
```

Every live test prints `SKIPPED: …` and **passes** when the ctnetlink socket cannot be opened,
`nf_conntrack` is missing, or `CAP_NET_ADMIN` is not held — an unprivileged `zig build test`
stays green. See SPEC.md for the full verification story (byte-exact captures of real
conntrack-tools traffic, the capture command, the live proof and the deferred list).

Provenance: clean-room from the kernel UAPI headers
(`linux/netfilter/nfnetlink.h`, `nfnetlink_conntrack.h`,
`nf_conntrack_common.h`, `nf_conntrack_tcp.h`; GPL-2.0 WITH Linux-syscall-note)
plus on-the-wire captures — only the uncopyrightable ABI facts they document are
used, the same Linux-syscall-note mechanism `netlink`/`ebpf`/`tc` rely on.
`conntrack-tools` / `libnetfilter_conntrack` (**GPL-2.0**) are named for WIRE
BEHAVIOR observed by capture; no source was read or ported, and this module
derives nothing from that codebase.