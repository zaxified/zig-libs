# rawsock — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Linux AF_PACKET capture + inject, no libpcap, no libc.** Open a `SOCK_RAW` capture socket for
  one EtherType (or every frame, `eth_p.all`), decode the kernel's `sockaddr_ll` into a typed
  `Frame`, attach an in-kernel classic-BPF filter, toggle promiscuous mode, and cook-inject frames
  on a named interface (a `SOCK_DGRAM` socket where the kernel builds the Ethernet header) or
  transmit a complete frame on the raw socket (`sendRaw`). Seeded from the authors' own axp
  `axp-core/src/task.zig` (`openPacketCapture`/`ifNameOf`, MIT, the receive-only ~25-LOC core); the
  send path, `SO_ATTACH_FILTER` filtering, `PACKET_ADD_MEMBERSHIP` promiscuous mode, interface
  enumeration, and the typed `Frame`/`LinkAddr`/`EthHeader` decode are new construction. Wire layout
  clean-room from `packet(7)`, `<linux/if_packet.h>`, `<linux/filter.h>`, IEEE 802.3, and ARP — see
  NOTICE. Model after libpcap's minimal AF_PACKET path.
- **Pure helpers need no socket/privilege:** `EthHeader.parse`/`.write`, `parseHwaddr`/
  `formatHwaddr` (MAC ⇄ `"aa:bb:cc:dd:ee:ff"`), `LinkAddr.fromSockaddr` (the `sockaddr_ll` decode
  `recv` uses), `bpf`/`etherTypeFilter` (classic-BPF program builder; wire-format `BpfInsn` is 8
  bytes, asserted), `arp.buildRequest`/`arp.parseReply` (addresses surface as `netaddr.Ip`).
- **Raw errno syscalls, no libc:** all socket/ioctl calls go through `std.os.linux` directly, a
  conscious ceiling shared with `icmp`/`netlink`. Kernel struct sizes (`sockaddr_ll`, `BpfInsn`) are
  asserted in tests against the documented ABI.
- **Concurrency:** reentrant — no shared state; one `Socket` per thread/loop.

## Threat model / out of scope

**Linux-only by design** — no BSD `/dev/bpf` path, no cross-platform abstraction attempted.
**Privilege-gated:** opening a capture/inject socket needs `CAP_NET_RAW`; without it `open` returns
a distinct `error.AccessDenied` rather than a generic failure (interface lookups like `ifaceByName`
are unprivileged and always available). This module is a **capability**, not a policy — it does not
itself restrict which interfaces/EtherTypes a caller may open; that access-control decision belongs
to the deployment (capability grant, network namespace, seccomp). The in-kernel BPF filter
(`setFilter`) reduces what userspace *sees*, it is not a security boundary against a co-resident
process with the same capability. Received frames are attacker-influenced wire data on a shared
L2 segment (spoofable source MAC, malformed lengths); the typed decode (`EthHeader.parse`,
`LinkAddr.fromSockaddr`, `arp.parseReply`) must reject malformed input without panicking — that
tolerant-parsing guarantee is the attack surface to audit, not the socket layer itself. Out of
scope: `PACKET_RX_RING`/`recvmmsg` batching, `TPACKET_V3`, IPv6 Neighbor Discovery (only ARP is
implemented).

## Verification

Root-free tests (pure helpers, `sockaddr_ll` decode, BPF encoding, struct ABI sizes) always run: 7
pass, 2 skip (the two socket tests need `CAP_NET_RAW` and `SkipZigTest` without it). Under an
unprivileged network namespace where root has the capability (`unshare -rn zig build test-rawsock`)
all 9 pass, including open/filter/promisc and an inject→capture loopback round-trip on `lo`. Run:
`zig build test-rawsock` (add `-Doptimize=ReleaseFast` for the release check; `unshare -rn` prefix
for the full socket path).

## Backlog / deferred

- **`PACKET_RX_RING`/`recvmmsg` batching** — mmap'd zero-copy RX for throughput; not built.
- **`TPACKET_V3` block-based capture** — not built.
- **IPv6 Neighbor Discovery helpers** — the ND counterpart to the ARP codec; only ARP exists today.
- **Remains Linux-only** — the documented AF_PACKET ceiling (no BSD `/dev/bpf`) is permanent, not a
  gap to close.

## Status

`gap (built: seed = axp task.zig openPacketCapture/ifNameOf, receive-only) · linux · both
(capture + inject) · reentrant` + deps: `netaddr` — canonical source is `pub const meta` in
src/root.zig.
