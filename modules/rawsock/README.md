# rawsock

Linux **AF_PACKET** raw-frame **capture + inject**: a minimal, libpcap-shaped
path to layer 2 in pure Zig — open a `SOCK_RAW` capture socket for one
EtherType (or every frame), decode the kernel's `sockaddr_ll` into a typed
`Frame`, attach an in-kernel **classic-BPF** filter, toggle **promiscuous**
mode, and cook-inject frames on a named interface. No libpcap, no libc.

- The initial receive-only core
  (`openPacketCapture` / `ifNameOf`) was inlined and minimal; send, BPF
  filtering, promiscuous mode, interface enumeration and the typed
  frame/`sockaddr_ll` decode are new construction.
- **Model after:** libpcap's AF_PACKET path; wire semantics from `packet(7)`
  and the BPF UAPI (`<linux/filter.h>` / `<linux/if_packet.h>`).
- **Why:** std has no AF_PACKET support; there is no small pure-Zig raw-L2
  library. Needed by `l2disco`-style tasks (LLDP/CDP/ARP/DHCP sniffing, ARP
  scan) that today open the socket ad hoc.
- **Platform:** linux (raw errno-encoded `std.os.linux` syscalls, no libc — a
  conscious ceiling, like `icmp` / `netlink`). **Role:** both (capture +
  inject). **Concurrency:** reentrant (no shared state; one `Socket` per
  thread/loop).
- **Deps:** `netaddr` (IP addresses that surface — the ARP codec — come back
  as `netaddr.Ip`).
- **Privileges:** needs `CAP_NET_RAW` to open a socket; without it `open`
  returns a distinct `error.AccessDenied`. Interface lookups (`ifaceByName`)
  are unprivileged.

Provenance: original work of the zig-libs authors (MIT), starting from a
minimal receive-only ~25-LOC core (`openPacketCapture` + `ifNameOf`). The
send path, `SO_ATTACH_FILTER` filtering, `PACKET_ADD_MEMBERSHIP` promiscuous
mode, interface enumeration, the `EtherType`/`pkt`/`bpf` enums and the typed
`Frame` / `LinkAddr` / `EthHeader` decode are new. Wire layout clean-room from
`packet(7)`, `<linux/if_packet.h>`, `<linux/filter.h>` and the IEEE 802.3 / ARP
formats. Linux-only by design; kernel struct sizes are asserted in tests.

## API

```zig
const rawsock = @import("rawsock");

// Capture — a SOCK_RAW socket; frames arrive with their full Ethernet header.
var cap = try rawsock.Socket.open(rawsock.eth_p.arp, .{
    .iface = "eth0",         // null = all interfaces
    .recv_timeout_ms = 1000, // SO_RCVTIMEO; 0 = block forever
});
defer cap.close();

try cap.setFilter(&rawsock.etherTypeFilter(rawsock.eth_p.arp)); // in-kernel BPF
try cap.setPromisc(try rawsock.ifaceByName("eth0"), true);

var buf: [2048]u8 = undefined;
const frame = try cap.recv(&buf); // Frame{ bytes, ifindex, src_hwaddr, ethertype, pkttype }
if (rawsock.EthHeader.parse(frame.bytes)) |eth| _ = .{ eth.dst, eth.src, eth.ethertype };

// Inject — a SOCK_DGRAM (cooked) socket; the kernel builds the Ethernet header.
const idx = try rawsock.ifaceByName("eth0");
var inj = try rawsock.Socket.openInject(idx);
defer inj.close();
try inj.send(idx, dst_mac, rawsock.eth_p.ip, payload); // header prepended by the kernel
// or, on a SOCK_RAW socket, transmit a complete frame yourself:
// try cap.sendRaw(idx, full_ethernet_frame);

// Interface helpers (SIOCGIFINDEX / SIOCGIFNAME / SIOCGIFHWADDR).
const mac = try rawsock.hwaddr(inj.fd, idx);        // [6]u8
var namebuf: [16]u8 = undefined;
const name = try rawsock.ifaceName(inj.fd, idx, &namebuf); // "eth0"
```

### Pure helpers (no socket, no privileges)

- `EthHeader.parse` / `.write` — Ethernet II header codec.
- `parseHwaddr` / `formatHwaddr` — MAC ⇄ `"aa:bb:cc:dd:ee:ff"`.
- `LinkAddr.fromSockaddr` — the typed `sockaddr_ll` decode used by `recv`.
- `bpf` + `etherTypeFilter` — build classic-BPF programs (the wire-format
  `BpfInsn` is 8 bytes, asserted).
- `arp.buildRequest` / `arp.parseReply` — minimal ARP-over-Ethernet codec;
  addresses surface as `netaddr.Ip`.

## Testing

Root-free tests (the pure helpers, `sockaddr_ll` decode, BPF encoding, struct
ABI sizes) always run:

```
zig build test-rawsock                          # 7 pass, 2 skip (no CAP_NET_RAW)
zig build test-rawsock -Doptimize=ReleaseFast
```

The two socket tests (open/filter/promisc, and an inject→capture loopback
round-trip on `lo`) need `CAP_NET_RAW`; without it they `SkipZigTest`. Run them
under an unprivileged network namespace, where root has the capability:

```
unshare -rn zig build test-rawsock              # 9 pass (full socket path)
```

## Deferred (v2)

- `PACKET_RX_RING` / `recvmmsg` batching (mmap'd zero-copy RX for throughput).
- `TPACKET_V3` block-based capture.
- IPv6 Neighbor-Discovery helpers (the ND counterpart to the ARP codec).
- Remains Linux-only — the documented AF_PACKET ceiling (no BSD `/dev/bpf`).
