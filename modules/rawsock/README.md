# rawsock

Linux **AF_PACKET** raw-frame **capture + inject**: a minimal, libpcap-shaped
path to layer 2 in pure Zig — open a `SOCK_RAW` capture socket for one
EtherType (or every frame), decode the kernel's `sockaddr_ll` into a typed
`Frame`, attach an in-kernel **classic-BPF** filter, toggle **promiscuous**
mode, and cook-inject frames on a named interface. No libpcap, no libc.

- The initial receive-only core
  (`openPacketCapture` / `ifNameOf`) was inlined and minimal; send, BPF
  filtering, promiscuous mode, interface lookup by name/index and the typed
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
mode, interface lookup by name/index, the `EtherType`/`pkt`/`bpf` enums and the typed
`Frame` / `LinkAddr` / `EthHeader` decode are new. Wire layout clean-room from
`packet(7)`, `<linux/if_packet.h>`, `<linux/filter.h>` and the IEEE 802.3 / ARP
formats. Linux-only by design; kernel struct sizes are asserted in tests. `tools/go_bench/go.mod` and `go.sum` come from `go get github.com/gopacket/gopacket@v1.7.5 golang.org/x/net@v0.55.0` and `go mod tidy` (pinned, BSD-3); `tools/rust_bench/Cargo.lock` comes from `cargo build --release` on `tools/rust_bench/Cargo.toml` (`pcap-file` `=2.0.0`, MIT, crates.io checksum `1fc1f139…25d1b2` equal to the reviewed `.crate`; build scripts of its dependencies only probe `rustc`), a bench-only tool; `src/testdata/link_oracle.zig` and `vlan_live.zig` are `tcpdump -y DLT -r` verdicts over the synthetic corpus and `tcpdump -i lo -dd` programs written by `tools/gen_link_oracle.py`; `src/testdata/run_diff.zig` is libpcap's interpreter output over synthetic random programs written by `tools/gen_run_diff.py`. The filter language, `pcap` and `pcapng` were built black-box against `tcpdump` 4.99.6 / libpcap 1.10.6 (no libpcap source read); committed data: `src/filter.zig`'s 30-frame corpus and expected verdicts are `tcpdump -r` output over frames written by `tools/gen_filter_oracle.py` (first 20 frames from the earlier 2026-10-04 corpus), and `src/pcapng.zig`'s fixtures are files Wireshark's `editcap` converted plus bytes encoded by `tools/gen_pcapng_fixtures.py`; all frame contents are synthetic, ours (MIT).

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
const frame = try cap.recv(&buf); // Frame{ bytes, wire_len, ifindex, src_hwaddr, ethertype, pkttype, vlan_tci, timestamp_ns }
if (rawsock.EthHeader.parse(frame.bytes)) |eth| _ = .{ eth.dst, eth.src, eth.ethertype };

// Inject — a SOCK_DGRAM (cooked) socket; the kernel builds the Ethernet header.
const idx = try rawsock.ifaceByName("eth0");
var inj = try rawsock.Socket.openInject(idx);
defer inj.close();
try inj.send(idx, dst_mac, rawsock.eth_p.ip, payload); // header prepended by the kernel
// or, on a SOCK_RAW socket, transmit a complete frame yourself:
// try cap.sendRaw(idx, full_ethernet_frame);

// Interface helpers (SIOCGIFINDEX / SIOCGIFNAME / SIOCGIFHWADDR /
// SIOCGIFADDR / SIOCGIFNETMASK).
const mac = try rawsock.hwaddr(inj.fd, idx);        // [6]u8
var namebuf: [16]u8 = undefined;
const name = try rawsock.ifaceName(inj.fd, idx, &namebuf); // "eth0"
const addr = try rawsock.ipv4Addr(inj.fd, idx);     // [4]u8, e.g. own subnet for an ARP sweep
const mask = try rawsock.ipv4Netmask(inj.fd, idx);  // [4]u8
```

### Pure helpers (no socket, no privileges)

- `EthHeader.parse` / `.write` — Ethernet II header codec.
- `parseHwaddr` / `formatHwaddr` — MAC ⇄ `"aa:bb:cc:dd:ee:ff"`.
- `LinkAddr.fromSockaddr` — the typed `sockaddr_ll` decode used by `recv`.
- `bpf` + `etherTypeFilter` — build classic-BPF programs (the wire-format
  `BpfInsn` is 8 bytes, asserted).
- `arp.buildRequest` / `arp.parseReply` — minimal ARP-over-Ethernet codec;
  addresses surface as `netaddr.Ip`.
- `filter.compile(gpa, "tcp dst port 22 and not ip src net 10.0.0.0/8")` — a
  tcpdump-style expression → classic BPF for `Options.filter`, same meaning as
  libpcap's (checked against `tcpdump -r` on a frame corpus); `filter.run(prog,
  frame)` executes any classic-BPF program in userspace, with the kernel's
  semantics (`and`/`or` share one precedence level, left to right, as in pcap-filter(7)). Besides protocol/port/net/host primitives it takes IPv6 `host`/`net`, bare `host`/`net` (IP, ARP, RARP), `portrange`, `less`/`greater`/`len`, `broadcast`/`multicast` and offset expressions (`ip[6:2] & 0x1fff = 0`, `tcp[13] & 2 != 0`); the language and what is refused is in `src/filter.zig`'s header.
- `pcap.writeHeader` / `pcap.writeRecord` / `pcap.Reader` — classic `.pcap`
  savefiles (µs or ns), byte-compatible with `tcpdump -w`/`-r`.
- `pcapng.writeHeader` / `pcapng.writeRecord` / `pcapng.Reader` — pcapng savefiles (Wireshark's default): the reader takes either byte order, several sections and interfaces, `if_tsresol`/`if_tsoffset`, and skips blocks it has no use for.

`rawsock.ring.Ring` — an opt-in `TPACKET_V3` receive ring (`init`, `next`, `release`, `stats`, `deinit`); `filter.compileOpts` takes `Options{ .vlan_ancillary, .link }` (`link`: `ethernet`, `linux_sll`, `linux_sll2`, `raw`, `bsd_null`, `bsd_loop`; `Link.dlt` gives the savefile link type); `filter.runLive` evaluates a live-form program in userspace from `Frame.vlan_tci`.

Performance (`zig build bench-rawsock`, ReleaseFast, 21 rounds 2026-11-04, spreads 8–45 % on a noisy shared host, ours/libpcap with libpcap built from source, lower is faster): filter interpreter 0.93× (instructions 0.94×, cycles 0.91× by `perf stat`), filter compile 0.98×. Against the distro's libpcap.so of the same source the interpreter is 1.14× (fewer instructions, lower IPC, unprofiled): the P2 claim rests on the source build, see SPEC. The savefile rows (0.15× / 0.55× / 0.21×) compare a slice parser with libpcap's stdio path and are not a speed claim; against the Rust `pcap-file` crate ours is within the noise of equal. `filter.validate` is the kernel's attach-time check list (agrees with the kernel on 210 programs); `filter.run` follows the kernel except for negative/ancillary loads (see `usesAncillary`, `runLive`, `runLiveMeta`).

### Capture extras

```zig
const prog = try rawsock.filter.compile(gpa, "udp port 67 or udp port 68");
defer gpa.free(prog);
const sock = try rawsock.Socket.open(rawsock.eth_p.all, .{ .filter = prog, .timestamps = true });
const f = try sock.recv(&buf);            // f.timestamp_ns = kernel receive time
try rawsock.pcap.writeRecord(&w, .nano, f.timestamp_ns.?, @intCast(f.wire_len), f.bytes);
try sock.joinFanout(7, .hash, .{});       // spread one capture over N sockets
```

## Testing

Root-free tests (the pure helpers, `sockaddr_ll` decode, BPF encoding, struct
ABI sizes) always run:

```
zig build test-rawsock                          # needs CAP_NET_RAW for the socket tests
zig build test-rawsock -Doptimize=ReleaseFast
```

The socket tests (open/filter/promisc, an inject→capture loopback
round-trip on `lo`, `stats`, …) need `CAP_NET_RAW`; without it they `SkipZigTest`. Run them
under an unprivileged network namespace, where root has the capability:

```
unshare -rn zig build test-rawsock              # full socket path, all pass
```

## Deferred (v2)

- `recvmmsg` batching, a TX ring, `TPACKET_V2` (the `TPACKET_V3` receive ring is `rawsock.ring`).
- A filter optimiser, `ip6 protochain` (the kernel refuses libpcap's backward jump; `run` is loop-free), `mpls`/`pppoes` combined with other primitives, `geneve`, 802.11 and foreign PPP savefiles (see SPEC).
- IPv6 Neighbor-Discovery helpers (the ND counterpart to the ARP codec).
- Remains Linux-only — the documented AF_PACKET ceiling (no BSD `/dev/bpf`).
