# SPEC — `l2disco`

**Purpose** — A Layer-2 / neighbor-discovery codec: parse *and* build the wire formats a host or
switch uses to announce and learn about its neighbours — LLDP, CDP, ARP, DHCP. Fills a gap (no
spec-complete pure-Zig LLDP / combined L2-discovery library exists) and feeds the axp
network-discovery work, which previously only faked these frames. Codec only: it operates on
frame-payload byte buffers and never opens a socket — capture (AF_PACKET / BPF) is a separate concern.

**Model after / Seed** — clean-room from the specifications: IEEE 802.1AB (LLDP) + the IEEE
802.1/802.3 organizationally-specific TLV definitions, RFC 826 (ARP), RFC 2131/2132 (DHCP), and the
publicly documented (reverse-engineered) Cisco CDP frame format used as a behavior reference only.
Greenfield — no packet-dissector source (Wireshark / lldpd / net-snmp / tcpdump) consulted or copied
(NOTICE records the clean-room provenance).

**Design & invariants**
- **Five submodules, one MAC helper:** `lldp` (802.1AB LLDPDU 7-bit-type/9-bit-length TLV stream:
  mandatory Chassis ID / Port ID / TTL / End, optional descriptions/capabilities/management address,
  org-specific type-127 with 802.1 + 802.3 decoding), `cdp` (version/holdtime/checksum header +
  type/length TLVs, RFC 1071 checksum compute/verify), `arp` (RFC 826 generic `Packet` + typed
  Ethernet+IPv4 `EthIpv4` request/reply/gratuitous/probe), `dhcp` (RFC 2131 header + magic cookie +
  RFC 2132 options), `mac` (48-bit EUI-48 parse/format + broadcast/multicast/local predicates).
- **Allocation-free hot path:** parse iterators slice the input buffer (values borrow it); builders
  write into a caller-provided buffer. No sockets, no syscalls.
- **Forward-compatible parsing:** unknown optional TLVs / options pass through raw and never fail the
  parse; every length is bounds-checked against the buffer.
- **Concurrency:** reentrant — no shared state; safe if instances are not shared.
- **Error policy:** malformed or truncated input is a typed error, never a panic.

**Threat model / out of scope** — A codec over untrusted, unauthenticated broadcast/multicast frames:
the defense is bounds-checking (every advertised length is validated against the buffer before it is
read) so hostile input yields a typed error, not a panic or out-of-bounds read. It does **not**
authenticate or validate the *semantics* of a frame — LLDP/CDP/ARP/DHCP are themselves unauthenticated
protocols, so a parsed neighbour/lease is a claim, not a verified fact (ARP-spoofing / rogue-DHCP
detection is the caller's policy). Out of scope: packet capture/injection (AF_PACKET, BPF), the
transmit scheduling of LLDP/CDP, DHCP state machines, and the checksum-secured integrity of any
protocol beyond the CDP checksum it computes.

**Verification** — Each protocol has golden-byte KATs transcribed from the specs asserting the parsed
typed model and round-tripping build → parse, plus malformed/truncated-input negatives and a
1000-iteration garbage-sweep (never panics). `zig build test-l2disco`.

**Status** — `gap · any · codec · reentrant` · deps: `netaddr`.
