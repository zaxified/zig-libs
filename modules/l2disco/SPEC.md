# l2disco — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Five submodules, one MAC helper:** `lldp` (802.1AB LLDPDU 7-bit-type/9-bit-length TLV stream:
  mandatory Chassis ID / Port ID / TTL / End, optional descriptions/capabilities/management
  address, org-specific type-127 with 802.1 + 802.3 decoding), `cdp` (version/holdtime/checksum
  header + type/length TLVs, RFC 1071 checksum compute/verify), `arp` (RFC 826 generic `Packet` +
  typed Ethernet+IPv4 `EthIpv4` request/reply/gratuitous/probe), `dhcp` (RFC 2131 header + magic
  cookie + RFC 2132 options), `mac` (48-bit EUI-48 parse/format + broadcast/multicast/local
  predicates). Modeled after IEEE 802.1AB, Cisco CDP (reverse-engineered reference), RFC 826, RFC
  2131/2132 — see NOTICE for clean-room provenance.
- **Allocation-free hot path:** parse iterators slice the input buffer (values borrow it); builders
  write into a caller-provided buffer. No sockets, no syscalls — codec only.
- **Forward-compatible parsing:** unknown optional TLVs/options pass through raw and never fail the
  parse; every length is bounds-checked against the buffer.
- **Concurrency:** reentrant — no shared state; safe if instances are not shared.
- **Error policy:** malformed or truncated input is a typed error, never a panic.

## Threat model / out of scope

A codec over untrusted, unauthenticated broadcast/multicast frames: the defense is
bounds-checking (every advertised length is validated against the buffer before it is read) so
hostile input yields a typed error, not a panic or out-of-bounds read. It does **not** authenticate
or validate the *semantics* of a frame — LLDP/CDP/ARP/DHCP are themselves unauthenticated
protocols, so a parsed neighbour/lease is a claim, not a verified fact (ARP-spoofing / rogue-DHCP
detection is the caller's policy). Out of scope: packet capture/injection (AF_PACKET, BPF), the
transmit scheduling of LLDP/CDP, DHCP state machines, and the checksum-secured integrity of any
protocol beyond the CDP checksum it computes.

## Verification

Each protocol has golden-byte KATs transcribed from the specs asserting the parsed typed model and
round-tripping build → parse, plus malformed/truncated-input negatives and a 1000-iteration
garbage-sweep (never panics). Run: `zig build test-l2disco`.

## Backlog / deferred

None recorded — no deferred-gap note beyond the general Linux-only-members-accepted
scope note (raw-syscall nature, not a functional gap), and the module README has no Deferred
section.

## Status

`gap · any · codec · reentrant` + deps: `netaddr` — canonical source is `pub const meta` in
src/root.zig.
