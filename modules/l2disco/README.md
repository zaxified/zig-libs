# l2disco

A pure-Zig **Layer-2 / neighbor-discovery codec** — parse *and* build the
wire formats a host or switch uses to announce and learn about its
neighbours. It is a codec only: it works on frame-payload byte buffers and
never opens a socket (raw capture via AF_PACKET / BPF is a separate module).

Status: **gap** — no spec-complete pure-Zig LLDP (or combined L2-discovery)
library exists; this fills it. Feeds network-discovery tooling that
previously only faked these frames.

## What's in it

| Sub | Protocol | Coverage |
|-----|----------|----------|
| `lldp` | IEEE 802.1AB LLDPDU | 7-bit-type / 9-bit-length TLV stream; mandatory Chassis ID (MAC / network-address / interface-name subtypes), Port ID, TTL, End-of-LLDPDU; optional Port Description, System Name/Description, System Capabilities (+ enabled), Management Address; org-specific (type 127) with IEEE 802.1 (port VLAN, VLAN name) + 802.3 (MAC/PHY, max frame size) decoding; unknown TLVs pass through raw. Typed `Lldpdu` model + iterators + `Builder`. |
| `cdp` | Cisco Discovery Protocol | version/holdtime/checksum header + type/length TLVs (Device ID, Addresses, Port ID, Capabilities, Software Version, Platform, VTP domain, Native VLAN, Duplex); RFC 1071 checksum compute/verify; unknown TLV passthrough. Typed `Frame` + `Builder`. |
| `arp` | RFC 826 | generic `Packet` (variable hardware/protocol address lengths) plus the typed Ethernet+IPv4 `EthIpv4` request/reply/gratuitous/probe case. |
| `dhcp` | RFC 2131 + options RFC 2132 | fixed header + magic cookie + options TLV list (message type, requested IP, server id, lease time, subnet mask, routers, DNS servers, domain/host name, parameter request list, client id, End/Pad); option-overload surfaced; unknown option passthrough. Typed `Message` + `Builder`. |
| `mac` | — | small 48-bit EUI-48 helper: `aa:bb:cc:dd:ee:ff` parse/format + broadcast/multicast/locally-administered predicates. |

Everything is bounds-checked: malformed or truncated input is a typed
error, never a panic. Parsing allocates nothing (iterators slice the input
buffer); builders write into a caller-provided buffer.

**`cdp.Frame.parse` verifies the RFC 1071 checksum by default.** That is correct — this codec
should catch corrupted or spoofed traffic — but a lot of real gear, and virtually every hand-rolled
test injector, emits a zero checksum. If parsing is failing with `ParseError.BadChecksum` on a
frame you built by hand or captured from an odd device, pass `.{ .verify_checksum = false }`; the
default itself is not going to change.

## Tolerant parsing (opt-in)

Both `lldp` and `cdp` are strict by default: a malformed TLV anywhere in the input discards the
whole parse. That is the right default — a codec that silently drops bytes it disagrees with is
not trustworthy — but for on-the-wire neighbour discovery ("which switch and port am I wired to?"),
losing an entire neighbour because one non-identifying TLV from a cheap device is malformed is a
real loss too. Two options exist for that, both opt-in, both defaulting to the strict behaviour:

- **`lldp.ParseOptions.tolerant_optionals`** (default `false`): when `true`, a malformed *optional*
  TLV (System Capabilities of the wrong length, an internally-inconsistent Management Address) is
  skipped instead of aborting the parse; `Lldpdu.skipped_optionals` counts how many were dropped.
  The mandatory Chassis ID / Port ID / TTL trio — and its ordering — is never relaxed by this option
  and always still fails the parse if malformed, in both modes.
- **`cdp.ParseOptions.tolerant_trailing_tlv`** (default `false`): when `true`, a truncated or
  malformed *trailing* TLV — the shape real 802.3 zero-padding to the 60-byte Ethernet minimum
  produces once the TLV walk reaches it — stops the walk and returns what parsed instead of failing
  the whole frame; `Frame.trailing_tlv_truncated` reports whether this happened.

## Depends on

- `netaddr` — `Ip` parse/format for LLDP/CDP management, ARP and DHCP
  addresses.

## Test

```
zig build test-l2disco
```

Each protocol has golden-byte KATs (transcribed from the specs) asserting
the parsed typed model and round-tripping build → parse, plus
malformed-input and 1000-iteration garbage-sweep tests.

Provenance: clean-room from the specifications: IEEE 802.1AB (LLDP) and the
IEEE 802.1 / 802.3 organizationally-specific TLV definitions, the publicly
documented Cisco CDP frame format (a Cisco-proprietary but publicly
described / reverse-engineered format — behaviour reference only), RFC 826
(ARP), and RFC 2131 / RFC 2132 (DHCP). Test data is a separate matter and is
answered in [`NOTICE`](NOTICE) beside this file: the module vendors real
tcpdump `tests/*.pcap` capture frames (BSD-3-Clause), which carry required
attribution, and it is listed in the root `NOTICE` §1. No third-party dissector source
(Wireshark, lldpd, net-snmp, tcpdump) was consulted or copied. License: MIT.
