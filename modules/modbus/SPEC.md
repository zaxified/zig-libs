# modbus — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Three allocation-free layers, all offline-testable: `pdu` (transport-independent request encode /
response parse — big-endian 16-bit registers, coil bits packed LSB-first; spec quantity limits
2000/125 read bits/registers, 1968/123 write, 125/121 for FC 17 are typed errors, not truncations);
`tcp` framing (MBAP header: transaction id, protocol id 0, length, unit id); `rtu` framing (address
+ PDU + CRC-16, poly 0xA001 reflected, low byte first on the wire); `Client` — a master driving a
caller-provided `Transport` seam (one blocking send-ADU/receive-ADU round-trip), tracking the TCP
transaction id. `TcpTransport` is an optional `std.Io.net` adapter, the only network-touching code.
Modeled after the Modbus Application Protocol V1.1b3 + Modbus over Serial Line V1.02 (open,
royalty-free specs); libmodbus is a behavior reference only — see NOTICE. Concurrency: single-owner
— the `Client` owns the transaction-id counter, no internal sync. Error policy: malformed/short/
corrupt replies never panic — every decode path returns a typed error (short frame, bad CRC,
transaction-id/unit/function mismatch, malformed byte counts, address+quantity overflow); exception
responses (`function | 0x80`, codes 1-11) map to a typed, non-exhaustive error set.

## Threat model / out of scope
Modbus is an unauthenticated, unencrypted field protocol by design — no on-wire security to
defend; transport security (TLS tunnel / Modbus Security) is entirely the caller's. The codec's job
is robustness: hostile/garbage frames from a misbehaving device or MITM resolve to typed errors,
never panics or out-of-bounds reads. Out of scope: ASCII framing; broadcast (unit 0, no reply); the
server (slave) side — though `pdu` is deliberately reusable for a future server.

## Verification
32 offline tests. Known-answer tests byte-compare every function code against the worked wire
examples in the application spec §6.1-6.17; CRC-16 pinned to the canonical `"123456789" →
0x4B37` check value plus classic example frames; bit packing checked LSB-first. A scripted mock
transport exercises TCP + RTU round-trips (incl. echoed-reply writes and FC 17), the exception
path, quantity limits, CRC corruption, MBAP/RTU field mismatches, buffer-too-small, and a
garbage-frame no-panic sweep. Run: `zig build test-modbus`.

## Backlog / deferred
Server (slave) side is out of scope by design but the `pdu` codec is reusable for it. ASCII framing
and broadcast (unit 0) not planned. No open gap beyond the noted batch-scheduling entry
(shipped alongside `whois`/`uci`/`rdap`/`mqtt`/`snmp`/`coap` in the same extraction wave).

## Status
`gap · any (codec+client pure; TcpTransport uses std.Io.net) · client(master)+codec · single-owner`
+ deps: none (std only) — canonical source is `pub const meta` in src/root.zig.
