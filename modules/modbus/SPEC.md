# modbus — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Four allocation-free layers, all offline-testable. `pdu` — transport-independent request encode /
response parse (big-endian 16-bit registers, coil bits packed LSB-first; spec quantity limits
2000/125 read bits/registers, 1968/123 write, 125/121 for FC 17 are typed errors, not truncations).
`tcp` framing (MBAP header: transaction id, protocol id 0, length, unit id). `rtu` framing (address
+ PDU + CRC-16, poly 0xA001 reflected, low byte first on the wire). `Client` — a master driving a
caller-provided `Transport` seam (one blocking send-ADU/receive-ADU round-trip), tracking the TCP
transaction id. `server.Server` — the slave: `handleAdu(request, out) -> ?[]u8` and
`handlePdu(request, out) -> []u8`, both pure functions over caller-owned storage, no threads, no
timers, no allocation; `null` means "stay silent". Its `DataBank` holds four windows (coils,
discrete inputs, holding registers, input registers), each an explicit `{ base, values }` pair, so
an out-of-window request produces `IllegalDataAddress` and can never wrap into a neighbour's data.
`TcpTransport` is an optional `std.Io.net` adapter, the only network-touching code.
Modeled after the Modbus Application Protocol V1.1b3 + Modbus over Serial Line V1.02 (open,
royalty-free specs); libmodbus is a behavior reference only, pymodbus a black-box interop peer only
— see NOTICE. Concurrency: single-owner — the `Client` owns the transaction-id counter, the
`Server` owns its data bank and diagnostic counters, no internal sync. Error policy: malformed/
short/corrupt frames never panic — the client returns typed errors (short frame, bad CRC,
transaction-id/unit/function mismatch, malformed byte counts, address+quantity overflow) and the
server returns a spec-correct exception response (`function | 0x80` + code) or silence. The only
error `handlePdu`/`handleAdu` can return is `BufferTooSmall`, which is a local programming mistake:
everything a peer can get wrong is answered on the wire.

## Framing-specific behaviour the server models
RTU address 0 is a **broadcast**: the write is applied and nothing is sent back (Serial Line
§2.4.1). An RTU frame whose CRC fails is **silently discarded**, never answered with an exception —
answering would let a corrupted address field pull two slaves onto the bus at once (§2.5.1.1). A
frame addressed to another slave is ignored but still counts toward the bus-message counter. On
TCP the MBAP unit ids 0 and 255 conventionally mean "the directly connected device"; both are
accepted by default and both are configurable, as is a gateway mode that answers for any unit.
Diagnostics sub-function 0x0004 (force listen-only) is honoured: the request that enters the mode
gets no response, and nothing is answered afterwards until sub-function 0x0001 restarts
communications.

## Threat model / out of scope
Modbus is an unauthenticated, unencrypted field protocol by design — no on-wire security to
defend; transport security (TLS tunnel / Modbus Security) is entirely the caller's. The codec's job
is robustness: hostile/garbage frames from a misbehaving device, a hostile master, or a MITM
resolve to typed errors, exception responses, or silence — never panics or out-of-bounds accesses.
Specifically covered: a byte count that contradicts the quantity, a byte count that contradicts the
actual PDU length, an MBAP length field that disagrees with the frame, a quantity past the spec
limit, an address span that overflows the 16-bit space, a write value that is neither 0xFF00 nor
0x0000, an empty PDU, and every unassigned function code. Out of scope: ASCII framing; FC 0x2B MEI;
file-record, mask-write and FIFO function codes; serial line timing (t1.5/t3.5).

## Verification
All tests run offline. Known-answer tests byte-compare every function code against the worked wire
examples in the application spec §6.1–6.17, now in both directions: the client building each
request and the server producing each response, including the FC 17 write-before-read ordering
made observable by reading exactly the range being written. CRC-16 pinned to the canonical
`"123456789" → 0x4B37` check value plus classic example frames; bit packing checked LSB-first. A
scripted mock transport exercises TCP + RTU round trips (incl. echoed-reply writes and FC 17), the
exception path, quantity limits, CRC corruption, MBAP/RTU field mismatches, buffer-too-small, and a
garbage-frame no-panic sweep. Two 20 000-iteration fuzz loops drive the server: one with fully
random bytes, one with a valid function code and random everything else, both asserting that every
reply is either an echo of the function code or that code with the high bit set.

**Interop (2026-07-23).** `src/goldens.zig` replays frames captured from a live pymodbus 3.14.0
session, in three directions:

1. *pymodbus master → this server.* A real `ModbusTcpClient` on a real loopback TCP socket, in
   front of a proxy that split the stream into MBAP frames and handed each to `server.Server`.
   FC 01/02/03/04/05/06/0F/10/17 plus FC 07, FC 08 sub 0, FC 11, and four exception cases. The
   values pymodbus reported for each reply are asserted separately from the bytes.
2. *This client → pymodbus server.* Our `Client`'s request bytes and pymodbus's `ModbusTcpServer`'s
   reply bytes, which cross-checks the master-side parser against a third-party encoder.
3. *pymodbus `FramerRTU` ↔ this RTU server.* pymodbus built the request frames with its own CRC-16
   implementation and validated the CRC on every reply — an independent check of ours.

Replaying session 1 **in order** reproduces every reply byte for byte, including the FC 08
bus-message counter, which only comes out right if the whole session's state evolved identically.
The capture also caught a case a hand-written golden would have got wrong: pymodbus's
`write_coils(8, 10 values)` runs past a 16-coil window and is correctly answered
`IllegalDataAddress`.

**Independent dissection.** The captured session was written to a pcap (Ethernet/IPv4/TCP framing
so the dissector sees port 502 and gets request/response direction right) and dissected with
Wireshark 4.6.4's Modbus dissector via `rawshark`. All 37 packets dissected cleanly with zero
malformed or expert-error indications, and every field matched our decoder: transaction ids
(1–15 and 200–203), unit ids, MBAP lengths, function codes, exception codes 1/2/2/3 in exactly the
expected places, register values (0x1000–0x1003, 0x2004/6/8, 0xBEEF, 0xAAAA/0x5555), coil bits, the
FC 07 status byte 0x5A, and the FC 11 Report Slave ID payload.

Run: `zig build test-modbus` (and `-Doptimize=ReleaseFast`).

## Backlog / deferred
ASCII framing — not planned. FC 0x2B/0x0E Read Device Identification, FC 0x14/0x15 file records,
FC 0x16 mask write, FC 0x18 read FIFO — not implemented (0x2B is answered `IllegalFunction`, as the
captured pymodbus exchange shows). Serial-line t1.5/t3.5 timing is the transport's concern. No
built-in TCP accept loop: `handleAdu` is a pure function and running it over a socket (or over a
simulated fleet) is the caller's job.

## Status
`gap · any (codec+client+server pure; TcpTransport uses std.Io.net) · client(master)+server(slave)+codec · single-owner`
+ deps: none (std only) — canonical source is `pub const meta` in src/root.zig.
