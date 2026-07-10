# modbus

Pure-Zig **Modbus protocol codec + client (master)** for **Modbus TCP** and
**Modbus RTU** framing. Feeds the SCADA/industrial simulation work: a typed,
allocation-free wire codec plus a transport-agnostic master that can drive
real devices or simulated fleets.

- No mature pure-Zig Modbus library exists.
- **Platform:** any (the codec and client are pure computation; only the
  optional `TcpTransport` demo adapter touches `std.Io.net`).
- **Model after:** Modbus Application Protocol V1.1b3 / libmodbus (behavior).
- **Scope:**
  - **PDU codec** (`pdu`): request build + response parse for function codes
    0x01 Read Coils, 0x02 Read Discrete Inputs, 0x03 Read Holding Registers,
    0x04 Read Input Registers, 0x05 Write Single Coil, 0x06 Write Single
    Register, 0x0F Write Multiple Coils, 0x10 Write Multiple Registers,
    0x17 Read/Write Multiple Registers. Spec quantity limits (2000 bits /
    125 registers read, 1968 bits / 123 registers write, 125/121 for FC 17)
    are typed errors; exception responses (function | 0x80, codes 1–11) map
    to a typed error set. Registers big-endian; coil bits LSB-first.
  - **Framing:** `tcp` (MBAP: transaction id, protocol id 0, length, unit)
    and `rtu` (address + PDU + CRC-16, poly 0xA001 reflected, low byte first).
    ASCII framing is out of scope. Broadcast and server (slave) side are out
    of scope for now — the codec is reusable for a future server.
  - **Client:** `Client` speaks through a `Transport` seam (one blocking
    "send request ADU, receive reply ADU" round-trip), so everything is
    offline-testable; `TcpTransport` is an optional real-socket adapter.
  - Malformed/short/garbage replies never panic — typed errors for short
    frame, bad CRC, transaction id / unit / function mismatch, malformed
    byte counts, and each exception code.

```zig
const modbus = @import("modbus");

var tt = try modbus.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();
var client = modbus.Client.init(.tcp, tt.transport()); // .rtu for serial

var regs: [3]u16 = undefined;
try client.readHoldingRegisters(0x11, 0x006B, &regs); // FC 03
try client.writeSingleRegister(0x11, 0x0001, 0x0003); // FC 06
var coils: [19]bool = undefined;
try client.readCoils(0x11, 0x0013, &coils); // FC 01
```

Tests are fully offline: known-answer tests byte-compare every function code
against the worked wire examples in the application-protocol spec (sections
6.1–6.17), the CRC-16 is pinned to the canonical `"123456789" -> 0x4B37`
check value plus classic example frames, and a scripted mock transport
exercises TCP + RTU round trips, the exception path, quantity limits, CRC
corruption, MBAP mismatches, and a garbage-frame no-panic sweep.

Provenance: clean-room from the public Modbus Application Protocol
Specification V1.1b3 and Modbus over Serial Line Specification V1.02
(modbus.org — the protocol is openly published and royalty-free); libmodbus
(LGPL-2.1+) referenced for behavior only, no source consulted or copied.
