# modbus

Pure-Zig **Modbus protocol codec + client (master) + server (slave)** for
**Modbus TCP** and **Modbus RTU** framing. Feeds the SCADA/industrial
simulation work: a typed, allocation-free wire codec, a transport-agnostic
master that can drive real devices, and a responder that turns a few caller-
owned arrays into a simulated field device fleet.

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
    ASCII framing is out of scope.
  - **Client:** `Client` speaks through a `Transport` seam (one blocking
    "send request ADU, receive reply ADU" round-trip), so everything is
    offline-testable; `TcpTransport` is an optional real-socket adapter.
  - **Server** (`server.Server`): the slave side, a pure
    request-frame-to-reply-frame responder over a caller-owned point database
    (`server.DataBank`). Four data areas — coils, discrete inputs, holding
    registers, input registers — each with an **explicit base address and
    length**, so a request outside the window is a real `IllegalDataAddress`
    rather than a silent wrap. Answers every function code the client speaks
    plus 0x07 Read Exception Status, 0x08 Diagnostics (return-query-data,
    restart, listen-only, clear-counters and the five serial-line counters)
    and 0x11 Report Slave ID. Spec-correct exception responses
    (`IllegalFunction` / `IllegalDataAddress` / `IllegalDataValue` /
    `ServerDeviceFailure`, function code with the high bit set), including
    the quantity limits — an over-large read is `IllegalDataValue`, not a
    truncated one. Optional `WriteHook` fires after each accepted write.
  - **Unit-id and broadcast semantics are modelled per framing:** an RTU
    broadcast (address 0) applies the write and answers nothing, an RTU frame
    with a bad CRC is silently dropped rather than answered with an
    exception, and on TCP the unit ids 0 and 255 conventionally address the
    directly-connected device (both configurable, plus a gateway
    "answer for anything" mode).
  - Malformed/short/garbage frames never panic on either side — typed errors
    for short frame, bad CRC, transaction id / unit / function mismatch,
    malformed byte counts, and each exception code; on the server side a
    hostile PDU always becomes an exception response or silence.

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

The slave side is a pure function from one frame to one frame — no threads, no
timers, no allocation, and the transport is left as a seam:

```zig
var coils = [_]bool{false} ** 16;
var holding = [_]u16{0} ** 32;

var server = modbus.server.Server.init(.{
    .unit_id = 7,
    .framing = .tcp,             // or .rtu
    .slave_id = "my-device",     // enables FC 0x11
    .exception_status = 0x00,    // enables FC 0x07
}, .{
    .coils = .{ .base = 0, .values = &coils },
    .holding_registers = .{ .base = 100, .values = &holding },
});

var out: [modbus.tcp.max_adu_len]u8 = undefined;
if (try server.handleAdu(request_bytes, &out)) |reply| {
    // send `reply`; `null` means "stay silent" (broadcast, bad CRC, not ours)
}
```

## Verify

```
zig build test-modbus           # Debug
zig build test-modbus -Doptimize=ReleaseFast
zig fmt --check modules/modbus
```

73 tests, all offline. Known-answer tests byte-compare every function code
against the worked wire examples in the application-protocol spec (§6.1–6.17)
in *both* directions — the client building each request and the server
producing each response. The CRC-16 is pinned to the canonical
`"123456789" -> 0x4B37` check value plus classic example frames. A scripted
mock transport exercises TCP + RTU round trips, the exception path, quantity
limits, CRC corruption, MBAP mismatches, and a garbage-frame no-panic sweep;
two 20 000-iteration fuzz loops hammer the server with random PDUs and ADUs.

`src/goldens.zig` holds frames **captured from a live pymodbus 3.14.0
session** in three directions: pymodbus's `ModbusTcpClient` driving this
module's `Server` over a real loopback socket (every function code above,
plus the exception cases), this module's `Client` driving pymodbus's
`ModbusTcpServer`, and pymodbus's `FramerRTU` exchanging RTU frames with our
RTU server — which cross-checks its CRC-16 against ours. Replaying the
captured session in order reproduces every reply byte for byte, diagnostic
counters included. The whole capture was also written to a pcap and dissected
with Wireshark 4.6.4's Modbus dissector (via `rawshark`); every field —
transaction id, unit id, length, function code, exception code, register
values, coil bits, the Report Slave ID payload — matched, with no malformed
packets.

## Deferred

Honest list of what this module does **not** do:

- **ASCII framing** (Modbus over Serial Line §2.5.2) — not planned; RTU and
  TCP cover every consumer we have.
- **FC 0x2B/0x0E Read Device Identification** — answered `IllegalFunction`;
  the captured pymodbus session shows exactly that.
- **FC 0x14/0x15 file records, 0x16 mask-write, 0x18 read FIFO** — not
  implemented on either side.
- **Modbus Security / TLS** — transport security is entirely the caller's;
  this module never touches a socket except in the optional `TcpTransport`.
- **Serial timing** — the RTU t1.5/t3.5 inter-character and inter-frame
  silences are the transport's concern. The server delimits frames by what it
  is handed; it does not measure time and owns no clock.
- The **listen-only** mode set by diagnostics sub-function 0x0004 is
  implemented as state, but there is no separate "restart communications
  option" side effect beyond leaving the mode and optionally clearing the
  counters.
- The server has **no built-in TCP accept loop**. `handleAdu` is a pure
  function; running it over `std.Io.net` (or over hundreds of simulated
  units at once) is the caller's job.

Provenance: clean-room from the public Modbus Application Protocol
Specification V1.1b3 and Modbus over Serial Line Specification V1.02
(modbus.org — the protocol is openly published and royalty-free); libmodbus
(LGPL-2.1+) referenced for behavior only, no source consulted or copied.
pymodbus (BSD-3-Clause) was used only as a black-box interop peer for the
captures described above — its master drove this server over a real socket
and its server answered this client; no pymodbus source was consulted or
copied.
