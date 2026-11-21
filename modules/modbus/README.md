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
    0x16 Mask Write Register, 0x17 Read/Write Multiple Registers,
    0x2B/0x0E Read Device Identification (`device_id`). Spec quantity limits (2000 bits /
    125 registers read, 1968 bits / 123 registers write, 125/121 for FC 17)
    are typed errors; exception responses (function | 0x80, codes 0x01–0x0B) map
    to a typed error set (named codes 0x01–0x08, 0x0A, 0x0B). Registers big-endian; coil bits LSB-first.
  - **Framing:** `tcp` (MBAP: transaction id, protocol id 0, length, unit)
    and `rtu` (address + PDU + CRC-16, poly 0xA001 reflected, low byte first).
    `RtuStream` reassembles RTU frames from a byte stream without t3.5
    silences (RTU over TCP): frame boundary by function code + byte count,
    confirmed by the CRC, bounded buffer, resync on garbage. ASCII framing is
    out of scope.
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
    restart, listen-only on RTU framing only (over TCP it is `IllegalFunction`: a single frame would mute the server for every master), clear-counters and the five serial-line counters)
    0x11 Report Slave ID and 0x16 Mask Write Register (`Config.mask_write_register`,
    on by default) and 0x2B/0x0E Read Device Identification (basic, regular,
    extended, individual; `Config.device_objects`, off while the table is empty). Spec-correct exception responses
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
var coils: [16]bool = @splat(false);
var holding: [32]u16 = @splat(0);

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

All tests run offline. Known-answer tests byte-compare every function code
against the worked wire examples in the application-protocol spec (§6.1–6.17)
in *both* directions — the client building each request and the server
producing each response. The CRC-16 is pinned to the canonical
`"123456789" -> 0x4B37` check value plus classic example frames. A scripted
mock transport exercises TCP + RTU round trips, the exception path, quantity
limits, CRC corruption, MBAP mismatches, and a garbage-frame no-panic sweep;
fuzz harnesses (random PDUs/ADUs, plus a deterministic `MODBUS_FUZZ` driver) hammer the server and the ADU decoder.

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

## Not provided

ASCII framing, TLS / Modbus Security and UDP variants, serial t1.5/t3.5 timing and a built-in TCP accept loop are left out by design, and FC 0x14/0x15 file records and FC 0x18 read FIFO are not implemented on either side; see SPEC *What is deliberately not done*.

Provenance: clean-room from the public Modbus Application Protocol
Specification V1.1b3 and Modbus over Serial Line Specification V1.02
(modbus.org — the protocol is openly published and royalty-free); libmodbus
(LGPL-2.1+) is cited as a behavior design reference only, no source consulted
or copied. pymodbus (BSD-3-Clause) was used only as a black-box interop peer for
the captures described above — its master drove this server over a real socket
and its server answered this client; no pymodbus source was consulted or
copied.