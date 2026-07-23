# fleetsim

Pure-Zig **in-process fleet of simulated industrial devices**. This repository
already speaks seven industrial protocols from the device side — `modbus`,
`dnp3`, `iec104`, `s7comm`, `bacnet`, `enip`, `opcua` — each responder pure,
packet-to-packet, clock-injected and driven in anger by a real third-party
master. `fleetsim` is the thing that **composes** them: one `Fleet` owning N
addressable nodes on one injected clock and one seed, with point-value
behaviour, fault injection, and an optional TCP/UDP binding so a real master can
connect.

- **Platform:** any for the core (no I/O, no clock reads, no threads); the
  optional `tcp.zig` binding is POSIX.
- **Role:** server — it answers masters.
- **Model after:** `netsim` / TigerBeetle-VOPR determinism applied to a SCADA
  device fleet (the ModbusPal / Kepware-simulator problem, done
  deterministically).
- **Concurrency:** single-owner. One thread owns a `Fleet`; there are no locks.
- **Depends on:** the seven responder modules plus `netsim`.

## Scope

- **`Node`** — the one vtable every responder satisfies. `deliver(bytes, out,
  now) -> ?reply` for request/response, `tick(out, now) -> ?frames` for
  unsolicited traffic (DNP3 unsolicited responses, IEC 104 spontaneous ASDUs,
  BACnet COV, OPC UA publish), `nextDeadline(now)` so a 1000-node fleet does not
  poll every node every millisecond, and `control(op, now) -> bool` for restart
  and device-trouble injection. `control` returns **false** when the protocol
  has no word for the fault, and the fleet logs that rather than faking it.
- **`Framing`** — per-protocol frame-boundary rules (MBAP, DNP3 link, IEC 104
  APCI, TPKT, ENIP encapsulation, OPC UA UA-TCP, BACnet BVLC). Used to split a
  TCP read into frames, and to split a responder's multi-frame answer back into
  individual frames so per-frame link faults are meaningful.
- **Adapters** — `ModbusNode`, `Dnp3Node`, `Iec104Node`, `S7Node`,
  `BacnetNode`, `EnipNode`, `OpcuaNode`. **No responder module was modified**;
  the two transport-driven ones (IEC 104, BACnet) get a small shim transport
  instead.
- **`Fleet`** — the deterministic scheduler. `submit` / `submitStream` in,
  `advance(to_ms)`, `outbound()` out. One event queue, total order
  `(time, insertion sequence)`, fixed memory pools, two seeded
  `std.Random.DefaultPrng` streams (link mechanics, signal drivers).
- **Point behaviour** — `Driver` (constant, ramp, sine, seeded random walk,
  step-on-schedule, recorded replay) plus `Sink` (u16 register, boolean
  threshold, IEEE-754 bytes, raw cell). A `Signal` is one driver feeding many
  sinks, so the same instance can animate a Modbus holding register, a DNP3
  analog input and an OPC UA variable at once.
- **Fault injection** — per-node link `delay / jitter / loss / duplication /
  reordering`, plus scheduled node faults: `silent`, `slow`, `trouble`,
  `restart`, `heal`, and the one-shot `drop_next` / `dup_next` / `delay_next`.
  `Fleet.applyNetsimTrace` maps a `netsim`-fuzzed fault schedule straight onto
  the fleet, so that churn-and-recover fuzzer and its shrinker are reused rather
  than rewritten.
- **Transport binding** — `serveTcp` / `serveUdp` in `tcp.zig`, the only file
  that knows what a socket is. The core works with no I/O at all.

## Use

Offline (no sockets anywhere):

```zig
const fleetsim = @import("fleetsim");

var f = try fleetsim.Fleet.init(gpa, .{ .seed = 0xC0FFEE, .max_frame_len = 300 });
defer f.deinit();

var holdings = [_]u16{0} ** 16;
var slave = fleetsim.ModbusNode.init(
    .{ .unit_id = 1, .framing = .tcp },
    .{ .holding_registers = .{ .base = 0, .values = &holdings } },
);
const id = try f.addNode(.{
    .node = slave.node(),
    .link = .{ .delay_ms = 5, .jitter_ms = 3, .loss_permille = 20 },
});

// A sine wave animating holding register 0 every 250 ms.
var reg0 = fleetsim.ScaledRegister{ .cell = &holdings[0], .scale = 1 };
const sinks = [_]fleetsim.Sink{reg0.sink()};
var sig = fleetsim.Signal{
    .driver = .{ .sine = .{ .mean = 500, .amplitude = 400, .period_ms = 5000 } },
    .sinks = &sinks,
    .period_ms = 250,
};
try f.addSignal(&sig);

// The device goes quiet between t=10s and t=15s, then power-cycles.
try f.addFault(.{ .at_ms = 10_000, .node = id, .kind = .{ .silent = .{ .until_ms = 15_000 } } });
try f.addFault(.{ .at_ms = 20_000, .node = id, .kind = .restart });

try f.submit(id, request_frame, now_ms);
_ = try f.advance(now_ms);
for (f.outbound()) |frame| send(f.frameBytes(frame));
```

With a real master on the other end:

```zig
const report = try fleetsim.serveTcp(gpa, io, &f, id, address, .{
    .idle_ms = 200,
    .run_ms = 60_000,
    .max_sessions = 8,
});
```

## Verify

```
zig build test-fleetsim                # Debug
zig build test-fleetsim --release=fast
```

The three live tests print `SKIPPED: …` and pass unless an endpoint is given:

```
FLEETSIM_TEST_LISTEN=127.0.0.1:15020   zig build test-fleetsim   # then point pymodbus at it
FLEETSIM_ENIP_LISTEN=127.0.0.1:15021   zig build test-fleetsim   # then pycomm3
FLEETSIM_BACNET_LISTEN=127.0.0.1:15022 zig build test-fleetsim   # then bacpypes3
```

What was actually run against real third-party masters, the determinism proof,
the measured scale numbers and the deferred list are in [SPEC.md](./SPEC.md).
Provenance: see [/NOTICE](../../NOTICE).
