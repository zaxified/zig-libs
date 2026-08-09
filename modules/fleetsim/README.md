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
  and device-trouble injection. `control` returns **false** only when the
  caller's device model gives the adapter nothing to degrade, and the fleet logs
  that rather than faking it.
- **`Framing`** — per-protocol frame-boundary rules (MBAP, DNP3 link, IEC 104
  APCI, TPKT, ENIP encapsulation, OPC UA UA-TCP, BACnet BVLC). Used to split a
  TCP read into frames, and to split a responder's multi-frame answer back into
  individual frames so per-frame link faults are meaningful.
- **Adapters** — `ModbusNode`, `Dnp3Node`, `Iec104Node`, `S7Node`,
  `BacnetNode`, `EnipNode`, `OpcuaNode`. **No responder module was modified**;
  the two transport-driven ones (IEC 104, BACnet) get a small shim transport
  from `shim.zig` instead. All seven implement `trouble` natively — Modbus
  exception `0x04`, DNP3 `IIN1.6`, IEC 104 `iv` quality, S7 CPU `STOP`, BACnet
  `Reliability`/`Status_Flags`/`Out_Of_Service`, the CIP Identity status word
  plus general status `0x10 Device State Conflict`, and OPC UA
  `BadDeviceFailure` plus `ServerStatus.State = Failed`.
- **`shim.zig`** — `Window` (one input chunk in, one output buffer out, no
  mailbox, no allocation) plus the two `Transport` bindings that IEC 104 and
  BACnet need. Public, because a consumer holding one of those responders wants
  exactly this and neither module can host it — see the file header.
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
- **Model checking** — `Vopr` (`src/vopr.zig`) plugs a `Fleet` into `netsim` as
  an ordinary `Protocol`, so the simulator can **search** for a failure instead
  of replaying a schedule you handed it: `netsim.findFailing` sweeps seeds and
  `netsim.shrinkTrace` returns a **minimised fault trace**, not a seed. Five
  invariants are checked after every event, and the module ships the
  deliberately-broken device that proves they bite. See SPEC.md.
- **Transport binding** — `serveTcp` / `serveUdp` / `serveTcpMulti` in
  `tcp.zig`, the only file that knows what a socket is. `serveTcpMulti` binds
  several listeners and services several peers **concurrently** from one thread
  over a `poll(2)` readiness loop — no per-node thread, no clock read inside the
  core. The core works with no I/O at all.

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

With several masters on several nodes at the same time (one thread, one clock —
this is also the shape to use when a fault schedule matters, because
`serveTcp`'s clock restarts at every accept while `serveTcpMulti`'s does not):

```zig
const bindings = [_]fleetsim.Binding{
    .{ .node = modbus_id, .address = try std.Io.net.IpAddress.parse("127.0.0.1", 15020) },
    .{ .node = iec104_id, .address = try std.Io.net.IpAddress.parse("127.0.0.1", 15021) },
};
const report = try fleetsim.serveTcpMulti(gpa, io, &f, &bindings, .{
    .idle_ms = 100,
    .run_ms = 60_000,
    .max_peers = 8,
});
// report.peak_concurrent is how many masters were connected simultaneously.
```

## Verify

```
zig build test-fleetsim                # Debug
zig build test-fleetsim --release=fast
```

Green in Debug and ReleaseFast (the live tests below skip without an
endpoint). They cover the framing rules and the frame
iterator, every adapter's round-trip plus its restart and its trouble path
(including a real BACnet `ReadProperty` of `Reliability` and a real CIP
`Get_Attributes_All` refused with `0x10`), an OPC UA HEL/ACK round-trip through
a whole `NodeStore`+`Server`, the drivers, the scheduler, three determinism
proofs plus a fourth over a toy node, hostile input, a `std.testing.fuzz` target
over three-adapter dispatch, the 1000-node scale run, the shim's buffer
discipline, the multi-peer binding driven by two in-process clients at once, and
the `netsim` model-checking harness — a bounded seed sweep over the real
`ModbusNode` that must stay clean, plus four planted device defects that
`findFailing` must catch and `shrinkTrace` must reduce to the single duplicated
request that causes them.

The live tests print `SKIPPED: …` and pass unless an endpoint is given.
Each one binds, waits for its master, and schedules a `trouble` fault at
t=15 s so the master watches the device degrade under it:

```
FLEETSIM_TEST_LISTEN=127.0.0.1:15020    zig build test-fleetsim   # pymodbus
FLEETSIM_ENIP_LISTEN=127.0.0.1:15021    zig build test-fleetsim   # pycomm3
FLEETSIM_BACNET_LISTEN=127.0.0.1:15022  zig build test-fleetsim   # bacpypes3 (UDP)
FLEETSIM_DNP3_LISTEN=127.0.0.1:20000    zig build test-fleetsim   # opendnp3 master-demo
FLEETSIM_IEC104_LISTEN=127.0.0.1:15023  zig build test-fleetsim   # c104 (lib60870)
FLEETSIM_S7_LISTEN=127.0.0.1:15024      zig build test-fleetsim   # python-snap7
FLEETSIM_OPCUA_LISTEN=127.0.0.1:15025   zig build test-fleetsim   # asyncua
FLEETSIM_MULTI_LISTEN=127.0.0.1:15026,15027 zig build test-fleetsim  # two masters at once
```

The DNP3 test matches opendnp3's `master-demo` defaults (outstation address 10,
master 1, port 20000) so the oracle needs no patching.

### The one-command route: the disposable-VM lane

Installing a SCADA master on a dev host is the reason these tests sat unrun.
The repo's VM lane removes that constraint entirely — inside a throwaway guest
there is no reason not to install freely, because the host is never touched:

```
scripts/vm/run.sh fleetsim debian
```

That boots the provisioned Debian guest, runs the live Modbus test inside it
with `FLEETSIM_EXPECT_LIVE=1`, and points a **real pymodbus 3.14.0** at the
simulated slave (installed into the image by the provisioning recipe, not by
you). It exits non-zero if the master does not complete its whole script, so
"nobody was listening" cannot read as a pass. ~80 s end to end; the one-off
`scripts/vm/provision.sh debian` before it takes ~2 min.

Only Modbus is wired up so far. Adding the next master is two edits that must
happen together — its pinned spec in `scripts/vm/manifest.sh`'s
`VM_DEBIAN_PIP`, and its test in `run.sh`'s `guest_default_filter` — plus a
guest-side driver script alongside
`scripts/vm/guests/fleetsim-modbus-master.py`.

What that run produced is frozen in `src/master_goldens.zig` and replays
offline on every build, so the ordinary `zig build test-fleetsim` carries the
third-party evidence even with no VM in sight.

### Installing the masters on a host, instead

The versions below are the ones the transcripts in [SPEC.md](./SPEC.md) were
recorded against; pin them, because a master's own defaults are part of the
oracle. Six of the seven are pip-only — no Debian package exists for them, and
`python3-pymodbus` ships 3.8.6, far behind the 3.14.0 that was used here.

```
pip install --user --break-system-packages \
    pymodbus==3.14.0 pycomm3==1.2.16 bacpypes3==0.0.106 \
    python-snap7==3.1.0 asyncua==2.0.1 c104==2.2.1
```

`c104` is the only one carrying a compiled extension (it wraps lib60870-C).
Its published wheels stop at CPython 3.13, so on a newer interpreter pip falls
back to a source build and needs `build-essential` and `cmake`.

DNP3 has no usable Python master: `pydnp3` on PyPI is a 2018 work-in-progress
and is *not* what the transcript was taken against. Build the real thing:

```
git clone --branch release https://github.com/dnp3/opendnp3.git
cmake -S opendnp3 -B opendnp3/build -DDNP3_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release
cmake --build opendnp3/build -j"$(nproc)"
```

then run its `master-demo` example unpatched.

What was actually run against real third-party masters (all seven protocols,
with the transcript of what each master did), the determinism proof, the
measured scale numbers and the deferred list are in [SPEC.md](./SPEC.md).
Provenance: original work of the zig-libs authors (MIT), composed over
[`netsim`](../netsim) — which carries its own entry for the TigerBeetle VOPR
methodology reference. The device-behavior envelope follows what SCADA device
simulators (ModbusPal, Kepware's simulation driver) expose in their public
documentation — observable behavior only, no source consulted. Recorded in the
root [`NOTICE`](../../NOTICE).
