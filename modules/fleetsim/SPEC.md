# fleetsim — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Four layers, in dependency order.

**`node.zig` — the seam.** `Node` is `{ ctx, vtable, protocol, framing }` with a
four-entry vtable: `deliver(bytes, out, now) -> ?reply` (required), `tick(out,
now) -> ?frames`, `nextDeadline(now) -> ?Time` and `control(op, now) -> bool`
(all optional). The seven responders were already shaped alike — bytes in, bytes
out, injected clock, caller-owned storage — but their signatures differ
(`handleAdu` / `handle` / `feedFrame` / `poll` / `feed`), so this is the
smallest interface that covers all of them. `Framing` carries the per-protocol
length rule; `FrameIterator` walks a buffer of concatenated frames and reports
the unconsumed tail separately from a malformed head, because "a truncated read"
and "the responder emitted garbage" are different bugs and must not be conflated.

**`adapters.zig` — seven translations.** Not one line of any responder module
changed. Three shapes:

1. *Already packet-to-packet* — Modbus, S7, ENIP. The adapter is a signature
   translation plus an error map.
2. *Framed session* — DNP3 (`Session.feedFrame`) and OPC UA (`Connection.feed`
   into a `std.Io.Writer.fixed(out)`). The adapter owns the session buffers.
3. *Transport-driven* — IEC 104 (`Server.poll`) and BACnet (`Device.poll`) pull
   from a `Transport` vtable. Each gets a **shim**: `StreamShim` (one injected
   chunk in, one output buffer out) and `DatagramShim` (one datagram in, every
   `send`/`broadcast` concatenated out). Both modules ship a `LoopTransport`,
   but those are peer-to-peer test rigs with a 16-slot × 1.5 kB mailbox (~24 kB
   per node) — unaffordable at fleet scale.

**Restart** is uniform: each adapter snapshots its responder *by value* at
construction and restores that snapshot on `Control.restart`. This is a genuine
power-cycle for these responders because their state is plain data over
caller-owned storage (the point values persist, which is what retentive memory
does). A master therefore sees DNP3 IIN1.7 set again, an S7 CPU that must
re-negotiate its PDU size, an ENIP session handle back to zero, an OPC UA
channel it must re-`HEL`.

**Trouble** is native where the protocol has a word for it and refused where it
does not. Modbus → exception `0x04 SlaveDeviceFailure` (synthesised by the
adapter, echoing the request's function code and MBAP header, since the
responder itself has no "be broken" switch). DNP3 → `IIN1.6 device_trouble`.
S7 → SZL 0x0424 CPU status `STOP`. IEC 104 → the `iv` quality bit on every point
whose element carries a quality descriptor (§7.2.6.3). BACnet, ENIP and OPC UA →
`control` returns **false**, the fleet records `control_unsupported`, and the
caller can fall back to a transport-level `silent` fault. Their trouble concepts
(BACnet `StatusFlags`/`Reliability`, the CIP Identity status word, an OPC UA
variable `StatusCode`) live in state these adapters do not own; faking them
would teach an operator the wrong lesson.

**`fleet.zig` — the scheduler.** One binary min-heap of events ordered by
`(time, insertion sequence)`; the sequence counter is bumped at push, and pushes
happen in a fixed order, so no two events compare equal and the order is total.
Event kinds: `deliver`, `emit`, `tick`, `signal`, `fault`. Inbound path:
`submit` draws the link faults (loss / duplication / delay / jitter / reorder)
**at submission time**, in submission order, and schedules `deliver` events;
`onDeliver` checks the node's behaviour faults (`silent` eats the frame, `slow`
reschedules it exactly once), calls the responder, splits the answer with the
node's framing, draws the outbound link faults per frame and schedules `emit`
events. `emit` copies into the per-advance outbox that `outbound()` exposes.
One outstanding `tick` per node at the earlier of the periodic slot and
`nextDeadline`, which is what keeps 1000 nodes from becoming 1000 timers per
millisecond.

**Memory is fixed at `init`.** A slot pool of `inflight_capacity ×
max_frame_len` bytes with an explicit free list holds every in-flight frame; the
trace is a ring; the outbox is a fixed byte budget. Nothing in the steady state
allocates, so an allocator that hands back different addresses cannot change
behaviour. Exhaustion is a counted, traced `capacity_exhausted` — the frame is
lost, the fleet stays consistent, and the tests assert that every slot returns to
the pool.

**`drivers.zig` — point behaviour.** `Driver` is a tagged union: `constant`,
`ramp` (clamped or wrapping), `sine`, `random_walk` (stateful, drawing two
values — magnitude and sign — so the walk is symmetric rather than correlated
with the low bits), `step` (piecewise-constant schedule) and `replay` (recorded
series, zero-order hold, optionally looping). `Sink` is a one-function vtable, so
a driver never knows which protocol it feeds; `Signal` pairs one driver with many
sinks and a period, and the fleet schedules it as an ordinary event.

**`tcp.zig` — the only socket code.** `serveTcp` binds, accepts up to
`max_sessions` peers one at a time, and pumps: `readVec` (one underlying read) →
`submitStream` → `advance(elapsed)` → write `outbound()`. `poll(2)` bounds both
the read and the accept so the `run_ms` budget means something and the fleet's
timers still fire on a quiet link. `serveUdp` is the same for BACnet, replying to
the last peer seen. Deliberately blocking and single-threaded: the moment this
file grows an event loop, the "no I/O in the core" property stops being visible.

## The determinism argument

Everything that could differ between two runs is either injected or seeded:

- **Time** enters only through `advance(to_ms)`. Nothing in the core reads a
  clock (`tcp.nowMs` is in the binding, not the core).
- **Randomness** comes from exactly two `std.Random.DefaultPrng` streams seeded
  from `Options.seed` — one for link mechanics, one for signal drivers, split so
  that adding a signal cannot perturb packet loss and vice versa. There is no
  `std.crypto.random` anywhere (it does not exist in 0.16, and would destroy
  replay if it did).
- **Order** is the total order `(time, seq)`. Ties are impossible.
- **Memory** is a fixed pool, so allocation addresses cannot leak into
  behaviour.
- **Fault schedules** are data (`Fault` values, or a `netsim` `FaultTrace`), not
  code.

The `fingerprint` is an FNV-1a rolling hash over *every* trace entry ever
produced — time, node, kind, payload length and payload bytes — mixed at record
time, before the ring decides whether to keep the entry. That is what makes
"same seed ⇒ same run" checkable on a 1000-node run whose full trace would never
fit in memory.

Proved, not asserted, by three tests:

1. `determinism: the same seed reproduces a byte-identical emitted stream` runs
   a two-node fleet (Modbus + DNP3) behind a lossy/jittery/duplicating/
   reordering link, animated by a seeded random walk, under a `netsim`-fuzzed
   fault schedule, twice with the same seed. It asserts equal fingerprints,
   equal event counts, equal trace lengths, **and** `expectEqualSlices` over
   every emitted byte. Teeth: it also asserts the run emitted >1000 bytes,
   processed >200 events, and that >20 trace entries record a fault actually
   biting (and the same count both times).
2. `determinism: a different seed diverges` — same harness, different seed;
   fingerprint, an independent output hash, and the byte stream must all differ.
3. `determinism: the trace entries themselves replay identically` — collects
   every `TraceEntry` (time, node, kind, payload length) plus the payload bytes
   for two same-seed runs and compares them field by field, then checks a
   different seed does not coincidentally produce the same trace.
4. `fleet.zig` carries a fourth, smaller version over the toy echo node, so the
   scheduler's determinism is testable without any protocol in the picture.

## What was verified live, against real third-party masters

All three ran on Linux against the module's own `tcp.zig` binding, Debug build.

- **`pymodbus` 3.14.0 → `ModbusNode`** (`FLEETSIM_TEST_LISTEN=127.0.0.1:15061`).
  The master performed 12 × `read_holding_registers(0, count=8)`, a
  `write_register(5, 0xBEEF)` with a read-back, a `write_coil(3, True)` with a
  `read_coils` read-back, a `read_input_registers`, and an out-of-range read
  which came back as an exception as it should. The sine `Signal` was visibly
  animating holding register 0 across the reads
  (`500 → 623 → 735 → 823 → 880 → 900 → 880 → … → 500`, a 5 s period sampled at
  250 ms). Our side printed:
  `live fleetsim Modbus: sessions=1 frames_in=18 frames_out=18 bytes_in=216 bytes_out=371 delivered=18 replied=18 signal_fires=13 hr0=264 hr5=0xBEEF coil3=true`
- **`pycomm3` 1.2.x → `EnipNode`** (`FLEETSIM_ENIP_LISTEN=127.0.0.1:15063`).
  `CIPDriver.list_identity` decoded our identity item completely
  (`product_type='Programmable Logic Controller'`, `product_code=1`,
  `revision={major:1,minor:0}`, `serial='00c0ffee'`,
  `product_name='zig-fleetsim adapter'`, `state=3`); then an **unconnected**
  `Get_Attributes_All` on the Identity object, and — the interesting one — a
  **connected** `Get_Attribute_Single` (attribute 7), which its driver
  implements via `Forward_Open` + connected send + `Forward_Close`. Both
  returned the product name. Our side printed:
  `live fleetsim EtherNet/IP: sessions=3 frames_in=11 frames_out=8 reads=0 writes=0 identity=3 speed=1500`
- **`bacpypes3` → `BacnetNode`** over UDP
  (`FLEETSIM_BACNET_LISTEN=127.0.0.1:15064`). A directed `whois` drew an I-Am
  identifying `260001 127.0.0.1:15064`; `ReadProperty analog-input,1
  present-value` returned `21.5`; `ReadProperty analog-input,1 object-name`
  returned `Zone-1-Temp`. Our side printed:
  `live fleetsim BACnet: datagrams_in=4 datagrams_out=4 delivered=4 replied=4`

Finding from the live work, worth recording: the first version of the TCP
binding used `std.Io.Reader.readSliceShort`, whose contract is "fill the whole
destination buffer unless end-of-stream" — **not** "return what is available".
On a request/response protocol that means blocking for 8 KiB a master will never
send, and every master timed out. `readVec` (one underlying read) is the right
call for a framed stream. Only a real master exposed this; every offline test
passed throughout.

The other four adapters (DNP3, IEC 104, S7comm, OPC UA) are exercised offline
against real protocol frames — a DNP3 `RESET_LINK_STATES` answered with a
link-layer ACK and a restart that re-arms IIN1.7, an IEC 104 `STARTDT act`
answered `STARTDT con` byte-exactly, an S7 COTP connect answered with a CC, and
the OPC UA connection wired through a fixed writer — but were **not** driven by a
third-party master in this pass. Their own modules already carry that evidence
(opendnp3, lib60870, snap7, open62541); what is untested here is the *adapter*,
not the responder. See the deferred list.

## Scale — measured, not estimated

`test "scale: 1000 in-process Modbus nodes, advanced over simulated minutes"`
stands up **1000 Modbus nodes** (16 holding registers each, 1 ms link delay,
3 ms jitter, 1% loss) plus **64 signals** (32 sine, 32 seeded random walk) and
polls every node once per simulated second for **six simulated minutes** =
**360 000 requests**. Measured on this machine (x86-64 Linux, Zig 0.16):

| build | wall time | per poll | replies | events | RSS before → after setup → peak |
|---|---|---|---|---|---|
| Debug | 2.0–2.6 s | 5.5–7.2 µs | 352 822 / 360 000 | 732 900 | 5.8 → 8.9 → 9.1 MiB |
| ReleaseFast | 171–188 ms | 0.48–0.52 µs | 352 822 / 360 000 | 732 900 | 2.9 → 3.6 → 4.1 MiB |

Reply count and event count are identical between builds and between runs — the
same determinism property, at scale. Zero capacity losses. The RSS delta for the
whole fleet is ~3 MiB, i.e. **~3 kB per node** including its point storage, its
adapter, its restart snapshot and its share of the fixed pools; the numbers
above are process RSS from `/proc/self/statm`, so the "before" column carries
whatever earlier tests left behind and only the deltas are meaningful.

1000 nodes was reached comfortably; the binding constraint is not the scheduler
but per-protocol state. A Modbus node is ~300 bytes of adapter plus its
registers. An OPC UA node needs an allocator, a `NodeStore` and a receive buffer
sized by the negotiated limits (≥ 8 KiB, 64 KiB by default) plus a reassembly
buffer — call it a megabyte each in a realistic configuration, so an OPC UA
fleet is measured in hundreds, not thousands. That is a property of the
protocol, not of this module.

## Hostile input & fuzzing

`std.testing.fuzz` drives `fuzzSmith` → `fuzzDispatch`, which builds a
three-adapter fleet (Modbus + S7 + IEC 104 with a 500 ms tick) and turns every
byte of the corpus into a frame-boundary decision, a node choice and a clock
step — so the fuzzer explores **dispatch**, not one parser. The invariant it
asserts is the one that matters for a scheduler: after the queue drains, every
in-flight slot is back in the pool. A deterministic seed corpus runs the same
body in CI without the fuzzer.

The hostile cases the task called for are covered explicitly:

- **A frame for an unknown node** — `error.UnknownNode` from `submit` and
  `submitStream`, typed, never a crash.
- **A responder that returns an error** — counted in `NodeStats.responder_errors`
  and traced as `responder_error`; nothing is emitted and nothing propagates.
- **A tick that generates more output than the buffer holds** — the responder's
  `BufferTooSmall` becomes `NodeError.OutputTooSmall`, traced as
  `output_overflow`; the frame is dropped, not truncated, and never stomps.
- **A fault schedule that expires mid-frame** — a frame in flight when a
  `silent` window opens *and* closes is answered normally (the window is
  evaluated at arrival, not at submission); a frame that lands inside the window
  is eaten; both paths return the slot to the pool.
- Garbage aimed at every adapter (empty, one byte, `0xFF`s, a 200-byte run, a
  bogus length header) is answered or ignored, never fatal.
- An exhausted in-flight pool loses frames, counts them, and leaves the pool
  exactly full again afterwards.
- A responder that emits bytes its own framing cannot describe is traced as
  `bad_framing` and shipped whole rather than swallowed — a fleet that hides a
  responder bug is worse than useless.

## Threat model / out of scope

This is a **simulator**, not a device. It authenticates nothing and encrypts
nothing, because the protocols it speaks do not (except OPC UA, whose security
lives in the `opcua` module). Binding `serveTcp`/`serveUdp` to a routable
address puts a fake PLC on the network: it will answer writes, report values a
`Driver` invented, and lie convincingly to anything that polls it. Run it on
loopback or an isolated lab segment. The binding accepts one peer at a time and
does no rate limiting; it is a test fixture, not a server.

The fleet is a **star**: every device talks to the outside world, not to its
peers. Peer-to-peer fabric behaviour is `netsim`'s job, which is why
`applyNetsimTrace` maps `netsim`'s link-scoped kinds onto the device end of the
link, maps a `partition` cut onto "those devices are unreachable", and reports
`clock_jump` as unmapped (a fleet has one clock by construction — per-node skew
would break the total order that makes replay work).

## DRY candidates found while building this

- `dnp3.outstation.Session` can frame a *solicited* fragment (`feedFrame`,
  `nextFrames`) but has no public way to frame an **unsolicited** one —
  `sendFragment` is private. `adapters.Dnp3.emitUnsolicited` re-does that
  eight-line job with the module's own public `link`/`transport` API. It belongs
  in `Session` as `unsolicitedFrames(now, out)`. Marked in the source.
- `iec104.outstation.Server` and `bacnet.device.Device` both ship a
  `LoopTransport` sized for peer-to-peer offline tests. A minimal
  one-chunk-in / one-buffer-out shim is generally useful and could live beside
  them, which would let the two shims here disappear.

## Deferred (honest list)

- **Four adapters have no third-party-master evidence in this pass** (DNP3,
  IEC 104, S7comm, OPC UA). Their responders do; their adapters do not. The
  hooks are in place — `Framing` handles all four and the live-test pattern is
  three lines — so this is an hour of work with opendnp3 / lib60870 / snap7 /
  open62541 installed, not a design gap.
- **`OpcuaNode` has no offline round-trip test here.** It compiles, wires
  `Connection.feed`/`tick` to a fixed writer, and its restart path re-`init`s
  the connection, but there is no test in this module that drives it with a
  HEL/OPN/MSG sequence — the `opcua` module's own `TestRig` does that far better,
  and standing up a `NodeStore` + `Server` per node is a page of setup. It is
  exported, and untested at this layer.
- **`Control.trouble` is unimplemented for BACnet, ENIP and OPC UA** — refused
  honestly (`control` returns false) rather than faked. Implementing them means
  reaching into object properties / the Identity status word / a variable's
  `StatusCode`, which those adapters do not own today.
- **No multi-connection binding.** `serveTcp` serves one peer at a time. A
  master that opens several sockets in parallel (some OPC UA and ENIP clients
  do) will queue. Fixing this means an event loop, which belongs in a consumer.
- **`applyNetsimTrace` drops `clock_jump`** and returns the count of unmapped
  events. Per-node clock skew would need a per-node clock offset, which the
  single total order does not currently model.
- **No shrinker of its own.** `netsim` has delta-debugging over a `FaultTrace`;
  a failing fleet run can be shrunk by shrinking the netsim trace it came from,
  but a fleet-native shrinker (over `Fault` lists and submitted frames) does not
  exist yet.
- **RTU framing is `opaque_whole`** — a Modbus RTU node cannot be fed a
  concatenated stream, only whole frames, because RTU has no length field (real
  RTU uses inter-character timing). Fine for TCP fleets; a serial-gateway
  simulation would need t3.5 gap modelling.
- **The scale test is Modbus-only.** A mixed 1000-node fleet would be a better
  number; the per-protocol memory story in the table above is reasoned, not
  measured, for the six non-Modbus adapters.

## Coordinator notes

- `build.zig`, the root `README.md` catalog row and the `check-catalog` step
  were pre-wired and were not touched.
- **No `/NOTICE` entry is required.** Nothing here ports third-party source and
  no third-party implementation was consulted as a design reference; the
  determinism methodology comes from the repo's own `netsim`, whose TigerBeetle
  VOPR design-reference entry already exists. `pymodbus`, `pycomm3` and
  `bacpypes3` were run as black-box compatibility oracles only, which
  CONVENTIONS §5 explicitly says needs no entry.
