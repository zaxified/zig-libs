# fleetsim — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

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
   from a `Transport` vtable. Each gets a **shim** from `shim.zig`: `StreamShim`
   (one injected chunk in, one output buffer out) and `DatagramShim` (one
   datagram in, every `send`/`broadcast` concatenated out), both over the same
   protocol-agnostic `Window`. Both modules ship a `LoopTransport`, but those
   are peer-to-peer test rigs with a 16-slot × 1.5 kB mailbox (~24 kB per node)
   — unaffordable at fleet scale.

**Why `shim.zig` lives here.** The shim could not go in `iec104` or `bacnet`
without that module depending on the other's `Transport` type: the two are
structurally alike (bytes in, bytes out, one peer) but nominally different
(`read`/`write` over a stream vs `send`/`broadcast`/`recv` over datagrams). A
separate module for ~60 lines of logic would be a dependency both ways for no
gain. `fleetsim` is the only place the two shapes meet and already depends on
both. The reusable half — `Window`, which owns all the buffer discipline
(all-or-nothing datagrams, a latching `overflow` that never writes half a frame)
— is protocol-agnostic and public, so an eighth `Transport`-driven responder
costs one ~15-line vtable binding, not another buffer discipline.

**Restart** is uniform: each adapter snapshots its responder *by value* at
construction and restores that snapshot on `Control.restart`. This is a genuine
power-cycle for these responders because their state is plain data over
caller-owned storage (the point values persist, which is what retentive memory
does). A master therefore sees DNP3 IIN1.7 set again, an S7 CPU that must
re-negotiate its PDU size, an ENIP session handle back to zero, an OPC UA
channel it must re-`HEL`.

**Trouble** is native in all seven, each in the vocabulary its own protocol
gives a degraded device:

| protocol | mechanism | what a real master saw |
|---|---|---|
| Modbus | exception `0x04 SlaveDeviceFailure`, synthesised by the adapter (the responder has no "be broken" switch), echoing the request's function code and MBAP header | offline test |
| DNP3 | `IIN1.6 device_trouble` | opendnp3: `IIN: [0x10, 0x00]` → `[0x50, 0x00]` |
| IEC 104 | the `iv` quality bit on every point whose element carries a quality descriptor (§7.2.6.3) | c104: `Quality set: {}` → `{ Invalid }` |
| S7comm | SZL `0x0424` operating mode `STOP` | python-snap7: `bzu_id=0x08 (RUN)` → `0x04 (STOP)` |
| BACnet | clause 12's fault triple: `Reliability = unreliable-other`, `Status_Flags = {in-alarm, fault, out-of-service}`, `Out_Of_Service = true` | bacpypes3: `no-fault-detected` → `unreliable-other` |
| EtherNet/IP | Identity status word → `0x0450` (extended status 5 "major fault" + bit 10 "major recoverable fault"), state → `major_unrecoverable_fault`, and CIP data services answer general status `0x10 Device State Conflict` | pycomm3: `status=b'0\x00'`/Success → `b'P\x04'`/"Device state conflict" |
| OPC UA | `BadDeviceFailure` on every Variable the caller nominated, plus `ServerStatus.State = Failed` | asyncua: `Good`/`State=0` → `BadDeviceFailure`/`State=1` |

Three of these reach state that belongs to the **caller** — BACnet object
properties, an OPC UA `NodeStore` — and they do it strictly through the
responder module's own public API (`Object.find` + `Device.update`;
`NodeStore.getNode` / `setValue` / `refreshServerStatus`). Not one line of any
responder module changed. Where the caller's model declares nothing to degrade
(a BACnet device whose objects carry none of the three fault properties),
`control` still returns **false** and the fleet records `control_unsupported`:
the honest answer is preserved for the case that actually deserves it.

Two design notes worth pinning down. A faulted EtherNet/IP device still answers
*encapsulation* — `ListIdentity`, `RegisterSession` — because the Identity
status word is precisely where CIP puts a fault; what it refuses is CIP object
traffic. And BACnet's COV notification for the fault is deferred to the next
`tick`: `control` has no output buffer to write a datagram into, so the adapter
sets `cov_pending` and the tick that *does* have a buffer emits it.

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

**`tcp.zig` — the only socket code.** Three bindings, all single-threaded.

`serveTcp` binds, accepts up to `max_sessions` peers one at a time, and pumps:
`readVec` (one underlying read) → `submitStream` → `advance(elapsed)` → write
`outbound()`. `poll(2)` bounds both the read and the accept so the `run_ms`
budget means something and the fleet's timers still fire on a quiet link.
`serveUdp` is the same for BACnet, replying to the last peer seen.

`serveTcpMulti` binds **several** listeners and services **several peers at
once**, still from one thread: build a readiness set (every listener that can
still take a peer, plus every connected peer), `poll(2)` it, accept what is new,
read what is ready, `advance` once, then write each node's `outbound()` back.
Concurrency here is a *readiness set*, not a thread pool — which is the only way
to add it without moving I/O into the core: there is still exactly one clock
read per loop iteration, at the top, and the fleet still receives an injected
`Time`. Everything is allocated before the loop (`max_peers` slots × three
buffers), so the steady state never touches the allocator.

Routing: a node's reply goes to the peer that most recently sent it something;
when nothing was asked (unsolicited traffic) it goes to every peer on that
node's listener, which is what a device with several connected masters does.
Closing a peer clears any `last_peer` entry pointing at its slot, so a reply can
never be routed to a slot a *different* master has since been given. A
connection beyond `max_peers` is accepted and immediately closed rather than
left in the backlog: an unserviceable connection that looks alive is a worse lie
than a refusal.

`serveTcpMulti` is also the right binding whenever a fault *schedule* matters:
`serveTcp` restarts its clock at every accept (each `serveTcpOn` measures from
its own accept), so a fault at t=15 s means something different to every
session, while `serveTcpMulti` keeps one clock for the whole run.

## The determinism argument

Everything that could differ between two runs is either injected or seeded:

- **Time** enters only through `advance(to_ms)`. Nothing in the core reads a
  clock (`tcp.nowMs` is in the binding, not the core — including in the
  multi-peer loop, which reads it once per iteration and nowhere else).
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

> **How to tell whether any of this ran.** The transcripts below are a record of
> runs that happened once, on a host where those masters were installed; they
> are prose, not a check. Two things make that record falsifiable:
>
> 1. **`FLEETSIM_EXPECT_LIVE=1`** — the live lane. With it set, every live test
>    whose `FLEETSIM_*_LISTEN` variable is missing (or whose binding gets no
>    peer) **fails** instead of skipping, so "0 of 8 live tests ran" can no
>    longer look identical to "all 8 passed" at the exit code. Without it, the
>    default run still skips, and its summary line still says so.
> 2. **`src/goldens.zig`** (plus the OPC UA vector in `src/root.zig`) — a
>    third-party *reading* of the bytes the adapters emit, frozen from
>    Wireshark 4.6.4's dissectors for all seven protocols. It runs offline on
>    every build with no new dependency. It grades frames, so it does not
>    replace a real master's state machine; it does mean a green
>    `test-fleetsim` is no longer entirely self-anchored.
> 3. **`scripts/vm/run.sh fleetsim debian`** — the live lane, actually run, in a
>    disposable VM with **five** real masters installed by the provisioning
>    recipe: pymodbus 3.14.0, pycomm3 1.2.16, bacpypes3 0.0.106, python-snap7
>    3.1.0 and asyncua 2.0.1. Their recorded sessions are frozen in
>    **`src/master_goldens.zig`** and replay offline on every build. So for
>    those five, the transcripts below are no longer only prose: they are
>    committed, byte-exact exchanges that a third party's encoder composed and
>    its decoder accepted. DNP3 (opendnp3) and IEC 104 (c104) are still prose —
>    see "Not wired into the VM lane" below.
>
> **The caution the VM lane produced — and what was done about it.**
> A live master is not automatically an anchor. `test "live: a real Modbus
> master drives a simulated slave over the TCP binding"` used to assert exactly
> two things: `stats.delivered > 0` and `stats.replied > 0`. Both are liveness —
> frames arrived, frames left — and neither says anything about what the device
> said. Measured: byte-swapping the register encoder (`.big` → `.little` in
> `modules/modbus/src/server.zig`'s read-registers reply) and re-running the
> live lane produced **`GUEST_EXIT=0`: the live test passed with every register
> value wrong**, because a wrong answer is still an answer and still gets
> counted. What went red was the master's own grading, enforced by a `grep` in
> `run.sh` for its `MODBUS_MASTER_OK` marker. A grade enforced by a shell gate
> is not a test suite.
>
> **The fix is that the master now reports what it decoded, in-band, and the
> live test grades that.** `scripts/vm/guests/fleetsim-modbus-master.py`
> compares every read against the fixture in its own number domain and writes
> its marks back into the device with FC 0x10 and FC 0x05 — a magic word, the
> number of checks it ran, the number it rejected, the exception code it
> *named* for an out-of-range read, the sum of the holding registers it
> decoded, the sum of the input registers, the coil bitmap it unpacked, and a
> pass bit written either way. `modbus_verdict` in `src/root.zig` asserts on all
> of it against constants derived from the fixture. Note what is deliberately
> *not* done: the decoded values are never echoed back verbatim, because an echo
> is the inverse of the read and a device that encoded and decoded with the same
> wrong convention would round-trip cleanly — sums and a bitmap cannot cancel
> that way.
>
> The gate in `run.sh` was correspondingly demoted to `MODBUS_MASTER_DONE`,
> which means "the counterpart connected and ran to the end" and never "the
> counterpart was satisfied". Re-running the same byte-swap mutation against the
> new arrangement: the marker gate passes, and **the live test itself fails**
> (`expected 0, found 4` on the master's failure count) — `GUEST_EXIT=1`,
> `run.sh` exit 1. The same marks are frozen into `src/master_goldens.zig`, so
> the offline suite carries the grading too.
>
> **Four more masters were then held to exactly that bar**, each with a verdict
> channel of its own, because the value of the live lane is in the counterpart's
> assertions and not in the counterpart's presence:
>
> | protocol | counterpart | write-back channel | marks |
> |----------|-------------|--------------------|-------|
> | EtherNet/IP | pycomm3 1.2.16 | CIP `Write Tag` 0x4D into `Verdict` DINT[8] + `VerdictPass` | magic, checks, failures, sum of a six-element DINT array, a REAL scaled x10, a checksum of the `ListIdentity` product name, the CIP general status it named for an unserved tag, and the sum of a three-element slice starting at element 2 (which grades array-element addressing) |
> | BACnet | bacpypes3 0.0.106 | `WriteProperty` into `analog-value,1..8` + `binary-value,1` | magic, checks, failures, present-value x10, an object-name checksum, the four status flags packed from what it unpacked *by name*, the device instance learned from an `I-Am`, and the error code it named for a missing property |
> | S7comm | python-snap7 3.1.0 | a DB write into DB2 | magic, checks, failures, the sum of DB1[16..47], a REAL x10, `DINT - INT` from a typed record, the two *different* S7 return codes it named for an unbound DB (0x0A) and a read past the end of a bound one (0x05), and the PDU length the device chose |
> | OPC UA | asyncua 2.0.1 | the `Write` service into `ns=1;s=verdict.0..7` + `verdict.pass` | magic, checks, failures, the Int32 measurement **plus** the Double setpoint x10, a decoded String checksum, the numeric `StatusCode` it named for an unknown node, a checksum of namespace 1's URI read from the server's own `NamespaceArray`, and DataType x100 + AccessLevel |
>
> **Never a plain echo, and OPC UA is why that rule is not pedantry.** An
> Int32 read followed by an Int32 write of the same number is precisely the
> round trip a server whose integer codec is byte-swapped in *both* directions
> survives untouched. Every numeric mark above is therefore a sum, a
> difference, a bitmap, a checksum, a scaled integer or a status code the
> counterpart itself named — a form a symmetric codec fault moves instead of
> cancelling inside.
>
> **Each was measured, not asserted.** For every one of the four, a wrong value
> was injected into that protocol's adapter and the run repeated; the exit
> codes are in "Mutation proofs" below. A master that connects but whose test
> survives a wrong value is not an anchor, and landing one would repeat exactly
> the defect this section is about.
>
> **Mutation proofs — one wrong value per adapter, measured, not asserted.**
> Each was injected on a clean tree, the offline suite and that master's live
> lane were run, and the file was reverted and `cmp`-checked byte-identical
> (`git diff --stat` empty in all four cases). What matters in the last column
> is that the master's presence marker still printed: the run went red because
> **the test** rejected the marks, not because a shell `grep` missed a marker.
>
> | master | mutation | offline `test-fleetsim` | live lane |
> |--------|----------|-------------------------|-----------|
> | pycomm3 | `modules/enip/src/adapter.zig` `pathElement` → always 0 (array member segment ignored) | **exit 1** — the frozen pycomm3 corpus bites | `ENIP_MASTER_DONE` present, `live: a real EtherNet/IP master … FAIL (TestExpectedEqual)`, `expected 0, found 1`, `1 passed; 0 skipped; 1 failed`, **`GUEST_EXIT=1`, `run.sh` exit 1** |
> | bacpypes3 | `modules/bacnet/src/tag.zig` `appReal` `.big` → `.little` | **exit 1** — the frozen bacpypes3 corpus bites | `BACNET_MASTER_DONE` present, `live: a real BACnet client … FAIL (TestExpectedEqual)`, `expected 0, found 1`, **`GUEST_EXIT=1`, `run.sh` exit 1** |
> | python-snap7 | `modules/s7comm/src/items.zig` `byteOffset` `>> 3` → `>> 2` | **exit 1** — the frozen python-snap7 corpus bites | `S7_MASTER_DONE` present, `live: a real S7 client … FAIL (TestExpectedEqual)`, **`expected 1008, found 1520`** — i.e. the client summed a different window, **`GUEST_EXIT=1`, `run.sh` exit 1** |
> | asyncua | `modules/opcua/src/encoding.zig` `encodeDouble` `.little` → `.big` | **exit 0, and that is expected** — there is no frozen OPC UA corpus to bite (see above) | `OPCUA_MASTER_DONE` present, `live: a real OPC UA client … FAIL (TestExpectedEqual)`, `expected 0, found 1`, **`GUEST_EXIT=1`, `run.sh` exit 1** |
>
> The S7 line is the most legible of the four: the mark is a *sum over a byte
> window*, so a halved address shift moves it from 1008 to 1520 and the failure
> message names both numbers. The other three report through the failure count
> the master itself wrote (`expected 0, found 1`) — the master graded, disagreed,
> and said so in-band.

> **Not wired into the VM lane, deliberately.** *opendnp3* publishes no wheel —
> it is a C++ library whose `master-demo` has to be built, which is a different
> kind of provisioning step. *c104* installs from a wheel fine, but the IEC 104
> lane was built once and **rolled back**: the link would not stay up in a
> two-master run, and the instability traces to a conformance defect in
> `modules/iec104` (its outstation confirms a global-common-address
> interrogation by echoing 0xFFFF back instead of identifying itself with its
> own CA 47). A half-wired lane that fails by default is worse than an absent
> one.

**All seven protocols now have third-party-master evidence through the adapter
and the module's own binding**, on Linux, Debug build. Each run schedules a
`trouble` fault at simulated t=15 s and the master polls across it, so the
transcripts below are also the proof that device trouble is expressible in every
one of the seven.

- **`pymodbus` 3.14.0 → `ModbusNode`** (`FLEETSIM_TEST_LISTEN`, `serveTcp`).
  12 × `read_holding_registers(0, count=8)`, a `write_register(5, 0xBEEF)` with
  a read-back, a `write_coil(3, True)` with a `read_coils` read-back, a
  `read_input_registers`, and an out-of-range read that came back as
  `ExceptionResponse(function_code=131, exception_code=2)`. The sine `Signal`
  was visibly animating holding register 0 across the reads
  (`500 → 623 → 735 → 823 → 880 → 900 → 880 → … → 500`, a 5 s period sampled at
  250 ms). Our side:
  `live fleetsim Modbus: sessions=1 frames_in=18 frames_out=18 bytes_in=216 bytes_out=371 delivered=18 replied=18 signal_fires=13 hr0=264 hr5=0xBEEF coil3=true`
  — byte-identical to the first pass, i.e. the multi-peer work changed nothing
  for the single-peer path.

- **`opendnp3` `master-demo` → `Dnp3Node`** (`FLEETSIM_DNP3_LISTEN`,
  `serveTcpMulti`). opendnp3 built from source (`release` branch, Apache-2.0),
  used unpatched: its demo dials 127.0.0.1:20000 with LocalAddr 1 / RemoteAddr
  10, so the test's outstation is configured to match. It ran its startup tasks,
  a 1-minute integrity poll, a 5-second Class-1 exception poll, three demanded
  integrity scans, a demanded exception scan and an ad-hoc range scan
  (`001,002 Binary Input - With Flags, 16-bit start stop [0, 3]`), decoding
  `001,001 Binary Input - Packed Format` and `030,001 Analog Input - 32-bit With
  Flag` on every response. **IIN over the run: `[0x90, 0x00]` (restart+need-time)
  → `[0x10, 0x00]` → `[0x50, 0x00]`** — that 0x40 is IIN1.6 `device_trouble`,
  set by the scheduled fault and seen by the master. Our side:
  `live fleetsim DNP3: peers=1 peak=1 frames_in=17 frames_out=17 bytes_in=370 bytes_out=558 delivered=17 replied=17 device_trouble=true`

- **`c104` 2.2.1 (lib60870-C) → `Iec104Node`** (`FLEETSIM_IEC104_LISTEN`,
  `serveTcpMulti`). The client's state machine went
  `CLOSED_AWAIT_OPEN → OPEN_MUTED → OPEN` (i.e. our `STARTDT con` was accepted),
  then issued **14 station interrogations** and received **76 APDUs**, including
  the byte-exact `680e0000020064010700ffff00000014` (C_IC_NA_1 activation
  confirm) and the M_ME_NC_1 report `6812060002000d8114002f00c900000000ac4100`
  carrying 21.5. **45 point updates**, quality
  `Quality set: {}, is_good: True` → **`Quality set: { Invalid }, is_good: False`**
  at t=15 s on all three points. Our side:
  `live fleetsim IEC 104: peers=1 frames_in=17 frames_out=76 delivered=17 replied=16 started=true iv101=true iv201=true`

- **`python-snap7` 3.1.0 → `S7Node`** (`FLEETSIM_S7_LISTEN`, `serveTcpMulti`).
  COTP connect, `Setup communication` negotiating a **480-byte PDU**, then 14
  rounds of `db_read(1, 0, 16)` + `read_szl(0x0424, 0)`. DB1.DBD8 was animated
  by a sine and the client decoded it as a big-endian REAL
  (`900.00 → 176.39 → 623.61 → …`); DB1[0:8] read back `0001020304050607` every
  time. **SZL 0x0424 record `5144ff08` (bzu_id 0x08 = RUN) → `5144ff04`
  (0x04 = STOP)** at t=15 s. Our side:
  `live fleetsim S7comm: peers=1 frames_in=31 frames_out=30 delivered=31 replied=30 pdu=480 cpu_status=stop`

  *Oracle defect worth recording:* python-snap7 3.1.0's own `get_cpu_state()`
  does **not** issue an SZL read — `build_cpu_state_request` sends a one-byte
  parameter `0x04` with the source comment "Use READ_AREA function for
  simplicity", which is not a valid S7 job. No real CPU would answer it, and
  this responder correctly does not either. `read_szl(0x0424, 0)` is the real
  request and works.

- **`asyncua` 2.0.1 → `OpcuaNode`** (`FLEETSIM_OPCUA_LISTEN`, `serveTcpMulti`).
  Full session bring-up (HEL/ACK, OpenSecureChannel, GetEndpoints, a second
  channel, CreateSession, ActivateSession — 78 messages in, 77 out, 10 365 bytes
  in / 6 384 bytes out), `get_namespace_array()` →
  `['http://opcfoundation.org/UA/', 'urn:zig-libs:fleetsim']`, a browse of the
  Objects folder → `['i=2253', 'ns=1;s=the.measurement']`, and 14 reads of the
  measurement. **`value=42 status=Good ServerState=0` → `value=42
  status=BadDeviceFailure ServerState=1`** at t=15 s. Our side:
  `live fleetsim OPC UA: peers=1 peak=1 frames_in=78 frames_out=77 delivered=78 replied=77 measurement_status=0x808B0000`

- **`pycomm3` 1.2.16 → `EnipNode`** (`FLEETSIM_ENIP_LISTEN`, `serveTcpMulti`).
  `CIPDriver.list_identity` decoded the identity item completely
  (`product_type='Programmable Logic Controller'`, `product_code=1`,
  `revision={major:1,minor:0}`, `serial='00c0ffee'`,
  `product_name='zig-fleetsim adapter'`), and an unconnected
  `Get_Attributes_All` on the Identity object was repeated across the fault.
  **`identity.status b'0\x00'` (0x0030) → `b'P\x04'` (0x0450), `state 3` →
  `state 5`, and `Get_Attributes_All` `ok=True error=None` → `ok=False
  error='Device state conflict'`.** pycomm3 opens a fresh socket per call, so
  this run also exercised the multi-peer binding hard:
  `live fleetsim EtherNet/IP: peers=29 peak=2 frames_in=87 frames_out=58 identity=20 identity_status=0x0450 state=major_unrecoverable_fault`

- **`bacpypes3` 0.0.106 → `BacnetNode`** over UDP (`FLEETSIM_BACNET_LISTEN`,
  `serveUdp`). A directed `who_is` drew an I-Am identifying `device,260001`;
  `ReadProperty analog-input,1 object-name` returned `Zone-1-Temp`; then 14
  rounds reading present-value, reliability, status-flags and out-of-service.
  **`reliability=no-fault-detected status-flags= out-of-service=0` →
  `reliability=unreliable-other status-flags=in-alarm;fault;out-of-service
  out-of-service=1`** at t=15 s. Our side:
  `live fleetsim BACnet: datagrams_in=58 datagrams_out=58 delivered=58 replied=58 reliability=7 status_flags=0xD0 out_of_service=true`

- **Two masters at once** (`FLEETSIM_MULTI_LISTEN`, `serveTcpMulti`).
  `pymodbus` on the Modbus node and `c104` on the IEC 104 node, two sockets, two
  protocols, one binding thread: 25 Modbus reads (`[1000, 1001, 1002, 1003]`
  every time — the *other* node's registers never leaked in) and 22 IEC 104
  point updates, with **28.8 s of overlapping traffic**. Our side:
  `live fleetsim multi-peer: peers=2 peak_concurrent=2 refused=0 frames_in=38 frames_out=70 modbus_replied=25 iec104_replied=13`

Findings from the live work, worth recording:

1. The first version of the TCP binding used `std.Io.Reader.readSliceShort`,
   whose contract is "fill the whole destination buffer unless end-of-stream" —
   **not** "return what is available". On a request/response protocol that means
   blocking for 8 KiB a master will never send, and every master timed out.
   `readVec` (one underlying read) is the right call for a framed stream.
2. `serveTcpMulti`'s first version had both an `errdefer` over the listeners
   bound so far *and* a `defer` over the whole array. On the "no peer connected"
   path that closes every bound listener **twice**, which aborts. Only a live
   run with no master reached it; the offline `error.BindFailed` test passed by
   luck, because it never bound anything. It is now one `defer` over
   `listeners[0..bound]`, evaluated at scope exit.
3. `OpcuaNode` did not compile once anything instantiated its vtable: the error
   map named `error.NoSpaceLeft`, which is not in `server.ServerError`. The
   adapter was exported and never called, so nothing had ever analysed
   `deliverFn`. Standing up the offline round-trip test found it immediately.

## Scale — measured, not estimated

`test "scale: 1000 in-process Modbus nodes, advanced over simulated minutes"`
stands up **1000 Modbus nodes** (16 holding registers each, 1 ms link delay,
3 ms jitter, 1% loss) plus **64 signals** (32 sine, 32 seeded random walk) and
polls every node once per simulated second for **six simulated minutes** =
**360 000 requests**. Measured on this machine (x86-64 Linux, Zig 0.16):

| build | wall time | per poll | replies | events | RSS before → after setup → peak |
|---|---|---|---|---|---|
| Debug | 2.5–2.6 s | 6.9–7.3 µs | 352 822 / 360 000 | 732 900 | 6.4 → 9.4 → 9.5 MiB |
| ReleaseFast | 175–202 ms | 0.49–0.56 µs | 352 822 / 360 000 | 732 900 | 3.0 → 3.7 → 4.2 MiB |

Re-measured after the trouble/multi-peer/shim work (three runs each, on a
machine with three other agents building concurrently — the earlier pass
recorded Debug 2.0–2.6 s / 5.5–7.2 µs and ReleaseFast 171–188 ms / 0.48–0.52 µs
on an idle machine). **Reply count and event count are byte-identical to the
first pass**, which is the number that matters: nothing in this work perturbed
the scheduler's behaviour, only its surroundings.

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

## Searching for a failure — the fleet as a `netsim` protocol

`Fleet.applyNetsimTrace` borrows netsim's *schedule fuzzer*: a generated
`FaultTrace` is translated into fleet faults and executed. It cannot borrow the
*search*, because nothing in that path decides whether the resulting run was
good — so no seed can be looked for, and `shrinkTrace` has no oracle to
minimise against. A failure could only ever be reported as "seed N breaks it".

`src/vopr.zig` closes that: it plugs a `Fleet` into netsim's engine as an
ordinary `Protocol`, so `run` / `replay` / `findFailing` / `shrinkTrace` work on
a device fleet exactly as they already do for `raft` or `df-elect`. netsim node
0 is the master (the SCADA poller), nodes `1..N` are the devices, one
bidirectional link each — the same star the threat-model section describes.

**The seam is a clean split, not a second copy of the same model.** netsim owns
the network (latency plus the whole adversary: drop / duplicate / delay spike /
link down+up / partition+heal / crash+restart); fleetsim owns the devices
(framing, the responders, point behaviour, the slot pool, the total order). The
fleet's own link-fault knobs are left at zero, deliberately: modelling loss at
both layers would make a minimised trace a lie, because half of what perturbed
the run would not be in the trace handed back, and ddmin would shrink against
noise. `onTimer` on the master is the poll loop; `onMessage` on a device is the
only place the fleet is driven (`submit`, then `advance` up to netsim's clock,
then every frame in `outbound()` goes back on the wire).

Five invariants are checked after **every** netsim event, all of them at the
master and all of them on bytes the devices authored — netsim can lose,
duplicate, delay and reorder a payload but cannot write one, so none of them can
fire merely because a fault fired: `MalformedReply` (not exactly one complete
frame of the sender's own `Framing`), `UnitIdMismatch` (cross-routing),
`UnknownTransaction` (an id this master never issued to that device),
`ValueOutOfRange` (outside the band the `Signal`'s driver can produce), and
`SlotLeak` (slot-pool conservation — the same property the fuzz target asserts
once at the end, here asserted continuously under an adversary).

Liveness is deliberately **not** an invariant. An adversary free to cut a link
and never heal it, or to crash the master, can starve any device of any reply;
"every poll is answered" would report the adversary as a bug.

**Teeth.** netsim's contract for a consumer is a deliberately-broken positive
control (its own `LoopyForward`, `raft`'s `BrokenRaft`). `BrokenDevice` is this
module's, and it carries four defects — one per master-side invariant. Each is
gated on the same transaction id arriving twice, which **only a duplicated
request can produce**, so each is provably unreachable on a clean run: the test
`every bug is unreachable without the adversary` replays each of them with an
empty fault trace and requires `.ok` *and* more than 20 answered polls. The
search then finds all four, and minimises each to a single fault:

```
length_counts_retransmit: seed=4 err=error.MalformedReply     trace 26 -> 1 events
stale_unit_id:            seed=4 err=error.UnitIdMismatch     trace 26 -> 1 events
invented_transaction:     seed=4 err=error.UnknownTransaction trace 26 -> 1 events
stale_register_buffer:    seed=4 err=error.ValueOutOfRange    trace 26 -> 1 events
    t= 489 dup_once 0->1
    replay(minimised) -> violated
```

That single surviving `dup_once 0->1` at t=489 is the root cause stated exactly:
one duplicated request on the master → device link. The same harness running the
real `adapters.Modbus` is clean across the whole seed sweep.

Every search here is **bounded** and modest (seeds 1..60, `until = 1200` ticks,
a 20-tick poll period): a netsim sweep is one replay per seed and ddmin is one
replay per candidate cut, so an unbounded budget would be a runaway rather than
a better test.

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

`serveTcpMulti` changes the exposure only in degree: it will hold `max_peers`
connections at once and still authenticates nothing. It does no rate limiting
and no per-peer accounting beyond the slot count; it is a test fixture, not a
server.

The fleet is a **star**: every device talks to the outside world, not to its
peers. Peer-to-peer fabric behaviour is `netsim`'s job, which is why
`applyNetsimTrace` maps `netsim`'s link-scoped kinds onto the device end of the
link, maps a `partition` cut onto "those devices are unreachable", and reports
`clock_jump` as unmapped (a fleet has one clock by construction — per-node skew
would break the total order that makes replay work).

## DRY candidates found while building this — both now resolved

- **`dnp3.outstation.Session.unsolicitedFrames(now_ms, out)` — added.**
  `Session` could frame a *solicited* fragment (`feedFrame`, `nextFrames`) but
  had no public way to frame an **unsolicited** one, because `sendFragment` is
  private; this adapter re-did that job over `dnp3`'s public `link`/`transport`
  API. It belongs on `Session` because `Session` owns `tx_seq`: framing an
  outstation-initiated fragment anywhere else means duplicating the transport
  sequence bookkeeping, which is exactly what confuses a master's reassembler.
  The addition is purely additive — `Outstation.unsolicited` is untouched for
  callers that own their framing — and `adapters.Dnp3.tickFn` now calls it.
- **`shim.zig` — added, in this module.** See "Why `shim.zig` lives here" above
  for why it cannot live in `iec104` or `bacnet`, and why a module of its own
  would be worse than either. It is public (`fleetsim.Window`,
  `fleetsim.StreamShim`, `fleetsim.DatagramShim`), because a consumer holding
  one of those two responders outside a fleet wants exactly this, and both
  `LoopTransport`s are the wrong shape for it.

## Deferred (honest list)

Four entries from the first pass have been **closed** and are recorded above
rather than here: third-party-master evidence for DNP3 / IEC 104 / S7comm /
OPC UA, `OpcuaNode`'s offline round-trip, `trouble` for BACnet / ENIP / OPC UA,
and the multi-connection binding. What is still open:

- **`applyNetsimTrace` drops `clock_jump`** and returns the count of unmapped
  events. Per-node clock skew would need a per-node clock offset, which the
  single total order does not currently model.
- **No fleet-native shrinker.** Delta-debugging over a *netsim* `FaultTrace` now
  works end to end on a fleet — see "Searching for a failure" above — so a
  failing run comes back as a minimised fault trace. What still does not exist
  is a shrinker over the fleet's *own* inputs (`Fault` lists and submitted
  frames), which is what you would want to minimise a failure that a netsim
  schedule cannot express.
- **RTU framing is `opaque_whole`** — a Modbus RTU node cannot be fed a
  concatenated stream, only whole frames, because RTU has no length field (real
  RTU uses inter-character timing). Fine for TCP fleets; a serial-gateway
  simulation would need t3.5 gap modelling.
- **The scale test is Modbus-only.** A mixed 1000-node fleet would be a better
  number; the per-protocol memory story in the table above is reasoned, not
  measured, for the six non-Modbus adapters.
- **`serveTcpMulti` fans a node's unsolicited traffic to every peer on that
  node's listener.** For a device with several masters subscribed that is the
  right behaviour; for one where the masters are meant to be isolated it is not,
  and the binding has no way to tell the difference. A per-peer session identity
  (which is what DNP3 and OPC UA actually have) would fix it, and belongs with
  whoever needs it.
- **The multi-peer binding is proved with two peers, not many.** The offline
  test uses two, the live run reached `peak_concurrent=2` with two different
  masters and 29 sequential peers from pycomm3. `max_peers` is honoured and
  over-limit connections are counted, but nothing here has driven 100 masters at
  one fleet.
- **`OpcuaNode`'s `trouble` degrades the Variables the caller nominates**
  (`trouble_nodes`), not "every process value the server has". There is no
  notion in the `NodeStore` of which Variables are process values as opposed to
  server diagnostics, and inventing one here would be a guess about the caller's
  address space.
- **BACnet's trouble sets one shared `StatusFlags` octet for every degraded
  object**, so an object that was already `in-alarm` for its own reasons comes
  back healthy on `trouble_off`. Per-object save/restore would need per-object
  storage; the simulator's answer is that a healthy simulated point has clear
  flags.

## Coordinator notes

- `build.zig`, the root `README.md` catalog row and the `check-catalog` step
  were pre-wired and were not touched.
- **No `/NOTICE` entry is required.** Nothing here ports third-party source and
  no third-party implementation was consulted as a design reference; the
  determinism methodology comes from the repo's own `netsim`, whose TigerBeetle
  VOPR design-reference entry already exists. `pymodbus`, `pycomm3`,
  `bacpypes3`, `opendnp3`, `c104`/lib60870, `python-snap7` and `asyncua` were
  run as black-box compatibility oracles only, which CONVENTIONS §5 explicitly
  says needs no entry. (`opendnp3` already has a NOTICE entry from the `dnp3`
  module's own interop work; nothing new is owed.)

  **The licences were checked rather than assumed**, because four of the five
  masters now baked into the VM image also have their sessions *frozen* into
  `src/master_goldens.zig`. pymodbus is BSD-3-Clause; pycomm3, bacpypes3 and
  python-snap7 are MIT; **asyncua is LGPL-3.0-or-later** and is the only one
  that would have needed thought. It did not need much: asyncua is run as a
  separate process inside a disposable guest, nothing from it is copied,
  translated, linked or redistributed, and — as it happens — nothing of its
  session is frozen either, because an OPC UA session is not byte-replayable
  (see `master_goldens.zig`). What *is* frozen for the other four is the byte
  output of two programs exchanging messages defined by public specifications
  (MODBUS Application Protocol, ODVA CIP Vol 1/2, ASHRAE 135, the published S7
  frame layouts), plus what each master reported it decoded. That statement is
  true of what was actually done.
- **`modules/dnp3` gained one additive public function**
  (`outstation.Session.unsolicitedFrames`) plus its test and doc updates. The
  existing public API is unchanged and source-compatible.
