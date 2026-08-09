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

That boots the provisioned Debian guest and runs **five** live tests inside it
with `FLEETSIM_EXPECT_LIVE=1`, each with a real third-party counterpart
installed into the image by the provisioning recipe, not by you:

| test | counterpart | write-back channel |
|------|-------------|--------------------|
| Modbus | pymodbus 3.14.0 | FC 0x10 / FC 0x05 into holding registers + a coil |
| EtherNet/IP | pycomm3 1.2.16 | CIP `Write Tag` into `Verdict` DINT[8] |
| BACnet | bacpypes3 0.0.106 | `WriteProperty` into eight analog-values + a binary-value |
| S7comm | python-snap7 3.1.0 | a DB write into DB2 |
| OPC UA | asyncua 2.0.1 | the `Write` service into `ns=1;s=verdict.*` |

~6 min end to end (the live tests run one after another, each holding its
socket for the full 60 s `live_run_ms`); the one-off `scripts/vm/provision.sh
debian` before it takes ~3 min.

**Two gates, and the split between them matters.** `run.sh` requires the guest
to print each master's `*_MASTER_DONE`, which means only "the counterpart
really was there and ran its script to the end" — that is a presence check and
a shell `grep` is the right place for it. *Correctness* is asserted in Zig:
every master grades what it read against the fixture **in its own number
domain** and commands the marks back into the device, and a `*_verdict` block
in `src/root.zig` asserts on them against constants recomputed from the
fixture.

That split is not decoration. Before it, the live Modbus test asserted only
`delivered > 0`/`replied > 0`, and a device with a byte-swapped register
encoder — every value wrong — **passed it**; only the shell gate went red. With
the verdict block the same mutation fails the live test itself, and each of the
four masters added afterwards was held to the same bar: a wrong value injected
into its adapter must turn *the test* red. See [SPEC.md](./SPEC.md)'s "What was
verified live" for the measurements.

**Never a plain echo.** Every mark is a sum, a bitmap, a checksum, a scaled
integer or an error code the counterpart itself named — never the decoded value
handed straight back. An echo is the inverse of the read, so a device whose
encoder and decoder share the same wrong convention round-trips it cleanly and
the fault hides inside the mark. OPC UA is where that bites hardest (Int32 in,
Int32 out), which is why its value mark folds a Double-derived term in.

One master is still not wired: **opendnp3** publishes no wheel — it is a C++
library with a `master-demo` example that has to be built, which is a different
kind of provisioning step from `pip install`. Adding a master is four edits that
must happen together, all listed in `run.sh`'s fleetsim master table: the pinned
spec in `scripts/vm/manifest.sh`'s `VM_DEBIAN_PIP`, a row in that table (which
drives the launcher, the marker gate and the test filter at once), a driver
script in `scripts/vm/guests/`, and a verdict channel in the live test. A master
that only reads leaves no trace of what it understood.

What those runs produced is frozen in `src/master_goldens.zig` and replays
offline on every build, so the ordinary `zig build test-fleetsim` carries the
third-party evidence even with no VM in sight — including the verdict
exchanges, whose request bytes are a function of what the device said.

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

`c104` is the only one carrying a compiled extension (it wraps lib60870-C) and
the only one under a copyleft licence (**GPL-3.0-or-later**; it runs as a
separate process in a throwaway guest, nothing is linked against it and nothing
from it is redistributed — see the root `NOTICE`). Its published wheels stop at
CPython 3.13, so on a **newer** interpreter pip falls back to a source build and
needs `build-essential` and `cmake`. Checked, not inherited: Debian 13 (trixie)
ships Python 3.13 and c104 2.2.1 publishes a `cp313-manylinux_2_28_x86_64`
wheel (954 KB), so in the VM lane's guest it installs from a wheel with **no
toolchain at all** — re-verified while provisioning the current image
(`Downloading c104-2.2.1-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`,
`Successfully installed … c104-2.2.1`, `PROVISION_EXIT=0`). The warning is
about interpreters ahead of that image, not about this lane.

### DNP3: what exists, and what it would cost

Surveyed 2026-08-10, because "no wheel" is the reason this one master is still
outstanding and the alternatives deserve to be on the record rather than
re-derived:

| Candidate | Verdict |
|---|---|
| `pydnp3` (PyPI, pybind11 over opendnp3) | **Dead.** Last release 2018-06-07. No Linux binary wheel ever published — the only wheels are macOS `cp27/cp35/cp36` plus `cpXX-none-any`. On Python 3.13 pip falls through to the sdist, i.e. a full C++ build. |
| `dnp3-python` (PyPI, VOLTTRON, wrapper over opendnp3) | **Wrong interpreter.** Newest wheel is `0.3.0b2-cp310-manylinux1_x86_64` (2024-11). No cp311+ build exists, and Debian 13 ships 3.13 — so it does not install, wheel or otherwise. |
| Debian package (`dnp3*`, `libopendnp3*`) | **Does not exist.** `packages.debian.org` returns no match in *any* suite, and there is no `opendnp3` source package. The cheap apt route is closed. |
| `stepfunc/dnp3` (Rust, the actively-maintained successor) | **Licence blocker.** Alive (crates.io 1.7.0-RC4, pushed 2026-07), but `LICENSE.txt` is a proprietary evaluation agreement limited to "non-commercial and non-production" use — an owner decision, not a drop-in. |
| `opendnp3` C++ itself | **Archived** upstream on 2022-05-18; last release 3.1.2 (2022-04-22), Apache-2.0. Still builds. |

So the only free, unencumbered DNP3 master is a source build of an archived C++
library. **Measured** (this host, 8 cores, `-j4`, g++ 15.2, `-DDNP3_TLS=OFF`):
`cmake` configure + build of 3.1.2 with `-DDNP3_EXAMPLES=ON` took **53 s** and
produced a **34 MB** build tree containing `cpp/examples/master/master-demo`.
It compiles clean on a 2026 toolchain despite the 2022 freeze.

The compile is *not* the expensive part. The VM lane caches its guest on a hash
of the recipe (`scripts/vm/recipe.sh`), and that recipe text has exactly two
slots — an apt package list and a pinned pip list. A from-source master needs a
third: a pinned source (URL + tag + checksum, matching what
`fetch-images.sh` already does for the images) and a build command, threaded
through `recipe_text` and `provision-debian.exp`, plus `build-essential` and
`cmake` in the guest. That is a change to how the lane defines an image, not a
list edit — which is why it is still open rather than done.

To run the master by hand instead:

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
