# iec104

Pure-Zig **IEC 60870-5-104 telecontrol**: the TCP/IP profile of IEC 60870-5-101
that European power grids run their SCADA on, between control centres
(controlling stations) and RTUs (controlled stations). A typed, allocation-free
wire codec, the k/w/t0..t3 flow-control state machine as a pure time-injected
machine, a controlling-station client and a controlled-station outstation that
doubles as a fleet-simulation target.

- No pure-Zig IEC 60870-5-104 library exists; the field is C (`lib60870`) and
  its bindings.
- **Platform:** any (the codecs and the state machine are pure computation;
  only the optional `TcpTransport` adapter touches `std.Io.net`).
- **Model after:** IEC 60870-5-104 + IEC 60870-5-101, with wire behaviour
  cross-checked against captured traffic between two independent third-party
  stacks (see SPEC.md).

## Scope

- **`apci`** (§5.1–§5.3) — the fixed six-octet header: start octet `0x68`, the
  length octet (which counts everything *after itself* and is capped at 253),
  and the four control octets selecting one of three formats:
  - **I-format** (information transfer) carrying an ASDU and both 15-bit
    sequence numbers `N(S)`/`N(R)`,
  - **S-format** (supervisory) acknowledging with `N(R)` only,
  - **U-format** (unnumbered): `STARTDT`/`STOPDT`/`TESTFR`, act or con.

  Plus `Framer`, a stream splitter — TCP has no message boundaries, so a read
  may deliver half a frame or three.
- **`state`** (§5.4–§5.6, §9.6) — **the heart of the protocol**: `k` maximum
  outstanding I-frames, acknowledge at the latest after `w` received ones, and
  the four timers `t0` (connect), `t1` (send-or-test), `t2` (acknowledge when
  idle, must be `< t1`), `t3` (idle test). It is a **pure, time-injected**
  state machine: the caller supplies `now_ms` and performs the I/O `tick` asks
  for. There is no clock, no thread and no socket inside, so k/w exhaustion,
  the **15-bit sequence wrap at 32768** and every timer are testable with a
  fake clock. Config validation refuses `w > k` and `t2 >= t1`.
- **`info`** (IEC 60870-5-101 §7.2.6) — the information elements: the quality
  descriptor (`IV`/`NT`/`SB`/`BL`/`OV`), the point values (SIQ, DIQ, VTI, BSI,
  NVA, SVA, IEEE-754 short float, BCR), the command qualifiers (SCO, DCO, RCO,
  QOS, QOI, QCC, QRP, COI) with the **S/E bit** that carries
  select-before-operate, and the `CP56Time2a`/`CP24Time2a`/`CP16Time2a` time
  tags — including the IV and summer-time flags and the fact that milliseconds
  and seconds **share one 16-bit field**. Impossible fields (minute 60, month
  13, …) are typed errors on both encode and decode.
- **`asdu`** (§7.2) — the data unit identifier (type id; the variable structure
  qualifier with its **SQ bit** and 7-bit count; the cause of transmission with
  the P/N and T bits and the originator address; the common address) plus the
  information objects. The **SQ bit changes the layout entirely** — `SQ = 0` is
  one address per object, `SQ = 1` is one address followed by bare elements at
  consecutive addresses — and both are encoded and decoded. Type ids modelled:
  monitoring 1–16, 20, 21, 30–37; control 45–51 and 58–64; system 70 and
  100–107; parameter 110–113 (recognised, elements passed through).
- **Address sizing is per system, not per standard.** The information-object
  address (1–3 octets), the common address (1–2) and the originator octet are
  explicit `Params`, never baked-in constants. `default_params` is the
  3/2/with-originator profile IEC 60870-5-104 fixes.
- **`client`** — a controlling station: connect, `STARTDT`, general and group
  interrogation, counter interrogation, monitoring-data reception, commands
  with **select-before-operate**, clock synchronisation, read and test
  commands, `STOPDT`.
- **`outstation`** — a controlled station: a point database that answers all of
  the above (including the "unknown …" causes of transmission a real RTU
  produces), plus `OutstationServer`, a complete peer that owns the framing,
  the flow control and a reply queue so an interrogation larger than `k` drains
  as the master acknowledges. Stand up one per simulated RTU for fleet
  simulation.
- Hostile input never panics anywhere: truncated APCI, a length octet that
  disagrees with the payload, a length above 253, an object count that
  disagrees with the body, an unknown type id, an impossible `CP56Time2a` and a
  sequence number outside the window are all typed errors.

## Use

```zig
const iec104 = @import("iec104");

// ── controlling station ─────────────────────────────────────────────────────
var tt = try iec104.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();
var frames: [iec104.apci.max_apdu_len * 2]u8 = undefined;
var master = try iec104.Client.init(tt.transport(), &frames, .{});

master.beginConnect(now);
master.onConnected(now);
try master.startDataTransfer(now);           // STARTDT act

while (true) : (now = clock()) {
    switch (try master.poll(now)) {          // drives t1/t2/t3 and the acks
        .started => try master.interrogate(47, .station, now),
        .asdu => |a| {
            var it = a.objects();
            while (try it.next()) |o| use(a.header.type_id, o.ioa, o.element, o.time);
        },
        .closed => break,                    // a protocol timeout fired
        else => {},
    }
}

// select-before-operate: the same command twice, differing in one bit
try master.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .select } }, .none, now);
// ... after the positive activation confirmation arrives ...
try master.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .execute } }, .none, now);

// ── controlled station (RTU / fleet-simulation target) ──────────────────────
var points = [_]iec104.Point{
    .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
    .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 3.14159, .quality = .{} } } },
    .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .select_and_execute },
};
var queue: [16 * 1024]u8 = undefined;
var rtu = try iec104.OutstationServer.init(
    .{ .common_address = 47 }, &points, transport, &frames, &queue, .{},
);
rtu.onConnected(now);
while (true) : (now = clock()) _ = try rtu.poll(now);
```

The pure layers are usable on their own — `apci.decode`/`apci.encode` for a
frame, `asdu.decode`/`asdu.Builder` for a payload, `state.Connection` for the
flow control with your own I/O.

## Verify

```
zig build test-iec104                          # Debug
zig build test-iec104 -Doptimize=ReleaseFast
zig fmt --check modules/iec104
```

The suite runs fully offline except for the live tests below, which skip
gracefully (printing `SKIPPED:` and passing) when no peer is present:

```
IEC104_TEST_SERVER=host:port  IEC104_TEST_CA=47   # our client -> a real RTU
IEC104_TEST_LISTEN=host:port                      # a real master -> our RTU
```

The offline suite includes **72 byte-exact goldens captured from real traffic
between two independent third-party implementations** — every one of them
decodes and re-encodes to the identical octets — plus the k/w and t0..t3 state
machine driven by a fake clock (including a full 32768-frame sequence-wrap
cycle), full master↔outstation round trips over an in-memory wire, and
`std.testing.fuzz` sweeps over the APCI decoder, the stream framer, the ASDU
decoder, `CP56Time2a` and the outstation's request handler. See SPEC.md for
what is third-party-validated versus self-derived, and what is deferred.

Provenance: clean-room from the IEC 60870-5-104 / IEC 60870-5-101 frame
layouts. No third-party source was consulted; a third-party stack was used as a
black-box test oracle only. See SPEC.md and `/NOTICE`.
