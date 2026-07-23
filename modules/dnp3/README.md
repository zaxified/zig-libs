# dnp3

Pure-Zig **DNP3 (IEEE 1815-2012)**: the Data Link Layer, the Transport
Function, the Application Layer and the object library as pure codecs — plus a
complete **outstation** built on top of them. The master role is the codecs
(build request / parse response); the outstation role is a real stateful
responder with IIN handling, event buffering, select-before-operate and
fragmentation. Feeds SCADA/utility fleet-simulation now; real RTU
monitoring/control is a later consumer.

- No mature pure-Zig DNP3 library exists.
- **Platform:** any — every codec is a pure function over byte slices, no
  allocation, no I/O. Wiring to a real transport (TCP or serial) is left to
  the caller.
- **Model after:** IEEE 1815-2012; structure/behavior cross-referenced
  against opendnp3 (Apache-2.0) and public DNP3 primers — no source
  consulted or copied.

## Scope

Implemented:

- **`link`** (§9) — the 0x0564 fixed frame: start bytes, length, the control
  octet (DIR/PRM/FCB/FCV + a 4-bit function code), 16-bit dest/source link
  addresses, and the **DNP3 CRC-16** (poly 0x3D65) over the 8-byte header
  block and each ≤16-byte user-data block.
- **`transport`** (§8) — the single transport octet (FIN/FIR + a 6-bit
  sequence number); `Segmenter` splits an application fragment into
  link-sized chunks, `Reassembler` puts them back together, enforcing the
  FIR/sequence rules.
- **`application`** (§4/§5) — the application control octet (FIR/FIN/CON/UNS
  + a 4-bit sequence), the function-code byte (CONFIRM, READ, WRITE, SELECT,
  OPERATE, DIRECT_OPERATE, RESPONSE, UNSOLICITED_RESPONSE, …), and the
  2-byte Internal Indications (IIN) bitfield carried in responses.
- **`objects`** — the object-header framing (group/variation + qualifier +
  range: start-stop, all-values, count, count+index-prefix) and a core
  static object library: binary input (g1), binary output status + CROB
  (g10/g12), binary counter (g20), analog input (g30), analog output status
  + block (g40/g41), time-and-date (g50), and class-data read markers (g60).
- **`records`** — a table-driven codec for the ~40 group/variation pairs an
  outstation actually has to emit. A variation is described as a *layout*
  (does it carry a flags octet, what width and type is the value, does a
  timestamp follow) rather than a hand-written struct: binary (g1/g2),
  double-bit binary (g3/g4), binary output status (g10/g11), counter
  (g20/g22), frozen counter (g21/g23), analog input (g30/g32) and analog
  output status (g40/g42), in the with-flags / without-flags / 16-bit /
  32-bit / float / absolute-time / relative-time shapes, including the
  packed single-bit and packed double-bit forms.
- **`outstation`** — the responder. `handle(request, now_ms, out) -> ?Reply`
  is a pure function from one application fragment to one application
  fragment over a caller-owned point database; `Session` wraps it in the
  transport function and the data-link layer so a caller can feed whole link
  frames. No threads, no owned timers, no allocation; every deadline is
  driven by an injected clock. Specifically:
  - **Function codes:** READ (class 0/1/2/3 polls and specific
    group/variation reads), WRITE (clear the restart IIN, set time),
    SELECT / OPERATE / DIRECT_OPERATE / DIRECT_OPERATE_NO_ACK for CROB (g12)
    and analog output blocks (g41), COLD_RESTART, WARM_RESTART,
    DELAY_MEASURE, ENABLE / DISABLE_UNSOLICITED, IMMEDIATE_FREEZE (+ no-ack
    and freeze-clear), ASSIGN_CLASS, RECORD_CURRENT_TIME and CONFIRM.
    Anything else answers IIN2.FUNC_NOT_SUPPORTED.
  - **IIN:** device restart (set at power-up, cleared only by an explicit
    WRITE of g80v1 index 7), class 1/2/3 events available, need-time, event
    buffer overflow, local control, device trouble, plus the per-request
    func-not-supported / object-unknown / parameter-error bits.
  - **Events:** a bounded caller-owned ring, reported oldest-first with the
    right event group and variation and an index prefix, retired only when
    the master's CONFIRM arrives. A response carrying events always sets CON.
    Overflow drops the oldest and latches IIN2.3 until the buffer drains.
    `confirmTimedOut()` puts the in-flight events back on the queue.
  - **Select-before-operate:** the select is remembered with its arm time and
    its exact object bytes; an OPERATE with the wrong sequence number or
    different objects is `NO_SELECT`, one that arrives after
    `select_timeout_ms` is `TIMEOUT`, and neither executes.
  - **Fragmentation:** a response too large for `max_tx_fragment` splits with
    correct FIR/FIN and an **incrementing** application sequence number, each
    non-final fragment asking for a confirm; `next()` produces the following
    one. The transport layer below segments consistently.
  - **Unsolicited responses:** `unsolicited()` builds the fragment (UNS + CON
    set, its own sequence counter, suppressed while one is unconfirmed or
    while the restart IIN is set). The *retry timer* is the caller's.
- Malformed/short/corrupt bytes never panic anywhere in `link`/`transport`/
  `application`/`objects`/`records`/`outstation` — every decode path returns
  a typed error, and every hostile request fragment becomes a response with
  the right IIN bits set.

**Secure Authentication — `sa` (SAv2 symmetric core, g120):** AES Key Wrap
(RFC 3394, byte-exact against the published vectors), the SA MAC-algorithm
registry (HMAC-SHA-1/SHA-256 truncated, AES-GMAC, constant-time verify), the
g120 v1/v2/v3/v4/v5/v6/v7/v9 message codecs, the challenge-response MAC-input
construction, and session-key wrap/unwrap + CSQ/KSQ/expiry state helpers. The
SAv5/SAv6 asymmetric update-key change (g120 v8/v10–v15: RSA/DSA +
certificates) is out of scope — see `sa.zig`'s doc comment and SPEC.md for
exactly what is implemented and validated against what.

## Deferred

Honest list of what this module does **not** do:

- **Unsolicited retry policy.** The fragment builder is here; the retry timer
  and back-off are the caller's, driven through `confirmTimedOut()`.
- **File transfer (g70), data sets (g85–g88), device attributes (g0), octet
  strings (g110/g111), time-and-interval (g50v4), analog deadbands (g34),
  time-synchronisation with delay compensation (g50v2/g51).**
- **Secure Authentication integration.** `sa.zig` is a complete SAv2
  symmetric codec, but nothing in `outstation.zig` wraps a fragment in g120
  objects yet.
- **Data-link confirmed user data.** The outstation answers RESET_LINK_STATES,
  TEST_LINK_STATES and REQUEST_LINK_STATUS, and accepts both confirmed and
  unconfirmed user data, but always sends its own frames as *unconfirmed*
  user data. The FCB/FCV toggle is decoded, not enforced.
- **Actual transport I/O.** `Session` produces and consumes byte slices;
  running it over TCP or a serial port (or over a simulated fleet) is the
  caller's job.
- **A stateful master session.** The master role is still the pure codecs —
  no poll scheduler, no task queue, no response-timeout state machine.
- **Relative-time event variations (g2v3, g4v3)** are encodable by
  `records`, but the outstation never chooses them: it emits absolute time.

## Use

```zig
const dnp3 = @import("dnp3");

// -- master: build a READ request for Analog Input (g30v1), points 0-3 --
var req_buf: [16]u8 = undefined;
const request = try dnp3.application.buildRequest(1, .read, .{
    .group = 30,
    .variation = 1,
    .qualifier = .{ .prefix_code = .none, .range_code = .start_stop_1b },
    .range = .{ .start_stop = .{ .start = 0, .stop = 3 } },
}, &req_buf);

// hand `request` to the transport function + link layer for the wire:
var wire_buf: [64]u8 = undefined;
const control = dnp3.link.Control{
    .dir = true, .prm = true, .fcv_or_dfc = true,
    .function = @intFromEnum(dnp3.link.PrimaryFunction.unconfirmed_user_data),
};
const frames = try dnp3.sendFragment(control, dest_addr, src_addr, request, &wire_buf);
// frames is ready to write to a socket/serial port.

// -- outstation: reassemble frames back into the request, then parse it --
var reasm_buf: [64]u8 = undefined;
var receiver = dnp3.FrameReceiver.init(&reasm_buf);
var scratch: [64]u8 = undefined;
const fragment = (try receiver.feedFrame(frames, &scratch)).?;
const req = try dnp3.application.decodeRequestHeader(fragment);
const obj = try dnp3.objects.decodeObjectHeader(req.rest);
// obj.header.group == 30, obj.header.range.objectCount() == 4
```

### Outstation

```zig
var binaries = [_]dnp3.outstation.BinaryInput{.{ .class = .class1 }} ** 8;
var analogs = [_]dnp3.outstation.AnalogInput{.{ .class = .class2 }} ** 4;
var event_storage: [64]dnp3.outstation.Event = undefined;

var station = dnp3.outstation.Outstation.init(.{
    .address = 10,
    .master_address = 1,
    .select_timeout_ms = 10_000,
}, .{
    .binary_inputs = &binaries,
    .analog_inputs = &analogs,
}, dnp3.outstation.EventBuffer.init(&event_storage));

// Drive the process image; the event is buffered with it.
station.update(.binary_input, 3, .{ .binary = true }, now_ms);

// Feed whole link frames, get whole link frames back.
var rx: [4096]u8 = undefined;
var scratch: [512]u8 = undefined;
var tx: [2048]u8 = undefined;
var session = dnp3.outstation.Session.init(&station, &rx, &scratch, &tx);

var out: [4096]u8 = undefined;
if (try session.feedFrame(frame_bytes, now_ms, &out)) |reply_frames| {
    // write `reply_frames` to the socket
}
```

Responses are built/parsed symmetrically with
`application.encodeResponseHeader`/`decodeResponseHeader` plus the relevant
`objects.gNN.VN.encode`/`.decode` for each point record. See
`src/root.zig`'s tests for a full master-builds/outstation-parses and
outstation-builds/master-parses round trip, including multi-frame
segmentation for fragments bigger than one link frame's user-data limit.

## Verify

```
zig build test-dnp3           # Debug
zig build test-dnp3 -Doptimize=ReleaseFast
zig fmt --check modules/dnp3
```

126 offline tests: DNP3 CRC-16 known-answer vectors (the reveng
CRC-catalogue "CRC-16/DNP" check value plus additional vectors cross-checked
against an independent from-scratch bit-serial CRC reference — see SPEC.md),
data-link frame round-trips (empty/short/exact-block-boundary/multi-block user
data), transport segmentation + reassembly (including sequence-mismatch and
FIR-restart edge cases), object-header qualifier/range round-trips for every
implemented range shape, every object variation's encode/decode round-trip,
and a full link→transport→application stack round-trip in both directions
(master↔outstation). The outstation is tested against every function code it
implements, the IIN bits, the event confirm/retire/timeout cycle, buffer
overflow, select-before-operate in all four failure modes, and multi-fragment
responses. Every decode path is exercised with short/corrupt/garbage input to
confirm it returns a typed error rather than panicking, and two
20 000-iteration fuzz loops drive random application fragments and random link
frames through the outstation and its `Session`.

**Interop (2026-07-23).** `src/goldens.zig` replays two sessions captured from
a live **opendnp3** peer (built from source):

1. *opendnp3's `master-demo` → this outstation*, over a real loopback TCP
   socket. Startup tasks, an integrity scan, an ad-hoc range scan, disable
   unsolicited, a CROB select+operate (opendnp3 reported
   `Received command result w/ summary: SUCCESS`), a class-1 exception scan
   across an injected process change, a cold restart (`Success, Time: 100`)
   and a second integrity scan — with no protocol warnings.
2. *The same master against a fragmented response*: 300 binary inputs with a
   400-byte fragment limit, so the class-0 scan spans several fragments that
   opendnp3 confirms and reassembles one by one.

Replaying either session in order reproduces every reply byte for byte,
including the 48-bit event timestamps (the tests advance the same injected
clock the harness did). A third capture runs the *reverse* direction: this
module's master-side codecs against opendnp3's `outstation-demo`, which
cross-checks the pre-existing parsers against a third-party encoder.

**Independent dissection.** The captured session was written to a pcap and
dissected with Wireshark 4.6.4's DNP3 dissector via `rawshark`. All 43 frames
dissected cleanly with zero malformed or expert-error indications, and every
field matched: DIR/PRM, link addresses, application function codes, FIR/FIN/
CON/SEQ, the IIN restart and class-1 bits, and every object identifier in the
class-0 response (0x0102, 0x0302, 0x0a02, 0x1401, 0x1501, 0x1e01, 0x2801).

Two real interop bugs were found and fixed this way — the outstation was
setting the link-layer DIR bit as if it were the master (opendnp3 logged
"master frame received for master" and dropped every reply), and continuation
fragments were reusing the request's application sequence number instead of
incrementing it ("Response with bad sequence").

Provenance: see `/NOTICE`.
