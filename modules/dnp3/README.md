# dnp3

Pure-Zig **DNP3 (IEEE 1815-2012) base protocol** codec: the Data Link Layer,
the Transport Function, and the Application Layer + a core object library —
for both **master** and **outstation** roles. Feeds SCADA/utility
fleet-simulation (outstation + master nodes) now; real RTU monitoring/control
is a later consumer.

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
- Malformed/short/corrupt bytes never panic anywhere in `link`/`transport`/
  `application`/`objects` — every decode path returns a typed error.

Both roles ride on the same pure codec functions — a master *builds*
requests and *parses* responses, an outstation *parses* requests and
*builds* responses — there is no separate "Master"/"Outstation" session
type in this base pass (no confirm/retry timers, no unsolicited-response
state machine).

**Secure Authentication — `sa` (SAv2 symmetric core, g120):** AES Key Wrap
(RFC 3394, byte-exact against the published vectors), the SA MAC-algorithm
registry (HMAC-SHA-1/SHA-256 truncated, AES-GMAC, constant-time verify), the
g120 v1/v2/v3/v4/v5/v6/v7/v9 message codecs, the challenge-response MAC-input
construction, and session-key wrap/unwrap + CSQ/KSQ/expiry state helpers. The
SAv5/SAv6 asymmetric update-key change (g120 v8/v10–v15: RSA/DSA +
certificates) is out of scope — see `sa.zig`'s doc comment and SPEC.md for
exactly what is implemented and validated against what.

Out of scope for this pass: event object variations (g2/g11/g22/g32/g42
etc.), file transfer, data sets, unsolicited-response confirmation/retry
state machines, and actual transport I/O.

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

51 offline tests: DNP3 CRC-16 known-answer vectors (the reveng CRC-catalogue
"CRC-16/DNP" check value plus additional vectors cross-checked against an
independent from-scratch bit-serial CRC reference — see SPEC.md), data-link
frame round-trips (empty/short/exact-block-boundary/multi-block user data),
transport segmentation + reassembly (including sequence-mismatch and
FIR-restart edge cases), object-header qualifier/range round-trips for every
implemented range shape, every core object's encode/decode round-trip, and a
full link→transport→application stack round-trip in both directions
(master↔outstation). Every decode path is exercised with short/corrupt/
garbage input to confirm it returns a typed error rather than panicking.

Provenance: see `/NOTICE`.
