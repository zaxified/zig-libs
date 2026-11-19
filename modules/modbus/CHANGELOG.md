# modbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-19** — **Behaviour change:** FC 0x2B/0x0E Read Device Identification follows the spec text (V1.1b3 §6.21, checked against the PDF): read codes 2 and 3 now stream cumulatively from object 0 (basic + regular, resp. + extended) instead of their own category alone; reserved ids 0x07-0x7F and objects with an empty value are no longer served (pymodbus: same); conformity is derived from the served objects. `device_id.categoryRange` returns the cumulative walk (regular 0x00-0x06, extended 0x00-0xFF); `device_id.isReserved` is new. Also: the pymodbus 3.16.2 differential oracle has run (`tools/oracle.py`, offline): `src/oracle_vectors.zig` + `src/oracle_test.zig` replay FC 0x16 (byte-equal), FC 0x2B/0x0E (byte-equal except three counted spec departures of pymodbus) and `RtuStream` on pymodbus-built frames. Delta mutation over the changed code: 10/10 killed.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation audit of `root.zig` and `server.zig` (622 mutants, 606 killed, 16 argued equivalent or unobservable, none a finding) and the 22 tests it added (`src/audit_test.zig`, four `TcpTransport` tests in `src/root.zig`); SPEC "Audit 2026-11-19 (whole-module mutation)" and the card's mutation entry (606/622, 16 eq). Also `tools/oracle.py` and `tools/README.md`: a differential oracle driver for pymodbus 3.16.2 (FC 0x16, FC 0x2B/0x0E, RTU framing). **The driver has NOT been run yet**; its vectors and replay test do not exist, so FC 0x16, FC 0x2B/0x0E and `RtuStream` are still unverified against pymodbus bytes (see the UNVERIFIED notes).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** docs only: SPEC records the delta mutation run over the FC 0x16 / FC 0x2B/0x0E / `RtuStream` code (120 mutants, 117 killed, 3 argued equivalent).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** tests only (`RtuStream` reuse across feeds, `feed` taking exactly the free room, file-record sizing by byte count); one redundant length clause removed from the individual-access branch of the device-identification handler (the 244-byte PDU limit already covers it).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** tests only (device identification category edges, zero-length objects, page-break rules, 256-byte `RtuStream` frames, reset behaviour), added from the delta mutation run over the three new items.
- **2026-11-19** — New `RtuStream`: RTU-over-TCP stream reassembly over the `rtu` codec (`feed` / `next` / `reset`, role request or response, fixed buffer, resync on garbage or a bad CRC by dropping one byte). Additive; nothing existing changes. Tests: every function code in both roles split at every byte, several frames per read, leading garbage and a corrupted frame, bounded buffer.
- **2026-11-19** — **Behaviour change:** FC 0x2B/0x0E Read Device Identification. New `device_id` namespace (`encodeRequest`, `parseResponse`, `Response.objects()`, `ReadCode`, `categoryRange`, `conformityLevel`), `Client.readDeviceIdentification`, `FunctionCode.encapsulated_interface`; the server serves it from `Config.device_objects` / `device_id_individual`. With no table configured the answer stays `IllegalFunction`. Tests: byte-exact responses, categories, restart rule, pagination, the 253-byte boundary, malformed requests and responses, client-vs-server loopback.
- **2026-11-19** — **Behaviour change:** FC 0x16 Mask Write Register. New `pdu.encodeMaskWriteRegister` / `applyMask` / `parseMaskWriteResponse`, `Client.maskWriteRegister`, `FunctionCode.mask_write_register`; the server now serves it (was `IllegalFunction`; `Config.mask_write_register = false` restores that). Tests: spec §6.16 KAT, window edges, wrong lengths, write hook, client-vs-server loopback incl. RTU broadcast.
- **2026-11-08** — **NO CONSUMER-VISIBLE CHANGE:** the private CRC-16 table and byte loop are replaced by `std.hash.crc` (`CRC-16/DNP` resp. `CRC-16/MODBUS`); same checksums (reveng check values and the module vectors are unchanged).
- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC brought up to Zig 0.17.0 (version statements, snippets, measurement labels).

- **2026-10-18** — Example only (big-endian): the peer address in `example/main.zig` was `@bitCast(in.addr)` to `[4]u8`, little-endian-logical in Zig 0.17 and so octet-reversed on big-endian; now `std.mem.toBytes` (memory = network order).
- **2026-10-18** — Ported to Zig 0.17.0. Test-only `ReadCueIo` now hooks `Io.VTable.operate` and counts `Operation.net_read` (`netRead` left the vtable).
- **2026-10-10** — tests: deterministic fuzz driver `MODBUS_FUZZ` over the existing harnesses (now generic over their choice source; the driver draws a corpus entry with 0-3 octets damaged, maybe truncated) with an in-suite reach test per harness. Harnesses: `decodeAdu`, `server`. Verdict: 200,000 runs each, ReleaseSafe, clean.
- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The two `TcpTransport` cancel tests
  canceled after a fixed sleep. On a loaded machine that could land in the request write instead,
  and the test then passed by that arm. Both now cancel once the exchange is inside its reply read
  (`ReadCueIo`, a `std.Io` double that counts `netRead` entries). The `timeout_ms = null` test keeps
  its 300 ms window after that event, because the window is what it asserts.

- **2026-09-10** — **A1 fix campaign, E1/E2 (examples backlog).** `TcpTransport` had no
  read deadline anywhere: `exchangeFn` ran `readSliceAll` straight through
  `std.Io.net.Stream.Reader` with nothing bounding it, so a peer that legitimately stays
  silent — `Server.handleAdu` returns `null` for a foreign unit, a broadcast, a bad CRC,
  or listen-only — parked the caller forever, and `TransportError.Timeout` was a value
  this transport could never produce. Measured against a live peer before the fix: the
  same client/server pair took 0.108 s when addressed correctly and hit a hard
  `timeout -s KILL 30` (exit 124, 30.038 s) when addressed to a silent unit. `TcpTransport`
  now has an additive `timeout_ms: ?u32 = null` field (default preserves today's unbounded
  behaviour byte for byte — no existing caller's behaviour changes); when set, one
  `exchange` (write + read) is bounded by running it on its own concurrent task and
  canceling that task at the deadline, the same `runBounded` construction `dns.Resolver`,
  `http.Client` and `whois.TcpTransport` already use for the identical std 0.16.0 gap (no
  per-read deadline on a `net.Stream`). New regression test
  `TcpTransport: timeout_ms bounds a silent peer (audit E1)`: a silent peer plus
  `timeout_ms = 80` returns `error.Timeout` in 50–5000 ms instead of hanging; a sibling
  test pins the `null` default to the pre-existing unbounded behaviour. Also (E2):
  `Client.exchangePdu` was private while `FunctionCode`'s doc comment told callers who
  need one of the three server-only PDUs to "build it by hand and use `Client`'s framing"
  — a promise the code could not keep (the module's own example had to duplicate the
  twelve lines as `rawExchange` to get the transaction-id and unit checks right). Made
  `pub` (P2: code now matches the documented promise); no signature changed.

- **2026-09-07** — Fuzz reach: neither fuzz target ever handled a frame. `fuzzDecodeAdu`
  opened `smith.bytes(&buf)` and then drew the length with `smith.valueRangeAtMost`;
  `bytes` consumes `@min(buf.len, in.len)` octets and a ranged draw reads EIGHT more as a
  little-endian `u64`, returning the range MINIMUM when fewer remain, so the length was 0
  — and with no corpus the one input it ever ran was empty, so both `decodeAdu`s answered
  `ShortFrame` on their first line and all four PDU response parsers got a zero-length
  slice. `fuzzServer` was worse: its FIRST draw was `smith.value(bool)`, the framing
  choice, so the `.tcp` arm was **never once constructed**, `len` was 0, the "half the
  budget goes to PDUs that start with a real function code" branch never ran (its gate is
  `len > 0`), and `handlePdu("")` was the whole target. Measured 2026-09-07: 1 round
  each, 0 frames decoded, 0 function codes dispatched. Both now draw byte-first with one
  `smith.slice`. `fuzzServer` has no knobs left at all — every input runs through BOTH
  framings, which is more coverage than the coin flip could give, and the function codes
  are written down in a corpus of 19 request PDUs instead of drawn after the bytes were
  eaten. `fuzzDecodeAdu` carries 20 real frames: MBAP requests whose length field agrees
  (and two where it does not), RTU frames with a correct CRC-16 (and one without), and
  response PDUs sized to the harness's own `[125]u16` / `[64]bool` out slices — ⚠ the
  smaller response seeds written first were refused with `MalformedResponse`, because
  those parsers demand `payload[0] == 2 * out.len`. ⚠ The server guard pins reply octets,
  not "it answered": `handlePdu("")` returns a legal two-octet exception reply, so the
  harness's own `reply.len >= 2` assertion was true throughout. Pinned: 6 TCP / 3 RTU
  decodes over 48 PDU octets and 4 response parses; 512 reply octets and 12 exception
  replies across both framings.

- **2026-09-02** — **Audit (drift campaign): 2 MEDIUM, 2 LOW.** ⭐ No live memory-safety or
  wrong-answer defect was reachable from the wire: every wire-driven index, byte count and
  quantity in `server.zig` is bounded correctly, and coil packing was checked against an
  independently written bit-by-bit reference over every span (quantity 1..200 × 43 offsets) —
  byte-identical. What the audit found is guards nothing tested, and a mode that talked.
  **MEDIUM — four of the guards between a peer PDU and the process image had NO test**: FC 0x10's
  address window, and FC 0x17's `body.len != 9 + byte_count` plus both address windows. Each one
  disabled separately left the suite green at 77/77, while the frames that reach them panic in
  Debug and, in ReleaseFast, write to the wrong register or store bytes read past the request
  frame — and answer the master with a positive reply. The `index(addr).?` after each `contains`
  is a `runtime_safety`-only net, so ReleaseFast catches none of it. Pinned now, one crafted frame
  each; the SPEC "Threat model" section claimed this coverage and it was true of the code, not of
  the tests.
  **MEDIUM — listen-only mode transmitted.** Only the frame that ENTERED the mode was suppressed,
  so any PDU matching the restart sub-function received while already muted was answered — a
  malformed one put an exception frame (`05 88 03 47 C0`) on a bus the device is supposed to be
  silent on. V1.1b3 §6.8 sub 01: "If the port is currently in Listen Only Mode, no response is
  returned." The existing test pinned the wrong behaviour and is corrected.
  **LOW, BEHAVIOURAL — `force listen only mode` is refused over TCP** (`illegal function`). The
  spec marks FC 08 serial-line-only, and over TCP it was an unauthenticated twelve-byte permanent
  denial of service for every master on every connection. Echo and the counters are untouched on
  both framings.
  **LOW — the read-limit ↔ reply-buffer coupling is now asserted in every build.** Nothing tied
  `max_read_registers`/`max_rw_read_registers` to the 253-byte reply buffer they bound. Raising
  `max_rw_read_registers` 125→250 panics in Debug and, in **ReleaseFast, writes 402 bytes into a
  253-byte stack buffer with no panic at all** — so the 2026-08-10 record's claim that "the
  failure mode really is a safety panic rather than silent corruption" held only in Debug.

- **2026-08-23** — **Breaking:** `packBits` and `unpackBits` return
  `error{BufferTooSmall}!` instead of a plain value/`void`. Both used to
  guard their caller-supplied `dst`/`src` buffer with `std.debug.assert`
  before indexing it (`dst[i / 8] |= ...` / `src[i / 8] & ...`); ReleaseFast
  compiles the assert (and the bounds check on those indexes) out together,
  so a buffer undersized relative to `bitByteCount` was a silent
  out-of-bounds write/read in the build that ships. Found by an audit sweep
  for this shape.
- **2026-08-23** — `example/main.zig` became `modbus-demo`, one binary with two
  modes (`server` and `client`) that exchange real frames over a real TCP
  socket instead of an in-process loopback. The server half is the listen /
  accept / delimit-MBAP / dispatch loop the module deliberately does not ship
  (`handleAdu` is a pure function by design); the client half reads all four
  data areas, writes a coil and registers, builds the three server-only PDUs
  (0x07, 0x08, 0x11) by hand, and provokes an exception. Cross-checked live
  against pymodbus 3.14.0 in both directions — its `ModbusTcpClient` against
  our server, our client against its `ModbusTcpServer`. Two gaps the demo
  surfaced, both documented in the example rather than worked around:
  `Client.exchangePdu` is private, so "use `Client`'s framing" for a
  hand-built PDU means re-implementing it; and `TcpTransport` has no read
  deadline, so a master blocks forever whenever a slave legitimately stays
  silent (`TransportError.Timeout` is unreachable through that transport).
- **2026-08-22** — `TransportError` gained a `Canceled` variant so a `std.Io`
  cancellation (`Future.cancel`) surfaces distinctly from `TransportFailed`
  and from `Timeout`. `TcpTransport.exchangeFn` recovers it from the concrete
  reader's/writer's out-of-band `err` field instead of collapsing every
  failure into `TransportFailed`.
- **2026-08-11** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Byte-exact
  vs the Modbus Application Protocol V1.1b3 worked wire examples for
  FC01/02/03/04/05/06/0F/10/17 (`root.zig:721`– `822`) and vs the reveng CRC-catalogue
  check.
- **2026-07-07** — New module: Modbus TCP (MBAP) + RTU (CRC-16) codec, master client and
  slave server — core function codes, diagnostics, exceptions, broadcast/unit-id
  semantics, transport-agnostic seam.
