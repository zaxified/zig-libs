# modbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
  Ledger: `~/CML/20260931-zig-libs-audit/modbus.md`.

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
