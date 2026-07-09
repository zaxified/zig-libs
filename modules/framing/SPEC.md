# framing — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Two layers, one module:** length-prefixed stream framing (`writeFrame`/`readFrame`) plus a
  generic JSON tagged-union envelope codec (`EnvelopeCodec(T)`) on top.
- **Wire shape:** a 4-byte little-endian `u32` byte length, then that many raw payload bytes. This
  is length-prefixed, not newline-delimited — a payload may freely contain `\n`, `\r`, `NUL`, or
  any other byte. (The MCP stdio newline-delimited convention is a different framing, served by the
  `mcp` module instead.)
- **`EnvelopeCodec(T)`** requires `T` to be a `union(enum)` whose payload types are
  `std.json`-serializable; `std.json.Stringify` serializes a plain tagged union as a tag-keyed
  object `{"<tag>": {...}}` — the union tag *is* the message type on the wire, no separate
  discriminator field needed, even when a payload struct itself contains an inner `enum` field
  (serializes as its tag name, a plain JSON string).
- **`max_frame` is a runtime parameter** (`Limits{ .max_frame = ... }`, default 1 MiB), not a
  compile-time constant, enforced on both `writeFrame` (before touching the writer) and
  `readFrame` (checked against both the announced length and the caller's buffer capacity).
- Pure `std` (`std.Io.Writer`/`std.Io.Reader` + `std.json`), no allocation in the framing layer
  itself (the envelope layer allocates via the caller's `gpa`). Reentrant — no shared/global state.

## Threat model / out of scope

Not a security boundary by itself, but the framing is the parse-desync defense for anything built
on it: an oversize announced length is rejected before the body is read (`FrameTooLarge`, checked
against both `max_frame` and the caller's buffer, so a bogus length never blocks waiting for a
body that will not arrive or overruns the buffer). It does not authenticate, encrypt, or
compress payloads, and does not implement any transport (socket/pipe) itself — it operates on any
`std.Io.Reader`/`Writer`. Trust in the payload's contents is entirely the caller's/the consuming
codec's concern.

## Verification

10 tests, all on a domain-free test-only `union(enum)` (no application types imported): frame round-trip,
oversize rejection on both the write and read paths (incl. `max_frame` enforced independently of
buffer size), envelope round-trip (normal + empty payload), an enum-payload variant, a payload
with embedded newline/`\r\n`/`NUL` bytes (proving the framing is not newline-delimited), a full
envelope-through-wire-frame round-trip, and oversize rejection through `EnvelopeCodec.writeFramed`.
Verified green in Debug and ReleaseFast; `zig fmt --check` clean. Run: `zig build test-framing`.

## Backlog / deferred

- **None substantive**: `max_frame` is already parameterized and the
  tag-keyed union behavior is confirmed — no open gap recorded.

## Status

`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
