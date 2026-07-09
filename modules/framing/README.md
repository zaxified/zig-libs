# framing

Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON
tagged-union envelope codec (`EnvelopeCodec(T)`) on top — folds what used to
be two small seed files (`wire.zig` + `message.zig`) into one module.

Provenance: extracted from `axp-core/src/wire.zig` (framing) +
`axp-core/src/message.zig` (envelope codec, genericized from AXP's
domain-specific `Message` union to `EnvelopeCodec(comptime T: type)`) — same
author's own code, MIT.

- **Status:** extract. **Platform:** any (pure `std`: `std.Io.Writer`/
  `std.Io.Reader` + `std.json`; dependency-free). **Role:** codec.
- **Concurrency:** reentrant — no shared/global state.

## Wire shape

A 4-byte little-endian `u32` byte length, then that many raw payload bytes.
This is **length-prefixed** framing — the payload may contain `\n`, `\r`,
`NUL`, or any other byte; it is not newline-delimited. If you need
newline-delimited JSON (the MCP stdio convention: one JSON object + `\n` per
message), see the `mcp` module instead — this module does not serve MCP
transports.

## API

```zig
const framing = @import("framing");

// low-level framing, generic over any std.Io.Writer/Reader
var w: std.Io.Writer = ...;
try framing.writeFrame(&w, payload, .{}); // .{} = default_max_frame (1 MiB)
try framing.writeFrame(&w, payload, .{ .max_frame = 4096 }); // tighter cap

var r: std.Io.Reader = ...;
var buf: [1 << 20]u8 = undefined;
const payload = try framing.readFrame(&r, &buf, .{});

// generic JSON envelope over any union(enum) of json-serializable payloads
const Message = union(enum) {
    hello: struct { id: u64 },
    ack: struct { ref: u64 },
};
const Codec = framing.EnvelopeCodec(Message);

const bytes = try Codec.encodeAlloc(msg, gpa); // caller frees
defer gpa.free(bytes);
const parsed = try Codec.parse(gpa, bytes); // caller calls .deinit()
defer parsed.deinit();
try Codec.writeFramed(msg, gpa, &w, .{}); // encode + frame in one step
```

`std.json.Stringify` serializes a plain `union(enum)` as a tag-keyed object
`{"<tag>": {...}}` by default — the union tag *is* the message type on the
wire, no separate discriminator field needed. This holds even when a payload
struct itself contains an inner `enum` field (it serializes as its tag name,
a plain JSON string) — covered by the "enum-payload variant" test.

`max_frame` is a runtime parameter (`Limits{ .max_frame = ... }`, default
`default_max_frame` = 1 MiB) rather than a compile-time constant, enforced on
both `writeFrame` (before touching the writer) and `readFrame` (checked
against both the announced length and the caller's buffer capacity).

## Tests

`zig build test-framing` — 10 tests, all on a domain-free test-only
`union(enum)` (no AXP types imported): frame round-trip, oversize rejection
on both the write and read paths (incl. `max_frame` enforced independently of
buffer size), envelope round-trip (normal + empty payload), an enum-payload
variant, a payload with embedded newline/`\r\n`/`NUL` bytes (proving the
framing is not newline-delimited), a full envelope-through-wire-frame
round-trip, and oversize rejection through `EnvelopeCodec.writeFramed`.

Verified green: `zig build test-framing` (Debug) and
`zig build test-framing -Doptimize=ReleaseFast`; `zig fmt --check
modules/framing` clean.
