# protobuf

Protocol Buffers **wire format** (proto3) — encode and decode — with the schema derived at
compile time from ordinary Zig structs. There is **no `.proto` compiler and no generated code**:
a message is a plain struct that declares `pub const pb_fields`, and the codec is specialised
from `@typeInfo`. Untrusted input is the design centre — every length-delimited field's declared
length is validated against the bytes actually present before it can size an allocation or bound
a loop, and embedded-message nesting is capped.

- **Model after:** [protocolbuffers/protobuf](https://github.com/protocolbuffers/protobuf) (the
  C++/Python reference implementation) and the published
  [encoding specification](https://protobuf.dev/programming-guides/encoding/). Verified live
  against the Python `protobuf` package, byte-for-byte, in both directions.
- **Platform:** any (pure logic, no I/O). **Role:** codec. **Concurrency:** reentrant (no shared
  state).
- **Deps:** none (std only).

Provenance: the protobuf encoding specification is a public specification (merger doctrine —
CONVENTIONS.md §5); clean-room, no third-party source ported. The Python `protobuf` package is
run as a black-box test oracle only. No NOTICE entry needed. Test data:
`src/testdata/reference.py` is this repo's own script (`SPDX-License-Identifier:
MIT`) that drives that oracle; it reproduces none of the `protobuf` package.

## Declaring a message

```zig
const protobuf = @import("protobuf");

const Address = struct {
    city: []const u8 = "",
    zip: u32 = 0,
    pub const pb_fields = .{
        .city = protobuf.Field{ .number = 1, .kind = .string },
        .zip  = protobuf.Field{ .number = 2, .kind = .uint32 },
    };
};

const Person = struct {
    name:   []const u8 = "",            // implicit presence
    id:     i32 = 0,
    score:  ?f64 = null,                // explicit presence ("optional")
    tags:   []const []const u8 = &.{},  // repeated
    scores: []const i32 = &.{},         // repeated, packed by default
    home:   ?Address = null,            // singular submessage
    unknown: protobuf.Unknown = .empty, // keep what we do not understand

    pub const pb_fields = .{
        .name   = protobuf.Field{ .number = 1, .kind = .string },
        .id     = protobuf.Field{ .number = 2, .kind = .int32 },
        .score  = protobuf.Field{ .number = 3, .kind = .double },
        .tags   = protobuf.Field{ .number = 4, .kind = .string },
        .scores = protobuf.Field{ .number = 5, .kind = .sint32 },
        .home   = protobuf.Field{ .number = 6, .kind = .message },
    };
};
```

**The descriptor names only the proto type; the Zig type carries the cardinality.**

| Zig field type | proto3 meaning |
|---|---|
| `T` | singular, *implicit* presence — omitted from the wire when it equals the type default |
| `?T` | singular, *explicit* presence (`optional`) — transmitted whenever non-null, zero or not |
| `[]const T` | `repeated` — packed by default for scalars, per proto3 |
| `?*const T` | singular submessage, boxed — the shape a self-recursive message needs |
| `protobuf.Unknown` | not a field: the sink for fields this build does not know (see below) |

`kind` covers every proto3 scalar: `.int32` `.int64` `.uint32` `.uint64` `.sint32` `.sint64`
`.bool` `.@"enum"` `.fixed32` `.fixed64` `.sfixed32` `.sfixed64` `.float` `.double` `.string`
`.bytes` `.message`. Each fixes the Zig element type (`.sint64` wants `i64`, `.fixed32` wants
`u32`, …); a mismatch is a compile error naming the field, as are a duplicate field number, a
number in the reserved 19000–19999 range, a field with no `pb_fields` entry, and a field with no
default value.

Enums must be declared `enum(i32)`, and should be **non-exhaustive** — proto3 enums are open, and
only `enum(i32) { …, _ }` can hold a value a newer peer invented:

```zig
const Color = enum(i32) { unspecified = 0, red = 1, green = 2, _ };
```

Repeated scalars are packed by default. `.{ .number = 5, .kind = .int32, .packed_encoding = false }`
opts a field out; the *decoder* always accepts both forms regardless, as the spec requires.

## Encoding

```zig
// Allocating: exactly-sized, caller owns it.
const bytes = try protobuf.encodeAlloc(gpa, person, .{});
defer gpa.free(bytes);

// Non-allocating: size first, then write into your own buffer.
const n = try protobuf.encodedSize(person, .{});      // also the gRPC frame length
var buf: [512]u8 = undefined;
const written = try protobuf.encodeInto(&buf, person, .{}); // error.NoSpaceLeft if short
```

`EncodeOptions` carries `max_depth` (default 64): a boxed self-recursive value can be arbitrarily
deep at run time, so the encoder is bounded too and returns `error.DepthExceeded` rather than
running out of stack.

## Decoding

```zig
var decoded = try protobuf.decode(Person, gpa, input, .{});
defer decoded.deinit();     // one arena owns every slice inside decoded.value
const name = decoded.value.name;
```

`DecodeOptions`:

| Option | Default | Effect |
|---|---|---|
| `max_depth` | 64 | Embedded-message nesting cap. `error.DepthExceeded` past it. |
| `copy_strings` | `true` | Copy `string`/`bytes` into the arena. Set `false` for a zero-copy decode whose slices alias `input` — then `input` must outlive the value and stay unmodified. |
| `reject_unknown_fields` | `false` | `error.UnknownField` instead of preserving/dropping. For a receiver that must not forward what it cannot check. |

Errors: `Truncated` (a declared length or a value ran past the end of the input),
`VarintOverflow` (a varint longer than 10 bytes, or one whose value will not fit a `u64`),
`FieldNumberZero`, `UnsupportedWireType` (groups — wire types 3/4 — and the two unassigned ones),
`DepthExceeded`, `InvalidEnumValue`, `UnknownField`, `OutOfMemory`.

## Unknown fields

Declare one field of type `protobuf.Unknown` and every field the schema does not describe is
captured **verbatim** — tag bytes and payload exactly as they arrived — and re-emitted on encode.
That is what lets an old build proxy a new peer's message without destroying it. Without the sink,
unknown fields are decoded and dropped.

```zig
var partial = try protobuf.decode(OldSchema, gpa, from_new_peer, .{});
defer partial.deinit();
const forwarded = try protobuf.encodeAlloc(gpa, partial.value, .{}); // still carries the rest
```

## Verify

```bash
zig build test-protobuf --summary all      # 59 tests
```

The interop tests (`reference_interop.zig`) drive the **Python `protobuf` package** (Google's own
implementation) as an external oracle: schemas are built at run time from `descriptor_pb2` +
`descriptor_pool` + `message_factory`, so neither a `.proto` file nor `protoc` is needed. They
compare our bytes with the reference's byte-for-byte, decode the reference's bytes with ours, and
hand the reference shapes it would never emit itself. They **skip loudly** (never silently, never
as a failure) when `python3` or the package is missing — set `ZIG_LIBS_VERBOSE_SKIP=1` to see the
reason.

`golden_test.zig` freezes the same anchor for every machine that lacks the reference package
(including CI, which always does): 36 cases' worth of bytes that the reference package actually
produced were captured once into `testdata/golden_bytes.zig` and are checked byte-for-byte both
ways — no python3, no subprocess, no skip path. See that file's doc comment for the exact
capture recipe and for what stays live-only and why.

## Not implemented

Groups (wire types 3/4, removed in proto3), `map<k,v>` (its wire form is a repeated submessage;
express it that way for now), `Any`/`oneof`/well-known types, the canonical JSON mapping, and
`.proto`-to-Zig code generation. See SPEC.md for why each, and for the threat model.
