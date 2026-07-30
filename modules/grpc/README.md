# grpc

A **gRPC client** over HTTP/2, per the [`grpc-over-http2`](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
protocol specification. It is the third piece of a stack whose other two already live here:
the multiplexing HTTP/2 client in [`http`](../http) carries the bytes, [`protobuf`](../protobuf)
codes the messages, and this module is the layer between them — the five-byte
Length-Prefixed-Message envelope, the header/trailer contract, the status, and the metadata.
There is **no code generation**: a service method is a path string and its messages are ordinary
Zig structs with a `pb_fields` descriptor.

- **Model after:** the published `grpc-over-http2` protocol specification. Verified live against
  **Python `grpcio` 1.83** (the reference implementation), which is also the first third-party
  HTTP/2 peer the `http` module's h2 client has talked to.
- **Platform:** any. **Role:** client. **Concurrency:** single-owner (one task drives a channel).
- **Deps:** `http`, `protobuf`.

Provenance: the `grpc-over-http2` protocol specification is a public specification (merger
doctrine — CONVENTIONS.md §5); clean-room, no gRPC implementation source ported or studied. The
Python `grpcio` package is run as a black-box test oracle only. No NOTICE entry needed.

**Client only.** There is no gRPC server here, and that is a scope decision with a concrete
cause — see [SPEC.md](SPEC.md).

## Quick start

```zig
const grpc = @import("grpc");
const pb = @import("protobuf");

const EchoRequest = struct {
    text: []const u8 = "",
    count: i32 = 0,
    pub const pb_fields = .{
        .text  = pb.Field{ .number = 1, .kind = .string },
        .count = pb.Field{ .number = 2, .kind = .int32 },
    };
};
const EchoReply = struct {
    text: []const u8 = "",
    index: i32 = 0,
    pub const pb_fields = .{
        .text  = pb.Field{ .number = 1, .kind = .string },
        .index = pb.Field{ .number = 2, .kind = .int32 },
    };
};

var client = http.Client.init(io, gpa, .{});
defer client.deinit();
const hs = try client.connectH2c("127.0.0.1", 50051, .{});
defer hs.close();

var ch = grpc.Channel.overH2Session(hs, .{});

var reply = try grpc.unary(EchoRequest, EchoReply, &ch,
    "/echo.Echo/Unary", .{ .text = "hi", .count = 7 }, .{});
defer reply.deinit();
// reply.value.text
```

Over TLS: do the handshake with your own TLS library offering `http.alpn_offer`, and when ALPN
selects `h2`, hand the plaintext reader/writer to `http.Client.connectH2Over`; then set
`.scheme = "https"` in `grpc.Options`. The `http` module is BYO-TLS throughout
(CONVENTIONS.md §2) and this module inherits that seam unchanged.

## The four call shapes

`grpc.Stream(Req, Rep)` covers all of them, because on the wire they are the same thing — only
the service contract differs. `grpc.unary` is a convenience over it.

```zig
const Echo = grpc.Stream(EchoRequest, EchoReply);

// server-streaming: one request, many replies
var s = try Echo.start(&ch, "/echo.Echo/ServerStream", .{});
defer s.deinit();
try s.sendEnd(.{ .text = "tick", .count = 5 });
while (try s.receive()) |*r| { defer @constCast(r).deinit(); use(r.value); }
try s.finish();

// client-streaming: many requests, one reply
var c = try Echo.start(&ch, "/echo.Echo/ClientStream", .{});
defer c.deinit();
try c.send(.{ .text = "a" });
try c.send(.{ .text = "b" });
try c.closeSend();
var reply = (try c.receive()).?;

// bidirectional: interleave freely — both halves stay open
var b = try Echo.start(&ch, "/echo.Echo/Bidi", .{});
defer b.deinit();
try b.send(.{ .text = "one" });
var first = (try b.receive()).?;   // reply read before the next request goes out
```

`receive()` returns null when the response is complete; `finish()` then reports the status.
Any number of calls may be in flight on one channel at once — they are separate HTTP/2 streams
on one connection.

## Status and errors

A non-OK status is a **Zig error, one per code** (`error.NotFound`, `error.PermissionDenied`,
…), so it cannot be ignored the way a returned enum can. `grpc.Status` is the enum form
(non-exhaustive: the wire may carry a code from a newer spec revision), and
`grpc.statusToError` / `grpc.statusFromError` convert.

The human-readable `grpc-message` cannot ride in a Zig error value, so it stays on the call
(`call.statusMessage()`) — or is copied out through `CallOptions.failure`:

```zig
var failure: grpc.Failure = .{};
defer failure.deinit(gpa);
const r = grpc.unary(Req, Rep, &ch, "/svc/M", req, .{ .failure = &failure });
// r == error.PermissionDenied; failure.status == .permission_denied;
// failure.message is the decoded grpc-message ("denied: ☃", newlines and all)
```

`grpc-message` is percent-encoded on the wire and is decoded for you.

## Options

`grpc.Options` (per channel):

| Option | Default | Effect |
|---|---|---|
| `max_recv_message_size` | 4 MiB | Ceiling on one received message, checked against the *declared* length before any of its payload is accepted. Exceeding it fails the call `RESOURCE_EXHAUSTED`. |
| `max_send_message_size` | null | Local ceiling on one sent message. |
| `content_subtype` | `"proto"` | The `application/grpc+{subtype}` sent and required. |
| `user_agent` | `"grpc-zig-libs/0.1"` | null omits it. |
| `accept_encoding` | `"identity"` | `grpc-accept-encoding`. |
| `scheme` | `"http"` | `:scheme` — `"https"` over TLS. |
| `read_chunk` | 16 KiB | Read buffer size, not a message limit. |

`grpc.CallOptions` (per call): `timeout`, `metadata`, `failure`.

## Deadlines

```zig
.{ .timeout = grpc.Timeout.fromMillis(250) }          // → grpc-timeout: 250000u
.{ .timeout = .{ .value = 30, .unit = .seconds } }    // → grpc-timeout: 30S
```

The wire grammar allows **at most 8 digits** plus a unit (`H`/`M`/`S`/`m`/`u`/`n`), so a
duration is converted to the finest unit that still fits, always rounding **up** — rounding a
deadline down would cancel a call the caller still wanted.

## Metadata

```zig
.{ .metadata = &.{
    .{ .name = "authorization", .value = "Bearer …" },
    .{ .name = "x-trace-bin",   .value = &raw_bytes },  // -bin: raw, not base64
} }
```

A key ending in `-bin` carries arbitrary binary and is base64-encoded on the wire for you; the
base64 never appears in the API in either direction, and unpadded values are accepted on receive
(as the spec requires). Received metadata:

```zig
const v = call.metadataValue("x-echo");                    // wire form
const b = (try call.metadataValueDecoded("x-echo-bin")).?; // decoded; b.deinit(gpa)
```

Header names this layer owns (`grpc-timeout`, `content-type`, `te`, the pseudo-headers, …) are
refused with `error.ReservedMetadata` rather than duplicated onto the wire.

## Untyped calls

`grpc.Call` is the same engine with opaque byte messages — for a codec other than protobuf
(`content_subtype = "json"`, say), or a schema not known at compile time:

```zig
var call = try ch.start("/svc/M", .{});
defer call.deinit();
try call.sendMessage(my_bytes, true);
while (try call.receive()) |msg| { … }   // borrowed until the next receive
try call.finish();
```

`grpc.frame` exposes the Length-Prefixed-Message envelope on its own (`Deframer`,
`encodeAlloc`), which is also what gRPC-Web rides on.

## Verify

```bash
zig build test-grpc --summary all      # 82 tests
```

The interop tests drive **Python `grpcio`** as an external oracle: a real gRPC server is stood
up on an ephemeral loopback port and our client makes real calls against it — all four shapes, a
Trailers-Only failure, a status in a trailer section after a body, metadata both ways including
`-bin`, a deadline the reference reads back, a 256 KiB reply reassembled across DATA frames, and
the receive limit refusing an oversized one. They **skip loudly** (never silently, never as a
failure) when the interpreter or `grpcio` is missing; set `GRPC_PYTHON` to point at a virtualenv
and `ZIG_LIBS_VERBOSE_SKIP=1` to see skip reasons.

## Not implemented

Message **compression** (`grpc-encoding` other than `identity`) — a compressed frame is refused
with `INTERNAL` rather than handed to the decoder as if it were plaintext. **Retries**, **channel
load balancing / name resolution**, **`grpc-status-details-bin`** (the `google.rpc.Status`
detail payload), **gRPC-Web** framing, **reflection/health** services, and a **server**. See
SPEC.md for why each.
