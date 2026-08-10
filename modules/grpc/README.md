# grpc

A **gRPC client and server** over HTTP/2, per the [`grpc-over-http2`](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
protocol specification. It is the third piece of a stack whose other two already live here:
the multiplexing HTTP/2 client and server in [`http`](../http) carry the bytes,
[`protobuf`](../protobuf) codes the messages, and this module is the layer between them — the
five-byte Length-Prefixed-Message envelope, the header/trailer contract, the status, and the
metadata. There is **no code generation**: a service method is a name and its messages are
ordinary Zig structs with a `pb_fields` descriptor.

- **Model after:** the published `grpc-over-http2` protocol specification. Verified live against
  **Python `grpcio` 1.83** (the reference implementation) in **both directions** — as the server
  our client calls, and as the client calling our server. It is also the first third-party
  HTTP/2 peer the `http` module's h2 client and h2 server have talked to.
- **Platform:** any. **Role:** both. **Concurrency:** single-owner (one task drives a channel;
  the server's handlers run on the connection's task).
- **Deps:** `http`, `protobuf`.

Provenance: the `grpc-over-http2` protocol specification and `doc/compression.md` are public
specifications (merger doctrine — CONVENTIONS.md §5); clean-room, no gRPC implementation source
ported or studied. The Python `grpcio` package is run as a black-box test oracle only. No NOTICE
entry needed.

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

## Server

```zig
const M = grpc.Methods(EchoRequest, EchoReply);

fn unary(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
    if (req.text.len == 0) return c.fail(.invalid_argument, "text is required");
    return .{ .text = try std.fmt.allocPrint(c.arena, "echo:{s}", .{req.text}) };
}
fn ticks(s: *M.Stream, req: EchoRequest) anyerror!void {
    var i: i32 = 0;
    while (i < req.count) : (i += 1) try s.send(.{ .index = i });
}

var router: grpc.Router = .{ .gpa = gpa, .services = &.{.{
    .name = "echo.Echo",
    .methods = &.{ M.unary("Unary", unary), M.serverStreaming("ServerStream", ticks) },
}} };

var srv = http.Server.init(io, gpa, router.httpOptions(.{
    .handler = grpc.handleHttp, .port = 50051,
}));
defer srv.deinit();
try srv.listen();
```

`Router.httpOptions` wires the handler, the context and the HTTP/2 streaming predicate together
— they all have to agree about which router they mean, and this is the one place that can
guarantee it. It forces `enable_h2c` on, because gRPC is HTTP/2 only. Over TLS, terminate it
yourself and call `http.h2_server.serveStream` with `Router.h2ServerOptions` instead.

**Registration is a data table, not comptime reflection.** `Service(MyImpl)` scanning a struct's
decls was rejected because the *call shape* cannot be read off a Zig signature without guessing:
`fn(*Stream) !Rep` could be client-streaming or a unary method that likes streams, and inferring
it means an accidental signature change silently rewrites a published method's wire contract.
Naming the shape at the call site makes a mismatched implementation a compile error instead. A
`.proto` service is data in every other gRPC stack, so a table also maps onto it one-to-one and
can be assembled at run time from configuration; the methods themselves stay comptime-typed.

The four constructors are `M.unary`, `M.serverStreaming`, `M.clientStreaming`,
`M.bidiStreaming`, plus `grpc.Method.raw` for opaque byte messages. A handler fails with
`return c.fail(.not_found, "…")` (or `c.failFmt`), reads request metadata with
`c.metadataValue`, sends its own with `c.addInitialMetadata` /
`c.declareTrailingMetadata` + `c.setTrailingMetadata`, and sees the client's deadline through
`c.remaining()` / `c.expired()`.

### The response contract

Two legal shapes, and they are not variants of each other:

| | frames |
|---|---|
| normal | `HEADERS(200, content-type, Trailer)` · `DATA…` · `HEADERS(grpc-status, …) END_STREAM` |
| Trailers-Only | `HEADERS(200, content-type, grpc-status, …) END_STREAM` — **one** field block, no DATA |

In the second, `grpc-status` is a *header*, not a trailer. A response is Trailers-Only exactly
when nothing has gone out ahead of the status — which includes a **successful** call that
produced no message, not only errors. There is one predicate for this (`head_committed`), it
flips in one place (`commitHead`, reached only from `send`/`sendInitialMetadata`), and that
place is the only caller of `ResponseWriter.declareTrailers`, so a response either has a trailer
section and went through it or does not and never did.

### Request validation

| condition | answer |
|---|---|
| `:method` is not POST | **405** + `Allow: POST` (HTTP, not gRPC — a gRPC error is HTTP 200) |
| `content-type` does not begin `application/grpc` | **415** (spec: SHOULD) |
| malformed path, unknown service, unknown method | `grpc-status` **12 UNIMPLEMENTED**, Trailers-Only |
| `grpc-encoding` this build cannot undo | **12 UNIMPLEMENTED** + `grpc-accept-encoding: identity` |
| malformed `grpc-timeout` | **13 INTERNAL** — never silently ignored |
| request message over `max_recv_message_size` | **8 RESOURCE_EXHAUSTED**, refused at the 5-byte header |

### Deadlines

`grpc-timeout` is parsed, surfaced (`c.remaining()`, `c.expired()`) and enforced at every engine
boundary — before dispatch, around each `receive`, before each `send`. It cannot be enforced
*during* a blocking body read: handlers run on the connection's task and the h2 request-body
reader has no deadline hook, so `http`'s own `read_timeout_ms` / `request_timeout_ms` are the
transport-level backstop. The clock is injected (`ServerOptions.clock`), so deadline tests are
exact and never sleep.

## Verify

```bash
zig build test-grpc --summary all
```

The interop tests drive **Python `grpcio`** as an external oracle in **both directions**:

- *our client → the reference server*: all four shapes, a Trailers-Only failure, a status in a
  trailer section after a body, metadata both ways including `-bin`, a deadline the reference
  reads back, a 256 KiB reply reassembled across DATA frames, and the receive limit refusing an
  oversized one;
- *the reference client → our server*: the same twelve observations, this time with everything
  **we produce** under a real parser — which is the stronger direction, because a client that
  mis-frames can still be understood by a lenient peer while a server that mis-frames cannot.

Offline, the server tests put an `h2.Connection` in client role on the other end of
`h2_server.serve` and assert on **frames**, not field values: how many HEADERS blocks, which one
carried END_STREAM, whether a DATA frame exists at all. That is the only way to see the
Trailers-Only distinction, since both shapes use the same field names.

All of them **skip loudly** (never silently, never as a failure) when the interpreter or
`grpcio` is missing; set `GRPC_PYTHON` to point at a virtualenv and `ZIG_LIBS_VERBOSE_SKIP=1` to
see skip reasons.

## Not implemented

Message **compression** (`grpc-encoding` other than `identity`) — a compressed frame is refused
rather than handed to the decoder as if it were plaintext. **Retries**, **channel load balancing
/ name resolution**, **`grpc-status-details-bin`** (the `google.rpc.Status` detail payload),
**gRPC-Web** framing, and **reflection/health** services. On the server: concurrent handlers (`h2_server`
has the dispatch seam, but `grpc.Server` installs no pool of its own — the default stays
sequential per connection) and preemptive deadline cancellation. See SPEC.md for why each.
