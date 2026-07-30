# grpc — design, invariants and threat model

See [README.md](README.md) for what this module is and how to use it.

Reference: the published [`grpc-over-http2`](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
protocol specification. Clean-room; the Python `grpcio` package is used only as a black-box test
oracle. `Provenance:` see README.

## Why there is no server

gRPC is symmetric on the wire, so a server looks like a small addition to a working client. It is
not, and the blocker is one level down: **`http`'s HTTP/2 server has no streaming handler
surface.**

Concretely, in `modules/http/src/h2_server.zig`:

- `onData` appends every DATA payload into `job.body` (an `ArrayList`);
- `takeReady` will only hand a job to the handler once `job.complete` is set, which happens only
  on END_STREAM;
- `serveJob` then runs the handler against an in-memory `Writer.Allocating`, stages a complete
  HTTP/1.1 response, and *re-frames* it as h2 frames afterwards.

Both directions are therefore fully buffered. A gRPC server built on that could answer a unary
call and nothing else: a client-streaming or bidirectional RPC would have to receive its entire
request before the handler ever ran — which is not client-streaming — and a server-streaming RPC
could not emit a message until it had produced all of them, which is not server-streaming. The
half that could be built is exactly the half gRPC users do not need a new implementation for.

The fix is real work on the server, not on this module: the same incremental surface the client
got in `6f05770` (`openStream`/`sendData`/`readBody`/`trailers`), mirrored for handlers. That is
its own task. Until it exists, shipping a "gRPC server" that silently degrades three of the four
call shapes would be worse than shipping none, so this module is client-only and says so.

## Layering

```
grpc.Stream(Req, Rep) / grpc.unary     typed: protobuf encode/decode
        │
grpc.Call / grpc.Channel  (call.zig)   headers, trailers, status, metadata, deadlines
        │
grpc.frame  (frame.zig)                the 5-byte Length-Prefixed-Message envelope
        │
http.h2_client.Session                 HTTP/2 streams, flow control, HPACK
```

Each layer is usable on its own: `frame` deframes an LPM stream from anywhere (gRPC-Web rides
the same envelope), and `Call` carries opaque bytes so a non-protobuf `content-subtype` needs no
change here.

There is **one** call engine, not four. The four gRPC call shapes are indistinguishable on the
wire — a unary call is a client-streaming call that happens to send one message — so modelling
them as four types would have produced four copies of the same framing bugs. `Stream` is the
whole surface; `unary` is twenty lines on top of it that enforce the "exactly one message each
way" contract.

## Invariants

### 1. The declared length never sizes an allocation

The LPM prefix carries a 32-bit length **read from the wire**, before any of the bytes it
describes exist. This is the same defect shape the `protobuf` module was built around, and the
highest-yield detector this repository has: *a length read from input, used to size an allocation
or bound a loop, before anything is verified*. Five bytes can claim 4 GiB.

`Deframer` therefore states something stronger than "validate before allocating":

> The declared length never sizes an allocation **at all**.

The only buffer that grows is the reassembly buffer, and it grows only by bytes that actually
arrived. The declared length is used for exactly two things — comparison against
`max_recv_message_size`, and deciding whether enough bytes are present yet. A lying header
therefore costs the liar the bandwidth of everything it claims and costs us nothing.

`max_recv_message_size` (4 MiB, gRPC's own default) is checked the instant the fifth header byte
lands, in `push` — *before* the buffer accepts another byte — and again in `next`, so no path
can hand back a message the limit forbids. Exceeding it fails the call with
`RESOURCE_EXHAUSTED`, which is what other gRPC implementations return for the same condition. A
locally-decided `RESOURCE_EXHAUSTED` is distinguishable from a server-sent one: the former
leaves `call.status` set with no trailer section behind it.

Tested at the default limit, with the limit raised to `maxInt(u32)` (where the limit is no
defence and only the no-allocation invariant remains), split across pushes so the check cannot
be one-shot, repeated so a failure cannot leak, and live against a real grpcio server producing a
256 KiB reply against a 64 KiB limit.

### 2. A message boundary has nothing to do with a DATA-frame boundary

One DATA frame may carry three messages or two bytes of one. A 256 KiB reply is split across a
long run of frames because the peer's `SETTINGS_MAX_FRAME_SIZE` is 16 KiB by default. This is the
normal case, not an edge case, and is tested at *every* split offset of a representative message
(including inside the 5-byte prefix), byte-at-a-time, and live.

### 3. The status is a trailer — except when it is a header

`grpc-status` normally arrives in the TRAILERS frame after the messages. But an error usually
arrives as **Trailers-Only**: a single HEADERS frame with END_STREAM carrying the status and no
body at all. Every server-side `abort()` produces it, so it is the *common* error path.

A client that waits for a trailer section after a body hangs forever on a Trailers-Only response
— it will never see a body and never see a second HEADERS frame. `readHead` therefore checks the
initial header block for `grpc-status` first and, finding it, treats that block as the entire
response. Both spellings are tested offline and live.

The mirror-image failure is treating Trailers-Only as an empty *successful* body. The two are
distinguished by the status, never by the emptiness: a genuinely empty successful response
(HEADERS, no DATA, trailers saying `grpc-status: 0`) has its own test right beside the error one.

### 4. A missing or malformed status is never OK

A response that ends with no `grpc-status` anywhere is `error.MissingStatus`. A `grpc-status`
that is not a bare decimal (`" 0"`, `"+0"`, `"0x0"`, `"ok"`, an overflowing number, a
full-width `０`) is `error.MalformedStatus`. Neither is promoted to `.ok`: returning success for
a broken peer is the worst single failure this module could have, since the caller then acts on
a reply that no one guaranteed.

Status codes outside 0–16 are representable (`Status` is a non-exhaustive `enum(u32)`) and map
to `error.Unknown` — a peer from a newer spec revision must not be undefined behaviour.

### 5. Nothing is decoded that was not identified

Before a single body byte is deframed, `readHead` requires `:status == 200` and an
`application/grpc` flavour of `content-type`. A non-200 goes through the spec's HTTP→gRPC status
table (404 → `UNIMPLEMENTED`, 401 → `UNAUTHENTICATED`, 429/502/503/504 → `UNAVAILABLE`, …); a
200 with the wrong content-type is `INTERNAL`. Otherwise an HTML error page from an intermediary
would be fed to the deframer and its first five bytes read as a length.

Likewise, the compressed flag: **any** non-zero value of the flag byte means compressed, not just
`0x01`, and a compressed frame is refused (`INTERNAL`) rather than handed to the protobuf decoder
as if it were plaintext. `grpc-encoding` on the response is checked against what we advertised
for the same reason.

### 6. Caller metadata cannot forge protocol headers

A caller-supplied entry whose name is one this layer owns (`grpc-timeout`, `content-type`, `te`,
`grpc-status`, `user-agent`, the pseudo-headers, …) is refused with `error.ReservedMetadata`
rather than appended alongside ours. Two `grpc-timeout` headers, or a `grpc-status` in a
*request*, are a way to confuse an intermediary that reads one of them; letting the last one win
is the shape of request smuggling.

### 7. Deadlines round up

`grpc-timeout` allows at most 8 digits plus a unit, so a duration is converted to the finest unit
that fits. The conversion rounds **up**: rounding down would silently shorten the caller's
deadline and cancel a call it still wanted.

## Verification

Three layers, and they answer different questions.

**Unit tests** (`status.zig`, `frame.zig`, `metadata.zig`, `call.zig`) pin the pure functions:
header layout, the percent-coding round trip, base64 `-bin` handling, the timeout ladder, the
status tables.

**Offline call tests** (`call_test.zig`) drive the real client over fixed buffers against a
server half fabricated frame by frame from an `http.h2.Connection` in server role. This is what
can script shapes a real server will not produce on demand — a status with no body, a message cut
at an awkward offset, a header that lies — and what pins the exact bytes the client emits. It
cannot prove those bytes are the *right* bytes.

**Live interop** (`reference_interop.zig`) is the module's real anchor: a Python `grpcio` server
on an ephemeral loopback port, driven by our client. All four call shapes, a Trailers-Only
failure with a `grpc-message` full of bytes the ABNF forbids, a status in a trailer section after
three messages, metadata both ways including `-bin`, a deadline the reference reads back and
reports, a 256 KiB reply reassembled across DATA frames, the receive limit refusing an oversized
one, and three calls multiplexed on one connection.

The anchor matters more than usual here, and the reason is worth stating plainly: **every
self-contained gRPC test is a conversation with ourselves.** Our framer writes the prefix and our
deframer reads it. Write the length little-endian in both halves, or move the compressed flag
after the length in both halves, and every self round trip still passes while nothing on the
network can read a byte we send. Those mutations are invisible to a self round trip *by
construction*. Only an outside implementation sees them.

Incidentally, grpcio serves real HTTP/2 (c-core), so these tests are also the first third-party
h2 peer the `http` module's client has faced: preface, SETTINGS, HPACK, flow control, DATA
framing and trailer sections are all being validated against a stack that has never seen our
code.

### Mutation testing

Fourteen mutations were applied to the implementation and the whole suite re-run — twice: once
in full, and once with the interop tests forced to skip (`GRPC_PYTHON` pointed at a nonexistent
interpreter), which answers "what would we know *without* the reference?".

| # | Mutation | Offline-only | Full suite |
|---|---|---|---|
| 1 | LPM length little-endian, **consistently** in writer and reader | 9 tests | **hangs** |
| 2 | Compressed flag after the length, **consistently** in both halves | 12 tests | **hangs** |
| 3 | A split message handed over short instead of waited for | 6 tests | 7 (+ live reassembly) |
| 4 | `grpc-status` read from the response headers, not the trailers | 8 tests | 17 (+ 9 live) |
| 5 | Trailers-Only not detected (an error reads as an empty body) | 3 tests | 5 (+ 2 live) |
| 6 | A non-OK status not raised as an error | 3 tests | 6 (+ 3 live) |
| 7 | `max_recv_message_size` not enforced | 9 tests | 10 (+ live limit) |
| 8 | `grpc-status` parsed leniently (`parseInt` with no prescan) | 3 tests | 3 |
| 9 | `grpc-message` passed through raw, not percent-decoded | 2 tests | 3 (+ live failure) |
| 10 | `-bin` metadata sent raw instead of base64 | 2 tests | 3 (+ live metadata) |
| 11 | `te: trailers` omitted from the request | 1 test | 13 (+ **all 12 live**) |
| 12 | `grpc-timeout` rounded down instead of up | 1 test | 1 |
| 13 | Response `content-type` not validated | 1 test | 1 |
| 14 | A stream ending mid-message accepted as a clean end | 3 tests | 3 |

Every mutation died, and none of them needed the reference to die — which is the point of how
the offline suite is written, not a sign that the anchor is redundant. Mutations 1, 2 and 10 are
exactly the consistent-in-both-halves kind, and the tests that caught them offline are the ones
that write **literal expected bytes** down (`frame.zig`'s header/encode tests, `call_test.zig`'s
request byte-golden, the adversarial hand-written frames). The round-trip tests beside them
stayed green: under mutation 1, "one message split across DATA frames, at every split point",
"three messages inside ONE DATA frame" and the whole unary happy path all pass, because both
halves agree with each other. Had the suite been written as round trips — the obvious way — those
three mutations would have survived it entirely.

What the reference adds is that it does not depend on us having thought to write a golden down.
Mutation 11 is the clearest case: omitting `te: trailers` is caught offline by exactly **one**
assertion — the one that happens to check for the header — and by **all twelve** live tests,
because grpcio rejects the request outright. And mutations 1 and 2 do not merely fail against the
reference, they **hang**: grpcio reads our five-byte prefix, believes the enormous length it
declares, and waits for a message that will never arrive. A wrong-framing client does not get a
clean error from the network; it gets silence.

### Fuzzing

Two harnesses (`adversarial.zig`), matching the repository's "never panic on arbitrary input"
threat model: the deframer fed arbitrary bytes in arbitrary chunk sizes, and the field parsers
(`grpc-status`, `grpc-timeout`, `grpc-message` percent-coding, `-bin` base64) fed arbitrary
bytes.

## Not implemented, and why

- **Message compression** (`grpc-encoding: gzip`/`deflate`/`snappy`). Doing it right means
  bounding the *decompressed* size against `max_recv_message_size` — a decompression bomb is a
  second, independent instance of invariant 1, and deserves its own design pass rather than being
  bolted on. Until then the client advertises `identity` only and refuses a compressed frame
  loudly. This is the most likely next addition.
- **Retries and hedging** (`grpc-retry-pushback-ms`, the service-config retry policy). Retry
  policy needs a channel that owns its connection lifecycle; this one borrows a session.
- **Name resolution and load balancing.** A channel here is one HTTP/2 connection the caller
  opened. Multi-address channels are a client-architecture feature, not a protocol one.
- **`grpc-status-details-bin`.** The value is a serialized `google.rpc.Status`, which pulls in
  `google.protobuf.Any` — and `protobuf` deliberately does not implement `Any`. The field is
  readable today as ordinary `-bin` metadata.
- **gRPC-Web.** Same LPM envelope over HTTP/1.1 with trailers folded into the body; `grpc.frame`
  is the reusable half and the rest is a different transport.
- **Reflection, health and channelz services.** Ordinary services, expressible with what is
  here; not protocol.
- **A server.** See the top of this file.
