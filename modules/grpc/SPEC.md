# grpc — design, invariants and threat model

See [README.md](README.md) for what this module is and how to use it.

Reference: the published [`grpc-over-http2`](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
protocol specification, plus [`doc/compression.md`](https://github.com/grpc/grpc/blob/master/doc/compression.md)
for the server's answer to an encoding it cannot undo. Clean-room; the Python `grpcio` package is
used only as a black-box test oracle. `Provenance:` see README.

## The server, and what unblocked it

This module was client-only at first, and the blocker was one level down: `http`'s HTTP/2 server
buffered every request body to END_STREAM before dispatching, and staged the whole response before
re-framing it. A gRPC server on that could answer a unary call and nothing else — a
client-streaming or bidirectional RPC would have had to receive its entire request before the
handler ran, and a server-streaming one could not have emitted a message until it had produced
all of them.

`c742eef` fixed that in `http`, not here: `Options.h2_stream_request` opts a route into starting
its handler at HEADERS and reading DATA as it lands (`RequestBody.external`), and the response
side re-frames *as the handler writes* through the h2 `Framer`. Both halves of a stream can now
be live at once, which is what all four call shapes need. The server here is built on exactly
that surface — see `server.zig`.

### How the two response shapes are kept apart

The spec's grammar gives a response two forms:

```
Response      → (Response-Headers *Length-Prefixed-Message Trailers) / Trailers-Only
Trailers-Only → HTTP-Status Content-Type Trailers
```

`Trailers-Only` is a **single field block**: `grpc-status` is a header there, there is no DATA
frame and no trailer section. The other form is three things: HEADERS, DATA, a trailing HEADERS
frame carrying END_STREAM. Both use the same field *names*, so no assertion about field values
can tell them apart — only frame counts and END_STREAM placement can, which is why the offline
tests drive an `h2.Connection` in client role and assert on frames.

The implementation makes the distinction structural rather than a matter of care:

- `Call.head_committed` is the only predicate, and it flips in only one place, `commitHead`;
- `commitHead` is reached only from `send` and `sendInitialMetadata` — i.e. only once something
  has irrevocably gone out ahead of the status;
- `commitHead` is also the only caller of `ResponseWriter.declareTrailers`, which is what
  commits the response to chunked framing and hence to having a trailer section at all;
- `finish` branches on `head_committed` exactly once: `setHeader` on the Trailers-Only side and
  `setTrailer` on the other.

So a response either has a trailer section and went through `commitHead`, or it does not and
never did. The rule "Trailers-Only iff nothing was sent yet" also covers a *successful* call
that produced no messages — that is what the reference implementation does, and a server that
reserved Trailers-Only for errors would emit an empty DATA frame plus a trailer section there
without any field value changing.

One consequence worth writing down: `ResponseWriter.end()` is called by this module *before* the
handler returns, not by the serving loop afterwards. Header and trailer values are stored without
copying and the ones `finish` sets (the status digits, the percent-encoded message, the metadata)
live in the per-call arena. The loop's `end()` runs after the handler, i.e. after the arena is
gone; it serialized freed memory. `end` is idempotent, so calling it first makes the loop's call
a no-op.

### What the server does not do

- **Concurrent handlers — not wired up here, but no longer absent.** `h2_server` gained an
  injectable dispatch seam (`h2_server.Options.dispatcher` / `Server.Options.h2_dispatcher`):
  with one installed, a connection's streams run on a bounded worker pool and a slow handler no
  longer holds up the others. `grpc.Server` does not install one — it passes the `http` options
  through, so the choice (and the thread pool) belongs to the application. **Left as-is, the
  default is still sequential**: one connection's streams are served on the connection's task,
  and only multiple *connections* run in parallel via the accept engine.
- **Preemptive deadlines.** `grpc-timeout` is enforced at every engine boundary, but a handler
  blocked in a body read cannot be interrupted — there is no deadline hook on the h2 request-body
  reader. `http`'s `read_timeout_ms`/`request_timeout_ms` are the transport-level backstop.
- **A 505 for gRPC over HTTP/1.1.** The reference implementations answer
  `505 HTTP Version Not Supported`; `http`'s handler-facing `Request` deliberately exposes no
  protocol discriminator (the h2 loop synthesizes an h1-shaped head so one handler serves both),
  so that answer is not available without changing `http`. Wiring the router with `httpOptions`
  / `h2ServerOptions` is what makes the question moot.

## Layering

```
client                                 server
──────                                 ──────
grpc.Stream(Req, Rep) / grpc.unary     grpc.Methods(Req, Rep)      typed: protobuf
        │                                      │
grpc.Call / grpc.Channel (call.zig)    grpc.Router / grpc.ServerCall (server.zig)
        │                                      │        headers, trailers, status,
        │                                      │        metadata, deadlines, routing
        └──────────┬───────────────────────────┘
                   │
        grpc.frame (frame.zig)         the 5-byte Length-Prefixed-Message envelope
                   │
http.h2_client.Session                 http.h2_server (Server / serveStream)
```

The two sides meet at `frame.zig`, `status.zig` and `metadata.zig` — one framer, one status
table, one metadata coder, used in both directions. That is not tidiness: the receive-limit
invariant below is a property of the `Deframer`, so having exactly one of them makes it one
property rather than two that can drift.

Each layer is usable on its own: `frame` deframes an LPM stream from anywhere (gRPC-Web rides
the same envelope), and `Call` carries opaque bytes so a non-protobuf `content-subtype` needs no
change here.

There is **one** call engine per side, not four. The four gRPC call shapes are
indistinguishable on the wire — a unary call is a client-streaming call that happens to send one
message — so modelling them as four types would have produced four copies of the same framing
bugs. On the client `Stream` is the whole surface and `unary` is twenty lines on top of it that
enforce the "exactly one message each way" contract; on the server `Call` is the whole surface
and the four `Methods(Req, Rep)` constructors are thin comptime wrappers that differ only in
which calls they make on it.

### Why the server's registration is a table and not comptime reflection

`Service(MyImpl)` — reflect over a struct's public decls, derive the routing table — is the
idiomatic-looking option and was rejected for one concrete reason: **the call shape cannot be
read off a Zig signature without guessing.** `fn(*Stream) !Rep` is client-streaming, or a unary
method whose author likes streams; `fn(*Stream, Req) !void` is server-streaming, or a
bidirectional method that happens to want its first message eagerly. Inferring the shape means an
accidental signature change silently rewrites the wire contract of a *published* method — the
sort of break that surfaces as a hung client at a customer, not as a compile error. Naming the
shape at the call site (`M.clientStreaming("Upload", …)`) makes a mismatched implementation a
compile error and the contract a written decision.

Two secondary reasons. A `.proto` service definition is data in every other gRPC stack, so a
table maps onto it one-to-one and is what a generator would emit. And a table can be assembled at
run time — a server mounting services from configuration cannot express that as a type. Nothing
is given up: the methods are still comptime-typed, with the schema derived from the Zig structs
exactly as on the client.

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

This is **one** property, not one per direction, because it is a property of the one `Deframer`
both sides use. The server enforces it against request messages exactly as the client does
against replies: a request frame declaring 4 GiB fails the call `RESOURCE_EXHAUSTED` having
buffered five bytes, and the limit comes from `ServerOptions.max_recv_message_size` on that path.

Tested at the default limit, with the limit raised to `maxInt(u32)` (where the limit is no
defence and only the no-allocation invariant remains), split across pushes so the check cannot
be one-shot, repeated so a failure cannot leak, at the exact boundary and one byte past it on
the server path, and live in both directions — a real grpcio server producing a 256 KiB reply
against a 64 KiB client limit, and a real grpcio client sending a 128 KiB request against a
64 KiB server limit.

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

On the **send** side the same invariant reads differently and is harder to test, because both
shapes carry the same field *names* — no assertion about field values can tell them apart. See
"How the two response shapes are kept apart" above for the structural argument, and the offline
frame-level tests for the evidence. The mutation that emits a trailer section on the
Trailers-Only path is the one place in this module where the live reference is **not** the
stronger oracle: grpcio accepts that response happily, and only counting frames catches it.

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

Four layers, and they answer different questions.

**Unit tests** (`status.zig`, `frame.zig`, `metadata.zig`, `call.zig`, `server.zig`) pin the pure
functions: header layout, the percent-coding round trip, base64 `-bin` handling, the timeout
ladder, the status tables, the path grammar, the content-type echo.

**Offline call tests** (`call_test.zig`) drive the real client over fixed buffers against a
server half fabricated frame by frame from an `http.h2.Connection` in server role. This is what
can script shapes a real server will not produce on demand — a status with no body, a message cut
at an awkward offset, a header that lies — and what pins the exact bytes the client emits. It
cannot prove those bytes are the *right* bytes.

**Offline server tests** (`server_test.zig`) are the same idea pointed the other way, with one
important difference: an `h2.Connection` in *client* role sits on the other end of
`h2_server.serve` and the assertions are about **frames**, not field values — how many HEADERS
blocks the response has, which one carried END_STREAM, whether a DATA frame exists at all. That
is not stylistic. The two legal response shapes use the same field *names*, so "is `grpc-status`
a header or a trailer?" is unanswerable from field values and trivial from frame counts. Every
mutation of the two response paths dies here, including the one the live reference does not
catch.

**Live interop** (`reference_interop.zig`) is the module's real anchor, and it runs in **both
directions**:

- *our client → a Python `grpcio` server* on an ephemeral loopback port: all four call shapes, a
  Trailers-Only failure with a `grpc-message` full of bytes the ABNF forbids, a status in a
  trailer section after three messages, metadata both ways including `-bin`, a deadline the
  reference reads back, a 256 KiB reply reassembled across DATA frames, the receive limit
  refusing an oversized one, three calls multiplexed on one connection;
- *a Python `grpcio` client → our server*: the same `echo.Echo` contract, now produced by us —
  all four shapes (with a genuinely interleaved bidirectional call, whose request generator does
  not yield message N+1 until reply N has arrived), a Trailers-Only failure whose `grpc-message`
  the reference percent-**decodes** back to the exact bytes we were given, a status in a real
  trailer section after three messages, metadata in both sections including `-bin`, our
  `grpc-timeout` parsing checked against the reference's own rendering (`30100m` — it pads the
  deadline by 100 ms), a 48 KiB reply spanning many DATA frames, and a 128 KiB request refused
  `RESOURCE_EXHAUSTED` by our receive limit.

The second direction is the stronger one, and worth stating plainly: a client that frames wrongly
can still be understood by a lenient peer, but a server that frames wrongly cannot — the peer has
to find every message boundary, the trailer section and the status without any help from us.

The anchor matters more than usual here, for a reason that applies to both directions: **every
self-contained gRPC test is a conversation with ourselves.** Our framer writes the prefix and our
deframer reads it. Write the length little-endian in both halves, or move the compressed flag
after the length in both halves, and every self round trip still passes while nothing on the
network can read a byte we send. Those mutations are invisible to a self round trip *by
construction*. Only an outside implementation — or a literal byte golden someone thought to write
down — sees them.

Incidentally, grpcio serves and speaks real HTTP/2 (c-core), so these tests are also the first
third-party h2 peer the `http` module's client *and server* have faced: preface, SETTINGS, HPACK,
flow control, DATA framing, trailer sections and the incremental request-body surface are all
being validated against a stack that has never seen our code.

### Mutation testing — the client

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

### Mutation testing — the server

Eight more, same protocol (full run, then a run with the live tests forced to skip). "Offline"
counts exclude the 13 skipped live tests.

| # | Mutation | Offline-only | Full suite |
|---|---|---|---|
| S1 | `grpc-status` set as a response **header** instead of a trailer | 8 tests | 9 (+ live) |
| S2 | The Trailers-Only path emits a trailer section as well | 10 tests | 10 (**live: no**) |
| S3 | LPM length little-endian, **consistently** in writer and reader | 12 tests | **hangs** |
| S4 | A non-OK status never reaches the client (always `0`) | 10 tests | 11 (+ live) |
| S5 | `max_recv_message_size` not applied to request messages | 2 tests | 3 (+ live) |
| S6 | Trailers-Only decided by "the call failed", not "nothing sent yet" | 2 tests | 3 (+ live) |
| S7 | Request bodies buffered to END_STREAM (streaming predicate off) | **0 tests** | 1 (**live only**) |
| S8 | A non-gRPC `content-type` accepted instead of answered 415 | 1 test | 1 (**live: no**) |

Every one died. Four of them are worth reading closely, because they are the ones that say
something about *how* the suite is written rather than that it exists.

**S2 is the counter-example to "the reference is always the stronger oracle."** Emitting a
trailer section on the Trailers-Only path leaves every field value identical — same status, same
message, same metadata, same names — and grpcio accepts it without complaint. The live test does
not notice. Ten offline tests do, because they count field blocks: `isTrailersOnly()` asserts
`headers_end_stream and data_frames == 0 and trailers == null`, and all three clauses are
load-bearing. This is the single most likely thing to get wrong in a gRPC server and the only
way to see it is to look at frames.

**S6 is the plausible version of the same bug** — "Trailers-Only is the error shape" is a
reasonable-sounding rule and it is wrong in both directions: a successful call with no messages
must be Trailers-Only, and a failing call that already sent messages must not be. grpcio reports
`UNKNOWN: "No status received"` for it, which is what a real client does when a server writes
the status somewhere the response cannot carry it.

**S1 is what a wrong answer looks like at the HTTP/2 layer**, not the gRPC layer: grpcio fails
with `UNKNOWN: "Stream removed (Data frame with END_STREAM flag received)"`. Putting the status
in the head means the head is no longer withheld, END_STREAM lands on the last DATA frame, and
the trailer section it then sends is a protocol violation the peer rejects outright.

**S7 is the opposite lesson from S2, and the sharpest result in the table**: turning the
streaming predicate off kills **zero** offline tests. The offline harness stages the whole
request before the server runs, so a body buffered to END_STREAM reads back identically —
correct-looking, and unbuildable as a real gRPC server. Only the live run catches it, where the
interleaved bidirectional call deadlocks: our server waits for END_STREAM, grpcio waits for
reply N before sending request N+1, neither moves, and the reference reports `UNAVAILABLE:
"Stream removed (Socket closed)"` after its watchdog fires. That is why the reference client's
bidirectional generator is written to withhold its next request until the previous reply lands —
a shape that "works" against a cooperative peer that sends everything up front is not the same
as one that works.

S3 confirms on the server what the client mutations already showed, and adds one thing: a
consistently little-endian length is invisible to every round trip and dies to the tests that
write the bytes down — including `server_test.zig`'s "the length prefix is big-endian on the
wire, byte for byte", which asserts the response body is literally `00 00 00 00 03 'A' 'B' 'C'`.
Against the reference it does not fail, it **hangs** in both directions, which is what
mis-framing looks like on a network.

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
- **Concurrent server handlers** and **preemptive deadline cancellation.** Both are properties of
  `h2_server`'s scheduling, not of this module; see "What the server does not do" above.
