# websocket

The WebSocket protocol (RFC 6455): the HTTP-Upgrade **opening handshake** and the **frame layer**
— transport-agnostic, so it drops onto any transport the caller has already set up (plain TCP,
`std.crypto.tls`, a reverse-proxy-terminated stream). Built for the P2 production HTTPS server's
WSS endpoint and WebSocket proxying, but has no dependency on that server beyond `http`'s
`h1.RequestHead`/`ResponseHead` types.

```zig
// server: validate the client's Upgrade request, answer 101
const accept = try websocket.handshake.acceptHandshake(request_head, .{ .protocols = &.{"chat"} });
try websocket.handshake.writeResponse(response_writer, accept);
// ...or, inside an `http.Server` handler: answer the 101 and take the
// connection over (HTTP timeouts lifted; works behind `http.proxy` too):
const up = try websocket.handshake.respondUpgraded(req, rw, try websocket.handshake.acceptHandshake(req.head, .{}));
var c = websocket.conn.Conn.init(.server, up.reader, up.writer, &message_buf, .{});
while (true) {
    const m = c.readMessage() catch |err| switch (err) {
        error.Closed => return, // closing handshake done
        else => return err,
    };
    try c.writeMessage(m.opcode, m.payload); // echo
}

// then, per received frame:
switch (try websocket.frame.parseFrame(read_buf, .server, max_frame_size)) {
    .need_more => {}, // read more bytes, retry
    .frame => |f| { … f.opcode, f.payload (already unmasked) … },
}
```

```zig
// client: generate a key, send the request, verify the 101 response
// `random` can be any `std.Random` (the key is an anti-cache-poisoning nonce,
// not a secret, so a fast non-CSPRNG is fine) — but RFC 6455 §4.1 point 7
// requires it to be selected randomly FOR EACH CONNECTION, so the seed must
// differ every time; never hardcode it the way this snippet used to.
var seed: u64 = undefined;
try io.randomSecure(std.mem.asBytes(&seed));
var prng = std.Random.DefaultPrng.init(seed);
const key = websocket.handshake.generateKey(prng.random());
try websocket.handshake.writeRequest(w, .{ .host = "example.com", .target = "/ws", .key = &key });
// … read the response head with http.h1.ResponseHead.parse …
const result = try websocket.handshake.verifyResponse(response_head, &key, &.{});
```

- **`handshake`** — `acceptHandshake(head, options) ServerAccept` / `writeResponse(w, accept)` /
  `respond(rw, accept)` / `respondUpgraded(req, rw, accept)` (server; from an `http.Server`
  handler, the latter also hands over the connection); `generateKey(random) [24]u8` / `writeRequest(w, options)` /
  `verifyResponse(head, key, offered_protocols) ClientVerifyResult` (client); shared
  `computeAcceptKey(key) [28]u8`. Subprotocol negotiation via `ServerAcceptOptions.protocols` /
  `ClientRequestOptions.protocols`. `ServerAcceptOptions.origins` is the server's `Origin`
  allow-list (empty default = same-host: no `Origin` header, or one whose host matches the
  request's `Host`; `"*"` allows any origin; a non-empty list otherwise replaces the same-host
  default with an explicit allow-list) — a mismatch is `error.OriginNotAllowed`, typically mapped
  to HTTP 403; see SPEC.md for the exact matching rule (case-insensitivity, port handling, `Origin:
  null`). Every malformed/non-conformant handshake is a typed `HandshakeError`, never a panic.
- **`frame`** — `Opcode` (continuation/text/binary/close/ping/pong), `Frame`, `Role` (`.server` /
  `.client` — which masking direction to enforce on parse), `parseFrame(buf, role,
  max_frame_size) FrameError!ParseResult` (streaming: `.frame`, `.need_more`, or a typed error —
  never blocks or panics on a truncated buffer), `parseHeader(buf, role, max_frame_size)` (the
  same checks, header only, payload untouched), `writeFrame(w, WriteOptions) WriteError!void`
  (refuses a fragmented or over-125-byte control frame with the same error names the parser uses,
  before writing anything). `mask_key: ?[4]u8`
  on `WriteOptions` is the entire masking decision — null = unmasked, a key = masked with that
  key. Helpers: `applyMask`, `pongFor(ping_payload, mask_key)`, `encodeCloseBody`/
  `decodeCloseBody`, `closeCode(err) u16` (maps any error from this module to its RFC close code).
- **`connection`** — `Connection.init(role, message_buf, max_frame_size)` +
  `receive(buf) Error!Result`: an optional small state machine that reassembles fragmented
  messages into `message_buf` (whose length is the aggregate max-message-size cap, alongside
  `max_fragments`, a per-message frame-count cap), lets control frames interleave
  mid-fragmentation, validates a text message's UTF-8 as it arrives (per fragment, and
  within a frame that is still incomplete), and surfaces the close
  handshake: `close_received` is set automatically on receipt; `close_sent` is a plain field the
  caller sets itself after writing its own close frame (this module does no I/O, so it cannot see
  that write); `bothClosed()` reflects both. `enableDeflate(compressed_buf, window)` turns on
  permessage-deflate receiving (RSV1 accepted on a message's first frame; the message is
  decompressed into `message_buf`, whose length stays the cap — the decompression-bomb bound).
- **`deflate`** — RFC 7692 permessage-deflate, **no context takeover in either direction** (the
  gorilla/websocket mode, coder/websocket's `CompressionNoContextTakeover`): `selectOffer`
  (server: first acceptable offer), `verifyResponse` (client), `response_value` / `offer_value`,
  `Compressor.compressMessage` (sender; std flate, ~225 KiB, reusable across connections that do
  not write at once), `inflate` (receiver; bounded by the output buffer, a back-reference before
  the start of the message is an error). Turned on by `ServerAcceptOptions.permessage_deflate` /
  `ClientRequestOptions.permessage_deflate` + `verifyResponseWith(.{ .permessage_deflate = true })`;
  `ServerAccept.deflate` / `ClientVerifyResult.deflate` say whether it was agreed, and
  `writeResponse`/`respond` then answer with the extension.
  ⚠ A libc-free executable that sends compressed messages should install `fastmem`
  (`fastmem.exportSymbols()` in its root): std 0.16's compressor memsets 96 KiB per message,
  which Zig 0.16's own memset does a byte at a time (~30 µs per message).
- **`conn`** — optional read/write loop over a `std.Io.Reader` + `std.Io.Writer`:
  `Conn.init(role, reader, writer, message_buf, .{ .mask_random, .deflate })`,
  `readMessage()` (answers pings, answers the peer's close and returns `error.Closed`, answers a
  protocol error with its close code), `writeMessage(opcode, payload)` (masks on the client,
  compresses messages ≥ `min_size` when deflate is on), `ping`, `close(code, reason)`.

```zig
// server with compression, after `acceptHandshake(head, .{ .permessage_deflate = true })`:
var c: websocket.conn.Conn = .init(.server, reader, writer, &message_buf, .{
    .deflate = if (accept.deflate != null) .{
        .compressed_buf = &compressed_buf, .window = &window, // receiving
        .compressor = &compressor, .out_buf = &out_buf, // sending
    } else null,
});
while (true) {
    const m = c.readMessage() catch |err| switch (err) {
        error.Closed => break, // the peer's close was answered
        else => return err,
    };
    try c.writeMessage(m.opcode, m.payload); // echo
}
```

- **Role:** both (client + server). **Platform:** any. **Deps:** `http` (the handshake's
  `h1.RequestHead`/`ResponseHead` + `Header`), `std.crypto.hash.Sha1`, `std.base64`,
  `std.unicode`. **Concurrency:** reentrant (`handshake`/`frame` carry no state); a `Connection`
  is single-owner if shared across calls (mutates its own fields, not thread-safe to share
  concurrently).

Provenance: written from RFC 6455 (The WebSocket Protocol) and RFC 7692 (permessage-deflate). No
third-party source copied. For permessage-deflate, coder/websocket v1.8.15 (ISC) was read for its
behaviour only: which offer parameters it accepts (`accept.go` `acceptDeflate`), and that it reads a
missing end-of-data as the end of a message (`read.go`). Its behaviour was matched where the RFC
leaves room; no code was taken.

## Verification

`zig build test-websocket` — 150 offline tests, green in Debug + ReleaseFast: the RFC 6455 §1.3
handshake worked example and the §5.7 frame examples byte-exact (both parse and serialize),
plus constructed Autobahn-style adversarial cases (unmasked-client/masked-server rejection,
RSV/opcode/length-encoding/size-cap/fragmentation-sequencing/UTF-8 rejections, each with a
positive control), every RFC 7692 §7.2.3 example, and deterministic fuzz harnesses over the
extension grammar, `inflate` and a deflate `Connection`. See SPEC.md for the full security-rule
rationale and what's deliberately out of scope.
