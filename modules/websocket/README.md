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

// then, per received frame:
switch (try websocket.frame.parseFrame(read_buf, .server, max_frame_size)) {
    .need_more => {}, // read more bytes, retry
    .frame => |f| { … f.opcode, f.payload (already unmasked) … },
}
```

```zig
// client: generate a key, send the request, verify the 101 response
var prng = std.Random.DefaultPrng.init(seed); // any std.Random — never std.crypto.random here
const key = websocket.handshake.generateKey(prng.random());
try websocket.handshake.writeRequest(w, .{ .host = "example.com", .target = "/ws", .key = &key });
// … read the response head with http.h1.ResponseHead.parse …
const result = try websocket.handshake.verifyResponse(response_head, &key, &.{});
```

- **`handshake`** — `acceptHandshake(head, options) ServerAccept` / `writeResponse(w, accept)`
  (server); `generateKey(random) [24]u8` / `writeRequest(w, options)` /
  `verifyResponse(head, key, offered_protocols) ClientVerifyResult` (client); shared
  `computeAcceptKey(key) [28]u8`. Subprotocol negotiation via `ServerAcceptOptions.protocols` /
  `ClientRequestOptions.protocols`. Every malformed/non-conformant handshake is a typed
  `HandshakeError`, never a panic.
- **`frame`** — `Opcode` (continuation/text/binary/close/ping/pong), `Frame`, `Role` (`.server` /
  `.client` — which masking direction to enforce on parse), `parseFrame(buf, role,
  max_frame_size) FrameError!ParseResult` (streaming: `.frame`, `.need_more`, or a typed error —
  never blocks or panics on a truncated buffer), `writeFrame(w, WriteOptions)`. `mask_key: ?[4]u8`
  on `WriteOptions` is the entire masking decision — null = unmasked, a key = masked with that
  key. Helpers: `applyMask`, `pongFor(ping_payload, mask_key)`, `encodeCloseBody`/
  `decodeCloseBody`, `closeCode(err) u16` (maps any error from this module to its RFC close code).
- **`connection`** — `Connection.init(role, message_buf, max_frame_size)` +
  `receive(buf) Error!Result`: an optional small state machine that reassembles fragmented
  messages into `message_buf` (whose length is the aggregate max-message-size cap), lets control
  frames interleave mid-fragmentation, validates UTF-8 on the complete text message, and tracks
  the close handshake (`close_sent`/`close_received`/`bothClosed()`).

- **Role:** both (client + server). **Platform:** any. **Deps:** `http` (the handshake's
  `h1.RequestHead`/`ResponseHead` + `Header`), `std.crypto.hash.Sha1`, `std.base64`,
  `std.unicode`. **Concurrency:** reentrant (`handshake`/`frame` carry no state); a `Connection`
  is single-owner if shared across calls (mutates its own fields, not thread-safe to share
  concurrently).

Provenance: clean-room from RFC 6455 (The WebSocket Protocol). No third-party source consulted or
copied.

## Verification

`zig build test-websocket` — 50 offline tests, green in Debug + ReleaseFast: the RFC 6455 §1.3
handshake worked example and the §5.7 frame examples byte-exact (both parse and serialize),
plus constructed Autobahn-style adversarial cases (unmasked-client/masked-server rejection,
RSV/opcode/length-encoding/size-cap/fragmentation-sequencing/UTF-8 rejections, each with a
positive control). See SPEC.md for the full security-rule rationale and what's deliberately out of
scope (permessage-deflate).
