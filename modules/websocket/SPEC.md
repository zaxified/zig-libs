# websocket — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

Submodules: `handshake` (§1.3/§4 opening handshake), `frame` (§5 wire codec), `connection` (a
small optional per-connection state machine on top of `frame`). Transport-agnostic throughout —
this module never opens a socket or touches TLS; it operates on caller-owned byte buffers and
`std.Io.Writer`s, so the P2 HTTPS server drops it onto its already-terminated TLS stream (same
seam pattern as `http`'s `serveStream`/`h2_server.serveStream`).

**Handshake.** `handshake.acceptHandshake` validates a parsed `http.h1.RequestHead` against §4.2.1:
GET, HTTP/1.1+, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, and a
`Sec-WebSocket-Key` that decodes to exactly 16 bytes. `computeAcceptKey` is
`base64(SHA1(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))` (§1.3) — hashes the raw base64 *key
string*, not its decoded bytes, per spec. Subprotocol negotiation (`Sec-WebSocket-Protocol`) picks
the first client-offered token (client preference order) present in the caller's allowed set;
absent that header or an empty allowed set, no subprotocol is negotiated. Client side mirrors this:
`generateKey` takes a caller-supplied `std.Random` (never `std.crypto.random` — this module has no
opinion on the CSPRNG source, matching the rest of zig-libs' caller-supplied-randomness
convention), and `verifyResponse` recomputes the expected accept value and rejects on any mismatch
— this is the handshake's core integrity check (RFC 6455 §4.1 point 9): it catches a transparent
cache, proxy, or non-WebSocket-aware server that answered `101` without actually understanding the
protocol.

**Frame layer.** `frame.parseFrame(buf: []u8, role, max_frame_size)` is a streaming, allocation-free
parser: `buf` is mutable because a masked payload is unmasked **in-place**, so `Frame.payload`
always aliases plaintext application data regardless of whether the wire frame was masked. Three
possible outcomes: a decoded `Frame`, `.need_more` (the buffer doesn't yet hold a complete frame —
not an error, the normal "read more and retry" signal for a streaming transport), or a typed
`FrameError`. `writeFrame` is the inverse, serializing to a `std.Io.Writer`; masking on the write
side is never inferred — the caller passes `mask_key: ?[4]u8` explicitly (null = unmasked, a key =
masked-with-that-key), which is also what makes the RFC §5.7 vectors byte-exact-reproducible in
tests (the masking key in those vectors is fixed, not random).

**Connection.** `connection.Connection` reassembles a fragmented message (§5.4: start frame
text/binary with `FIN=0`, zero or more `continuation` frames, a final `continuation` with `FIN=1`)
into a caller-owned `message_buf`; that buffer's length **is** the aggregate max-message-size cap
(a fragmented message can exceed any single frame's `max_frame_size` even with every individual
frame compliant, so this is a separate bound from the per-frame one). Control frames (ping/pong/
close) are dispatched before fragmentation state is even consulted, which is what makes
interleaving them mid-fragmentation "just work" — no special-casing needed. UTF-8 validation
(§5.6, required for `text`/`.continuation`-reassembled-as-text) runs against the **complete**
message: a single unfragmented frame validates directly against its payload with no copy; a
reassembled one validates `message_buf[0..message_len]` once the final fragment arrives. This is
correct per the RFC's actual requirement (the *message* must be valid UTF-8) and is exercised by a
test that deliberately splits a multi-byte codepoint across two fragments — the split bytes are
*not* independently valid UTF-8, only the reassembled whole is, proving the deferred-validation
design doesn't false-positive on legitimate fragmentation.

## Threat model / out of scope

This module parses untrusted network input end to end (the handshake request/response headers and
every frame byte) — no panics on malformed input anywhere; every rejection is a typed error.

- **Masking direction (§5.3) is the security-critical invariant**, not a nicety: a client that
  fails to mask makes its traffic indistinguishable from a raw TCP/HTTP stream to any
  packet-inspecting intermediary sitting between it and the server, which is the basis of several
  cross-protocol attacks documented alongside RFC 6455 (e.g. smuggling non-WebSocket traffic past a
  cache that thinks it's looking at opaque masked bytes). `parseFrame` enforces the *inbound*
  direction unconditionally from its `role` parameter: a server-role parser rejects any unmasked
  frame (`error.UnmaskedClientFrame`, close 1002), a client-role parser rejects any masked one
  (`error.MaskedServerFrame`, close 1002). There is no configuration flag to disable this.
- **RSV bits / reserved opcodes:** this module negotiates no extensions, so any RSV bit set is
  immediately `error.ReservedRsvBits` (close 1002) — never silently ignored, which matters because
  silently ignoring an RSV bit is exactly how an extension-confusion attack would look. Opcodes
  0x3-0x7 and 0xB-0xF → `error.ReservedOpcode` (close 1002).
- **Size caps (DoS bound):** `max_frame_size` is checked as soon as the length prefix is decoded —
  *before* the parser waits for (or would need to buffer) the payload bytes, so an attacker cannot
  force buffering of an oversized frame merely by claiming a huge length (`error.FrameTooLarge`,
  close 1009). `Connection.message_buf.len` bounds the aggregate reassembled-message size
  (`error.MessageTooLarge`, close 1009) — this is the fragmentation-amplification bound: many
  small, individually-compliant frames could otherwise build an unbounded message.
- **Control-frame constraints (§5.5):** `FIN=0` on close/ping/pong → `error.FragmentedControlFrame`
  (close 1002); payload over 125 bytes → `error.ControlFrameTooLarge` (close 1002). Both checked
  before any payload bytes are required to be present.
- **Non-minimal length encoding:** a 126/127-prefixed frame whose extended length field encodes a
  value the shorter form could have carried, or a 64-bit length with the MSB set (RFC requires it
  0), is `error.InvalidPayloadLength` (close 1002) — not a spec nicety, a classic length-encoding
  confusion vector (parsers that accept multiple encodings of the same length disagree with each
  other about frame boundaries, which is a request-smuggling-shaped bug in this protocol too).
- **UTF-8:** invalid UTF-8 in a text message (`error.InvalidUtf8`, close 1007) or a close-frame
  reason (same error) is rejected; binary messages are never validated.
- **Fragmentation sequencing:** a continuation frame with no message in progress, or a new
  text/binary frame while one is already in progress, is `error.InvalidFragmentation` (close 1002).
- **Every error maps to an RFC close code** via `frame.closeCode(err: anyerror) u16` (1002/1007/
  1009 per the table above; everything else defaults to 1002) so the caller doesn't need its own
  mapping switch to build the failing close frame.
- **Out of scope:** TLS/TCP transport (the caller's — see `http`'s BYO-TLS seam for the pattern),
  **permessage-deflate (RFC 7692)** — no extension negotiation of any kind is implemented, so
  `Sec-WebSocket-Extensions` is never read or written and any RSV bit is always rejected (deferred:
  a real perf win for text-heavy workloads, but a distinct, security-sensitive feature — DEFLATE
  decompression bombs are a known WebSocket DoS vector — that deserves its own audited pass rather
  than a token-budget afterthought here), origin-header policy / CSRF-via-WebSocket-handshake
  checks (the caller's — this module surfaces the `Origin` header like any other but doesn't police
  it, since the correct policy is application-specific), and automatic ping/keepalive scheduling
  (the caller drives the event loop; `frame.pongFor` is the one building block provided).

## Verification

`zig build test-websocket` — 50 offline tests, green in Debug + ReleaseFast.
- **RFC 6455 vector-backed (byte-exact):** the §1.3 handshake worked example
  (`dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, both as a standalone
  `computeAcceptKey` check and as a full `acceptHandshake` + `writeResponse` round trip over the
  verbatim §1.3 example request/response headers); the §5.7 frame examples — unmasked text
  "Hello", masked text "Hello" (exact mask key + masked bytes), fragmented "Hel"+"lo", unmasked
  ping "Hello", unmasked pong "Hello", 256-byte binary (16-bit length form), 64KiB binary (64-bit
  length form) — each both parsed from and re-serialized to the literal RFC bytes.
- **Constructed (Autobahn-style) teeth, each with a positive control alongside it:** unmasked
  client frame rejected / masked server frame rejected, RSV-bit rejection, reserved-opcode
  rejection, oversized-frame rejection (checked before the payload is even available), fragmented-
  control-frame rejection, oversized-control-payload rejection, non-minimal 16-bit and 64-bit
  length encodings rejected, 64-bit length with MSB set rejected, masking round-trip
  (`applyMask` is its own inverse), close-body encode/decode round trip + malformed cases (1-byte
  payload, invalid-UTF-8 reason), handshake rejections (non-GET, missing Upgrade/Connection/
  version, missing/malformed key, unoffered-subprotocol echo, accept mismatch, non-101 status),
  `Connection` fragmentation-sequencing errors (orphan continuation, new frame before finishing
  the previous one), aggregate message-size cap, single-frame and reassembled invalid-UTF-8
  rejection, the split-codepoint-across-fragments positive control, and control-frame interleaving
  mid-fragmentation.

## Backlog / deferred

- permessage-deflate (RFC 7692) extension negotiation + DEFLATE framing — see "Out of scope" above.
- No automatic keepalive/ping-interval scheduling — event-loop-specific, left to the caller.
