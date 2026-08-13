# grpc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — **BEHAVIOURAL, not breaking** (server) — `handleRequest` no longer calls
  `ResponseWriter.end()` itself. It did so to beat the per-call arena's
  `deinit` to the metadata `Call.finish` had just handed `setHeader` /
  `setTrailer` — the status digits, the percent-encoded `grpc-message`, the
  trailing metadata — which `http` copies into the writer now, so the arena
  dying with the frame no longer reaches them. **What changes for a consumer:**
  the response head (and, on the Trailers-Only path, the whole response) is
  committed by the serving loop after the handler returns rather than inside
  it, so a middleware wrapped around the gRPC router can still touch the head.
  The frames on the wire are unchanged.

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: live
  bidirectional interop against a real Python `grpcio` server and client.
- **2026-07-30** — New module: a gRPC **client** over HTTP/2, per the `grpc-over-http2`
  specification — the layer between the `http` module's multiplexing h2
  client and the `protobuf` codec, with no code generation (a method is a
  path, its messages are Zig structs with a `pb_fields` descriptor).
  Length-Prefixed-Message framing where "several messages in one DATA
  frame" and "one message across many DATA frames" are both the normal
  case; Trailers-Only responses detected as such (the common error path,
  and what hangs a client that only looks for trailers after a body);
  status 0-16 as one Zig error per code with the percent-encoded
  `grpc-message` decoded; `-bin` metadata base64-coded in both directions;
  all four call shapes from one engine. The LPM length is read from the
  wire, so the invariant is stronger than "check before allocating" — *the
  declared length never sizes an allocation at all* — and
  `max_recv_message_size` (4 MiB, gRPC's own default) is enforced the
  instant the 5-byte header completes. Anchored live on Python `grpcio`:
  all four shapes, a real Trailers-Only failure, metadata both ways, a
  deadline the reference reads back, a 256 KiB reply reassembled across
  DATA frames — which also makes it the first third-party HTTP/2 peer our
  h2 client has faced. 14 mutations run; three of them (little-endian
  length, compressed flag misplaced, `-bin` sent raw) stay consistent
  between our framer and our parser and so survive every self round trip,
  dying only to the reference. **Client only**: the sibling `http`
  module's h2 server buffers each request to END_STREAM before dispatch
  and stages the whole response before framing it, so three of the four
  call shapes cannot be built on it today (`SPEC.md`).
