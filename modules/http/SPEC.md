# http — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Submodules: `Client` / `Server` (h1), `h1` (parser), `hpack` + `h2` + `h2_server` + `h2_client`
(HTTP/2), `proxy` (reverse-proxy handler) + `h2_upstream` (h2 upstream pool) + `bufpool` (shared
client buffer pool), plus request/response feature layers `conditional`, `body`, `multipart`, `sse`,
`range`, `conneg`, `gzip`. One `test { _ = … }` aggregator pulls every submodule's tests (the dark-tests
rule). Same handler serves h1 and h2 — h2 pseudo-headers map to the stock `Request`, the
`ResponseWriter` is re-framed as HEADERS+DATA; h2 is opt-in (`enable_h2c`), off by default so the h1
path is byte-for-byte unchanged. Streaming + backpressure: `ResponseWriter.flush()` for incremental
output; bodies stream with flow control. **h2 server streaming, both directions:** the h1→h2
re-framing runs *as the response is written* (`h2_server.Framer`, a `std.Io.Writer` `ResponseWriter`
drains into) rather than over a staged copy — deliberately ONE response engine, so every
`ResponseWriter` feature (gzip/range/conditional/conneg/trailers) is inherited rather than
reimplemented, and a response inside `response_buffer_size` is still framed byte-identically
(HEADERS + one END_STREAM DATA). The alternatives — a second streaming-only handler type, or an h2
framing mode inside `ResponseWriter` — were rejected as, respectively, two engines that drift and a
protocol branch through the type every h1 handler runs through. The cost: a handler failing after
part of the body is on the wire gets RST_STREAM(INTERNAL_ERROR), not a rewritten 500. Request bodies
buffer to END_STREAM by default and stream per-route via `Options.h2_stream_request`
(`h2_server.StreamBody`); the default exists because the pre-dispatch 413 (`max_body_bytes`) and 400
(§8.1.1 content-length vs DATA total) both need the whole body, and both survive on the streaming
surface as read failures. **Receive-window policy is surface-dependent and must be:** buffered
bodies credit WINDOW_UPDATE on *arrival* (consumption-based crediting would withhold the credit the
peer needs to send the END_STREAM the dispatch waits for → deadlock above the initial window; memory
is bounded by `max_body_bytes` instead), streaming bodies on *consumption* (same policy and argument
as `h2_client.readBody` — unread octets then cannot exceed the advertised window). Discarded octets
are always credited to the connection window immediately (§6.9.1), and a handler that answers
without reading is retired with RST_STREAM(NO_ERROR) per §8.1. `setHeader` stores the value slice **without copying** —
dynamic header values need caller-stable memory (documented per-helper). BYO-TLS seam:
`serveStream` / `connectH2Over` + ALPN run h2/h1 over a caller-terminated (TLS) stream — TLS
termination is out of this module. **Reverse proxy (`proxy`):** forwards over HTTP/1.1 (streaming)
or, per-backend (`Backend.protocol` `.h2c`/`.h2`), over HTTP/2 through `h2_upstream.Pool` — one
multiplexed h2 connection per backend origin, each proxied request a stream on it (reuses
`h2_client.Session`; no second h2 stack). Header translation (hop-by-hop, `X-Forwarded-*`, `Via`) is
shared across both forward paths; the h2 path buffers bodies (bounded, `h2_max_body_bytes`) where h1
streams, and per-connection response collection is mutex-serialized (multiplex is on the wire, full
cross-thread parallelism needs a dedicated reader task — deferred). h2 flow control is exercised
end-to-end (WINDOW_UPDATE past the initial window); h2 upstream trailers are not forwarded (the h2
client surfaces them on `Response.trailers`, but the proxy layer does not relay them). **Client buffer pool (`bufpool.BufferPool`):** an optional bounded, shared,
thread-safe slab pool wired via `Client.Options.buffer_pool`, backing h2 upstream dial buffers so a
gateway that churns h2 connections reuses `O(peak)` slabs instead of allocating one per dial (h1's
idle `Pool` already recycles whole warm connections, so it does not need it). **Trailers, both directions, both protocols:** the read side captures an incoming chunked trailer
section (h1) or request trailer HEADERS frame (h2) behind one handler surface
(`Request.trailer`/`iterateTrailers`/`trailers`); the write side is
`ResponseWriter.declareTrailers` + `setTrailer`, emitted after the terminating chunk on h1 (RFC 9112
§7.1.2) and as a trailing HEADERS frame carrying END_STREAM on h2 (RFC 9113 §8.1 — the final DATA
frame then does *not* carry it). Declaring trailers commits the response to chunked framing, so
`Trailer` and `Content-Length` can never coexist; every framing that cannot carry a trailer section
(HTTP/1.0 peer, declared Content-Length, HEAD/1xx/204/304) is a typed error at set time, never a
silent drop. **Trailer field policy is deny-list ∧ allow-list:** the RFC 9110 §6.5.1 forbidden set
(framing/routing/request-modifier/auth/response-control/payload-processing fields, plus
connection-specific ones, `Cookie`/`Set-Cookie` and any `:`-prefixed pseudo-header) is rejected
unconditionally, *and* a field must have been advertised in `Trailer` first — arbitrary
handler-chosen trailers are a request-smuggling and cache-poisoning vector because intermediaries
treat trailers inconsistently. Incoming h2 trailer blocks containing pseudo-headers are dropped
whole (§8.1 malformed; a late `:status`/`:path` is an override primitive). Never-panic: malformed
requests are typed errors → 400/413/414/431/500; handler errors/panics become a clean 500.
Foundational module: `router`, `dns` (DoH),
`rdap`, `acme`, `mcp-http`, and the whole REST/API cluster sit on it. Original work of the zig-libs
authors; design refs (behavior only, no source copied):
lalinsky/dusty (1.1 client), Go net/http (redirect semantics, server shape, gzip handler); RFCs
7230/9110 (1.1), 7541 (HPACK), 9113 (h2), 7301 (ALPN), 7233 (Range), 9110 §8.8/12 (conditional/
content-negotiation), 7578 (multipart); TLS via `std.crypto.tls`. See NOTICE.

## Threat model / out of scope
Hardened for direct internet exposure (no reverse proxy required):
- **Request smuggling:** duplicate/disagreeing Content-Length → 400; Content-Length **and**
  Transfer-Encoding both present → 400 (no CL.TE); TE-without-chunked, duplicate Host, obs-fold, and
  **bare-LF** line endings (RFC 9112 §2.2) all rejected.
- **Resource/DoS:** slowloris read/request/write timeouts; size caps (413/431/414); per-connection
  request-count cap; inbound gzip is zip-bomb-capped (`max_decompressed_request_bytes` → 413).
- **HTTP/2 DoS:** rapid-reset (CVE-2023-44487), CONTINUATION-flood (CVE-2024-27316),
  MAX_CONCURRENT_STREAMS, control-frame flood budgets, total-streams-per-conn cap — all
  configurable, safe by default (so `enable_h2c` is hardened out of the box). With
  `Options.h2_dispatcher` installed (concurrent handlers, off by default) two more caps apply:
  per-connection `Dispatcher.max_concurrent_handlers` (a ready stream over it waits in the
  already-bounded jobs map) and the dispatcher's own global admission, whose refusal is answered
  with RST_STREAM(REFUSED_STREAM) rather than a queue. Rapid-reset stays a *budget* rather than a
  consequence of one-handler-at-a-time: a cancellation after dispatch is charged exactly like one
  before it. **Not covered:** per-user connection-rate limiting — that belongs on the accept path
  (`Options.on_connect`), not in the h2 loop.
- **Header injection:** outbound header names/values reject CR/LF/NUL (response-splitting guard).
- Response bodies of 304/204/1xx are suppressed (framing correctness).
- **Out of scope:** TLS termination (bring-your-own via the seam — reverse proxy today, ianic/std
  server later), HTTP/3 (QUIC), auth (`aaa-gate`/`jwt`), rate limiting (`ratelimit`), path-traversal
  normalization beyond what `router` does.

## Verification
HPACK vs RFC 7541 Appendix C vectors (bytes + decoded fields + dynamic-table state per step); h2
offline scripted client↔server pipe exchanges + h2spec-style negatives; h2 DoS attack-sim tests
(rapid-reset proves no handler runs); serveStream goldens for conditional/range/multipart/content-
neg; smuggling/timeout/size negatives; a BYO-TLS in-memory dogfood (connectH2Over ↔ serveStream).
**Trailers are anchored against a live third party, not only against ourselves**
(`src/curl_interop.zig`): a real `Server` on loopback answered by `curl` 8.18 / nghttp2 1.68 on both
`--http1.1` and `--http2-prior-knowledge`, asserting curl's own header dump carries the trailer
fields *after* the head — i.e. curl parsed a trailer section, rather than our bytes merely containing
those strings. Self-interop cannot catch a shared misreading of the framing (the writer and reader
agree on the same mistake); mutation testing confirms the difference — emitting the h1 trailer block
before the last-chunk line fails curl outright (exit 56), and leaving END_STREAM on the last h2 DATA
frame makes curl/nghttp2 *silently discard* the trailer frame and still exit 0, so on h2 the
load-bearing assertion is the surfacing check rather than the exit code. Offline byte goldens pin the
h1 wire layout and the h2 END_STREAM placement; the forbidden-field policy has its own rejection
tests for both gates. **h2 server streaming is anchored against curl too**, which is the right
direction here (curl is the client): a 256 KiB upload consumed incrementally — it cannot complete at
all unless the consumption-driven WINDOW_UPDATEs are accounted right, since nghttp2 simply stops at
the 65 535-octet initial window — a complete response produced from the first 8 octets of that
upload (§8.1 + RST_STREAM(NO_ERROR), which curl accepts, exit 0, surfacing the early body), and a
256 KiB flushed response whose END_STREAM rides an empty DATA frame, a framing only the streaming
engine emits. Offline, the load-bearing assertions are about the frames actually on the wire: the
handler answering a stream that NEVER carried END_STREAM (dispatch timing), and the split of
returned window credit between the stream and connection windows — the only observable that
distinguishes consumption-driven from arrival-driven crediting, since the *totals* agree either way.
9 mutations were run and each turned tests red; the sharpest is arrival-driven crediting on the
streaming surface (8 tests red, 2 of them curl's). h2 upstreaming: loopback h1-proxy → h2c-backend end-to-end (forwarding headers + hop-by-hop strip +
large-body flow control + concurrent clients over one shared upstream connection + 502 on dead
backend); pool-level multiplex (two streams in flight on one connection), sequential-reuse and
buffer-pool reuse/bounded proofs. Run: `zig build test-http`.

**Fuzz harnesses (HD1):** every untrusted-wire parser has a `std.testing.fuzz` harness asserting
"typed error or valid result, never a panic" — `h1.RequestHead.parse`/`ResponseHead.parse`/
`ChunkedReader` (request/status line, header block, chunked framing), `body.ContentType.parse`/
`urlencoded` (Content-Type + form body), `multipart.parse` (form-data boundary/part parse),
`range.parse` (Range header), `hpack.Decoder.decodeBlock` (HPACK header-block decode), and
`h2.parseFrame`/`h2.Connection.recv` (HTTP/2 frame decode, both pre- and post-handshake). They run
as a deterministic empty-input smoke test under plain `zig build test` and as real continuous fuzzing
under `zig build test-http --fuzz`; verified green in both Debug and `-Doptimize=ReleaseFast`. The
same pattern covers `jwt.parse`/`jwt.parseJwks` (compact-token + JWKS parse, `modules/jwt`) and
`x509.extensions.findExtensions`/the extension-value parsers + `x509.chain.parsePssParams`
(`modules/x509`) — see those modules' own test files. **Deferred, not fuzzed:** any path that calls
into `std`'s own parser on attacker bytes without this collection's bounds-safety wrapper around it —
namely `std.crypto.Certificate.parse` (used by `x509.chain`'s per-link verify once a certificate is
accepted for path building; `x509`'s own `extensions`/`parsePssParams` DER walks are fuzzed instead,
see `x509/root.zig`'s doc comment) and `std.compress.flate.Decompress` (`gzip.zig`'s inbound
request-body decompression, size-capped by `max_decompressed_request_bytes` but not itself
fuzz-verified here). These are std's parsers, not ours, to fix or fuzz-harness directly; ReleaseSafe
(below) is exactly the mitigation for that residual, un-fuzzed surface.

## Hardening: ReleaseSafe vs ReleaseFast for the exposed binary (HD7)
This module's entire job is turning fully attacker-controlled bytes (request line, headers, chunked
framing, multipart bodies, Range headers, HPACK blocks, HTTP/2 frames) into typed values before any
handler sees them. **Recommendation: build the internet-facing binary `ReleaseSafe`, not
`ReleaseFast`.** ReleaseSafe keeps bounds/overflow/UB checks live, so a parser bug that would
otherwise be silent, exploitable undefined behavior in `ReleaseFast` instead becomes a controlled
panic — a crash-and-restart under a process supervisor, not a memory-safety break. The fuzz harnesses
above (this module, `jwt`, `x509`) are the safety net that makes this a defense-in-depth choice rather
than a crutch: they already prove "no panic on arbitrary input" for every *fuzzed* code path in both
Debug and ReleaseFast, so ReleaseSafe's checks are there for what fuzzing has NOT reached yet
(untested branches, and the explicitly deferred `std`-parser call sites above) — not a substitute for
fuzzing, and not the other way around. If a deployment genuinely needs `ReleaseFast`'s throughput for
this binary, treat a `-Doptimize=ReleaseSafe` fuzz/CI lane (`zig build test-http --fuzz`, ditto
`test-jwt`/`test-x509`) as a *mandatory*, continuously-running gate on that decision, not an optional
extra — the perf gap being traded away is small next to what a missed bounds check costs on a
directly-exposed parser.

## Backlog / deferred
**h2 upstream forwarding** reuses the multiplexing `h2_client.Session` through its *buffered*
surface, so it (a) buffers request/response bodies in memory (bounded) rather than streaming like
the h1 path — no longer an engine limitation since `h2_client` grew `openStream`/`sendData`/
`readBody`, just work not yet done in `h2_upstream`/`proxy` — (b) does not
forward trailers, and (c) serializes response collection per upstream connection under a mutex —
genuinely parallel in-flight streams across OS threads would need a dedicated per-connection reader
task (a larger async redesign), deferred to avoid forking a second h2 stack. A shared *server*-side
`ResponseWriter` buffer pool (across connections) is still open; the *client*-side one now exists
(`bufpool`). WebSocket and an MQTT broker are noted (see the Non-goals section of /README.md) as
candidate consumers layered on top of `http`'s server template, not gaps in `http` itself. TLS
termination stays BYO (reverse proxy today)
pending a native std TLS server.

## Status
`extract+gap · any · both · single_owner` · deps: `netaddr` (+ `std.crypto.tls`, `std.Io.net`,
`std.compress.flate`) — canonical source is `pub const meta` in src/root.zig.
