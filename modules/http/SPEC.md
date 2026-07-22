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
output; bodies stream with flow control. `setHeader` stores the value slice **without copying** —
dynamic header values need caller-stable memory (documented per-helper). BYO-TLS seam:
`serveStream` / `connectH2Over` + ALPN run h2/h1 over a caller-terminated (TLS) stream — TLS
termination is out of this module. **Reverse proxy (`proxy`):** forwards over HTTP/1.1 (streaming)
or, per-backend (`Backend.protocol` `.h2c`/`.h2`), over HTTP/2 through `h2_upstream.Pool` — one
multiplexed h2 connection per backend origin, each proxied request a stream on it (reuses
`h2_client.Session`; no second h2 stack). Header translation (hop-by-hop, `X-Forwarded-*`, `Via`) is
shared across both forward paths; the h2 path buffers bodies (bounded, `h2_max_body_bytes`) where h1
streams, and per-connection response collection is mutex-serialized (multiplex is on the wire, full
cross-thread parallelism needs a dedicated reader task — deferred). h2 flow control is exercised
end-to-end (WINDOW_UPDATE past the initial window); h2 upstream trailers are not forwarded (h2 client
does not surface them). **Client buffer pool (`bufpool.BufferPool`):** an optional bounded, shared,
thread-safe slab pool wired via `Client.Options.buffer_pool`, backing h2 upstream dial buffers so a
gateway that churns h2 connections reuses `O(peak)` slabs instead of allocating one per dial (h1's
idle `Pool` already recycles whole warm connections, so it does not need it). Never-panic: malformed
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
  configurable, safe by default (so `enable_h2c` is hardened out of the box).
- **Header injection:** outbound header names/values reject CR/LF/NUL (response-splitting guard).
- Response bodies of 304/204/1xx are suppressed (framing correctness).
- **Out of scope:** TLS termination (bring-your-own via the seam — reverse proxy today, ianic/std
  server later), HTTP/3 (QUIC), auth (`aaa-gate`/`jwt`), rate limiting (`ratelimit`), path-traversal
  normalization beyond what `router` does, and response-trailer *writing* (read side only —
  deferred as disproportionately invasive).

## Verification
HPACK vs RFC 7541 Appendix C vectors (bytes + decoded fields + dynamic-table state per step); h2
offline scripted client↔server pipe exchanges + h2spec-style negatives; h2 DoS attack-sim tests
(rapid-reset proves 0 handler runs); serveStream goldens for conditional/range/multipart/content-
neg; smuggling/timeout/size negatives; a BYO-TLS in-memory dogfood (connectH2Over ↔ serveStream).
h2 upstreaming: loopback h1-proxy → h2c-backend end-to-end (forwarding headers + hop-by-hop strip +
large-body flow control + concurrent clients over one shared upstream connection + 502 on dead
backend); pool-level multiplex (two streams in flight on one connection), sequential-reuse and
buffer-pool reuse/bounded proofs. 331 tests. Run: `zig build test-http`.

## Backlog / deferred
Response-trailer *writing* remains explicitly deferred (read side only) as disproportionately
invasive. **h2 upstream forwarding** reuses the multiplexing `h2_client.Session`, so it (a) buffers
request/response bodies in memory (bounded) rather than streaming like the h1 path, (b) does not
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
