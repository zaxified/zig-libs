# http

HTTP/1.1 client **and server** in pure Zig (client TLS over `std.crypto.tls`).

- **Status:** `extract+gap` — client shape seeded in axp
  (`axp-core/src/httpclient.zig`); HTTP/1.1 framing + server written here.
- **Model after:** `lalinsky/dusty` (1.1 client shape) + Go `net/http`
  (redirect/header semantics, Server shape); `nghttp2` + h2spec later for
  HTTP/2.
- **Why:** a native client instead of shelling `curl` or depending on the
  churny `std.http` (explicit non-dependency). `dns` (DoH), `rdap` and the
  REST cluster (`router` → `ratelimit` → …) sit on this.
- **Platform:** any (the server's read timeout needs poll(2) and is
  compile-time disabled elsewhere). **Role:** both.
  **Concurrency:** single-owner handles; the Server runs its own
  per-connection tasks — handlers must be thread-safe if they share state.
  **Deps:** `netaddr`, `std.crypto.tls`, `std.Io.net`.

Provenance: client shape extracted from axp `axp-core/src/httpclient.zig`
(same authors, Apache-2.0, relicensed MIT); the HTTP/1.1 framing + the
server are clean-room from RFC 7230/9110. Design refs in
[NOTICE](../../NOTICE).

## Phases

1. **DONE — HTTP/1.1 client over TCP + TLS.**
2. **DONE — HTTP/1.1 server** (request codec, response writer, serving
   loop). **Phase 2.1 (DONE) hardened it for direct internet exposure** —
   peer address + request index on `Request`, `on_connect` accept hook +
   `activeConnections()`, 431/414/413 size limits, stall + whole-request +
   write timeouts (details below). **Phase 2.2 (DONE) added negotiated
   gzip response compression** (`Options.compression`, off by default —
   see "Response compression"). Still plain HTTP only: a TLS-terminating
   server is a separate later task (a reverse proxy also works).
3. TODO — HTTP/2 (framing + HPACK), verified against h2spec. Not started.

## Client API

```zig
const http = @import("http");

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
var client = http.Client.init(threaded.io(), gpa, .{});
defer client.deinit();

// One-liners
const body = try client.getAlloc(gpa, "https://example.com/", 1 << 20);
_ = try client.getToFile("https://host/fw.bin", std.Io.Dir.cwd(), "fw.bin");
_ = try client.putFile("http://host:9070/v1/backup", std.Io.Dir.cwd(), "db.tar", .{});

// Full control + streaming response body
var res = try client.request(.post, "https://api.example/v1", .{
    .headers = &.{.{ .name = "Authorization", .value = "Bearer …" }},
    .body = payload, // in-memory; replayed on 307/308
});
defer res.deinit();
_ = res.status; // u16
_ = res.header("content-type");
_ = try res.reader().streamRemaining(some_writer); // no full-body buffering

// Streaming request body (unknown length → chunked)
var up = try client.requestStreaming(.put, url, .{}, null);
try up.writer().writeAll(part1); // … as much as you like
var res2 = try up.finish();
defer res2.deinit();
```

## Server API

```zig
fn handler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    // req: .method (http.Method), .target, .path, .query,
    //      .header("name"), .iterateHeaders(), .reader() (streaming body,
    //      Content-Length + chunked already decoded), .context,
    //      .peerAddress() (socket peer, the direct client),
    //      .connRequestIndex() (Nth request on this keep-alive connection).
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.writeAll("hello");            // or stream via rw.writer()
        // rw.end() is optional — the loop calls it after the handler.
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

var server = http.Server.init(threaded.io(), gpa, .{
    .handler = handler,
    .addr = "127.0.0.1",
    .port = 0, // ephemeral; resolved port via server.boundAddress()
    // Hardening knobs (defaults shown; see "Direct-internet posture"):
    // .read_timeout_ms = 10_000, .request_timeout_ms = 60_000,
    // .write_timeout_ms = 10_000, .max_header_bytes = 16 * 1024,
    // .max_request_line_bytes = 8 * 1024, .max_body_bytes = 1 << 20,
    // .on_connect = myGate, .on_connect_ctx = &gate,   // accept/reject
    // .on_conn_state = myMetrics,                      // Go ConnState-style
    // .compression = .{},   // negotiated gzip; off when omitted (see below)
});
defer server.deinit();
try server.bind();                    // boundAddress() valid from here
try server.serve();                   // accept loop; or server.listen() = bind+serve
// From another thread: server.shutdown() → serve() drains and returns;
// server.activeConnections() = admitted, not-yet-closed connections.
```

The codec works **without a socket**: `h1.RequestHead.parse` +
`Server.RequestBody` decode requests from any `std.Io.Reader`,
`Server.ResponseWriter` emits to any `std.Io.Writer`, and
`Server.serveStream` runs the whole per-connection loop over an arbitrary
Reader/Writer pair — that is what the offline tests (and the future
`router`) use.

## Server behavior notes

- **Concurrency = task per connection** (Go's model): `serve` accepts and
  spawns each connection into an `std.Io.Group` (`Io.concurrent`; with
  `std.Io.Threaded` that is one OS thread per connection). `serve` returns
  only after all connection tasks drain. Limiting concurrency is the later
  `throttle` module's job.
- **Keep-alive:** HTTP/1.1 persistent by default; `Connection: close`
  honored both ways; unread request bodies are drained up to 256 KiB before
  the next request (beyond that the connection closes). HTTP/1.0
  connections always close (no keep-alive opt-in) and large 1.0 responses
  use identity-until-close instead of chunked.
- **Response framing (Go-like):** bodies that fit the response buffer
  (`response_buffer_size`, default 4 KiB) get an exact auto
  `Content-Length`; larger bodies switch to chunked streaming. A
  `Content-Length` set via `setHeader` selects identity framing and the
  byte count is enforced (mismatch → connection close; before the head is
  sent it degrades to a 500). HEAD/204/304 never send a body; HEAD mirrors
  GET's Content-Length when known.
- **Auto headers:** `Date` (IMF-fixdate) + `Server` on every response,
  overridable via `setHeader`; `Connection`/`Transfer-Encoding` are managed
  by the writer (`setHeader("Connection", "close")` requests a close,
  Transfer-Encoding is ignored). `setHeader` replaces same-named headers —
  repeated fields (multiple Set-Cookie) are not supported yet.
- **Errors:** malformed head → 400; oversized head → 431; over-long
  request line → 414; oversized body → 413; unsupported HTTP version →
  505; unknown method token → 501; missing Host on 1.1 → 400;
  `Transfer-Encoding` without chunked → 400 (Go answers 501 here);
  handler error → 500 when nothing was sent, otherwise the connection dies
  mid-response. `Expect: 100-continue` is acknowledged eagerly. Absolute-
  form request targets are rejected (origin-form + `*` only).
- **No TLS in the server** — terminate TLS in front (Caddy/any proxy); a
  native TLS-terminating server is a separate later task.

## Direct-internet posture (Phase 2.1 hardening)

The server is built to run **without a reverse proxy in front**. Model:
Go `net/http` (`ConnState`, `MaxHeaderBytes`, `ReadTimeout`) + nginx
(`client_max_body_size`, `limit_conn`).

**Client identity.** `req.peerAddress()` is the socket peer (`?IpAddress`;
null only when the codec runs socket-free via `serveStream` without
`StreamOptions.peer`), `req.connRequestIndex()` the 0-based request ordinal
on the connection. `ratelimit` keys on the peer when no trusted
`X-Forwarded-For` is present; `abuseguard` (next) builds per-IP caps/bans
on the same surface.

**Admission.** `Options.on_connect(ctx, peer) → .accept | .reject` runs on
the accept loop right after `accept`, before any allocation or read —
keep it fast and thread-safe. A `.reject` **closes the socket without
writing anything** (no 429/503; nginx `limit_conn` answers 503, we drop at
the TCP level so abusive peers cost no response bytes — a polite 503 can
be layered as middleware). `Server.activeConnections()` is a thread-safe
count of admitted, not-yet-closed connections — the enforcement input for
a global cap. `Options.on_conn_state` optionally observes
`new / active / idle / closed` per connection (Go ConnState-style;
`active` fires when a request head arrived, not on the first byte;
rejected connections fire nothing).

**Size limits** (all configurable in `Options`):

| Limit | Default | Response |
|---|---|---|
| `max_header_bytes` — whole request head | 16 KiB | 431 |
| `max_request_line_bytes` — request line (within the head budget; null = off) | 8 KiB | 414 |
| `max_body_bytes` — request body (null = off) | 1 MiB | 413 |

An over-limit **declared** Content-Length is refused before the handler
runs (and before any `100 Continue`). A **chunked** body is capped *while
streaming*: the handler's body reader fails once decoded bytes cross the
cap, the server answers 413 (if nothing was sent) and closes. Bodies are
never buffered — memory per connection is a fixed buffer slab regardless
of body size; the cap protects body-buffering handlers and bandwidth, not
server memory.

**Timeouts** (poll(2)-based; compile-time disabled on platforms without
poll — then none of these fire):

| Timeout | Default | Bounds |
|---|---|---|
| `read_timeout_ms` | 10 s | any single read **stall**: head wait, body wait, keep-alive idle |
| `request_timeout_ms` | 60 s | one whole request-read cycle — keep-alive idle + head + body, **dribble included** (Go `ReadTimeout` semantics; re-checked at every refill, so slowloris byte-trickling is bounded). Handler compute and response writing are not counted |
| `write_timeout_ms` | 10 s | any single write **stall** (peer stops reading — slow-read attack); polled before every socket write. A trickle-reading peer restarts the window per write |

0 (or null for the size limits) disables the individual bound.

## Response compression (Phase 2.2)

Negotiated **gzip** response compression, `Options.compression: ?Compression`
— modeled after the Go `net/http` gzip-handler / nginx `gzip` semantics
(std `std.compress.flate` + RFC 9110/1952 behavior, no third-party code).

**Posture: off by default** (`null` — zero behavior change); `.{}` enables
with safe defaults:

| Knob | Default | Meaning |
|---|---|---|
| `min_size` | 1 KiB | plain-body size below which compression is skipped (nginx `gzip_min_length`). A body whose size is *unknown* when it starts streaming (no declared length, outgrew the response buffer) is compressed regardless — nginx's unknown-length behavior |
| `level` | 6 | flate level 1 (fastest) … 9 (best); 6 = zlib / Go default. Out-of-range clamps |
| `content_types` | see below | compressible-type allowlist |

**Default allowlist:** `text/` (every text subtype), `application/json`,
`application/javascript`, `application/xml`, plus the structured-syntax
suffixes `+json` / `+xml` (covers `image/svg+xml`,
`application/problem+json`, Atom/RSS…). Entries match the response
`Content-Type` case-insensitively with parameters (`; charset=…`) stripped;
entry forms: exact, `type/` prefix (trailing `/`), `+suffix` (leading `+`).
No `Content-Type` → never compressed.

**Negotiation (RFC 9110):** compressed only when the request's
`Accept-Encoding` admits gzip — an explicit `gzip` (or `x-gzip`) entry wins
over `*`; `q=0` is a refusal; an **absent header compresses nothing** (the
conservative Go/nginx middleware posture). **Eligibility:** a body must
exist (HEAD/1xx/204/304 never compress; HEAD advertises the identity
variant), the response must not already carry a `Content-Encoding`
(handler-set = pre-compressed → passed through, never double-compressed),
HTTP/1.1 only (nginx `gzip_http_version 1.1`; 1.0 has no chunked framing).

**Encoding path — streaming** (the SPEC's preferred option): handler bytes
→ `std.compress.flate` gzip encoder → the existing chunked framing.
Handler code is unchanged — it writes normally and the server compresses
transparently in bounded memory. Compressed responses are therefore always
`Transfer-Encoding: chunked` with **no** `Content-Length` — a
handler-declared length is dropped from the wire, exactly like Go's gzip
middleware and nginx (the declared byte count is still enforced against
what the handler writes). **`Vary: Accept-Encoding` goes on every response
while compression is enabled** — compressed or not — so caches key
correctly for clients that didn't opt in (added next to a handler-set
`Vary` unless that one already covers Accept-Encoding or `*`).

**Cost:** one gzip encoder state per connection while enabled — ~290 KiB
(deflate's inherent window + match tables; zlib pays the same), allocated
at connection admission, reused across keep-alive requests. Socket-free
`serveStream` callers pass it via `StreamBuffers.gzip`
(`Server.GzipScratch`); without it, `StreamOptions.compression` stays
inert. `deflate` and `brotli` response codings are not implemented (gzip
covers the client population; `deflate` adds nothing over it).

## Client behavior notes

- **Redirects:** 301/302/303 rewrite non-GET/HEAD to GET and drop the body;
  307/308 preserve method + body (Go semantics). `Authorization` is dropped
  when the redirect changes the host (exact host match, unlike Go's
  subdomain rule). Cap via `Options.max_redirects`.
- **Connections:** one per request, `Connection: close`. Keep-alive/pooling
  is a deliberate Phase 1 non-goal (TODO).
- **TLS:** `std.crypto.tls.Client`, system CA bundle loaded lazily once per
  Client; `tls.verify = .insecure_no_verify` opt-out for testing.
- **Timeouts:** `total_timeout_ms` is checked between phases (connect, head,
  hops), not inside a blocking body read (TODO: async-race enforcement).
  `connect_timeout_ms` is currently NOT enforced natively — std 0.16.0's
  `Io.Threaded` panics ("TODO implement netConnectIpPosix with timeout")
  when one is passed; re-enable in `connectTimeout` once std lands it.
- **Decompression is the caller's job** (`Accept-Encoding: identity` is sent
  by default); adopt `std.compress` at the call site if you ask for gzip.
- 1xx interim responses are skipped (101 returned as-is); HEAD/204/304
  responses get an empty body reader; chunked trailers are consumed and
  discarded.

## Submodules

`http.h1` — pure HTTP/1.1 wire framing (request + response head parsers,
chunked encoder/decoder, Content-Length reader with truncation detection),
fully offline-testable and shared by both sides; `http.Url` / `http.Method`
/ `http.Header` — shared vocabulary; `http.redirectMethodFor` /
`http.resolveLocation` (RFC 3986 §5.2) — the redirect state machine as pure
functions; `http.Server.serveStream` / `http.Server.ResponseWriter` /
`http.Server.RequestBody` — the server codec, socket-free.

## Verification

- `zig build test-http` — offline: URL parser, request- and response-head
  parsers (incl. malformed corpora), chunked decoder (split reads, trailers,
  extensions, truncation), chunked encoder round-trip, Content-Length
  truncation, request-head writer (exact bytes), redirect chain on
  fabricated responses; server: golden response bytes (fixed, chunked,
  HEAD/204, error pages), keep-alive two-requests-from-one-buffer, chunked +
  Content-Length request body decode, 100-continue, HTTP/1.0 fallback,
  declared-Content-Length enforcement, handler-error 500, IMF-fixdate;
  hardening: over-long request line → 414 (configurable), declared
  Content-Length over cap → golden 413 before the handler, chunked body
  over cap → 413 mid-stream with the body larger than all serving buffers
  combined (bounded-memory proof), exact-at-cap passes + keep-alive
  survives, peer address + request index surfaced socket-free, ConnState
  sequence `new→active→idle→active→closed`; compression:
  Accept-Encoding negotiation table (gzip/absent/`q=0`/`*`/alias/
  precedence), content-type allowlist matching, gzip round-trip through a
  `GzipScratch`, compressed responses (streaming + fully-buffered paths)
  decode chunked→gunzip back to the exact handler bytes, identity fallbacks
  (no opt-in / refusal / HTTP 1.0 / tiny body / non-listed type /
  pre-encoded) each with `Vary` present, HEAD/204 exclusion, declared
  Content-Length dropped, keep-alive across a compressed response.
- **In-process integration (dogfood, not skipped):** the Phase-1 `Client`
  drives the `Server` on `127.0.0.1:0` — GET with query + headers, POST
  with body (echo), chunked response decode; a raw TCP connection proves
  keep-alive (two requests, one connection, close honored), the read
  timeout (stalled half-request gets dropped), the loopback peer address +
  rising request index across keep-alive reuse (`on_connect` fires once
  per connection), an `on_connect` reject (handshake completes, first read
  fails, never admitted) and `activeConnections()` around an in-flight
  request (0 → 1 → 0); compression on over loopback — a gzip-accepting
  request to a >1 KiB JSON route comes back `Content-Encoding: gzip` +
  `Vary` + chunked and gunzips (via `std.compress.flate`, since the
  Phase-1 client leaves decode to the caller) to the exact JSON, the same
  route without the opt-in arrives plain, a tiny body stays uncompressed.
  Skips via `SkipZigTest` only if loopback is unavailable.
- Live client tests (auto-skipped without network): `GET
  https://example.com` over TLS returns 200 + body; an `http://` request
  completes.
