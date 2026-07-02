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

## Phases

1. **DONE — HTTP/1.1 client over TCP + TLS.**
2. **DONE — HTTP/1.1 server** (request codec, response writer, serving
   loop). Plain HTTP only — a reverse proxy (Caddy) terminates TLS.
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
    //      Content-Length + chunked already decoded), .context.
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
});
defer server.deinit();
try server.bind();                    // boundAddress() valid from here
try server.serve();                   // accept loop; or server.listen() = bind+serve
// From another thread: server.shutdown() → serve() drains and returns.
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
- **Errors:** malformed head → 400; oversized head → 431; unsupported
  HTTP version → 505; unknown method token → 501; missing Host on 1.1 →
  400; `Transfer-Encoding` without chunked → 400 (Go answers 501 here);
  handler error → 500 when nothing was sent, otherwise the connection dies
  mid-response. `Expect: 100-continue` is acknowledged eagerly. Absolute-
  form request targets are rejected (origin-form + `*` only; fine behind a
  reverse proxy).
- **Timeout:** one `read_timeout_ms` (default 10 s) bounds every read
  *stall* — head wait, body wait, keep-alive idle — via poll(2) before
  blocking reads. A dribbling client can extend the total time; slowloris
  hardening belongs to the later `abuseguard` module.
- **No TLS in the server** — Caddy (or any reverse proxy) terminates TLS.

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
  declared-Content-Length enforcement, handler-error 500, IMF-fixdate.
- **In-process integration (dogfood, not skipped):** the Phase-1 `Client`
  drives the `Server` on `127.0.0.1:0` — GET with query + headers, POST
  with body (echo), chunked response decode; a raw TCP connection proves
  keep-alive (two requests, one connection, close honored) and the read
  timeout (stalled half-request gets dropped). Skips via `SkipZigTest` only
  if loopback is unavailable.
- Live client tests (auto-skipped without network): `GET
  https://example.com` over TLS returns 200 + body; an `http://` request
  completes.
