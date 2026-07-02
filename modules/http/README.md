# http

HTTP client (and later server codec) in pure Zig, over `std.crypto.tls`.

- **Status:** `extract+gap` — client shape seeded in axp
  (`axp-core/src/httpclient.zig`); HTTP/1.1 framing written here.
- **Model after:** `lalinsky/dusty` (1.1 client shape) + Go `net/http`
  (redirect/header semantics); `nghttp2` + h2spec later for HTTP/2.
- **Why:** a native client instead of shelling `curl` or depending on the
  churny `std.http.Client` (explicit non-dependency). `dns` (DoH), `rdap` and
  the REST cluster sit on this.
- **Platform:** any. **Role:** client (→ both after Phase 2).
  **Concurrency:** single-owner. **Deps:** `netaddr`, `std.crypto.tls`,
  `std.Io.net`.

## Phases

1. **DONE — HTTP/1.1 client over TCP + TLS** (this code).
2. TODO — server codec (request parse / response write, streaming); will
   reuse `h1.zig` (the codec is already split out and server-agnostic).
3. TODO — HTTP/2 (framing + HPACK), verified against h2spec. Not started.

## API

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

Submodules: `http.h1` — pure HTTP/1.1 wire framing (head parser,
chunked encoder/decoder, Content-Length reader with truncation detection),
fully offline-testable; `http.Url` / `http.Method` / `http.Header` —
shared vocabulary; `http.redirectMethodFor` / `http.resolveLocation`
(RFC 3986 §5.2) — the redirect state machine as pure functions.

## Behavior notes

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

## Verification

- `zig build test-http` — offline: URL parser, response-head parser (incl.
  malformed corpus), chunked decoder (split reads, trailers, extensions,
  truncation), chunked encoder round-trip, Content-Length truncation,
  request-head writer (exact bytes), redirect chain on fabricated responses.
- Live (auto-skipped without network): `GET https://example.com` over TLS
  returns 200 + body; an `http://` request completes.
