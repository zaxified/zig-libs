# http

HTTP/1.1 client **and server** in pure Zig (client TLS over `std.crypto.tls`).

- HTTP/1.1 **and HTTP/2** client + server, plus a reverse-proxy handler and
  an opt-in multicore (SO_REUSEPORT thread-per-core) accept engine.
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

Provenance: original work of the zig-libs authors (MIT); the HTTP/1.1 framing,
the server, HPACK, HTTP/2 and the reverse proxy are clean-room from the RFCs.
Design references (behavior only, no source copied): `lalinsky/dusty` (MIT; the
1.1 client shape), Go `net/http` (BSD-3-Clause, The Go Authors; redirect
semantics, server shape, gzip handler), Go `net/http/httputil.ReverseProxy`
(BSD-3-Clause) and nginx `proxy_pass` (BSD-2-Clause) for the reverse-proxy
behavior. The full spec list and the design-reference record are in
[`NOTICE`](NOTICE) beside this file.

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
3. **DONE — HTTP/2** (`hpack` RFC 7541 + `h2` RFC 9113 framing/state
   machine/flow control): opt-in cleartext h2c on the server
   (`Options.enable_h2c`, prior knowledge), a multiplexing client
   (`Client.connectH2c`), and the bring-your-own-TLS seam
   (`h2_server.serveStream` / `Client.connectH2Over` after ALPN "h2").
   Client *and* server are incremental in both directions — see "HTTP/2
   client" and "HTTP/2 server" below.
4. **DONE — API-gateway building blocks:** a reverse-proxy handler
   (`http.proxy`, see "Reverse proxy") and an opt-in multicore accept
   engine (`Options.accept_threads`, see "Multicore accept engine").

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

### Plaintext-only client

`Client.requestPlain` / `Client.requestStreamingPlain` / `Client.putFilePlain`
are `http://`-only twins of `request`/`requestStreaming`/`putFile` — same
redirect/retry/pooling behavior, `error.UnsupportedScheme` on `https://`
(checked before any dial, including a redirect hop that points there). They
exist for one measured reason: a consumer shipping a device agent on an 8 MB
router overlay measured `http.Client` at **+351 000 B on x86-64
musl/ReleaseSmall (+49%) and +607 200 B on big-endian MIPS32** for two
plaintext one-shot operations (a `putFile` upload and a `request` +
`streamRemaining` fetch, both to an IP literal, no TLS) — attributed almost
entirely (**89.8%, 325 760 B**) to one thing: `dialConn` computing
`tls_needed` from a runtime URL value meant the `if (tls_needed)` branch
forced every caller, plaintext-only or not, to pull in the whole TLS client
(handshake state machine, X.509 parse/verify, every hash/curve/AEAD it uses).

```zig
var client = http.Client.init(threaded.io(), gpa, .{});
defer client.deinit();

_ = try client.putFilePlain("http://10.0.0.1:9070/v1/backup", std.Io.Dir.cwd(), "db.tar", .{});

var res = try client.requestPlain(.get, "http://10.0.0.1:9070/v1/status", .{});
defer res.deinit();
_ = try res.reader().streamRemaining(some_writer);

// error.UnsupportedScheme, not a TLS attempt:
_ = client.requestPlain(.get, "https://example.com/", .{});
```

`request`/`requestStreaming`/`putFile` are **unchanged** — they still go
through `dialConn` (now a two-line dispatcher onto `dialPlain`/`dialTls`)
and still cost what they always cost, TLS included; `requestPlain` and
friends are a separate call graph (`acquireConnPlain`/`dialPlain`) that never
names `dialConn`/`dialTls`/`ensureCaBundle`, so nothing forces Sema to
analyse the TLS client for a binary that only calls the plaintext entry
points — the same mechanism that already gives HTTP/2 (`connectH2c`, its own
entry point `dialConn` never calls) its zero cost when unused.

**Measured saving** (`modules/http/sizeprobe/`, static `ReleaseSmall`, the
same two call sites as the consumer measurement above):

| target | before (TLS-capable entry points) | after (plaintext-only entry points) | delta |
|---|---:|---:|---:|
| x86_64-linux-musl | 490 408 B | 165 520 B | **324 888 B** |
| mips-linux-musleabi (BE MIPS32) | 923 904 B | 238 576 B | **685 328 B** |

`nm` on an unstripped build of the plaintext-only probe shows **zero**
`tls.Client`/`Certificate`/curve/hash symbols on either target (196 such
symbols on the TLS-capable probe, for contrast — see the sizeprobe README).

### HTTP/2 client: multiplexed, and incremental in both directions

`Client.connectH2c` (cleartext h2c, prior knowledge) / `connectH2Over` (a
stream that ALPN already selected `h2` on) return an `H2Session` that
multiplexes any number of requests. Buffered use is `request` + a fully
assembled `awaitResponse`. Underneath it — and usable directly for a body
you do not have yet, a response you must process as it arrives, or both at
once on one stream — is the incremental surface:

```zig
const hs = try client.connectH2c("127.0.0.1", 8080, .{});
defer hs.close();

const sid = try hs.openStream(.post, "/rpc", .{});  // HEADERS, no END_STREAM
const s = &hs.session;                              // the rest lives here

try s.sendData(sid, first_chunk, false);            // blocks until it is away
const head = try s.awaitHead(sid);                  // status/headers, early
try s.sendData(sid, last_chunk, true);              // END_STREAM: body done

var buf: [4096]u8 = undefined;
while (true) {
    const n = try s.readBody(sid, &buf);            // 0 = body complete
    if (n == 0) break;
    consume(buf[0..n]);
}
if (s.trailers(sid)) |tr| { … }                     // distinct from the end
s.release(sid);
```

- **Receive-side flow control follows consumption, not arrival**: the
  WINDOW_UPDATE for an octet (§6.9) is sent when `readBody` hands it to the
  caller, so "credit outstanding" means "buffer space actually free". A
  caller that stops reading applies real backpressure to the peer (and, on
  the shared connection window, to the other streams — §6.9 head-of-line
  blocking, which is what backpressure over one connection *is*).
- **Send-side**: `sendData` blocks until every octet is away, reading the
  connection for grants when the peer's window is shut; `sendDataPartial`
  is the non-blocking variant and returns the count it accepted, which Zig
  will not let you drop by accident.
- `cancel(sid, .cancel)` aborts a stream (RST_STREAM) and returns the
  unconsumed octets' connection-window credit — §6.9.1, or an abandoned
  download shrinks the shared window for good.
- `awaitResponse` is written on top of all this, so there is one
  flow-control engine, not a buffered one and a streaming one that drift.

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
server.bind() catch |err| {           // boundAddress() valid from here
    // BindError is still just { BadAddress, ListenFailed, Canceled }; the
    // underlying std.Io.net error (e.g. "AddressInUse") survives in
    // bindErrorName() for logging, since the tag alone often is not enough.
    std.log.err("bind failed: {s} ({s})", .{ @errorName(err), server.bindErrorName() orelse "?" });
    return err;
};
try server.serve();                   // accept loop; or server.listen() = bind+serve
// From another thread: server.shutdown() → serve() drains and returns;
// server.activeConnections() = admitted, not-yet-closed connections.
```

### Response trailers

Fields whose value is only known once the body is finished (payload
checksum, row count, generation time) — RFC 9112 §7.1.2 on HTTP/1.1, RFC
9113 §8.1 on HTTP/2, from the same handler code:

```zig
try rw.declareTrailers(&.{ "X-Checksum", "X-Rows" }); // before the head goes out
try rw.writeAll(body);                                 // stream as usual
try rw.setTrailer("X-Checksum", checksum_hex);         // after it
try rw.setTrailer("X-Rows", rows_str);
```

- **Declaring commits the response to chunked framing** — an exact
  `Content-Length` is deliberately not used, and `setHeader("Content-Length",
  …)` afterwards is refused. h2 re-frames that as a trailing HEADERS frame
  with END_STREAM (so the last DATA frame does not carry it).
- **`setTrailer` is a two-gate filter.** The name must not be in the RFC 9110
  §6.5.1 forbidden set (`error.ForbiddenTrailer`: framing, routing, request
  modifiers, auth, response control data, payload-processing fields, plus
  connection-specific ones, `Cookie`/`Set-Cookie` and any `:` pseudo-header),
  **and** it must have been advertised (`error.TrailerNotDeclared`).
  Arbitrary handler-chosen trailers are a request-smuggling / cache-poisoning
  vector — intermediaries treat trailers inconsistently.
- **Nothing is dropped silently.** A response that cannot carry a trailer
  section — HTTP/1.0 peer, declared `Content-Length`, HEAD/1xx/204/304 —
  fails with `error.TrailersUnsupported` at set time (check
  `rw.trailersSupported()` first if you must serve HTTP/1.0 too), or fails
  `end()` in the one case only `setStatus` could have caused.
- Reading them is symmetric: `req.trailer("X-Checksum")` /
  `req.iterateTrailers()` work on both protocols, valid once the request body
  has been drained to end-of-stream. On the client, `h2_client`'s
  `Response.trailer(name)` / `Response.trailers`.

The codec works **without a socket**: `h1.RequestHead.parse` +
`Server.RequestBody` decode requests from any `std.Io.Reader`,
`Server.ResponseWriter` emits to any `std.Io.Writer`, and
`Server.serveStream` runs the whole per-connection loop over an arbitrary
Reader/Writer pair — that is what the offline tests (and the future
`router`) use.

### HTTP/2 server: streaming in both directions

The h2 serving loop (`Options.enable_h2c`, or `h2_server.serveStream` behind
your own TLS) runs the *same* `Options.handler` as HTTP/1.1. Both directions
stream, and both can be live on one stream at once.

**Responses stream always — no opt-in, and no second code path.** The
handler still writes an ordinary HTTP/1.1 response through `ResponseWriter`;
what changed is that the h1→h2 re-framing now happens *as it is written*
rather than after it. So the whole `ResponseWriter` feature set (gzip,
ranges, conditional requests, content negotiation, response trailers) works
on h2 unchanged — none of it knows the difference — and there is exactly one
response engine that cannot drift from itself:

```zig
// Nothing h2-specific. Reaches the client progressively on both protocols.
try rw.setHeader("Content-Type", "text/event-stream");
while (try next_event()) |ev| {
    try rw.writeAll(ev);
    try rw.flush();     // h1: a chunk. h2: a DATA frame.
}
```

A response that fits `response_buffer_size` is still framed exactly as
before (HEADERS + one DATA frame carrying END_STREAM); past that it streams,
under §5.2 flow control, without ever holding the whole body. The one visible
consequence: a handler that fails *after* part of the body is already on the
wire can no longer be rewritten into a clean 500 — that stream is reset with
INTERNAL_ERROR (h1 kills the connection in the same situation).

**Request bodies are buffered until END_STREAM by default, and stream
per-route on opt-in** (`Options.h2_stream_request`). The default is not
laziness. Two answers this server gives *before* a handler runs — 413 for a
body over `max_body_bytes`, 400 for a `content-length` that disagrees with
the DATA total (RFC 9113 §8.1.1) — both need the whole body first, and h1
only manages them because it knows the length up front. Opting a route in
trades those two pre-dispatch answers for h1's actual behavior:

```zig
fn streamUploads(_: ?*anyopaque, p: http.Server.H2RequestPreview) bool {
    return std.mem.eql(u8, p.path(), "/upload");
}
// …
.enable_h2c = true,
.h2_stream_request = streamUploads,
```

On such a route the handler is dispatched when the HEADERS arrive and
`req.reader()` yields DATA as it lands (blocking only when nothing has
arrived, ending only at END_STREAM). Both checks survive as read failures
rather than disappearing: over `max_body_bytes` still answers 413, and a
`content-length` mismatch fails the read. `req.trailer()` /
`iterateTrailers()` are the same surface as everywhere else — the trailer
HEADERS frame is materialized into it once the body ends.

- **Receive-side flow control differs by surface, on purpose.** A *buffered*
  body's WINDOW_UPDATE goes back on **arrival**: nothing can consume an
  octet before END_STREAM, so waiting for consumption would withhold exactly
  the credit the peer needs to send the END_STREAM the dispatch is waiting
  for — any upload past the initial 64 KiB window would deadlock. The memory
  is bounded by `max_body_bytes` instead. A *streaming* body's credit goes
  back on **consumption**, the same policy and the same argument as the h2
  client's `readBody`: an octet sitting unread in our buffer is still
  occupying us, so unread octets can never exceed the advertised window
  however slowly the handler reads. Either policy applied to the other
  surface is a bug.
- **A handler that never reads the body cannot wedge the connection.** It
  gets no stream-level credit (it is not invited to send more), and when the
  response is done the stream is retired with RST_STREAM(NO_ERROR) — RFC
  9113 §8.1's "complete response before the request finished" — while the
  discarded octets' connection-window credit is handed back (§6.9.1).

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
  `Content-Length`; larger bodies switch to chunked streaming — **silently**,
  which has bitten a consumer whose own minimal HTTP client on the other end
  does not decode `Transfer-Encoding: chunked`. If a response can exceed the
  buffer and the peer is such a client, set an explicit
  `rw.setHeader("Content-Length", …)` on it instead of relying on the auto
  framing. A `Content-Length` set via `setHeader` selects identity framing
  and the byte count is enforced (mismatch → connection close; before the
  head is sent it degrades to a 500). HEAD/204/304 never send a body; HEAD
  mirrors GET's Content-Length when known.
- **Auto headers:** `Date` (IMF-fixdate) + `Server` on every response,
  overridable via `setHeader`; `Connection`/`Transfer-Encoding` are managed
  by the writer (`setHeader("Connection", "close")` requests a close,
  Transfer-Encoding is ignored). `setHeader` replaces same-named headers —
  repeated fields (multiple Set-Cookie) are not supported yet. To omit
  either auto header instead of overriding it, set `Options.server_name =
  null` (`Server`) — omits `Server`; `.emit_date = false` — omits `Date`.
  Both default to their historical always-on behavior, and both are also
  available on the socket-free codec (`StreamOptions.server_name = null` /
  `.now = null`), which the socket path now agrees with byte-for-byte.
- **Errors:** malformed head → 400; oversized head → 431; over-long
  request line → 414; oversized body → 413; unsupported HTTP version →
  505; unknown method token → 501; missing Host on 1.1 → 400;
  `Transfer-Encoding` without chunked → 400 (Go answers 501 here);
  handler error → 500 when nothing was sent, otherwise the connection dies
  mid-response. `Expect: 100-continue` is acknowledged eagerly. Absolute-
  form request targets are rejected (origin-form + `*` only).
- **No TLS in the server** — terminate TLS in front (Caddy/any proxy); a
  native TLS-terminating server is a separate later task.

## Multicore accept engine (SO_REUSEPORT thread-per-core)

`Options.accept_threads` (default 1 = the classic single accept loop on the
caller's thread) opts into an N-listener engine: `bind` binds N listener
sockets on the same address — each with SO_REUSEPORT (`reuse_address`,
forced on) — and `serve` runs N independent accept loops, each on its own
OS thread pinned to a distinct core (Linux `sched_setaffinity`; a
best-effort no-op elsewhere). The kernel load-balances incoming connections
across the listeners (the nginx/glommio model), so there is **zero
cross-core accept contention** and no thundering herd on one listen queue.
Each accept loop owns its own `Io.Group`; `shutdown` drains all N, `serve`
returns once every listener's connections have drained. Pass
`http.Server.cpuCount()` for one listener per core. With an ephemeral port
(port 0) all N listeners share the *resolved* port. io_uring is deliberately
not used — its net vtable is `Unavailable` in std 0.16.

```zig
var server = http.Server.init(io, gpa, .{
    .handler = handler,
    .accept_threads = http.Server.cpuCount(), // one core-pinned listener per CPU
});
```

## Reverse proxy (`http.proxy`)

`http.proxy.ProxyHandler` is a `Server.Handler` that forwards a request to a
backend through the `Client` and streams the response back — the forwarding
half of an API gateway. It strips hop-by-hop headers both ways (RFC 9110
§7.6.1: `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`,
`Upgrade`, every `Proxy-*`, and every field named in the request's
`Connection`), appends the socket peer to `X-Forwarded-For`, sets
`X-Forwarded-Proto` / `X-Forwarded-Host`, injects `Via: 1.1 <pseudonym>`
(both directions), rewrites `Host` to the backend authority (default),
streams request and response bodies without full buffering, and maps a
dead backend → **502**, a timeout → **504**, no selectable backend → **503**.

```zig
var client = http.Client.init(io, gpa, .{});
var ph = http.proxy.ProxyHandler.init(.{
    .client = &client,
    .backend = .{ .host = "10.0.0.1", .port = 8080 },
});
var server = http.Server.init(io, gpa, .{
    .handler = http.proxy.ProxyHandler.handler,
    .context = &ph,
    .accept_threads = http.Server.cpuCount(),
});
```

Backend selection is a **seam** (`Config.selector` — a `ctx + fn` returning
a `Backend`), not a hard dependency, because `http` is foundational and
`router`/`upstream` sit *on top of it* (importing them back would cycle or
drag the resilience/probe stack into every `http` consumer). An
`upstream.Pool` (load-balanced, health-checked backends) or a `router`
route composes from above through that seam; `resilience` wraps the
forward operation there too. Backends can also be forwarded over **HTTP/2**
per-backend (`Backend.protocol` = `.h2c`/`.h2`), multiplexed through an
`h2_upstream.Pool` — see "Reverse proxy" below. **Known gaps this pass:**
h2-upstream bodies are buffered (bounded), not streamed like the h1 path;
no shared response buffer pool for the *server*-side `ResponseWriter`
(the *client*-side one, `Client.Options.buffer_pool`, already exists).
Backend connection pooling is **not** a gap: `Client` keeps a keyed idle
`Pool` on by default, and every backend connection this handler opens is
checked out of and returned to it transparently.

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

**`max_body_bytes` defaults to 1 MiB — set it to `null` for any route that
streams or accepts real uploads,** or every request body over 1 MiB gets a
413 before the handler ever runs. This is the single most likely first-run
failure for a new consumer moving real traffic onto this server. It applies
to `enable_h2c` requests identically (`Server` forwards the same value into
the HTTP/2 path), so raising or nulling it once covers both protocols.

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
- **Connections:** a keyed idle-connection `Pool` (`Options.pool`, on by
  default) keeps warm, keep-alive-eligible connections per origin; a
  request checks one out on a hit or dials fresh on a miss, and returns it
  to the pool only when the response left it clean and fully drained
  (`Connection: close`, an HTTP/1.0 response with no explicit
  `keep-alive`, a `101` upgrade, an undrained body, or any read/write error
  all close the connection instead of pooling it). Set
  `Options.pool.enabled = false` for the old one-shot-per-request behavior
  (`Connection: close` on every request).
- **TLS:** `std.crypto.tls.Client`, system CA bundle loaded lazily once per
  Client; `tls.verify = .insecure_no_verify` opt-out for testing.
- **Plaintext-only entry points:** `requestPlain`/`requestStreamingPlain`/
  `putFilePlain` never reference the TLS client at all (see "Plaintext-only
  client" above) — use them when every target is `http://` and binary size
  matters; `request`/`requestStreaming`/`putFile` are unaffected either way.
- **Timeouts:** both budgets are enforced, and neither by the socket layer —
  std 0.16.0 has no per-read deadline and `Io.Threaded` panics outright ("TODO
  implement netConnectIpPosix with timeout") if `ConnectOptions.timeout` is
  set. What std does offer is cancelation, so each blocking phase runs on a
  concurrent task and blowing the deadline cancels it, interrupting the
  syscall it is parked in. `connect_timeout_ms` bounds name resolution +
  `connect`; `total_timeout_ms` bounds a whole `request` (every redirect hop,
  the TLS handshake and the response-head read) and, measured from the call,
  an `Upload.finish`. **Not** bounded: reading a response body through
  `Response.reader` (the caller drives those reads), an `H2Session` past its
  dial, and anything at all on an `Io` that cannot supply a unit of
  concurrency (single-threaded build, or a `Threaded` at its
  `concurrent_limit`) — there is then nothing to cancel and only the
  between-phase deadline checks apply.
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
`http.Server.RequestBody` — the server codec, socket-free; `http.hpack` /
`http.h2` / `http.h2_client` / `http.h2_server` — the HTTP/2 stack;
`http.proxy` — the reverse-proxy handler (offline-testable pure helpers
`isHopByHop` / `statusForBackendError` / URL + `Via` builders, plus a
loopback origin↔proxy↔client integration test).

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
