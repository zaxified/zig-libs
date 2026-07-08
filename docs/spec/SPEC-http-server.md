# SPEC — `http` Phase 2 (server codec + serving loop)

Adds the **`http.Server`** submodule to the existing `http` module. Builds directly on the
Phase-1 wire codec in `modules/http/src/h1.zig` (readHead, ChunkedReader/Writer,
ContentLengthReader). Model after: Go `net/http` Server (minimal) / `lalinsky/dusty` server /
picohttpparser. `any · server · async`. **Do NOT start HTTP/2 (Phase 3).**

## Why

The REST/API cluster (`router` → `ratelimit` → `abuseguard` → `throttle` → `openapi`) — the
internet-behind-Caddy goal — sits on an HTTP/1.1 server. Caddy terminates TLS + h2/h3 and reverse-
proxies plain HTTP/1.1 to us, so a solid HTTP/1.1 server codec is exactly the app-layer surface we need.

## Scope

1. **Request parse:** reuse `h1.readHead`; expose `Request { method, target, version, headers,
   path, query, body reader }`. Body via Content-Length **and** chunked (streaming reader). Bounded
   header size; malformed request → 400 (never panic).
2. **Response write:** `ResponseWriter { setStatus, setHeader, write/writer, end }` — Content-Length
   when known, chunked when streamed. Correct framing for HEAD / 204 / 304 (no body). Auto Date +
   Server headers (overridable).
3. **Keep-alive:** HTTP/1.1 persistent connections by default; honor `Connection: close`; serve
   multiple requests per connection; close on error or client close.
4. **Serving loop:** `Server` that binds a TCP listener (`127.0.0.1:port`, port 0 = ephemeral),
   accepts, and dispatches each request to a caller handler `fn(*Request, *ResponseWriter)`.
   Concurrency: pick a reasonable model (thread-per-connection or a small worker pool) and document
   it — `throttle` will add concurrency limiting later. A basic read-header timeout is fine here;
   slowloris/abuse hardening is the later `abuseguard` module.
5. **No TLS in the server** — Caddy terminates TLS; the server speaks plain HTTP/1.1. (TLS client
   stays in Phase 1.)

## Public API sketch (final shape your call; keep it small)

```zig
pub const Server = struct {
    pub fn init(io, gpa, Options) Server;   // Options: addr, port, read_header_timeout_ms, ...
    pub fn deinit(*Server) void;
    pub fn listen(self) !void;               // bind + accept loop; dispatch to handler
    pub fn boundAddress(self) net.Address;   // for ephemeral-port tests
    // handler set via Options.handler: *const fn(*Request, *ResponseWriter) anyerror!void
};
pub const Request = struct { method: Method, target: []const u8, path: []const u8, query: []const u8,
    headers: ..., pub fn header(name) ?[]const u8, pub fn reader() *std.Io.Reader };
pub const ResponseWriter = struct { pub fn setStatus(u16) void; pub fn setHeader(name, val) !void;
    pub fn writer() *std.Io.Writer; pub fn writeAll([]const u8) !void; pub fn end() !void; };
```

## Acceptance / verification

- **Offline unit tests:** request-line + header parse on canned bytes (+ malformed → error);
  response writer → exact golden bytes (fixed body, chunked body, HEAD/204 no-body framing);
  keep-alive: two requests parsed from one buffered stream; chunked request body decoded.
  `zig build test-http` green.
- **In-process integration (dogfood — no external network, must NOT skip):** start the `Server` on
  `127.0.0.1:0` in a thread with a small echo/hello handler, then drive it with the Phase-1
  `http.Client` (GET + POST-with-body + a keep-alive reuse) and assert status/body/headers.
  This proves client and server against each other. Bind failures (sandbox) → skip via
  `error.SkipZigTest`, but localhost loopback should work in the sandbox.
- `zig build test` (all) green (Debug + ReleaseFast); `zig fmt --check` clean. No new module_list
  entry (server is a submodule of `http`); expose as `http.Server`.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 std APIs (std.Io.net listener/accept, threads, buffered
  reader/writer). Reuse `h1.zig` for all framing — do not duplicate the parser/encoder.
- Keep the request parser and response writer usable independently of the serving loop (so `router`
  and tests can use the codec without opening a socket).
- Same std.Io connect-timeout caveat noted in Phase 1 does not apply to accept; but add a
  read-header timeout to avoid a trivially-stuck connection.
