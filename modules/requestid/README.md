# requestid

Request / correlation ID as a `router` middleware — a stable ID per request
for log correlation and cross-service tracing.

Per request the middleware:

1. **Adopts** the incoming correlation header (`X-Request-Id` by default) when
   `trust_incoming` is set and the value is valid (non-empty, ≤ 200 bytes, every
   byte in `[A-Za-z0-9._-]`) — the edge/ingress already assigned it.
2. Otherwise **generates** one (built-in, or your `Options.generator`).
3. **Echoes** the ID on the response under the same header and exposes it to
   handlers and the access log via `requestid.current()`.

It deliberately avoids `Ctx.data` (that slot belongs to an auth middleware like
`aaa-gate`/`jwt`), so request-ID **composes with authentication** on the same
routes. Register it **first** (outermost) so every response — including 401/404
short-circuits — carries the ID.

```zig
var ri = requestid.RequestId{};
try r.use(ri.middleware()); // outermost
// … in a handler or the access log:
const id = requestid.current() orelse "-";
```

### Generated IDs

A 32-hex-char token: a per-process prefix and a process-wide atomic sequence
number — unique within the process across all threads, no allocation, no OS
entropy call. It is a **correlation** ID (unique for tracing), **not** an
unpredictable security token.

For another scheme (UUID, ULID, a CSPRNG token) plug in a generator; its output
must pass `isAdoptable`, otherwise the built-in ID is used:

```zig
const Gen = struct {
    var n: u64 = 0; // single-threaded example; `context` can carry real state
    fn run(_: ?*anyopaque, buf: *[requestid.max_adopt_len]u8) []const u8 {
        n += 1;
        return std.fmt.bufPrint(buf, "svc-{x}", .{n}) catch unreachable;
    }
};
var ri = requestid.RequestId{ .options = .{ .generator = .{ .run = Gen.run } } };
```

- **Role:** util. **Platform:** any. **Deps:** `router`,
  `http`. **Concurrency:** threadsafe — per-request state is thread-local
  (the server is task-per-connection: one request at a time per thread, so the
  ID lives until the response is flushed); the config is immutable. `current()`
  is meaningful only from the connection thread handling the request.

Provenance: clean-room from the conventional `X-Request-Id` correlation-ID
pattern (nginx `request_id`, Envoy `x-request-id`) — original work of the
zig-libs authors (MIT). No third-party source consulted or copied. The comparative benchmark under `tools/` (`bench.zig`, its `go_bench/` reference side, 2026-10-10, and its `rust_fast_bench/` tower-http side, 2026-10-24) and the `lead_probe/` behaviour probe of chi (2026-10-24) are our own tooling; they drive the other implementations only through their public APIs.

## Verification

`zig build test-requestid` — 16 offline tests (adopt-or-generate through
`http.Server.serveStream`, the `isAdoptable` charset and length cap, no duplicate
ID across 32 threads, the custom generator and its fallback, seeded model-fuzz);
details in `SPEC.md` § Verification.
