# requestid

Request / correlation ID as a `router` middleware — a stable ID per request
for log correlation and cross-service tracing.

Per request the middleware:

1. **Adopts** the incoming correlation header (`X-Request-Id` by default) when
   `trust_incoming` is set and the value is valid (non-empty, ≤ 200 bytes, all
   printable non-space ASCII) — the edge/ingress already assigned it.
2. Otherwise **generates** one.
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

A unique-per-request 32-hex-char token from the monotonic clock, a
per-connection-thread nonce and a per-thread counter — no allocation, no OS
entropy call, fully portable. It is a **correlation** ID (unique for tracing),
**not** an unpredictable security token; where unguessability matters, adopt an
edge-assigned header or set the header yourself.

- **Role:** util. **Platform:** any. **Deps:** `router`,
  `http`. **Concurrency:** threadsafe — per-request state is thread-local
  (the server is task-per-connection: one request at a time per thread, so the
  ID lives until the response is flushed); the config is immutable. `current()`
  is meaningful only from the connection thread handling the request.

Provenance: clean-room from the conventional `X-Request-Id` correlation-ID
pattern (nginx `request_id`, Envoy `x-request-id`) — original work of the
zig-libs authors (MIT). No third-party source consulted or copied.

## Verification

`zig build test-requestid` — 6 offline tests through `http.Server.serveStream`
(generate + echo + `current()` agreement, uniqueness across requests, adopt a
valid incoming ID, regenerate on malformed / `trust_incoming=false`,
`echo=false`, custom header name), green in Debug + ReleaseFast.
