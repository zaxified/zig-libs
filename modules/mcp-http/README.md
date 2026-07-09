# mcp-http

The MCP **Streamable HTTP** transport (2025-06-18 revision) as a `router`
middleware, so a `mcp.Server` (JSON-RPC 2.0 tools / resources / prompts) is
reachable remotely over HTTP instead of only over stdio.

The request/response half: a single endpoint (`/mcp` by default) where the
client **POST**s one JSON-RPC message and gets back either the response
(`application/json`) or — for a notification / anything with no reply —
**202 Accepted** with no body. It wraps the transport-agnostic
`mcp.Server.handleMessage`, which does all protocol work (version negotiation,
dispatch, error objects) and, per the MCP spec, rejects JSON-RPC batches.

**Sessions** are optional. Leave `Transport.sessions` null for a **stateless**
server (no `Mcp-Session-Id`; `GET`/`DELETE` → 405; every POST independent — the
spec permits this). Set a `*Sessions` to enable the full session model: an
`Mcp-Session-Id` assigned at `initialize` and validated on later requests
(unknown → 404, so the client re-initializes), `DELETE /mcp` teardown, and a
server→client **`GET /mcp` stream**. That stream is **drain-and-close** (a
long-poll over SSE): it replays every event queued since the request's
`Last-Event-ID`, then closes; the client's `EventSource` auto-reconnects (with
`Last-Event-ID`) for more. This fits the io-less handler model (a handler can't
park a connection waiting for a future push) and MCP's low-frequency
server→client traffic — nothing is lost within the bounded resumable replay
buffer. Enqueue a message from any thread with `Sessions.push(id, data)`.

```zig
var server = mcp.Server.init(gpa, .{ .name = "netops", .version = "1.0" });
defer server.deinit();
try server.addTool(.{ ... });

var transport = mcphttp.Transport{ .gpa = gpa, .server = &server };
try router.use(transport.middleware()); // after any auth / origin middleware
```

## Security

This module does no authentication. Bind to loopback for a local integration,
or put auth in front: register an `aaa-gate` / `jwt` middleware **before** this
one (MCP has no read/write method split, so gate every POST). The MCP spec also
requires validating the `Origin` header against DNS-rebinding for locally-bound
servers — do that with a dedicated middleware or a reverse proxy.

## Concurrency

`mcp.Server` is not internally synchronized and `http.Server` serves from
several connection threads. Inject `Transport.lock` (a `Lock` seam, same shape
as `jwt.Lock`) to serialize `handleMessage`, or run the server single-threaded.
Body reads and response framing happen outside the lock.

- **Status:** `gap`. **Role:** server. **Platform:** any. **Deps:** `router`,
  `http`, `mcp`.

Provenance: clean-room from the MCP Streamable HTTP transport specification
(2025-06-18) + JSON-RPC 2.0; the behavioral contract was cross-checked for
parity against a reference Dart server wrapping the third-party `mcp_dart`
package — no `mcp_dart` or other MCP-transport source consulted or copied.

## Verification

`zig build test-mcp-http` — 13 offline tests through a real `router` +
`http.Server.serveStream`: request/response (initialize, tools/list, tools/call,
notification → 202), SSE-on-POST (streamed result, **live tool progress**,
notification → 202, `stream=.off`), Origin allowlist (match/mismatch/absent),
sessions (assign + validate + 404 + DELETE, `GET` push + `Last-Event-ID` replay
+ heartbeat, unknown-session 404), path pass-through / 405, oversized → 413.
Green in Debug + ReleaseFast.
