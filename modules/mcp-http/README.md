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

**Stateless** — assigns no `Mcp-Session-Id` (the spec permits this); every POST
is handled independently. `GET`/`DELETE` on the endpoint answer **405** for now:
the server→client **SSE stream** (`GET /mcp`, built on `http.sse`) and
**session management** are follow-up parts.

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
(2025-06-18) + JSON-RPC 2.0; the behavioral contract was cross-checked against
the authors' own bxp-gui Dart server (wrapping the third-party `mcp_dart`) for
parity — no `mcp_dart` or other MCP-transport source consulted or copied.

## Verification

`zig build test-mcp-http` — 5 offline tests through a real `router` +
`http.Server.serveStream` (initialize → 200 result, tools/list + tools/call,
notification → 202, path pass-through + `GET` → 405, oversized body → 413),
green in Debug + ReleaseFast.
