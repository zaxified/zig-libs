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
spec permits this). One thing a stateless endpoint cannot do is complete a
server→client round trip: with no session there is no handle to tell two
clients apart, so a client's *response* to a `sampling`/`elicitation` request
is refused with **400** rather than delivered into whichever flow happens to
match the id. Set `stateless_responses = .single_client` to opt back in when
the endpoint really does serve one client — see [Security](#security). Set a `*Sessions` to enable the full session model: an
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

**Server→client answers need a session.** A stateless endpoint cannot attribute
a client's response to a `sampling`/`elicitation` request — every POST is peer
0 — so it refuses those POSTs with 400 by default
(`Transport.stateless_responses`). Configure `sessions` for a multi-client
endpoint; set `.single_client` only where one client is a fact about the
deployment, not a hope.

## Concurrency

`mcp.Server` is not internally synchronized and `http.Server` serves from
several connection threads. Inject `Transport.lock` (a `Lock` seam, same shape
as `jwt.Lock`) to serialize `handleMessage`, or run the server single-threaded.
Body reads and response framing happen outside the lock.

- **Role:** server. **Platform:** any. **Deps:** `router`,
  `http`, `mcp`.

Provenance: clean-room from the MCP Streamable HTTP transport specification
(2025-06-18) + JSON-RPC 2.0. Earlier revisions of this note claimed the
behavioral contract was "cross-checked for parity against a reference Dart
server (`mcp_dart`)" — no captured bytes or live check ever backed that claim,
so it is corrected here: this module's Streamable HTTP transport is verified
against a single live capture of the **official `mcp` Python SDK**
(modelcontextprotocol.io, the specification's own reference implementation) —
its real client and real server, talking over an actual loopback connection —
frozen offline in `oracle_vectors.zig` and replayed through this module's own
`Transport` with no socket at test time. See `SPEC.md`'s Verification section
for exactly what that capture covers and two benign differences it surfaced.
No `mcp_dart`, the official SDK, or any other MCP-transport source was ported
or copied; the SDK ran only as a black-box test oracle.

## Verification

`zig build test-mcp-http` — 26 offline tests through a real `router` +
`http.Server.serveStream`, in two groups:

- 18 tests built from the spec text directly: request/response (initialize,
  tools/list, tools/call, notification → 202), SSE-on-POST (streamed result,
  **live tool progress**, notification → 202, `stream=.off`), Origin allowlist
  (match/mismatch/absent), sessions (assign + validate + 404 + DELETE, `GET`
  push + `Last-Event-ID` replay + heartbeat, unknown-session 404,
  `max_sessions` cap rejected), path pass-through / 405, oversized → 413.
- 8 tests replaying a real session captured once from the **official `mcp`
  Python SDK** (initialize, `notifications/initialized`, `tools/list`, two
  `tools/call`s — one with live progress notifications — all byte-exact
  against the captured request/response bytes; see `oracle_vectors.zig`).

Green in Debug + ReleaseFast.

## Server→client requests (sampling / elicitation)

`mcp.Server` can ask the client for an LLM completion (`sampling/createMessage`)
or for user input (`elicitation/create`). Over HTTP the answer arrives as a
**separate later POST**, so nothing blocks waiting for it — see the `mcp`
module's README for the issue-now / correlate-later shape.

What this transport adds:

- **Per-session peer scoping — this is what `sessions` buys you.** Each session
  gets a handle (`Sessions.tagOf`) passed to `mcp.Server.handleMessageFrom`, so
  a response POSTed on one session can never resolve a request issued to
  another. Pass it as `mcp.RequestOptions.peer` when you issue a request out of
  band:

  ```zig
  var line: std.Io.Writer.Allocating = .init(gpa);
  defer line.deinit();
  _ = try server.sendSamplingRequest(&line.writer, req, .{
      .peer = sessions.tagOf(sid).?, .on_response = &onAnswer, .ctx = app,
  });
  _ = try sessions.push(sid, std.mem.trimEnd(u8, line.written(), "\n"));
  ```

- **Delivery.** A request issued from inside a `tools/call` rides that POST's
  response: an SSE `data:` event in stream mode; in `application/json` mode the
  body must stay a single JSON object, so it is queued for the session's `GET`
  stream instead (and dropped on a stateless endpoint, which has no channel for
  it).
- **The answer** POSTs to `/mcp` and produces no reply → **202 Accepted**; your
  `mcp.ResponseHandler` runs during that request.
- **Without `sessions`, the answer is refused (400).** Peer scoping is not a
  property of this transport as such — it is a property of the *session
  handle*. A stateless endpoint has none: every POST would be peer 0, and
  `mcp`'s peer check only ever compares the issuing peer to the answering one,
  so it cannot separate two clients that are both 0. Request ids are small
  consecutive integers, so a second client guessing one is not work. Rather
  than deliver a stranger's answer into your tool call, a stateless endpoint
  refuses any POST that could correlate — no `method`, integer `id`, a `result`
  or `error` — and leaves the request pending. Everything else (requests,
  notifications) is unaffected. If your endpoint genuinely serves **one**
  client, say so with `stateless_responses = .single_client` and the round trip
  works as before; on a multi-client endpoint that flag is a data leak between
  clients and the transport cannot tell the two situations apart, which is why
  it is an explicit opt-in.
