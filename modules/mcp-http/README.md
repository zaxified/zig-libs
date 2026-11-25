# mcp-http

The MCP **Streamable HTTP** transport as a `router` middleware, so a
`mcp.Server` (JSON-RPC 2.0 tools / resources / prompts) is reachable remotely
over HTTP instead of only over stdio. It speaks both the **2026-07-28**
stateless transport and the session-era one (2025-06-18 / 2025-11-25),
decided per POST — see [Spec 2026-07-28](#spec-2026-07-28-stateless).

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
server→client **`GET /mcp` stream**. That stream is **held open** over a real connection, as the reference SDKs'
servers hold it: it replays every event queued since the request's
`Last-Event-ID`, then stays open and carries each message the session is sent
the moment it is enqueued (one stream per session: a second `GET` is 409);
when it ends (client gone, queue overflow) the client's `EventSource`
reconnects with `Last-Event-ID` and the bounded resumable
replay buffer. Enqueue a message from any thread with `Sessions.push(id, data)`.

```zig
var server = mcp.Server.init(gpa, .{ .name = "netops", .version = "1.0" });
defer server.deinit();
try server.addTool(.{ ... });

var transport = mcphttp.Transport{ .gpa = gpa, .server = &server };
try router.use(transport.middleware()); // after any auth / origin middleware
```

## Security

**Authorization** (MCP authorization, resource-server side, as the official SDKs
have it): set `Transport.auth` to an `mcp_http.auth.Auth`. Every request to the
endpoint then needs `Authorization: Bearer <token>`, which your `verify` hook
checks (a local JWT, RFC 7662 introspection, …); the transport answers 401/403
with the RFC 6750 `WWW-Authenticate` challenge naming your RFC 9728 document,
serves that document at `/.well-known/oauth-protected-resource<path>`, and hands
the token's `mcp.AuthInfo` to every handler as `call.auth`.

```zig
fn verify(_: ?*anyopaque, arena: std.mem.Allocator, token: []const u8) !mcp_http.auth.Verdict {
    const claims = myJwtCheck(arena, token) orelse return .{ .invalid = "Invalid token" };
    return .{ .ok = .{ .subject = claims.sub, .scopes = claims.scopes, .expires_at = claims.exp, .resource = claims.aud } };
}
const auth: mcp_http.auth.Auth = .{
    .verify = verify,
    .resource_metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    .metadata = .{ .resource = "https://mcp.example.com/mcp", .authorization_servers = &.{"https://auth.example.com"} },
    .expected_resource = "https://mcp.example.com/mcp", // RFC 8707 audience
    .required_scopes = &.{"mcp"},
};
var transport: mcp_http.Transport = .{ .gpa = gpa, .server = &server, .auth = &auth };
```

`scope_for` adds per-operation scopes (403 before the handler runs). A
middleware of your own that stores an `mcp.AuthInfo` with `ctx.setTyped` works
too: the transport passes it on.

**DNS rebinding.** `Transport.allowed_origins` (exact match; a present but
unlisted `Origin` gets 403, no `Origin` is allowed, empty accepts every origin)
and the `Host` half: `host_guard` (`http.HostGuard`) or, by default,
`localhost_protection` — a request from a loopback peer with a non-loopback
`Host` gets 403, as in the Go SDK.

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
  `http`, `mcp`, `clock`.

Provenance: clean-room from the MCP Streamable HTTP transport specification
(2025-06-18 and 2026-07-28) + JSON-RPC 2.0. The session-era transport is
verified against a single live capture of the **official `mcp` Python SDK**
(modelcontextprotocol.io, the specification's own reference implementation) —
its real client and real server, talking over an actual loopback connection —
frozen offline in `oracle_vectors.zig` and replayed through this module's own
`Transport` with no socket at test time. See `SPEC.md`'s Verification section
for exactly what that capture covers and the benign differences it surfaced.
No SDK or other MCP-transport source was ported or copied; the SDK ran only as
a black-box test oracle.

## Verification

`scripts/modtest mcp-http` — offline tests through a real `router` +
`http.Server`, in three groups:

- built from the spec text directly: request/response (initialize,
  tools/list, tools/call, notification → 202), SSE-on-POST (streamed result,
  **live tool progress**, notification → 202, `stream=.off`), Origin allowlist
  (match/mismatch/absent), sessions (assign + validate + 404 + DELETE, `GET`
  push + `Last-Event-ID` replay + heartbeat, unknown-session 404,
  `max_sessions` cap rejected), path pass-through / 405, oversized → 413.
- the 2026-07-28 rules: header/body validation, statuses, SSE versus a lone
  JSON answer, `subscriptions/listen`, multi round-trip requests.
- tests replaying a real session captured once from the **official `mcp`
  Python SDK** (initialize, `notifications/initialized`, `tools/list`, two
  `tools/call`s — one with live progress notifications — all byte-exact
  against the captured request/response bytes; see `oracle_vectors.zig`).
- a replay of every exchange the **official Python SDK 2.3.0** client made over a
  socket in both revisions (`sdk_oracle_vectors.zig`, taken by
  `zig build interop-mcp-http`, which also checks a held listen and a
  cancelled call live).
- held listens and cancellation over a real `http.Server`.

Fuzz: `MCP_HTTP_FUZZ=<runs>`. SPEC *Verification* has the rest.

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

## Spec 2026-07-28 (stateless)

A POST whose body carries `params._meta["io.modelcontextprotocol/protocolVersion"]`
is served by the 2026-07-28 rules, with no configuration and next to any
session-era clients on the same endpoint:

- **No session.** None is required or minted; `Mcp-Session-Id` is ignored.
- **Headers must mirror the body**: `MCP-Protocol-Version`, `Mcp-Method`,
  `Mcp-Name` (on `tools/call` / `prompts/get` / `resources/read`, Base64
  sentinel `=?base64?…?=` decoded), and `Mcp-Param-{Name}` for each tool
  argument marked `x-mcp-header` in the tool's `inputSchema`. Missing,
  duplicated, malformed or disagreeing → **400** with a `HeaderMismatch`
  (-32020) JSON-RPC error; `mcp` never sees the request.
- **Statuses**: unsupported revision (-32022) and missing client capability
  (-32021) → 400, unknown method → 404, anything else 200.
- **SSE** only when the server has something to stream before the answer
  (progress, the `subscriptions/listen` acknowledgment); a lone answer goes out
  as `application/json`, so its status is visible. Closing the stream (or the
  connection of a JSON answer) is the client's cancellation: a running
  `tools/call` sees `ToolCall.cancelled()` at once (over a socket).
- **Sampling / elicitation** travel as multi round-trip requests
  (`InputRequiredResult`, then the client's retry) — nothing to correlate, no
  session, no `stateless_responses` question. See `mcp`'s README.
- **`subscriptions/listen`** is held open when `Transport.listens` is set and
  `mcp.Server.push` is on: the acknowledgment, then every notification the
  application pushes, until the client closes it or the server ends it with
  the graceful-close result. Without a registry it is closed at once.

  ```zig
  var listens = mcphttp.Listens.init(gpa);
  var transport = mcphttp.Transport{ .gpa = gpa, .server = &server, .listens = &listens, .lock = lock };
  // later, on any thread, under the same lock as every mcp.Server call:
  lock.acquire(); _ = server.notifyListChanged(transport.pushSink(), .tools); lock.release();
  // shutting down: listens.finishAll() (http.Server.shutdownGraceful does it too)
  ```

## Not provided

TLS, rate limiting, issuing tokens or an authorization server (SPEC *What is
deliberately not done*), a pluggable event store for the session era across
nodes, the older HTTP+SSE dual-endpoint transport.
