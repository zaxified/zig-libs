# mcp

Model Context Protocol **server** transport: JSON-RPC 2.0 + the MCP
handshake/tools over a generic reader/writer, with a built-in stdio transport.
The split it enforces: **server = transport, app = tools** — you register
tools whose handlers thread live **application state via a `ctx` pointer**
(the point of this module versus thin MCP libs).

Provenance: original work of the zig-libs authors (MIT); protocol per the
MCP spec 2025-11-25.

- **Model after:** MCP spec 2025-11-25 + JSON-RPC 2.0.
- **Platform:** any (pure `std`: `std.json` + `std.Io` reader/writer;
  dependency-free). **Role:** server.
- **Concurrency:** `reentrant` — no globals; one `Server` instance is owned by
  one thread/loop (wrap in your own lock to share).

## Protocol surface

- `initialize` — **protocol-version negotiation** (echoes the client's
  requested revision when supported — `2025-11-25`, `2025-06-18` — else
  answers with the latest) + server capabilities (`tools`, `listChanged:
  false`) + `serverInfo` + optional `instructions`.
- `notifications/initialized` — accepted; sets `server.client_initialized`.
- `tools/list` — built from the registered catalog (`name`, `description`,
  `inputSchema`, optional `outputSchema`).
- `tools/call` — dispatch by name; result = text content block +
  `structuredContent` (when the tool allows it and its output is a single
  JSON object) + `isError` (tool failure; a domain `{"ok":false}` answer stays
  `isError:false`). Unknown tool → `-32602` (a deliberate choice for a bad
  tool name on a valid method).
- `ping` — `{}`.
- `notifications/progress` — server→client during a `tools/call`, sent only
  when the client opted in via `params._meta.progressToken` (string or
  integer, echoed verbatim).
- **Resources:** `resources/list`, `resources/read` (text + base64 blob), and
  `resources/templates/list` — register with `addResource` /
  `addResourceTemplate`; an unresolvable read answers `-32002` (resource not
  found).
- **Prompts:** `prompts/list` and `prompts/get` (argument-validated, rendered
  messages) — register with `addPrompt`; a bad argument answers `-32602`.
- `initialize` advertises the tools / resources / prompts capabilities it
  actually serves. (Resource `subscribe` is not implemented —
  `subscribe:false` is advertised.) It also **records what the client
  advertised** in `server.client_capabilities` — the gate on the two
  server→client requests below.
- **Sampling / elicitation (server→client requests):**
  `sendSamplingRequest` (`sampling/createMessage`) and
  `sendElicitationRequest` (`elicitation/create`), plus `cancelRequest`
  (`notifications/cancelled`). See "Server→client requests" below.

Malformed input **never panics** — it yields the proper JSON-RPC error
(`-32700` parse, `-32600` invalid request, `-32601` method not found,
`-32602` invalid params, `-32603` internal). A request (has `id`) gets exactly
one response; a notification (no `id`) gets none. JSON-RPC **batch arrays are
not supported** (MCP doesn't use them) → `-32600`.

## Framing

**Newline-delimited JSON** — the MCP stdio framing: every
message in either direction is exactly one JSON object followed by one `\n`
(raw newlines inside spliced JSON are stripped). No `Content-Length` headers.

## API

```zig
const mcp = @import("mcp");

const App = struct { db: *Db, calls: u32 = 0 };

fn queryHandler(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    const app: *App = @ptrCast(@alignCast(ctx.?));           // ← app state
    const sql = call.strArg("sql") orelse return call.fail("missing 'sql'");
    call.reportProgress(1, 2, "executing");                   // no-op without a progressToken
    const rows = app.db.run(call.arena, sql) catch |e| return call.fail(@errorName(e));
    call.write(rows); // JSON object text ⇒ also emitted as structuredContent
    return false;     // true = tool failure ⇒ isError:true
}

var app = App{ .db = &db };
var server = mcp.Server.init(gpa, .{
    .name = "my-server", .version = "1.0.0",
    .instructions = "Call db_query with a SQL string.",
});
defer server.deinit();
try server.addTool(.{
    .name = "db_query",
    .description = "Run a read-only SQL query.",
    .input_schema  = \\{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}
    ,
    .output_schema = \\{"type":"object"}
    , // optional; "" = none
    // .allow_structured = false for stream-shaped (NDJSON) outputs
    .handler = &queryHandler,
    .ctx = &app,                                              // ← threaded to every call
});

// stdio (the MCP stdio transport):
try server.serveStdio(io);

// or any reader/writer pair (pipe, socket, test harness):
try server.serve(reader, writer);

// or one message at a time:
try server.handleMessage(one_line, writer);
```

**HTTP transport** — no `http` dependency here; wire it into your `http` /
`router` handler in one line (each POST body is one JSON-RPC message, the
response line is the reply body):

```zig
try server.handleMessage(request.body, response_writer);
```

**Allocation:** allocator-explicit; each message is handled on a per-message
arena freed after the response is written (`ToolCall.arena` — allocate freely,
never store). Tool metadata slices must outlive the server.

**JSON-RPC encode helpers** (`writeErrorLine`, `writeResultLine`,
`writeSamplingRequestLine`, `writeElicitationRequestLine`,
`mcp.error_code.*`) are public for custom transports.

## Server→client requests (sampling + elicitation)

`sampling/createMessage` asks the **client's** LLM for a completion;
`elicitation/create` asks the client to collect input from the user. Both flow
server→client, which is the opposite of everything else here.

**They do not block.** `handleMessage` is given one message and one writer — it
has no reader — and over `mcp-http` the client's answer arrives on a *separate
POST*. So the API is issue-now / correlate-later:

```zig
// 1. issue (returns the server-side request id; never waits)
const id = try server.sendElicitationRequest(writer, .{ .form = .{
    .message = "Which branch should I deploy?",
    .requested_schema =
        \\{"type":"object","properties":{"branch":{"type":"string"}},"required":["branch"]}
    ,
} }, .{ .on_response = &onAnswer, .ctx = &app });

// 2. correlate — handleMessage recognizes the client's response, matches it to
//    the pending request and calls your handler. Nothing is written back
//    (JSON-RPC never answers a response).
fn onAnswer(ctx: ?*anyopaque, resp: *const mcp.ClientResponse) void {
    const app: *App = @ptrCast(@alignCast(ctx.?));
    const r = resp.elicitationResult() catch return;
    switch (r.action) {
        .accept => app.branch = copy(r.content.?),   // arena dies with the callback
        .decline, .cancel => {},                     // NOT errors — normal outcomes
    }
}
```

A tool handler can issue one mid-call (`call.requestSampling` /
`call.requestElicitation`); the request line goes out before the tool result.
The answer still arrives later, so a tool that *needs* it must be two calls:
ask on the first, act on the second. There is no third option that this
transport can express.

- **Capability-gated.** Both refuse (`error.SamplingNotSupported` /
  `error.ElicitationNotSupported`, and per-mode `Elicitation{Form,Url}NotSupported`)
  unless the client declared it at `initialize` — the spec's MUST NOT, enforced
  rather than documented. Check `call.clientCapabilities()` first to avoid
  offering a feature the client can't serve.
- **Ids are never reused**, even when a send fails. Unanswered requests are
  capped (`max_pending`, default 256); `cancelRequest` drops one and tells the
  client.
- **Peer scoping.** `RequestOptions.peer` + `handleMessageFrom` keep a response
  from resolving another connection's request — as long as the transport gives
  each connection its own handle. `mcp-http` wires each *session's* handle
  automatically; its stateless mode has no handle to wire, so it refuses
  client responses instead of feeding them here as peer 0.

### Elicitation: schemas are restricted, and secrets are refused

`requested_schema` is validated against the spec's restricted JSON-Schema
subset — a **flat** object of primitives (string / number / integer / boolean,
single-select enums in either the `enum`+`enumNames` or `oneOf` spelling, and
2025-11-25 multi-select enum arrays). Nesting, arrays of objects and general
JSON Schema are rejected, as are unknown keywords: a client that can't render
what you asked for produces an unusable answer.

The spec also says a server **MUST NOT** use form mode to ask for passwords,
API keys, tokens or payment credentials, and **MUST** use URL mode instead.
That one is a phishing primitive — the prompt is chosen by the server but
rendered inside a client the user already trusts — so this module **refuses**
it: a form schema with a credential-shaped property name or title fails with
`error.SchemaSensitiveField` (`looksLikeSecretField` is public, so you can
apply the same test yourself). It is a name heuristic, not a proof; it catches
the accident, and the structural answer for a real credential is
`.url` mode, where the value never transits the client at all.

Not implemented: sampling-with-tools (`tools`/`toolChoice`), `includeContext`,
`metadata`, and `notifications/elicitation/complete` (emit it yourself — it is
one notification line).

Tests: `zig build test-mcp` — JSON-RPC parse/encode incl. all standard error
codes, version negotiation, golden `tools/list`/`initialize` JSON, ctx-pointer
threading, structuredContent gating, progress interleaving, and a full
in-process `initialize → initialized → tools/list → tools/call` round-trip
over an in-memory pipe. For sampling/elicitation: request lines compared
**byte-for-byte against the MCP specification's own JSON examples**, capability
and per-mode gating, the schema subset, the credential refusal, response
correlation (by id, out of order, wrong peer, unknown id, after cancel), and an
ask-then-act round-trip over `serve`.
