# mcp

Model Context Protocol **server** transport: JSON-RPC 2.0 + the MCP
handshake/tools over a generic reader/writer, with a built-in stdio transport.
The split it enforces: **server = transport, app = tools** — you register
tools whose handlers thread live **application state via a `ctx` pointer**
(the point of this module versus thin MCP libs).

Provenance: extracted from bxp `bxp-mcp/src/server.zig` (+ `tools.zig`,
`progress.zig`) — same authors, Apache-2.0, relicensed MIT; protocol per the
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
  `isError:false`). Unknown tool → `-32602` (the seed's/MCP's choice for a bad
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
  `subscribe:false` is advertised.)

Malformed input **never panics** — it yields the proper JSON-RPC error
(`-32700` parse, `-32600` invalid request, `-32601` method not found,
`-32602` invalid params, `-32603` internal). A request (has `id`) gets exactly
one response; a notification (no `id`) gets none. JSON-RPC **batch arrays are
not supported** (MCP doesn't use them) → `-32600`.

## Framing

**Newline-delimited JSON** — the MCP stdio framing, matching the seed: every
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
`mcp.error_code.*`) are public for custom transports.

Tests: `zig build test-mcp` — JSON-RPC parse/encode incl. all standard error
codes, version negotiation, golden `tools/list`/`initialize` JSON, ctx-pointer
threading, structuredContent gating, progress interleaving, and a full
in-process `initialize → initialized → tools/list → tools/call` round-trip
over an in-memory pipe.
