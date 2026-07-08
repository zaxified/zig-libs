# SPEC — `mcp`

Model Context Protocol server: JSON-RPC 2.0 + the MCP handshake/tools over a generic transport
(stdio built in). Wave P1. `extract · any · server · reentrant`. Model after: the **MCP spec
(2025-11-25)** + JSON-RPC 2.0. **Seed: extract from `~/workspace/bxp/bxp-mcp/src/server.zig`
(+ `tools.zig`, `progress.zig`)** — same authors' Apache-2.0 code, relicensed MIT; the stateless
`inspect.zig` handler shape may inform the design. Deps: **none (std only — `std.json` + a generic
reader/writer transport)**. New `build.zig` entry `.{ .name = "mcp" }`.

## Why

Both bxp and axp expose themselves to AI agents over MCP and deliberately mirror the same
"server = transport, app = tools" split; existing Zig MCP libs are too thin to thread app state.
This lifts bxp's proven server out as the shared transport core. (This is the cross-project shared
lib named in the catalog.)

## Scope

1. **JSON-RPC 2.0 core:** parse/encode requests / responses / notifications (id, method, params,
   result, error with standard codes: -32700 parse, -32600 invalid request, -32601 method not
   found, -32602 invalid params, -32603 internal). Batch not required (MCP doesn't use it — note if
   skipped). Never panic on malformed input → a proper JSON-RPC error.
2. **MCP server:** the `initialize` handshake with **protocol-version negotiation** + server
   capabilities; `tools/list` and `tools/call` (with `structuredContent` / `outputSchema` and the
   text-content fallback); `notifications/*` (e.g. `initialized`, progress). Resources/prompts are
   OPTIONAL — include the shape if the seed has them, else note as extension points.
3. **Tool registration:** register a tool = `{ name, description, input_schema (JSON Schema text),
   output_schema? }` + a handler `fn(params, ctx) → result` that can thread **app state** (a context
   pointer — the whole point vs. thin libs). Dispatch `tools/call` by name; unknown → method-not-found.
4. **Transport:** a generic transport over a `*std.Io.Reader` + `*std.Io.Writer` (so it works over
   stdio, a pipe, or an HTTP body). **Built-in stdio transport** matching MCP's stdio framing (match
   the seed — newline-delimited JSON-RPC unless the seed uses Content-Length; document which).
   `serve()` loops reading messages and writing responses. (HTTP transport = the caller wires the
   handler into an `http`/`router` route — document the one-liner, don't add an http dep.)
5. **Progress notifications:** the seed's `progress.zig` mechanism (server→client `notifications/
   progress` during a long `tools/call`) — port it.

## Public API sketch (final = the seed's shape)

```zig
pub const Server = struct {
    pub fn init(gpa, Info) Server;              // Info: name, version, instructions
    pub fn deinit(*Server) void;
    pub fn addTool(self, Tool) !void;           // { name, description, input_schema, output_schema?, handler, ctx }
    pub fn handleMessage(self, msg: []const u8, out: *std.Io.Writer) !void;  // one JSON-RPC message
    pub fn serve(self, in: *std.Io.Reader, out: *std.Io.Writer) !void;      // stdio/pipe loop
};
```

## Acceptance / verification

- **Offline unit tests:** JSON-RPC parse/encode incl. all standard error codes; malformed JSON /
  missing method / bad params → the right JSON-RPC error (no panic); `initialize` → correct
  capabilities + negotiated protocol version; `tools/list` → the registered tools (golden JSON);
  `tools/call` dispatch to a registered handler returning `structuredContent` (+ threads a ctx
  pointer — assert app state was reached); unknown tool → -32601/-32602 per the seed; a notification
  (no id) produces no response; progress notification emitted during a tool call.
- **In-process integration (must NOT skip):** drive `serve()` over an in-memory pipe (or
  `handleMessage` sequence) — full `initialize` → `initialized` → `tools/list` → `tools/call`
  round-trip, asserting the JSON at each step. No network needed.
- `zig build test-mcp` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.
  Registered with no deps.

## Notes for the implementer

- Use the **zig skill** (std.json Value + Stringify, std.Io.Reader/Writer). This is an **EXTRACTION**
  — keep the seed's proven protocol handling + version negotiation + `structuredContent`/progress;
  port its behavior; adapt any 0.16 stdlib drift.
- Keep it dependency-free: the transport is generic reader/writer; the app-state threading (ctx
  pointer on tools) is the key feature — don't lose it.
- Provenance: README `Provenance:` line = "extracted from bxp `bxp-mcp/src/server.zig` (same
  authors, Apache-2.0, relicensed MIT); protocol per the MCP spec 2025-11-25". SPDX MIT header. No
  NOTICE entry (own code) beyond noting the MCP spec.
