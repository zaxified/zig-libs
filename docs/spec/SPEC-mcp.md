# SPEC — `mcp`

**Purpose** — A Model Context Protocol **server** transport: JSON-RPC 2.0 + the MCP handshake, with
tools, resources and prompts, over a generic reader/writer (stdio built in). The split it enforces
is **server = transport, app = primitives**: the server owns the protocol (framing, `initialize`
version negotiation, `tools/*`/`resources/*`/`prompts/*` dispatch, progress notifications); the
application registers tools/resources/prompts whose handlers thread live **app state via a `ctx`
pointer**. That ctx threading — a tool call is a plain function call into your running application,
not a stateless echo — is the point of this module versus thin MCP libs.

**Model after / Seed** — MCP spec revision 2025-11-25 + the JSON-RPC 2.0 spec. Extracted from the
authors' bxp `bxp-mcp/src/server.zig` (+ `tools.zig`, `progress.zig`; Apache-2.0, relicensed MIT);
the JSON-RPC core is that seed, while resources + prompts were added clean-room from the MCP spec (no
SDK source consulted). See `NOTICE` (the sibling `mcp-http` transport builds on this JSON-RPC core).

**Design & invariants**
- **Newline-delimited JSON framing.** Every message in either direction is exactly one JSON object
  followed by one `\n` (raw `\n`/`\r` inside a spliced JSON literal are stripped to preserve the
  one-object-per-line invariant); no `Content-Length` headers. JSON-RPC **batch arrays are
  unsupported** (MCP does not use them) → -32600.
- **Protocol surface:** `initialize` (echo the client's requested revision when in
  `supported_versions` = {2025-11-25, 2025-06-18}, else the latest; advertise tools/resources/prompts
  capabilities with `subscribe:false`/`listChanged:false`), `notifications/initialized`,
  `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`,
  `prompts/list`, `prompts/get`, `ping`, and server→client `notifications/progress`. Subscriptions,
  list-change notifications and pagination (`nextCursor`) are deliberately **not** implemented (the
  advertised capabilities say so).
- **Dispatch + ctx.** Tools dispatch by name; resources resolve by uri (exact static match first,
  then each registered template handler in order — a template handler inspects the uri itself and
  declines with `false`, this module does not evaluate uri templates); prompts dispatch by name with
  declared required arguments validated by the server (-32602) before the handler runs. Every
  handler receives the opaque `ctx` given at registration. `tools/call` results carry a text content
  block plus `structuredContent` **only** when the tool allows it and its output is structurally a
  single top-level JSON object (a brace-matcher rejects NDJSON/arrays); `isError:true` marks a tool
  failure, while a deliberate domain `{"ok":false}` answer stays `isError:false`.
- **Never-panic error policy.** Malformed input becomes the proper JSON-RPC error (-32700 / -32600 /
  -32601 / -32602 / -32603, plus MCP's -32002 for an unresolvable `resources/read` uri), never a
  panic or a Zig error; only OOM and transport write-failure surface as `error`. A request (has `id`)
  gets exactly one response; a notification (no `id`) gets none (a stray id-less request-only line is
  dropped).
- **Allocation + concurrency.** Allocator-explicit; each message is handled on a per-message arena
  freed after the response is written (handlers allocate freely on it, never store). Registered
  metadata slices must outlive the server. `reentrant` — no globals; one `Server` = one owner (wrap
  in a lock to share). Transports: `serve(reader,writer)` loops; `serveStdio(io)` wires stdin/stdout;
  HTTP is one line inside an `http`/`router` handler (`server.handleMessage(body, w)`), no `http` dep.

**Threat model / out of scope** — This is a transport, not an authorization boundary: it does **not**
authenticate or authorize callers, rate-limit, or sandbox tool handlers — a registered tool runs
with the app's full privileges, so exposing it (especially over HTTP) is the caller's trust
decision. It hardens the framing/parse surface (malformed JSON, wrong types, batch arrays, stray
notifications, an invalid registered schema literal → -32603 not a crash; a bounded per-message
arena; the `structuredContent` structural re-check so a text/error blob never emits invalid
structure). Out of scope: MCP client/host roles, sampling, roots, subscriptions and list-change
notifications, pagination, and the HTTP/SSE session transport (the sibling `mcp-http` module).

**Verification** — Offline tests: JSON-RPC parse/encode for every standard error code, malformed
JSON / non-object / missing-or-bad method → the right error only when an id is present, unknown
method dropped when id-less; version negotiation + golden `initialize` (capabilities/serverInfo) and
`tools/list` JSON; `tools/call` param validation, ctx-threading to app state, structuredContent
gating (single-object emits, NDJSON and non-object outputs stay text-only), `isError` on handler
failure, and progress notifications interleaving before the result; golden `resources/list`
/`templates/list`/`prompts/list`, `resources/read` text + base64-blob + template-uri resolution +
-32002 on an unresolvable uri, `prompts/get` argument substitution + -32602/-32603; duplicate
registration rejected; blank-line/CRLF tolerance; and a full in-process `initialize → initialized →
tools/list → tools/call` round-trip over an in-memory pipe via `serve`.

**Status** — `extract · any · server · reentrant` · deps: none (std only — `std.json` + `std.Io`).
