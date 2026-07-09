# mcp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Newline-delimited JSON framing.** Every message in either direction is exactly one JSON object
  followed by one `\n` (raw `\n`/`\r` inside a spliced JSON literal are stripped to preserve the
  one-object-per-line invariant); no `Content-Length` headers. JSON-RPC batch arrays are
  unsupported (MCP does not use them) → -32600.
- **Protocol surface:** `initialize` (echo the client's requested revision when in
  `supported_versions` = {2025-11-25, 2025-06-18}, else the latest), `notifications/initialized`,
  `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`,
  `prompts/list`, `prompts/get`, `ping`, and server→client `notifications/progress`. Subscriptions,
  list-change notifications and pagination (`nextCursor`) are deliberately not implemented (the
  advertised capabilities say so). Modeled after MCP spec revision 2025-11-25 + JSON-RPC 2.0; the
  JSON-RPC core is extracted from the authors' bxp `bxp-mcp/src/server.zig` — see NOTICE.
- **Dispatch + ctx.** Tools dispatch by name; resources resolve by uri (exact static match first,
  then each registered template handler in order); prompts dispatch by name with declared required
  arguments validated by the server (-32602) before the handler runs. Every handler receives the
  opaque `ctx` given at registration — **server = transport, app = primitives** is the split this
  module enforces. `tools/call` results carry a text content block plus `structuredContent` only
  when the tool allows it and its output is structurally a single top-level JSON object (a
  brace-matcher rejects NDJSON/arrays); `isError:true` marks a tool failure.
- **Never-panic error policy.** Malformed input becomes the proper JSON-RPC error (-32700/-32600/
  -32601/-32602/-32603, plus MCP's -32002 for an unresolvable `resources/read` uri), never a panic
  or a Zig error; only OOM and transport write-failure surface as `error`. A request (has `id`)
  gets exactly one response; a notification (no `id`) gets none.
- **Allocation + concurrency.** Allocator-explicit; each message is handled on a per-message arena
  freed after the response is written (handlers allocate freely on it, never store). Registered
  metadata slices must outlive the server. Reentrant — no globals; one `Server` = one owner (wrap
  in a lock to share). Transports: `serve(reader,writer)` loops; `serveStdio(io)` wires
  stdin/stdout; HTTP is one line inside an `http`/`router` handler (no `http` dep of its own).

## Threat model / out of scope

This is a transport, not an authorization boundary: it does **not** authenticate or authorize
callers, rate-limit, or sandbox tool handlers — a registered tool runs with the app's full
privileges, so exposing it (especially over HTTP) is the caller's trust decision. It hardens the
framing/parse surface (malformed JSON, wrong types, batch arrays, stray notifications, an invalid
registered schema literal → -32603 not a crash; a bounded per-message arena; the `structuredContent`
structural re-check so a text/error blob never emits invalid structure). Out of scope: MCP
client/host roles, sampling, roots, subscriptions and list-change notifications, pagination, and
the HTTP/SSE session transport (the sibling `mcp-http` module).

## Verification

Offline tests: JSON-RPC parse/encode for every standard error code, malformed JSON/non-object/
missing-or-bad method → the right error only when an id is present, unknown method dropped when
id-less; version negotiation + golden `initialize` (capabilities/serverInfo) and `tools/list` JSON;
`tools/call` param validation, ctx-threading to app state, structuredContent gating, `isError` on
handler failure, and progress notifications interleaving before the result; golden
`resources/list`/`templates/list`/`prompts/list`, `resources/read` text + base64-blob +
template-uri resolution + -32002 on an unresolvable uri, `prompts/get` argument substitution +
-32602/-32603; duplicate registration rejected; blank-line/CRLF tolerance; and a full in-process
`initialize → initialized → tools/list → tools/call` round-trip over an in-memory pipe via `serve`.
Run: `zig build test-mcp`.

## Backlog / deferred

None recorded beyond the explicit out-of-scope list above (client/host roles, sampling, roots,
subscriptions, pagination) — no PLAN.md deferred-gap note and the module README has no Deferred
section.

## Status

`extract · any · server · reentrant` + deps: none (std only — `std.json` + `std.Io`) — canonical
source is `pub const meta` in src/root.zig.
