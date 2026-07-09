# llmclient

An Anthropic Messages API client (`POST /v1/messages`) over the sibling
`http` module — buffered `Client.create` and a streaming
`Client.stream`/`EventIterator` built on a new client-side Server-Sent
Events line-accumulator (`sse_parse`).

- **Status:** gap — greenfield client for the Anthropic Messages API;
  nothing in Zig std or the ecosystem worth adopting for this.
- **Model after:** the Anthropic Messages API wire contract (request/response
  JSON shapes, SSE event sequence) and the WHATWG "server-sent events"
  grammar for `sse_parse`.
- **Why:** a native, dependency-free way to call Claude from other
  zig-libs modules/consumers without shelling `curl` or vendoring a
  generated SDK. `http.Client`'s h1 stack already does real HTTPS via
  `std.crypto.tls` (the BYO-TLS caveat in `http`'s docs only applies to
  its HTTP/2 stack), so this module is pure request/response/SSE glue —
  no new transport code.
- **Platform:** any. **Role:** client. **Concurrency:** single-owner
  (like `http.Client` itself — one task drives a `Client` and its
  in-flight `EventIterator`s). **Deps:** `http`.

Provenance: clean-room implementation from the public Anthropic Messages
API documentation (request/response JSON shapes, streaming event sequence,
tool-use shape) and the WHATWG HTML Living Standard §9.2 "server-sent
events" (`text/event-stream` parsing grammar). No third-party client
library or SDK code copied.

## API

```zig
const llmclient = @import("llmclient");
const http = @import("http");

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
var transport = http.Client.init(threaded.io(), gpa, .{});
defer transport.deinit();

var client = llmclient.Client.init(&transport, api_key);

// Buffered.
var parsed = try client.create(gpa, .{
    .max_tokens = 1024,
    .messages = &.{llmclient.MessageParam.user(&.{llmclient.textBlock("Hello, Claude")})},
});
defer parsed.deinit(); // frees the arena backing parsed.value

for (parsed.value.content) |block| switch (block) {
    .text => |t| std.debug.print("{s}\n", .{t.text}),
    else => {},
};

// Streaming.
var it = try client.stream(gpa, .{
    .max_tokens = 1024,
    .messages = &.{llmclient.MessageParam.user(&.{llmclient.textBlock("Hello, Claude")})},
});
defer it.deinit();
while (try it.next()) |event| switch (event) {
    .content_block_delta => |d| switch (d.delta) {
        .text_delta => |t| std.debug.print("{s}", .{t.text}),
        else => {},
    },
    else => {},
};
```

Tools, `tool_choice`, `thinking` (adaptive/enabled/disabled), and system
prompts are all on `MessageRequest` — see `src/types.zig` for the full
shape and the `textBlock`/`thinkingBlock`/`toolUseBlock`/`toolResultBlock`
content-block constructors.

## Design notes

- **Polymorphic wire shapes vs. `std.json`'s union encoding.** Anthropic's
  content blocks / stream events are all `{"type": "...", ...fields}`
  objects — not the `{"tagname": value}` shape `std.json.Stringify`
  produces for a bare `union(enum)`. Request-side types work around this
  with a hand-written `jsonStringify` per union that delegates to the
  active variant's payload struct (which itself carries a literal `type`
  field, so the default struct serialization already produces the right
  flat shape). Response-side parsing goes through `std.json.Value` once,
  then a manual walk dispatching on each object's `"type"` string — the
  same idiom `acme.Client` and `jwt` already use in this repo for other
  polymorphic JSON (ACME problem documents, JWK sets).
- **`sse_parse`** is the reusable SSE line-accumulator the streaming half
  needed — `http.sse` only implements the *server* write side of
  `text/event-stream`, and there was no client-side consumer anywhere in
  this repo. It follows the WHATWG grammar with two deliberate
  simplifications documented at the top of the file (LF/CRLF only, no
  persisted "last event ID buffer" across dispatch groups) — both fine
  for a well-behaved API like Anthropic's, not meant as a generic
  browser-grade parser.
- **Ownership.** `Client.create` returns `std.json.Parsed(Message)` (the
  same wrapper `std.json.parseFromSlice` uses) — `.deinit()` frees the
  arena backing every string in `.value`. `EventIterator.next()` reuses
  one internal arena across calls (reset, not re-allocated, each call) —
  each returned `StreamEvent`'s memory is only valid until the next
  `next()` call or `deinit()`.

## DEFER (not in this v1)

- **OpenAI-compatible variant** — sketched only (a `chat/completions`
  request/response mapping is a fairly mechanical follow-up once a second
  consumer needs it; not built here).
- Retries / 429 backoff — compose with the `resilience` module later
  rather than duplicating retry policy in this client.
- Token counting endpoint (`/v1/messages/count_tokens`).
- Prompt-caching tooling beyond the plain `cache_control` block field
  (breakpoint-placement helpers, cache-hit diagnostics).
- Files/vision (image and document content blocks, the Files API).
- Batch API (`/v1/messages/batches`).
- Connection reuse — `http.Client` opens a fresh connection per request
  (`Connection: close`); this client inherits that, so a long chat session
  pays a new TLS handshake per turn. Follow-up once `http.Client` grows
  keep-alive/pooling.
- Upstreaming `sse_parse` as `http.sse.ClientReader` — it's fully generic
  SSE parsing with nothing Anthropic-specific in it, and belongs in `http`
  once a second consumer needs client-side SSE.
