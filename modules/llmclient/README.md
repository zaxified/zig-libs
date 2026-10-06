# llmclient

An Anthropic Messages API client (`POST /v1/messages`) over the sibling
`http` module — buffered `Client.create` and a streaming
`Client.stream`/`EventIterator` built on a new client-side Server-Sent
Events line-accumulator (`sse_parse`).

- Greenfield client for the Anthropic Messages API;
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

### Images, PDFs, cached system prompts, beta headers, token counting

```zig
// Base64 data goes on the wire verbatim: standard alphabet, padded, no newlines.
const b64 = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(png.len));
defer gpa.free(b64);
_ = std.base64.standard.Encoder.encode(b64, png);

const req: llmclient.MessageRequest = .{
    .model = "claude-opus-5-5",
    .max_tokens = 1024,
    // The array form of `system`; each block may be a cache breakpoint.
    // (`.system = "..."`, the plain string, still works. Both set → the
    // string goes first as an uncached block.)
    .system_blocks = &.{llmclient.systemBlockCached(long_stable_instructions)},
    .messages = &.{llmclient.MessageParam.user(&.{
        llmclient.imageBlock(.@"image/png", b64), // or imageUrlBlock(url)
        llmclient.pdfBlock(pdf_b64), // or pdfUrlBlock(url), textDocumentBlock(text)
        llmclient.textBlock("Compare the chart with the report."),
    })},
};

client.betas = &.{"context-management-2025-06-27"}; // → `anthropic-beta: ...` on every request

// POST /v1/messages/count_tokens — what `req` would cost, without running it.
const n = try client.countTokens(gpa, .fromMessageRequest(req));
std.debug.print("{d} input tokens\n", .{n.input_tokens});
```

- `ImageMediaType` is `image/jpeg`, `image/png`, `image/gif` or `image/webp` — the formats the
  API accepts. A document block also takes `title`, `context` and
  `citations = .{ .enabled = true }` (set them on `block.document`), and both block kinds a
  `cache_control`.
- `count_tokens` accepts base64 and text document sources, not `url` (the API's rule; this
  client does not police it — the server answers 400, `lastErrorBody` has why).
- `betas` entries must be plain tokens (`A-Z a-z 0-9 . _ -`); anything else is
  `error.InvalidBeta` before a byte is sent. Several are joined with commas into one header,
  the form Anthropic documents.
- Image/document blocks that come back inside a response parse as `ContentBlock.other`.

**Knobs on `Client`, and what each one bounds** (defaults in brackets):
`max_response_bytes` [10 MiB] — a buffered body's bytes on the wire;
`max_parsed_bytes` [64 MiB] — the memory one response or one stream event
may cost to parse (`error.ResponseTooLarge` past it — this is the one that
protects you, the wire cap alone does not); `max_event_bytes` [1 MiB] —
one SSE dispatch group; `read_timeout_ms` [60 s] — the body read
(`error.Timeout`; the transport's `total_timeout_ms` stops at the response
head). The key is sent to `base_url` only: a 3xx is `error.UnexpectedStatus`,
never followed.

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
- Prompt-caching tooling beyond the per-block `cache_control` field
  (top-level automatic `cache_control`, breakpoint-placement helpers,
  cache-hit diagnostics).
- The Files API (and `file` image/document sources that reference it).
- Block-array `tool_result` content (images inside a tool result).
- Batch API (`/v1/messages/batches`).
- Upstreaming `sse_parse` as `http.sse.ClientReader` — it's fully generic
  SSE parsing with nothing Anthropic-specific in it, and belongs in `http`
  once a second consumer needs client-side SSE.
