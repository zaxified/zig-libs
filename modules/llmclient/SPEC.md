# llmclient — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
An Anthropic Messages API client (`POST /v1/messages`) layered over the sibling `http` module:
buffered `Client.create` and a streaming `Client.stream`/`EventIterator` built on a new
client-side SSE line-accumulator (`sse_parse`, following the WHATWG "server-sent events" grammar —
`http.sse` only implements the server write side, there was no client-side consumer anywhere else
in this repo). `http.Client`'s h1 stack does real HTTPS via `std.crypto.tls` (the BYO-TLS caveat
elsewhere in this repo applies only to `http`'s h2 stack), so this module is pure request/response/
SSE glue, no new transport code. Polymorphic wire shapes vs. `std.json`'s union encoding: request-
side types (`{"type": "...", ...fields}` objects, not `std.json.Stringify`'s default
`{"tagname": value}` union shape) carry a hand-written `jsonStringify` per union delegating to the
active variant's payload struct; response-side parsing goes through `std.json.Value` once, then a
manual walk dispatching on each object's `"type"` string (the same idiom `acme.Client`/`jwt` use
elsewhere in this repo for other polymorphic JSON). Ownership: `Client.create` returns
`std.json.Parsed(Message)` — `.deinit()` frees the arena backing every string in `.value`;
`EventIterator.next()` reuses one internal arena across calls (reset, not re-allocated) — each
returned `StreamEvent`'s memory is valid only until the next `next()` call or `deinit()`.
Concurrency: single-owner, like `http.Client` itself — one task drives a `Client` and its in-flight
`EventIterator`s. `api_key` is stored plaintext in the `Client` struct and sent verbatim as the
`x-api-key` header on every request; `lastErrorBody` caches up to 512 bytes of the most recent
non-2xx response body (server-side error detail, not a caller secret) for diagnostics. Clean-room
implementation from the public Anthropic Messages API documentation (request/response JSON shapes,
streaming event sequence, tool-use shape) and the WHATWG HTML Living Standard §9.2 (SSE parsing
grammar) — see NOTICE. No third-party client library or SDK code copied.

## Threat model / out of scope
The API key is a bearer credential handled like any HTTP client credential: held in memory for the
`Client`'s lifetime, never logged, sent only over the (real, `std.crypto.tls`) HTTPS connection to
`base_url` — **and to no other host, whatever the peer says.** A caller who overrides `base_url`
(e.g. to a proxy) chooses where the key is sent; a peer that answers a 3xx does not: redirects are
never followed (`follow_redirects = false` on every request), and a 3xx is `error.UnexpectedStatus`
with its body in `lastErrorBody`. Measured 2026-09-06 (A1 F1) before that line existed: one
`Location:` from `base_url` sent `x-api-key` and the whole prompt to a host of the peer's choosing
and `create` returned `OK` — `http.Client` strips `Authorization`/`Cookie` across an origin change
but cannot know `x-api-key` is a credential, and even a same-origin hop resends the prompt.

**Bounds, and which quantity each one bounds.** The peer controls the size of everything it sends
and the pace at which it sends it; each of the four is bounded by a knob on `Client`:
- `max_response_bytes` (10 MiB) — bytes ON THE WIRE of a buffered body. That is not what a body
  costs: 7.8 MB of one-character content blocks parsed into 310 MiB of `std.json` nodes under it
  (A1 F5), so
- `max_parsed_bytes` (64 MiB) — the memory a response's or an event's parse may allocate, enforced by
  a `BoundedAllocator` over the parse arena; past it, `error.ResponseTooLarge` and the arena is
  released, never `OK` with a giant tree.
- `max_event_bytes` (1 MiB) — one SSE dispatch group's joined `data:` payload
  (`sse_parse.Parser.max_data_bytes`). Each line is bounded by the reader (~4 KiB); the number of
  lines in a group was not, and 10 MB of legal lines made 2.4 GB live that stayed allocated after
  the error (A1 F3/F15). Past it, `error.ResponseTooLarge` and the buffers are freed.
- `read_timeout_ms` (60 s) — the body read: the whole body for `create`, each `next()` for a stream.
  `http.Client.total_timeout_ms` covers connect + request + response HEAD and, by its own design,
  not the body; a peer trickling one byte a second held `create` 30 s against a 2 s total timeout
  and a stream 60 s, both ended by the peer (A1 F4). Enforced by racing the read on a concurrent
  task (the same shape `http.Client` uses for its total timeout); when the `std.Io` cannot spare a
  unit of concurrency the read runs unbounded, as `http.Client`'s does.

**Numbers from the wire are checked, not cast.** A content-block `index` above `u32`, or a
`usage` count that is negative, ≥ 2^64, or not finite, is `error.MalformedResponse`. They were
`@intCast`/`@intFromFloat` on the raw value: a panic in Debug/ReleaseSafe and a silently wrong
`index`/billing number in ReleaseFast (A1 F2).

`sse_parse` makes two deliberate,
documented simplifications vs. the full WHATWG grammar (LF/CRLF only, no persisted "last event ID
buffer" across dispatch groups) — acceptable for a well-behaved API like Anthropic's, not a
generic browser-grade parser; malformed/hostile SSE bytes resolve to typed errors
(`EndOfStream`/`LineTooLong` surfaced as `error.HttpFailed`; `DataTooLarge` as
`error.ResponseTooLarge`; `ReadFailed` goes through
`http.Client.Response.readFailure()` first and surfaces as `error.Canceled` when a
`std.Io` cancelation is the real cause, `error.HttpFailed` otherwise), not panics. Out of
scope: OpenAI-compatible variant, retries/429 backoff (compose with `resilience` instead),
token-counting endpoint, prompt-caching tooling beyond the plain `cache_control` field, files/
vision content blocks, the Batch API, and connection reuse (each request opens a fresh connection
via `http.Client`'s `Connection: close`, so a long chat session pays a new TLS handshake per turn).

## Verification
Tests span `root.zig`/`Client.zig`/`response.zig`/`sse_parse.zig`/`types.zig` (dark-aggregated
via the `test { _ = ...; }` block in root.zig). Covers: golden request headers/URL construction,
non-2xx → `error.UnexpectedStatus` + `lastErrorBody` round-trip, request/response type re-exports,
JSON stringify of polymorphic content-block/tool-choice unions, response parsing of every
`StreamEvent`/`ContentBlock` variant, and `sse_parse` line-accumulation edge cases.

**External anchor, added 2026-08-01**: the hand-built "full sequence" SSE fixture above is an
in-house re-derivation (this module's own author wrote it to match a mental model of the docs,
never checked against an independently-published example). `response.zig`'s test "external
anchor: Anthropic's own published basic-streaming SSE example parses byte-exact" instead embeds,
byte-for-byte, the "Basic streaming request" → "Response" example published at
`https://platform.claude.com/docs/en/build-with-claude/streaming.md` (fetched 2026-08-01, no API
key used, no network call made by the committed test) — including its `ping` event, which no
hand-built fixture in this module previously exercised — and asserts the documented literal
values (message id, model, token counts, delta text, `stop_reason`) after running it through this
module's own `sse_parse.Parser` + `parseStreamEvent`. This is a genuine external anchor for the
SSE wire format and this module's parsing of it. Treated the same as this module's existing
"clean-room from the public Anthropic Messages API documentation" framing (see the module's
design comment above) rather than as vendored third-party data — the example illustrates a wire
format, not creative expression, the same rationale root `NOTICE` §0 already applies to RFC/spec
citations.

**The originally-graded `S` (assuming the skipped live test could simply be un-skipped) does not
hold up.** A real call to `POST /v1/messages` needs a paid API key, costs money per request, and
returns a nondeterministic body (the exact response text varies run to run) — none of which is
compatible with a frozen, offline, checked-in golden. No API call was made or considered for this
module. What *can* be anchored without a key is exactly the SSE wire-format shape covered above;
the "live test currently `error.SkipZigTest`" gap in the Backlog section below is real and
distinct from that anchor — it stays open because there is no way to close it without spending
money on a nondeterministic response. **Recommended grade: one tier below the original `S`** —
the SSE wire format itself is now genuinely externally anchored, but the live end-to-end call
against the real API remains untested (and cannot be, offline, without paying for a nondeterministic
response), so this module should not carry the same grade as one whose live path is actually
exercised.

One live test
against the real API is present but unconditionally `error.SkipZigTest` — Zig 0.16's
`std.process.Environ` (needed to read `ANTHROPIC_API_KEY`) is only reachable from `main`'s `Init`
parameter, not from a plain `test` block; the dead-code path (`if (false)`) still type-checks the
real call shape so an API-shape regression fails `zig build test-llmclient` without ever making a
network call. Run: `zig build test-llmclient`.

## Backlog / deferred
Per the module README's DEFER list: OpenAI-compatible variant (sketched only); retries/429 backoff
(defer to `resilience`); `/v1/messages/count_tokens`; prompt-caching tooling beyond
`cache_control`; files/vision content blocks and the Files API; the Batch API
(`/v1/messages/batches`); connection pooling/keep-alive (follow-up once `http.Client` grows it);
upstreaming `sse_parse` as `http.sse.ClientReader` once a second client-side-SSE consumer exists in
this repo.

## Status
`gap · any · client · single_owner` + deps: `http` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/response.zig:450 parses Anthropic's own published basic-streaming SSE example byte-exact, including a `ping` event no hand-built fixture had; every other fixture is docs-derived and the one live API test is unconditionally SkipZigTest, so it anchors nothing

**How it got there.** The anchoring work landed. DONE 88eda93: Anthropic published SSE example; S grade was WRONG (paid, nondeterministic)
