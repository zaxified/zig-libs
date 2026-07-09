# llmclient — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

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
`base_url`. A caller who overrides `base_url` (e.g. to a proxy) redirects where the key is sent —
that is a caller configuration choice, not a module gap. `sse_parse` makes two deliberate,
documented simplifications vs. the full WHATWG grammar (LF/CRLF only, no persisted "last event ID
buffer" across dispatch groups) — acceptable for a well-behaved API like Anthropic's, not a
generic browser-grade parser; malformed/hostile SSE bytes resolve to typed errors
(`EndOfStream`/`ReadFailed`/`LineTooLong` surfaced as `error.HttpFailed`), not panics. Out of
scope: OpenAI-compatible variant, retries/429 backoff (compose with `resilience` instead),
token-counting endpoint, prompt-caching tooling beyond the plain `cache_control` field, files/
vision content blocks, the Batch API, and connection reuse (each request opens a fresh connection
via `http.Client`'s `Connection: close`, so a long chat session pays a new TLS handshake per turn).

## Verification
15 tests across `root.zig`/`Client.zig`/`response.zig`/`sse_parse.zig`/`types.zig` (dark-aggregated
via the `test { _ = ...; }` block in root.zig). Covers: golden request headers/URL construction,
non-2xx → `error.UnexpectedStatus` + `lastErrorBody` round-trip, request/response type re-exports,
JSON stringify of polymorphic content-block/tool-choice unions, response parsing of every
`StreamEvent`/`ContentBlock` variant, and `sse_parse` line-accumulation edge cases. One live test
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
