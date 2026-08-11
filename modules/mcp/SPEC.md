# mcp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Newline-delimited JSON framing.** Every message in either direction is exactly one JSON object
  followed by one `\n` (raw `\n`/`\r` inside a spliced JSON literal are stripped to preserve the
  one-object-per-line invariant); no `Content-Length` headers. JSON-RPC batch arrays are
  unsupported (MCP does not use them) → -32600.
- **The `id` shape is validated, not just echoed.** JSON-RPC 2.0 §4 allows String, Number or NULL;
  an object, array or bool `id` is refused with -32600 and a **NULL** id in the reply (§5: when the
  id cannot be determined the error carries null). The gate sits once in front of every dispatch
  path rather than at each `writeId`, because the serializer is shape-agnostic and would mirror any
  value back — handing a strict client a response it cannot correlate to any request it made.
- **Protocol surface:** `initialize` (echo the client's requested revision when in
  `supported_versions` = {2025-11-25, 2025-06-18}, else the latest), `notifications/initialized`,
  `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`,
  `prompts/list`, `prompts/get`, `ping`, server→client `notifications/progress`, and the two
  server→client *requests* `sampling/createMessage` + `elicitation/create` (with
  `notifications/cancelled`). Subscriptions,
  list-change notifications and pagination (`nextCursor`) are deliberately not implemented (the
  advertised capabilities say so). Modeled after MCP spec revision 2025-11-25 + JSON-RPC 2.0; the
  JSON-RPC core is the zig-libs authors' original work (MIT).
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
- **Server→client requests are issue-now / correlate-later, by necessity.** `handleMessage` takes
  one message and one writer and owns no reader; under `mcp-http` the client's answer arrives on a
  *different HTTP request*, which cannot be serviced while the first is parked (the same constraint
  the `GET` drain-and-close stream documents). A "handler blocks on sampling" API is therefore not
  implementable without an async runtime inside a transport module, and would deadlock the HTTP
  transport outright. What is implemented instead: `sendSamplingRequest`/`sendElicitationRequest`
  allocate a **never-reused** monotonic id (burnt even when the send fails), validate, check the
  capability, write one request line and record a pending entry; `handleMessage` recognizes an
  inbound response (`id` + `result`/`error`, no `method`), matches the pending table and invokes the
  registered `ResponseHandler`, writing **nothing** — JSON-RPC forbids answering a response, and
  answering with the same id would loop. Consequence a consumer must design around: a tool that
  needs the answer is two calls (ask, then act). Pending entries are capped (`max_pending`);
  `cancelRequest` drops one and emits `notifications/cancelled`. **This fixed a live bug**: before
  this, a client's response hit the "Missing method" branch and got a -32600 *reply*.
- **Capabilities are stored, not just parsed.** `initialize` records `client_capabilities` (and
  `negotiated_version`), replacing any prior set wholesale, and all-false before a handshake — so a
  server fails closed. A capability is granted only by **the JSON shape the spec defines** (each
  capability an object; `roots.listChanged` a bool), never by "something is present": a malformed
  declaration such as `{"elicitation":true}` or `{"elicitation":"url"}` grants nothing at all. (The
  latter used to grant *form* mode and deny url — the inverse of the declaration, and the
  phishing-relevant half; re-audit 2026-08-11 F7.) The spec's MUST NOTs (no `sampling/createMessage` without `sampling`, no
  `elicitation/create` without `elicitation`, no elicitation *mode* the client did not declare, with
  `elicitation:{}` meaning form-only for backwards compatibility) are enforced at the send seam.
  `negotiateVersion` returns one of **our** static literals, never the caller's slice — the request
  is parsed on a per-message arena, so echoing it back would dangle in `negotiated_version`.
- **Peer scoping.** `handleMessageFrom(msg, out, peer)` correlates a response only to a pending
  request issued to the *same* peer; `handleMessage` is `peer = 0`. Multiplexing transports
  (`mcp-http` sessions) pass a per-session handle, so one session cannot consume another's sampling
  completion or the user's elicitation answer. Not a wildcard in either direction.
- **Elicitation schema subset + credential refusal.** `requestedSchema` is validated against the
  spec's restricted subset (flat object of primitives; single-select enums in both the 2025-06-18
  `enum`/`enumNames` and 2025-11-25 `oneOf` spellings; 2025-11-25 multi-select enum arrays) and is
  *strict* — an unknown keyword is rejected, not passed through, because a client that ignores it
  renders a form that does not match what the server asked for. Elicitation results force
  `content = null` on `decline`/`cancel`, so a refused answer cannot be read as data; neither
  action is an error.
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
client/host roles, roots, subscriptions and list-change notifications, pagination, and
the HTTP/SSE session transport (the sibling `mcp-http` module). Also out of scope within the
sampling/elicitation surface: sampling-with-tools (`tools`/`toolChoice` and the tool-use/tool-result
message shapes — `SamplingResult.parse` refuses an array content block rather than half-decoding
it), `includeContext`, `metadata`, and emitting `notifications/elicitation/complete`.

**Sampling's trust asymmetry.** The server picks the prompt; the client owns the model access, the
credential and the bill. The spec expects a human in the loop client-side, but a server MUST NOT
rely on it: the returned completion is untrusted text, never an instruction. Conversely a *client*
cannot verify anything about the request it renders.

**Elicitation is a phishing primitive if left unguarded**, which is why the spec forbids form mode
for secrets and mandates URL mode instead: the message is chosen by the server but rendered inside a
UI the user already trusts, and a form-mode value transits the client, its logs and possibly an LLM
context. This module refuses form schemas whose property names/titles look like credentials
(`looksLikeSecretField`, public and unit-tested in both directions so its false-positive behaviour
is pinned). **Its limits are real**: it matches names only — not the free-text `message`, not intent,
and not what the value is later used for — so it stops the accident, not the adversary. The
structural mitigation is `.url` mode, whose URL is scheme-checked (https, or http for loopback only)
so `javascript:`/`data:`/`file:` payloads never reach a client that is about to open them. The
loopback allowance compares the **parsed authority's host** — userinfo stripped at the last `@`,
IPv6 literals kept bracketed, port digits only — so neither `http://localhost:8080@evil.example/`
nor `http://localhost.evil.example/` is loopback (the first was accepted before re-audit F3). Every
other URL-safety rule in the spec (no credentials in the URL, no pre-authenticated links, verifying
that the user who opens it is the user it was minted for) is the application's, not this module's.

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

Sampling/elicitation are anchored on the **specification's own JSON examples**, not on
self-consistency: the emitted `sampling/createMessage` line (2025-11-25 "Creating Messages"), the
form-mode and URL-mode `elicitation/create` lines (2025-11-25), the form-mode line for a 2025-06-18
peer (that revision's example — no `mode` member), and the decode of both revisions' result examples
including the `-1` "user rejected" error. Behaviours with **no external anchor** — pinned only by our
own tests, and therefore only as good as the reasoning behind them: the image/audio request line and
`temperature`/`stopSequences` placement (the spec shows no wire example carrying them), the exact
`SchemaError`/`SendError` taxonomy, the credential-name word list, the loopback-http URL allowance,
the never-reuse id rule, `max_pending`, and the whole `peer` concept (an implementation invention —
the spec says nothing about multiplexing one server over several sessions).

The rest of the protocol surface is anchored the same way, extending the sampling/elicitation
treatment to every other method this server dispatches or emits: `initialize`'s request (the
lifecycle page's full example, including `roots`/`tasks` capabilities and clientInfo fields this
module ignores, decoded without crashing or mis-parsing what it does read), `ping`, `tools/call`
(the `get_weather` text example and the `get_weather_data` output-schema/`structuredContent`
example, byte-identical down to the response's own internal whitespace; the "Unknown tool"
protocol-error *code* and the execution-error *content*, both from tools.mdx), `resources/read`
(the `main.rs` example), `prompts/get` (the `code_review` example), and the `notifications/progress`
wire shape (progress/total/message field order and values). `initialize`'s response, and the
`tools/list`/`resources/list`/`resources/templates/list`/`prompts/list` responses, cannot be
byte-identical to the spec's own illustrative responses: this server's capability shape is fixed
and narrower (no `logging`/`tasks`, `listChanged` always false), and its `Tool`/`Resource`/
`ResourceTemplate`/`Prompt` types carry none of `title`/`icons`/`execution` — so those methods are
anchored on request-decode only (the spec's literal request, including an ignored pagination
`cursor`, parses without error). `notifications/cancelled` matches the spec's `requestId`/`reason`
shape and reason text exactly, except `requestId` is always a bare integer (this server's own
monotonic ids) where the spec's illustrative id is a quoted string — JSON-RPC permits either as a
request id, so this is not a divergence. The full classification (`.literal_example` / `.partial` /
`.no_example`, with a `reason` for every non-full entry) lives in `pub const spec_anchor_index` in
src/root.zig, guarded by a canary test that **derives one side from the other**: `DispatchMethod` is
the enum `handleMessage`'s exhaustive switch is written over and `OriginatedMethod` supplies the
wire name every outbound emitter prints, and the canary checks both lists against the index in both
directions, so a method added to (or dropped from) the dispatch surface without updating the
classification fails loudly. (Until re-audit 2026-08-11 F9 this was a *count* canary comparing the
index against hardcoded numbers; it never read the dispatch chain, so the drift it promised to
catch was invisible to it.) **No disagreements were found**: every spec example this server can
reproduce byte-for-byte, it does. Retrieved from
`modelcontextprotocol/modelcontextprotocol` (2025-11-25 spec pages) directly, never reconstructed
from memory.

Provenance: these are literal JSON snippets from the MCP specification quoted as test-oracle data,
the same clean-room-from-a-public-spec relationship this module already has with the MCP spec as a
whole (root NOTICE §0) — no third-party source was read or ported, so this needs no NOTICE entry
(module-level or root), matching how `linkheader` cites RFC 8288 in its own SPEC.md rather than
NOTICE. (The spec's docs are dual-licensed Apache-2.0/MIT, both permissive; Apache-2.0's
NOTICE-preservation clause (§4(d)) applies to redistributing the specification itself as a
Derivative Work, not to citing a handful of short wire-format examples as our own original test
fixtures — the same merger-doctrine reasoning NOTICE §0 already states for protocol/format
descriptions.)

Every central invariant was **mutation-tested**: 21 deliberate mutations (drop the capability gate;
accept a nested/array-of-objects schema; treat `decline` as an error; surface content on `decline`;
reuse an id after a failed send; correlate by arrival order instead of id; drop the peer check; set
peer to 0 on both the send and correlate sides — the *consistent* mutation that survives every
round trip; answer a response instead of consuming it; record both request kinds as `.sampling`;
misspell `maxTokens`; emit `mode` to a 2025-06-18 peer; reorder the URL-mode keys; remove the
pending cap; remove the credential refusal; drop the empty-`elicitation:{}` form default; silently
decode tool-use content; and, in `mcp-http`, let the JSON body keep every line and let all sessions
share peer 0). All 21 turned a test red on behaviour, none on a compile error alone. The newly added
spec-literal anchors were spot-checked the same way: swapping `progress`/`total` in
`Progress.report`'s formatted values turned both the pre-existing progress test and the new
`notifications/progress` spec-anchor test red (wrong numbers on the wire), confirming a compile-only
mutation was not mistaken for coverage; reverted byte-for-byte (`md5sum` before/after matched).
Run: `zig build test-mcp`.

**What those 21 did not cover** (re-audit 2026-08-11): every one of them is a *behaviour/guard*
mutation, so the module's **limit values** were unpinned — `max_line_len` could be shrunk to 1 KiB
and `max_pending` raised to `maxInt(usize)` with the suite green. Both are now pinned by absolute
numbers (16 MiB exactly, with a 1 MiB line still delivered and 17 MiB refused; 256 unanswered
requests fit and the 257th does not) rather than in terms of the constant they check. The fuzz layer
was one direction short as well: the response harness now pre-arms pending entries so
`SamplingResult.parse`, `parseContentBlock`, `ElicitationResult.parse` and the error-object decode
are actually reached, and asserts that it reached them.

## Backlog / deferred

None recorded beyond the explicit out-of-scope list above (client/host roles, roots, subscriptions,
pagination, sampling-with-tools, `notifications/elicitation/complete`). Worth revisiting if a
consumer needs it: sampling-with-tools is the largest remaining piece (a multi-turn tool loop with
`ToolUseContent`/`ToolResultContent` balance rules the spec makes normative), and
`URLElicitationRequiredError` (-32042) is exposed as a code but not as a helper that builds its
`data.elicitations` payload.

## Status

`extract · any · server · reentrant` + deps: none (std only — `std.json` + `std.Io`) — canonical
source is `pub const meta` in src/root.zig.
