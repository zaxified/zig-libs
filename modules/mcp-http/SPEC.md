# mcp-http — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **`POST /mcp`** → the JSON-RPC request runs against the `mcp.Server`; the response is either
  `application/json` (one result) or, when the client sends `Accept: text/event-stream`, a live
  SSE stream where each JSON-RPC line becomes one `data:` event (tool-call
  `notifications/progress` delivered as they happen); a pure notification → `202`. Clean-room from
  the MCP "Streamable HTTP" transport spec (2025-06-18) + JSON-RPC 2.0 — see NOTICE. The
  behavioral contract is verified against a live capture of the official `mcp` Python SDK (see
  Verification below), superseding an earlier, unbacked claim of parity against a Dart reference.
- **Sessions (optional):** an `Mcp-Session-Id` is minted at `initialize` and validated thereafter
  (unknown → 404); `GET /mcp` opens a server→client SSE stream; `DELETE /mcp` tears it down.
- **`GET` is drain-and-close, not held-open** — io-less handlers can't park a connection on a
  future push, so the stream drains the buffered queue and closes; EventSource auto-reconnect +
  `Last-Event-ID` replay (bounded per-session buffer) makes delivery lossless. `Sessions.push` is
  callable from any thread (one spinlock; snapshot-under-lock so a concurrent `DELETE` can't UAF).
- **Server→client requests (sampling / elicitation)** are supported to exactly the degree HTTP
  allows: the client's answer is a *later, separate POST*, so nothing parks waiting for it (the same
  constraint the drain-and-close `GET` documents). Three concrete pieces: (1) each session's numeric
  handle (`Sessions.tag`, allocated from the create-lock's `seq`, never reused, and returned
  *by `create` itself* so the transport never re-looks-it-up) is passed to
  `mcp.Server.handleMessageFrom` as the **peer**, so a response POSTed on session B cannot resolve a
  request issued to session A — a cross-tenant data-delivery bug, not a cosmetic one; (2) a request
  issued from inside a `tools/call` rides that POST's response — an SSE `data:` event in stream
  mode, or (JSON mode) the session queue; (3) the client's response POST produces no reply line, so
  the endpoint answers **202 Accepted** and the `mcp.ResponseHandler` runs during that POST.
- **Peer scoping needs a session; a stateless endpoint refuses to correlate instead of guessing.**
  The peer handle is the *only* thing that separates two clients here, and a stateless endpoint
  (`sessions == null`) has none: every POST would be peer 0, which `mcp`'s peer check — it compares
  the issuing peer against the answering one, nothing more — cannot tell apart. Outbound request
  ids are small consecutive integers, so guessing one is not work. A stateless endpoint therefore
  **refuses** (`400`) any POST that could correlate: no `method`, an integer `id`, and a `result` or
  `error` — precisely the set `mcp.Server.handleMessageFrom` routes to `deliverResponse`, so nothing
  else changes behaviour. Set `Transport.stateless_responses = .single_client` to opt back in where
  the endpoint genuinely serves one client (a loopback bridge, a sidecar); on a multi-client
  endpoint that flag *is* a leak between clients and the transport cannot detect the difference,
  which is why it is named, explicit and not the default. Before 2026-08-11 the promise "one session
  cannot consume another's sampling reply" was written without this qualifier while the stateless
  mode silently shared peer 0 — the promise was true of the configuration it described and false of
  the default one. Latent, not exploited: only one consumer speaks HTTP/SSE today.
- **The `application/json` body is exactly one JSON object.** The server may write several lines for
  one message (progress notifications, and now server→client requests) before the response line;
  only the last is the body and the earlier ones are pushed to the session's `GET` queue (dropped on
  a stateless endpoint, which has no channel for them). Previously the whole capture was returned,
  so any pre-response line would have concatenated multiple objects into one body — latent before
  (only reachable via a progressToken in JSON mode), unavoidable once a tool can issue a request.
- Built on `http` (streaming `ResponseWriter.flush` + `sse` encoder) + `router`; a `Lock` seam for
  the session store; size-capped bodies.

## Threat model / out of scope

- **Origin allowlist (DNS-rebinding guard):** `POST`/`GET` are gated by an `Origin` allowlist — the
  documented MCP mitigation for a browser-based DNS-rebinding attack against a locally-bound
  server.
- **No auth of its own** — bearer/OAuth is layered in front by composing `aaa-gate`/`jwt` as
  earlier middleware; this module does not authenticate callers.
- **Session ids** are unguessable capability tokens for stream resumption, not an auth boundary;
  the replay buffer is bounded (old events drop). No cross-process session sharing (single-server).
  The session **peer handle** derived from them scopes response correlation only — it inherits the
  session id's trust level and is not an authentication of the answering party.
- **Out of scope:** TLS (the server's/a proxy's), rate limiting (`ratelimit`), and the older
  HTTP+SSE dual-endpoint transport (only Streamable HTTP is implemented).

## Verification

Offline tests over the `http` server harness: POST→JSON and POST→202, SSE-on-POST progress
delivery, Origin accept/reject, session assign/validate/unknown-404, GET drain-and-close with
`Last-Event-ID` replay, `DELETE` teardown, and a `max_sessions` cap rejection (audit MED). Plus, for
server→client requests: a response POST → 202 with the handler run, cross-session correlation
refused (session B's answer leaves session A's request pending, and the request lands only on A's
`GET` stream), the `application/json` body carrying exactly one object while the tool's elicitation
goes to the session queue, and the SSE ordering (request event precedes the tool result). 18 tests.

The peer-scoping promise is pinned by an **attacker's** test in each configuration, not a
happy-path one — client A has a request outstanding, client B (who was never asked anything) posts
a response carrying A's id — with an innocent third party's pending request as a bystander oracle,
so "still pending" cannot pass for the wrong reason (nothing resolving anything). Session-ful: B's
answer leaves both A's and C's requests pending, A's own answer resolves only A's. Stateless: B's
answer is refused with 400 and so is A's, which is the *documented cost* of the default rather than
a filter that happens to catch attackers; ordinary requests on the same endpoint are unaffected.
Six mutations, each red on behaviour and attributed to a named test: dropping `mcp`'s peer check
(session-ful test, on the leak assertion), forcing the transport's peer to a constant (session-ful
test, on the genuine answer no longer arriving), giving every session the same handle (the
tag-distinctness precondition — and, with that precondition disabled, the leak assertion itself),
flipping the stateless default back to `.single_client` (stateless test, leak assertion), making
the response detector never fire (same), and dropping its `!has_method` term (detector test — this
one *survived* until a `{"id":1,"method":"tools/list","result":{}}` case was added, the only input
that separates precision from safety here).

### Oracle: a real captured session from the official `mcp` Python SDK

This module's README/NOTICE previously described the behavioral contract as "cross-checked for
parity against a reference Dart server (`mcp_dart`)" with no captured bytes and no live check
behind that claim — the worst of the false-anchor shapes, since it told a reader the opposite of
the truth. Fixed: a single live run of the **official `mcp` Python SDK** (modelcontextprotocol.io,
package `mcp` 2.0.0) — its real `ClientSession` + `streamable_http_client` talking to its real
`MCPServer.streamable_http_app()` (via uvicorn) over an actual loopback TCP connection, with a raw
byte-logging proxy observing (not altering) the exchange — captured `initialize`,
`notifications/initialized`, `GET` session-stream open, `tools/list`, and two `tools/call`s (one
with two live `notifications/progress` events), through `DELETE`. Frozen once in
`oracle_vectors.zig`; `root.zig`'s "oracle:" tests replay those exact request bytes through this
module's own `Transport` (offline, the same in-memory `runWire` harness every other test uses — no
socket) and assert:

| Piece | Assertion |
|---|---|
| `initialize` | this module's response negotiates the identical `protocolVersion` the real SDK did, and mints a session id |
| `notifications/initialized` | → `202`, matching the reference server |
| `tools/list` | lists this module's tools, matching the real response's tool names |
| `tools/call` (`echo`) | `structuredContent` byte-comparable to the real captured value (both use the same `{"result": <value>}` wrapping) |
| `tools/call` (`work`) | the two `notifications/progress` SSE frames are asserted **as literal substrings of this module's own output** — this module's field order (`jsonrpc, method, params.{progressToken,progress,total,message}`) is identical to the reference server's, so this is a byte-exact match, not merely a parsed-and-compared one |

Two differences the capture surfaced, both confirmed benign (not bugs — recorded because they were
observed, not assumed): the reference server's `GET` stream never closed on its own (a genuine
held-open long-poll) where this module is deliberately drain-and-close (documented above — an
io-less handler cannot park a connection); and `DELETE` got `200 OK` from the reference vs. this
module's `204 No Content` (both valid 2xx responses; the spec does not mandate one). A third,
cosmetic-only difference: the reference names every SSE event `event: message` explicitly, this
module omits `event:` — WHATWG SSE defines the absent case as the same default type, so the two are
wire-identical to any `EventSource`. See `oracle_vectors.zig`'s doc comment for the full capture
recap and provenance. `mcp` run as a black-box test oracle needs no root `NOTICE` entry (§0); no
`mcp_dart`, the official SDK, or any other MCP-transport source was ported or copied.

**30 tests total**, of which 5 are the oracle replays above and 3 came from the 2026-08-11
peer-scoping pass. (Earlier revisions of this line said "26 (18 + 8)" — a hand-kept split that had
already drifted from the tree; the total is now the counted one, and `scripts/dark-tests.sh`
asserts every declared test actually runs.) Run: `zig build test-mcp-http`.

## Backlog / deferred

- Reviewed 2026-07-10 (adversarial security pass) as part of the `http` parser-cluster re-audit
  (body/multipart/mcp-http/webhooksig/cookies/range/conneg) — clean; the cluster's redirect
  Authorization-stripping and cross-origin Cookie-leak fixes (both HIGH) landed in `http` itself.
- No functional backlog beyond the explicit out-of-scope list above (module README has no Deferred
  section).

## Status

`gap · any · server · reentrant (session store: Lock seam)` + deps: `router`, `http`, `mcp` —
canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/oracle_vectors.zig freezes one real Streamable-HTTP session with the python MCP SDK and root.zig's `oracle:` tests replay it; the unbacked mcp_dart parity claim was retracted rather than counted, and the remaining HTTP/SSE framing paths are self-tested

**How it got there.** The anchoring work landed. DONE 0341464: real MCP Python SDK session; unbacked mcp_dart parity claim RETRACTED
