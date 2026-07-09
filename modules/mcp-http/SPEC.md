# mcp-http — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **`POST /mcp`** → the JSON-RPC request runs against the `mcp.Server`; the response is either
  `application/json` (one result) or, when the client sends `Accept: text/event-stream`, a live
  SSE stream where each JSON-RPC line becomes one `data:` event (tool-call
  `notifications/progress` delivered as they happen); a pure notification → `202`. Clean-room from
  the MCP "Streamable HTTP" transport spec (2025-06-18); bxp-gui's Dart `mcp_dart` client is the
  behavioral reference — see NOTICE.
- **Sessions (optional):** an `Mcp-Session-Id` is minted at `initialize` and validated thereafter
  (unknown → 404); `GET /mcp` opens a server→client SSE stream; `DELETE /mcp` tears it down.
- **`GET` is drain-and-close, not held-open** — io-less handlers can't park a connection on a
  future push, so the stream drains the buffered queue and closes; EventSource auto-reconnect +
  `Last-Event-ID` replay (bounded per-session buffer) makes delivery lossless. `Sessions.push` is
  callable from any thread (one spinlock; snapshot-under-lock so a concurrent `DELETE` can't UAF).
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
- **Out of scope:** TLS (the server's/a proxy's), rate limiting (`ratelimit`), and the older
  HTTP+SSE dual-endpoint transport (only Streamable HTTP is implemented).

## Verification

Offline tests over the `http` server harness: POST→JSON and POST→202, SSE-on-POST progress
delivery, Origin accept/reject, session assign/validate/unknown-404, GET drain-and-close with
`Last-Event-ID` replay, and `DELETE` teardown. 13 tests. Run: `zig build test-mcp-http`.

## Backlog / deferred

- Pending repo-wide **security/similarity review pass** (see /docs/pre-public-review.md): `mcp-http`
  is named as part of the `http` parser-cluster re-audit (body/multipart/mcp-http/webhooksig/
  cookies/range/conneg), not yet run.
- No functional backlog beyond the explicit out-of-scope list above (module README has no Deferred
  section).

## Status

`gap · any · server · reentrant (session store: Lock seam)` + deps: `router`, `http`, `mcp` —
canonical source is `pub const meta` in src/root.zig.
