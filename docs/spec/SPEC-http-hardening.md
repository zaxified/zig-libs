# SPEC — `http` Phase 2.1 (server hardening for direct-internet)

Extends the existing `http.Server` (no new module). Makes it safe to run **directly on the
internet without a reverse proxy**. Model after: Go `net/http` Server (`ConnState`,
`MaxHeaderBytes`, `ReadTimeout`) + nginx (`client_max_body_size`, `limit_conn`). `any · server`.
**Still no HTTP/2 (Phase 3); TLS-terminating server is a separate later task.**

## Why

We decided the API may be exposed directly (no Caddy). So the server itself must surface the real
client and enforce edge limits, and provide the hooks the `abuseguard`/`throttle` modules need
(per-IP connection caps, bans, load-shedding). Also fixes `ratelimit`'s peer fallback (it currently
can't see the connection peer).

## Scope

1. **Expose peer address:** `Request` (and the connection) exposes the socket **peer `net.Address`**
   and a per-connection **request counter** (Nth request on this keep-alive connection). `ratelimit`
   and `abuseguard` key on this when no trusted `X-Forwarded-For` is present.
2. **Connection hook + accounting:** `Options.on_connect: ?*const fn(state, peer) ConnDecision`
   (ConnDecision = `.accept | .reject`), called right after `accept`, before serving — lets
   abuseguard enforce per-IP connection caps + bans and throttle enforce a global cap. Maintain a
   thread-safe **active-connection count** (and expose it) so a global limit is enforceable. A
   `.reject` closes the socket immediately (optionally after writing a 429/503 — pick one, document).
3. **Size limits:** configurable `max_header_bytes` (already partly present as max_head_bytes —
   unify) → **431**; `max_body_bytes` → **413** (enforced while streaming the request body, not by
   buffering it). `max_request_line_bytes` → 414. Never buffer an unbounded body.
4. **Timeouts (confirm/extend):** the existing poll-based `read_timeout` bounds slowloris on the
   head and body and keep-alive idle — verify it does, and add a **whole-request deadline** and a
   **write timeout** if cheap. Document what each bounds.
5. **Connection state callback (optional, Go ConnState-style):** a hook for new/active/idle/closed
   so `metrics` can count connections later. Keep it optional.

## API sketch (extend existing types; keep Client + current Server API stable)

```zig
// Request gains:
pub fn peerAddress(self: *Request) std.Io.net.Address;
pub fn connRequestIndex(self: *Request) u32;          // 0-based, per keep-alive connection
// Options gain:
on_connect: ?*const fn(*anyopaque, peer: std.Io.net.Address) ConnDecision = null,
on_connect_ctx: ?*anyopaque = null,
max_header_bytes: usize, max_body_bytes: usize, max_request_line_bytes: usize,
// Server gains:
pub fn activeConnections(self: *Server) usize;
```

## Acceptance / verification

- **Offline unit tests:** oversized header → 431, oversized request line → 414, oversized body →
  413 (streamed, not buffered — prove memory stays bounded); limits are configurable.
- **In-process integration (must NOT skip normally):** start `http.Server` on `127.0.0.1:0`, hit it
  with `http.Client` and assert the handler sees the **loopback peer address** and a rising
  per-connection request index across a keep-alive reuse; an `on_connect` that rejects a chosen peer
  causes the connection to be refused; `activeConnections()` reflects an in-flight request.
- `zig build test-http` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Client API unchanged; existing server tests still pass.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 std APIs (std.Io.net accept exposes the peer address; threads;
  atomics for the connection counter). Reuse `h1.zig` framing; don't duplicate.
- Keep the `on_connect` hook signature clean and stable — `abuseguard` (next task) plugs into it.
- Update `ratelimit` to use `peerAddress()` as the fallback key (replacing its shared-bucket
  fallback) — small follow-up in that module, keep its tests green.
- README + module doc: document every limit and timeout, and the direct-internet posture.
