# requestid — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Per request:** adopt the incoming `X-Request-Id` header (default name) when `trust_incoming` is
  set *and* the value validates (non-empty, ≤ 200 bytes, all printable non-space ASCII) — a
  malformed or over-long incoming value is never trusted, a fresh ID is generated instead.
  Otherwise generate. Echo the ID back on the response under the same header. Clean-room from the
  conventional `X-Request-Id` correlation-ID pattern (nginx `request_id`, Envoy `x-request-id`) — a
  generic HTTP convention, not one project's design; no NOTICE entry.
- **Deliberately does not use `Ctx.data`** — that single slot is reserved for an auth middleware
  (`aaa-gate`/`jwt`); the ID is exposed only through `requestid.current()`, so request-ID composes
  with authentication on the same routes without a slot conflict.
- **Register first (outermost)** so every response — including 401/404 short-circuits from other
  middleware — carries the ID.
- **Generated IDs:** a 32-hex-char token derived from the monotonic clock, a per-connection-thread
  nonce and a per-thread counter — no allocation, no OS entropy call, fully portable. Explicitly a
  **correlation** ID (unique for tracing), not a CSPRNG token.
- **Memory/concurrency:** an adopted ID borrows the request head (stable for the life of the
  response). A generated ID lives in thread-local storage — valid because the server is
  task-per-connection (one request at a time per thread) — reused only by the *next* request on
  that thread. `current()` reads that thread-local, so it is meaningful only from the connection
  thread handling the request the middleware ran on. Config is immutable after init (threadsafe).

## Threat model / out of scope

Explicitly **not** an unguessability/security primitive: the generated ID must never be used where
an attacker guessing it matters (e.g. as a session token or capability). Trusting an incoming header
is opt-in (`trust_incoming`) and validated only for shape (length, charset) — it does not verify the
header came from a trusted edge; that trust boundary is the caller's network topology (e.g. only
accept `X-Request-Id` from a reverse proxy that strips/overwrites it from the public internet). If
CSPRNG unguessability is required, adopt an edge-assigned header or set it yourself — this module
does not fill that need.

## Verification

6 offline tests through `http.Server.serveStream`: generate + echo + `current()` agreement, ID
uniqueness across requests, adopt a valid incoming ID, regenerate on a malformed incoming value or
`trust_incoming=false`, `echo=false` suppresses the response header, custom header name. Green in
Debug + ReleaseFast. Run: `zig build test-requestid`.

## Backlog / deferred

None recorded — the module README has no Deferred section.

## Status

`gap · any · util · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.
