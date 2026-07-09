# aaa-gate — spec

Auth + audit front for an API (Bearer/API-key gate). Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- Credential check is **constant-time** (never a short-circuiting `mem.eql`) so a network attacker
  cannot recover a valid token/key byte-by-byte via timing.
- `protect` default = `.all` (every method gated) — secure-by-default, a deliberate deviation from
  the seed (which gated only mutations, restorable via `.mutations`). Register `cors` before the
  gate under `.all` (preflights carry no `Authorization`).
- **Open plane:** an empty token set (no `token`/`extra_tokens`) disables auth entirely
  (`Identity.scheme == .open`) — kept as the dev/demo default; configuring any token closes it.
- **Audit** is a synchronous hook (`on_audit(entry)`), never a logger: fires on every authenticated
  mutation and every denial; authenticated reads are not audited. Entry slices borrow request-scoped
  memory.
- **Denied-request throttle** (seed's `AuditThrottle`, per-key): coalesces repeated 401s from one
  client key within `throttle_window_ms`; suppressed count folds into the next admitted entry so
  nothing is silently dropped, while responses themselves are never throttled (every denial still
  gets its 401). Bounded store (`throttle_max_keys`, LRU); clock injected for deterministic tests;
  fails **open** on allocator exhaustion (OOM must not silence the audit trail).
- Throttle key = `ratelimit`'s trust rule (rightmost XFF hop, else X-Real-IP, else peer IP, else a
  shared fallback) — same forgeability caveat as `ratelimit` when directly reachable.
- Threadsafe; identity attached for downstream handlers; RFC 6750 challenge (401 +
  `WWW-Authenticate`) on failure.

## Threat model / out of scope
- Defends: credential brute-force (constant-time compare + denied-throttle) and provides an audit
  trail for post-incident review.
- Static shared-secret credentials only — not token issuance, not OAuth2/OIDC (use `jwt`), not
  session management; storage/rotation/zeroization is the caller's.
- AuthZ is coarse (authenticates + can gate); fine-grained scopes/RBAC are the application's or
  `jwt`'s job.
- Out of scope: TLS (server/proxy), rate limiting of successful traffic (`ratelimit`), and
  connection-level DoS/abuse controls (`abuseguard`/`throttle`).

## Verification
`zig build test-aaa-gate`. Offline unit tests (constant-time verify both branches incl. length
mismatch; open plane; rotation via `extra_tokens`/`addToken`/`removeToken`; throttle
coalescing/fold/reset, window-0 disable, max-keys bound, OOM fail-open) plus wire-level goldens over
the socket-free `http.Server.serveStream` (401 + challenge, valid/wrong/missing token, malformed
`Authorization` corpus never panics, `.mutations` split, audit-entry fields, throttle keying) and a
loopback integration (`router`+`http.Server`+`http.Client`), skipping only when loopback binding is
unavailable. 28 tests.

## Backlog / deferred
Pending pre-public **security/similarity review** (tracked in PLAN.md, not module-specific work
yet): const-time compare + alg-confusion + JWKS-smuggling + rotation review, paired with `jwt`.

## Status
`extract · any · server · threadsafe` + deps `router`, `http` — canonical source is `pub const meta`
in src/root.zig.
