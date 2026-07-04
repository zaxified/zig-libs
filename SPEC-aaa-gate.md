# SPEC — `aaa-gate`

Authentication + audit + abuse-throttle gate for the API — the auth layer the Web/API cluster is
missing. Wave P1. `extract · any · server · tsafe`. Model after: envoy / oauth2-proxy (minimal) —
really just bearer-token auth + an audit trail. **Seed: extract from
`~/workspace/axp/axp-central/src/rest.zig`** (`AuditThrottle`, `admin_token`/`admin_tokens_file`,
`auditMutation` — same authors' Apache-2.0 code, relicensed MIT). Deps: `router`, `http`. New
`build.zig` entry `.{ .name = "aaa-gate", .deps = &.{ "router", "http" } }` (import
`@import("aaa-gate")`, hyphen OK like `security-headers`/`cors`).

## Why

The cluster has rate-limiting, abuse defense, throttling, CORS, security headers, metrics, validation
— but no **auth**. `aaa-gate` adds bearer-token authentication, an audit trail for mutations, and a
denied-request throttle (bound repeated-401 flooding), extracted from axp's proven gate. It attaches
the caller identity to `ctx.data` (the aaa-gate hook `router` reserved).

## Scope

1. **Bearer auth (`router.Middleware`):** check `Authorization: Bearer <token>` against a configured
   token (and optional extra tokens for rotation). On missing/invalid → **401** (with
   `WWW-Authenticate: Bearer`), do NOT call `next`. On valid → attach an identity marker to
   `ctx.data` and call `next`. Optionally scope which methods require auth (e.g. only mutations
   POST/PUT/PATCH/DELETE) vs. protect everything — pick a default, document. Constant-time token
   compare (`std.crypto.timing_safe.eql` or equivalent) to avoid timing leaks.
2. **Audit trail:** an `on_audit(entry)` hook called for audited requests —
   `{ method, path, target, detail, authed: bool, status }` — so the caller logs/persists. Extract
   the seed's `auditMutation` fields. Keep it a hook, not a logger.
3. **Denied-request throttle (from the seed's `AuditThrottle`):** coalesce/bound repeated denied
   (401) requests so an attacker can't flood the audit sink — a per-key (IP via `http.Server`
   peer / `X-Forwarded-For`, like `ratelimit`) counter with a documented window; clock-injected for
   deterministic tests. Extract the seed's coalescing logic.
4. **Token config + rotation:** primary token + a set of extra/rotating tokens; a way to add/replace
   at runtime (match the seed's `admin_tokens_file` idea but as an API — don't hard-require a file).

## Public API sketch (final = the seed's shape adapted)

```zig
pub const Gate = struct {
    pub fn init(gpa, Options) Gate;   // Options: token, extra_tokens, protect (all|mutations),
                                      //   on_audit, on_audit_ctx, throttle window, clock, key
    pub fn deinit(*Gate) void;
    pub fn middleware(self) router.Middleware;   // 401 on bad/missing token; identity -> ctx.data
    pub fn addToken(self, token) !void;  pub fn removeToken(self, token) void;   // rotation
};
```

## Acceptance / verification

- **Offline unit tests:** valid token → pass (+ identity in `ctx.data`); missing / malformed /
  wrong token → 401 with `WWW-Authenticate` (constant-time compare — assert both branches);
  `protect = .mutations` lets GET through unauthenticated but 401s a POST; token rotation (add a new
  token, old still works until removed); audit hook fires with the right fields on audited requests;
  **denied-throttle** coalesces repeated 401s from one key within the window (injected clock,
  deterministic) so the audit hook isn't flooded. Never panic on a malformed header.
- **In-process integration (must NOT skip normally):** router+`http.Server`+`http.Client` — a
  protected route: no token → 401, valid `Authorization: Bearer` → 200 and the handler sees the
  identity; a wrong token → 401.
- `zig build test-aaa-gate` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with `deps = &.{"router","http"}`.

## Notes for the implementer

- Use the **zig skill**; constant-time compare via `std.crypto.timing_safe.eql`. Reuse
  `router.Middleware {state,run}`, `Ctx.data`, `http.Server.Request` (Authorization header, peer/XFF
  for the throttle key — same trust rule as `ratelimit`). Thread-safe (documented lock/atomics).
- EXTRACTION: lift the seed's `AuditThrottle` + token/audit logic; adapt to the middleware shape.
- Provenance: README `Provenance:` line = "extracted from axp `axp-central/src/rest.zig` (same
  authors, Apache-2.0, relicensed MIT); design ref envoy/oauth2-proxy (behavior only)". SPDX MIT
  header. Add the design-ref to NOTICE if you cite envoy/oauth2-proxy.
