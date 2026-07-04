# aaa-gate

Bearer-token authentication + audit hook + denied-request throttle as a
`router` middleware — the AAA layer of the Web/API cluster. Wave P1.

Provenance: extracted from the authors' axp project
(`axp-central/src/rest.zig` — the admin-token gate, `auditMutation` and
`AuditThrottle`; Apache-2.0, relicensed MIT by the copyright holder).
Design references: envoy ext_authz and oauth2-proxy (bearer-gate behavior
only — no source consulted or copied); bearer semantics per RFC 6750,
auth framework per RFC 9110. See `NOTICE`.

- **Status:** `extract`.
- **Model after:** the axp seed; envoy / oauth2-proxy (behavior only).
- **Platform:** any. **Role:** server. **Concurrency:** threadsafe —
  token set + throttle store behind one documented spinlock
  (`std.atomic.Mutex`, the ratelimit pattern); token hashing outside the
  lock; no hidden globals, caller-supplied allocator.
- **Deps:** `router` (Middleware/Ctx/Next, the reserved `Ctx.data` slot),
  `http` (`Request.header`/`peerAddress`, `ResponseWriter`).

Import name: the module registers as **`aaa-gate`** —
`@import("aaa-gate")` (a hyphen is fine in a module name, like
`security-headers`); bind it to an identifier such as
`const aaa_gate = @import("aaa-gate");`.

## Usage

```zig
const aaa_gate = @import("aaa-gate");
const router = @import("router");

var gate = try aaa_gate.Gate.init(gpa, .{
    .token = primary_token,               // not retained (SHA-256 digest stored)
    .extra_tokens = &.{old_token},        // rotation set
    .protect = .all,                      // default; .mutations = seed's R/W split
    .realm = "api",                       // optional: Bearer realm="api"
    .on_audit = myAuditHook,              // optional hook (not a logger)
    .on_audit_ctx = &my_sink,
});
defer gate.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(cors_mw);           // CORS first: preflights can't carry Authorization
try r.use(gate.middleware()); // then the gate, before routes (chi rule)
try r.post("/api/devices/:id/reboot", rebootHandler);

// Zero-downtime rotation (the seed's admin_tokens_file idea, as an API):
try gate.addToken(new_token); // both valid now — migrate clients…
gate.removeToken(primary_token); // …then retire the old one
```

In a handler behind the gate:

```zig
fn rebootHandler(ctx: *router.Ctx) !void {
    const id = aaa_gate.identityOf(ctx).?; // .scheme = .bearer (or .open)
    id.audit_target = device_id;           // lands in the audit entry
    id.audit_detail = "reboot";
    ...
}
```

The `Gate` must outlive the `Router`, at a stable address (the
middleware's `state` points at it).

## Semantics

- **Auth check.** Requests in the protected scope need
  `Authorization: Bearer <token>` matching a configured token. Both sides
  are hashed (SHA-256) and the fixed-size digests compared with
  `std.crypto.timing_safe.eql`, scanning the whole token set without
  early exit — constant-time in token content, candidate length and
  which slot matched. Deny → **401** + `WWW-Authenticate: Bearer`
  (`realm="…"` when configured), plain-text body, chain short-circuited.
  Pass → an `Identity` on `ctx.data` (the slot `router` reserved for
  this module; restored after the chain), then `next`.
- **`protect` default = `.all`** — every method is gated. This is a
  deliberate deviation from the seed (which gated only mutations):
  secure by default for a standalone auth layer. `.mutations` restores
  the seed's R/W boundary: POST/PUT/PATCH/DELETE gated, GET/HEAD/OPTIONS
  open (out-of-scope requests get no identity and no audit). Under
  `.all`, register `cors` **before** the gate — browser preflights
  cannot carry `Authorization` and would otherwise 401.
- **Open plane.** An empty token set (no `token`, no `extra_tokens`)
  disables authentication: everything passes with
  `Identity.scheme == .open`. Kept from the seed as the dev/demo default
  — configuring any token closes the plane; removing the last token
  reopens it.
- **Audit** = a hook (`on_audit(entry)`), never a logger. Fires
  synchronously for every **authenticated mutation** (after the handler:
  final status + the `target`/`detail` the handler set on the Identity;
  a handler error is audited as the 500 the server will send) and every
  **denial** (401, any method; empty target/detail). Authenticated reads
  are not audited (seed behavior). Entry slices borrow request-scoped
  memory — copy what you keep. Entry shape:
  `{ method, path, target, detail, authed, status, suppressed }`.
- **Denied-request throttle** (the seed's `AuditThrottle`, per-key):
  within `throttle_window_ms` (default **5 s**; `0` disables) repeated
  401s from one client key are coalesced — the hook stays quiet and the
  suppressed count is **folded into the next admitted entry**
  (`entry.suppressed`), so nothing is silently dropped while an
  unauthenticated flood cannot flood the audit sink. Responses are never
  throttled — every denied request still gets its 401. The store is
  bounded (`throttle_max_keys`, default 1024, LRU eviction; evicting a
  key may drop its pending fold count — bounded memory wins). Clock
  injected via `Options.clock` (POSIX `clock_gettime(MONOTONIC)` /
  QueryPerformanceCounter by default) for deterministic tests. On
  allocator exhaustion the throttle **fails open** — the denial is
  audited untracked (OOM must not silence the trail).
- **Throttle key = the client IP, `ratelimit`'s trust rule:** rightmost
  element of the *last* `X-Forwarded-For` header (the only part a client
  cannot forge behind a compliant proxy), else `X-Real-IP`, else the
  socket peer IP (port excluded; IPv4-mapped IPv6 unified with plain
  IPv4), else one shared fallback key. Same caveat as `ratelimit`: when
  the server is directly reachable, forged forwarding headers let a
  client pick its own throttle key (per-client coalescing, not a
  bypass); use `Options.throttle_key` to go straight to the peer, or
  strip those headers at the edge.

## Verification

`zig build test-aaa-gate` — offline unit tests (constant-time verify on
both branches incl. length mismatches; open plane; rotation via
`extra_tokens`/`addToken`/`removeToken`; throttle coalescing/fold/reset,
window-0 disable, max-keys bound, lossless idle sweep, OOM fail-open)
plus wire-level goldens over the socket-free `http.Server.serveStream`
(byte-exact 401 with `WWW-Authenticate`; valid/wrong/missing token;
case-insensitive scheme; malformed-Authorization corpus never panics;
`protect=.mutations` read/write split with identity-absence proof; open
plane; realm challenge; audit-entry fields for authed/denied/erroring
handlers; throttle coalescing + XFF/X-Real-IP/peer/fallback keying), and
an in-process integration test (`router` + `http.Server` + `http.Client`
over loopback: no token → 401 + challenge, valid `Bearer` → 200/201 with
the handler seeing the identity, wrong token → 401) that only skips when
loopback binding is unavailable.
