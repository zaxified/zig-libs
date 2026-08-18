# aaa-gate

Bearer-token authentication + audit hook + denied-request throttle as a
`router` middleware — the AAA layer of the Web/API cluster. Wave P1.

Provenance: original work of the zig-libs authors (MIT); modeled after envoy
ext_authz (Apache-2.0) and oauth2-proxy (MIT) — bearer-gate behavior only, no
source consulted or copied; bearer semantics per RFC 6750, auth framework per
RFC 9110.

- **Model after:** envoy / oauth2-proxy (behavior only).
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
    .protect = .all,                      // default; .mutations = R/W split (gate only mutations)
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

// Zero-downtime rotation (an admin-token-file rotation flow, as an API):
try gate.addToken(new_token); // both valid now — migrate clients…
gate.removeToken(primary_token); // …then retire the old one
```

API-key auth (alone, or alongside bearer):

```zig
var gate = try aaa_gate.Gate.init(gpa, .{
    .auth_mode = .either,                 // valid bearer OR valid API key
    .token = bearer_token,                // bearer wins when both are valid
    .api_key = primary_api_key,           // not retained (SHA-256 digest stored)
    .extra_api_keys = &.{old_api_key},    // rotation set (addApiKey/removeApiKey too)
    .api_key_header = "X-Api-Key",         // default; rename for a custom header
    .api_key_query_param = "api_key",     // optional fallback ?api_key=… (header wins)
    // Dynamic store instead of / in addition to the static set:
    // .api_key_verify = myVerify,        // must compare in constant time
    // .api_key_verify_ctx = &my_store,   // use aaa_gate.secretEqual inside it
});
```

A bearer store the gate cannot mirror (an operator token file another
process rewrites), a JSON denial body, and one open endpoint:

```zig
var gate = try aaa_gate.Gate.init(gpa, .{
    .token_verify = tokenFileVerify,      // tried after the static set
    .token_verify_ctx = &token_file,      // its presence closes the open plane
    .deny_body = "{\"error\":\"unauthorized\"}", // copied into the gate
    .deny_content_type = "application/json",
    .exempt = .{ .isExempt = liveness },  // /healthz needs no credential
});

fn tokenFileVerify(ctx: ?*anyopaque, presented: []const u8) bool {
    const store: *TokenFile = @ptrCast(@alignCast(ctx.?));
    return aaa_gate.secretEqual(presented, store.current); // never std.mem.eql
}

fn liveness(_: ?*anyopaque, ctx: *router.Ctx) bool {
    return std.mem.eql(u8, ctx.req.path, "/healthz");
}
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
  which slot matched. A miss falls through to the optional
  `token_verify` callback (below). Deny → **401** +
  `WWW-Authenticate: Bearer` (`realm="…"` when configured), plain-text
  body by default, chain short-circuited. Pass → an `Identity` on
  `ctx.data` (the slot `router` reserved for this module; restored after
  the chain), then `next`.
- **Dynamic token store (`token_verify`).** The exact mirror of
  `api_key_verify` for bearer: a `TokenVerifyFn` consulted **after** the
  static set misses and **outside** the gate's lock, for a store the gate
  cannot mirror — an operator token file rewritten at runtime, an external
  secret store. It must compare in constant time; use the exported
  `secretEqual` (the module's SHA-256 + `timing_safe.eql` compare), never
  `std.mem.eql`. **Its presence alone closes the bearer open plane**: a
  gate with no static tokens but a verifier denies on a wrong token even
  under `allow_when_unconfigured = true`, because the verifier *is* the
  configuration. Rotation then needs no `addToken`/`removeToken` call and
  no plaintext kept around to diff into the gate.
  **This makes "is auth on" a startup decision, not a runtime one.**
  `token_verify`/`token_verify_ctx` (and `api_key_verify` likewise) are
  set only in `Options` at `Gate.init` — there is no call to attach or
  detach a verifier on a gate that is already serving. So enabling or
  disabling auth by adding or removing a verifier needs a **restart**.
  What does *not* need one is *which* credentials an already-configured
  verifier accepts: if it re-reads its own backing store per call (a
  token file, an external secret store), that rotates on the next gated
  request with no gate-side action at all — the same zero-restart
  rotation `addToken`/`removeToken` give the static set, just decided
  by the verifier instead of the gate. The reason the plane still closes
  with an empty static set is the same one behind the mechanism above: a
  verifier's presence is itself a statement that credentials exist
  somewhere the gate cannot enumerate, so an empty static set must never
  be read as "nothing is configured" — that misreading is exactly what
  would reopen the plane out from under a caller who configured a
  verifier believing auth was on.
- **API-key scheme (`auth_mode`).** Besides bearer, the gate accepts an
  API key. `Options.auth_mode` selects `.bearer` (default — unchanged),
  `.api_key`, or `.either`. The key arrives in the `X-Api-Key` header
  (rename via `api_key_header`) or, when `api_key_query_param` is set, as
  that query parameter (verbatim, not percent-decoded; header wins). It is
  checked against the configured set (`api_key` ∪ `extra_api_keys`,
  rotatable at runtime via `addApiKey`/`removeApiKey`) with the **same**
  SHA-256 + `std.crypto.timing_safe.eql` constant-time compare as bearer,
  or by an `api_key_verify` callback (dynamic store — must itself compare
  in constant time; use the exported `secretEqual`). A failed API-key
  attempt is audited and throttled **exactly** like a failed bearer
  attempt (same 401, same `WWW-Authenticate`, same denied-request
  coalescing). In `.either` a valid bearer **or** a valid API key passes;
  **bearer takes precedence** (checked first, its `Identity.scheme` wins
  when both are valid). The open plane applies per mode: open only when no
  credential for the active mode(s) is configured. `Identity.scheme` is
  `.bearer`, `.api_key`, or `.open`.
- **`protect` default = `.all`** — every method is gated: secure by
  default for a standalone auth layer. `.mutations` selects an R/W
  boundary instead: POST/PUT/PATCH/DELETE gated, GET/HEAD/OPTIONS
  open (out-of-scope requests get no identity and no audit). Under
  `.all`, register `cors` **before** the gate — browser preflights
  cannot carry `Authorization` and would otherwise 401.
- **Route exemption (`exempt`).** A predicate over the request
  (`ExemptFn`, the shape of `throttle_key`'s `KeyFn`) that takes
  individual routes out of the protected scope whatever `protect` says —
  the liveness probe of a service whose reads must otherwise stay gated,
  where `.mutations` would wrongly open every read. An exempt request is
  handled exactly like an out-of-scope one: no credential check, no
  `Identity`, no audit, no throttle. Null (default) ⇒ nothing is exempt.
  `ctx.matchedPattern()` is the bounded-cardinality way to name a route;
  `ctx.req.path` is the raw one.
- **Denial response (`deny_body` / `deny_content_type`).** The 401 body
  defaults to `Unauthorized\n` as `text/plain`; both are configurable
  (copied into the gate at `init`, so the deny path still writes stable
  memory and formats nothing per request), which is how a JSON API answers
  denials in its own `{"error":"…"}` shape without an outer middleware
  rewriting the response. The body may be empty (a bodiless 401). The
  status, the `WWW-Authenticate` challenge, the audit entry and the
  denied-request throttle are unaffected by the override.
- **Open plane.** An empty credential set fails **closed** (denies
  everything) by default. To disable auth entirely so everything passes
  with `Identity.scheme == .open` (the old dev/demo default), set
  `allow_when_unconfigured = true` explicitly — configuring any token/key
  closes the plane regardless.
- **Audit** = a hook (`on_audit(entry)`), never a logger. Without it, a
  denied request leaves no trace anywhere in the gate — wiring `on_audit`
  is what makes denials observable at all, not an optional add-on to a
  visibility the gate already has. Fires synchronously for every
  **authenticated mutation** (after the handler:
  final status + the `target`/`detail` the handler set on the Identity;
  a handler error is audited as the 500 the server will send) and every
  **denial** (401, any method; empty target/detail). Authenticated reads
  are not audited. Entry slices borrow request-scoped
  memory — copy what you keep. Entry shape:
  `{ method, path, target, detail, authed, status, suppressed }`.
- **Denied-request throttle** (`AuditThrottle`, per-key):
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
`extra_tokens`/`addToken`/`removeToken`; `token_verify` accepted/rejected,
consulted only after a static miss, and closing the open plane a bare
`allow_when_unconfigured` would have opened; throttle
coalescing/fold/reset, window-0 disable, max-keys bound, lossless idle
sweep, OOM fail-open; `init` leak-free at every allocation-failure index)
plus wire-level goldens over the socket-free
`http.Server.serveStream` (byte-exact 401 with `WWW-Authenticate`;
valid/wrong/missing token; case-insensitive scheme;
malformed-Authorization corpus never panics; `protect=.mutations`
read/write split with identity-absence proof; open plane; realm
challenge; a dynamic token store rotating behind the gate's back;
byte-exact JSON `deny_body`/`deny_content_type` override with audit +
throttle proven unchanged, and the empty-body case; `exempt` routes
bypassing the gate with no identity and no audit while the rest stays
gated; audit-entry fields for authed/denied/erroring
handlers; throttle coalescing + XFF/X-Real-IP/peer/fallback keying), and
an in-process integration test (`router` + `http.Server` + `http.Client`
over loopback: no token → 401 + challenge, valid `Bearer` → 200/201 with
the handler seeing the identity, wrong token → 401) that only skips when
loopback binding is unavailable.
