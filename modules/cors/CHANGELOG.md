# cors — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-23** — **Faster preflight** (net 1.38× → 1.13–1.23× tower-http): the request headers a
  preflight reads (Origin, Access-Control-Request-Method/-Headers/-Private-Network) are found in one
  pass over the head instead of one `req.header` scan each (the middleware no longer looks up the
  request method twice), and the constant `Vary` / `*` / PNA values go through `setHeaderStatic`.
  Same answers. **Card:** fastest in the field measured (`bench-cors` also times labstack/echo
  v5.4.2, `tools/go_fast_bench`, and tower-http 0.7.1, `tools/rust_fast_bench`).
- **2026-10-20** — **CONSUMER-VISIBLE (headers):** with a `.list`, `.patterns` or `.predicate`
  origin policy, every actual response now carries `Vary: Origin` — also when the Origin is
  absent or refused or the method gate fails, not only on a grant (rs/cors parity; audit
  2026-10-19 S8-2). Without it a shared cache could store a response without CORS headers and
  serve it to an allowed cross-origin page. `.any`, `.none` and the static posture are
  unchanged; on a grant the header order is unchanged. Browser-oracle vectors re-taken with
  Chrome 155 (504 fetches agree; 74 refusal answers gained the field).

- **2026-10-18** — Ported to Zig 0.17.0. `std.ascii.indexOfIgnoreCase` -> `findIgnoreCase` (test and bench tool). No behaviour change.

- **2026-10-12** — The actual-request gate checks the method as sent (`Request.methodName()`,
  http R9: extension methods now reach handlers). `.other` in `allowed_methods` is the new
  `InitError.UnnamedAllowedMethod`: a preflight can only grant named methods.

- **2026-10-11** — rs/cors v1.11.1 parity (grade 2). New: `Origins.patterns` (`.exact` + validated
  `scheme://*.host[:port]` subdomain patterns; stricter than rs/cors: the `*` covers whole labels only, so
  `https://evil.com/.example.com` does not match; `error.InvalidOriginPattern` at init), `Options.allow_private_network`
  (`Access-Control-Allow-Private-Network` + extended preflight `Vary`), `Options.preflight_passthrough` (handler
  answers the OPTIONS after the CORS headers). Debug logging and request-aware origin functions rejected
  (SPEC Backlog). Pattern matcher added to the `CORS_FUZZ` gates harness. New `tools/bench.zig` +
  `tools/go_bench` (`zig build bench-cors`) against rs/cors v1.11.1. Existing behaviour unchanged.
- **2026-10-09** — tests: deterministic fuzz driver `CORS_FUZZ` over the existing harnesses (`gates`).
- **2026-10-05** — **Anchoring: headless Chrome** (`tools/interop.zig`, `tools/browser_oracle.js`,
  `src/browser_oracle_test.zig`): 504 `fetch()` calls from two origins under 16 gated and 2 static
  configurations; Chrome's verdict must equal the configured policy, and the middleware must still
  answer each request Chrome sent with the head it judged. Anchor grade MIXED → EXTERNAL.
  - **BEHAVIOURAL:** `methodTokenAllowed` compares methods byte for byte (RFC 9110). A preflight for
    `patch` -- `fetch()` upper-cases only DELETE/GET/HEAD/OPTIONS/POST/PUT -- was granted with
    `Access-Control-Allow-Methods: ..., PATCH`, which the browser refuses anyway; it is now a failed
    preflight. Canonical upper-case tokens answer as before.
  - `allowed_headers = .list` entries are trimmed before comparing: `" X-A"` used to match no
    requested header.

- **2026-10-04** — Tests: mutation schemata run (36 mutants, all killed). Two new tests: a
  listed origin grants only its exact serialization (not a longer host or a port variant), and
  a bare OPTIONS under `allow_unconditional_wildcard` carries no Allow-Methods/Max-Age. No
  behaviour change.
- **2026-09-10** — A1 audit close-out, 4 findings from the original audit
  report (the ledger's own table only carried 2 of them — the other 2 were
  listed in `0a53c673`'s own commit message as "reported in the audit notes,
  not fixed"). (1)+(2) `requestedHeadersAllowed`'s inactive-union-field read
  (HIGH — a wild slice deref in ReleaseFast under the *default* `.reflect`
  config) and the long-`Access-Control-Request-Headers`-turns-204-into-500
  (MEDIUM) were already fixed by `0a53c673` (2026-09-01) — verified
  structurally against `0a53c673^` and confirmed green in the current suite.
  (3) NEW: `allow_unconditional_wildcard`'s preflight early return used to
  answer a REAL preflight (ACRM present) with only
  `Access-Control-Allow-Origin: *` — no Allow-Methods/-Headers/-Max-Age, so
  a browser fails the very DELETE/PUT/custom-header request the flag exists
  to permit "without changing what is on the wire". SPEC.md frames the flag
  as skipping the origin/method/header GATES, not the emission; it now
  emits the full grant while still skipping the three gates. (4) NEW: `init`
  now rejects an empty `allowed_methods` with the new `error.EmptyAllowedMethods`
  — the comptime `StaticOptions` twin already refuses this with a
  `@compileError`, but the runtime `Options` path (the primary API) had no
  equivalent, so a config-driven empty list silently emitted a bare
  `Access-Control-Allow-Methods: ` on every preflight. Both (3) and (4) are
  new behavior; the module has 0 consumers in the repo (P1). Measured: RED
  37/39 → GREEN 39/39 (`zig build test-cors`).
- **2026-09-07** — **Test-only: `fuzzGates` handed all three pure gates the
  empty string on every run.** It opened with `smith.bytes(&buf)` and then drew
  the length with `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the eight
  it reads as a little-endian `u64` and returned the range MINIMUM. `len` was 0
  for every input the ordinary test lane can carry. That is the *worst*
  possible single input here: `requestedHeadersAllowed("")` returns `true`
  through the "no header named" path without ever reaching the comma split, so
  the refusal branch this gate exists for had never executed. The harness now
  draws with one `smith.slice(&buf)` over a 14-seed corpus of real `Origin`,
  `Access-Control-Request-Method` and `Access-Control-Request-Headers` values.
  Measured 2026-09-07: **0 of 14 seeds arrived non-empty before, 14 of 14
  after; 0 origins granted before, 2 after; 0 method tokens allowed, now 3; 0
  header lists refused, now 10.** ⭐ An `accepted > 0` guard would have read
  green throughout — under the DEFAULT `.reflect` policy
  `requestedHeadersAllowed` answers `true` for any input at all — so the new
  corpus guard pins origins granted, methods allowed and header lists refused,
  none of which the empty input can produce.

- **2026-08-18** — New opt-in `Options.allow_unconditional_wildcard` (default `false`, unchanged
  behavior) — a named, deliberate deviation from spec-correct CORS for one migration shape: an
  existing API that has always answered every `OPTIONS` with 204 and put
  `Access-Control-Allow-Origin: *` on every response, and cannot change what's on the wire to adopt
  this module. Requires `allowed_origins = .any` (`Cors.init` rejects any other combination with the
  new `error.UnconditionalWildcardRequiresAnyOrigin`). `applyActual` is now `pub` — it was always
  called automatically before `next.run`, and is now also documented as the concrete fix for an
  outer response-rewriting middleware that calls `ResponseWriter.reset()` after `next.run` and needs
  to re-apply the CORS headers `reset()` wiped (see README's "Header timing vs.
  `ResponseWriter.reset()`" and SPEC.md for why the default ordering itself was evaluated and kept).
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the preflight short-circuit no longer
  forces an early `ResponseWriter.end()`. Unlike the sites this mirrors
  (`ratelimit`, `throttle`), none of `handlePreflight`'s header values ever
  needed the early `end()` for their own sake: the reflected
  `Access-Control-Allow-Headers` is the *request's* own header slice, which
  outlives the response head regardless of copying, and every other value
  comes from the `Cors` instance, not a stack frame. **What changes for a
  consumer:** the 204 preflight head reaches the wire when the serving loop
  ends the response, not inside the middleware — so an *outer* middleware
  that works after `next.run` can still touch a preflight response. That is
  the point rather than a side effect: `sessions` saves its cookie there and
  `csrf` issues its token there; both writes were being swallowed as
  `error.HeadersSent` on every preflight. The status, headers and (absence
  of) body of the 204 are unchanged.
- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on rs/cors (Go), expressjs/cors,
  gin-contrib/cors (design reference, not a test anchor).
