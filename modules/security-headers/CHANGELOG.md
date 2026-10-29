# security-headers — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: 6 mutants (old CR/LF/NUL predicate, slot check dropped, built-in and repeated-extra dedupe dropped, CSP copied instead of lent, every built-in counted): 6/6 killed on the first run; the RID-1 test gained a CSP-only case first, because the default set alone freed enough room to hide a copied CSP. Card A1 again.
- **2026-10-29** — **Behaviour change (fix):** `init` refuses a value with any byte `http` refuses in a field value (control bytes, DEL; was only CR/LF/NUL) with `InvalidHeaderValue`, and a configuration with more distinct header names than `http`'s response table with `HeaderBudgetExceeded` — both made every request fail. `apply` lends the configured values to the response (`setHeaderBorrowed`/`setHeaderStatic`) and copies only HSTS and `extra`, so a peer-sized header copied by an earlier middleware cannot starve it into a 500. No-panic sweep + blind review (§ GJ).
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the example handles the new `error.InvalidHeaderValue` in its exhaustive `init` error switches (it did not compile since the grade-1 commit; `modtest` does not build examples, `check-examples` does).
- **2026-10-24** — **Behaviour change:** `SecurityHeaders.init` returns the new
  `InitError.InvalidHeaderValue` for a CR/LF/NUL in any value, in every build mode (was a Debug-only assert,
  so a ReleaseFast build failed every request instead), and `InvalidExtraHeaderName` for an `extra` named
  `Connection`, `Content-Length`, `Transfer-Encoding` or `Trailer` (`http` acts on those instead of emitting
  them; `applyStatic` already refused them). Docs: server error replies carry the headers through
  `error_headers` + `staticHeaders`; the nonce replace's double header-budget cost. Tools: a gofiber/fiber
  v3.6.1 helmet side in the bench (`tools/go_fast_bench`, `BENCH_FAST=0` skips; a row the contender cannot
  run is judged against the reference) and `tools/lead_probe` (unrolled/secure ships an invalid HSTS preload
  and corrupts a `%` in a nonce policy). Grade 1.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — Ported to Zig 0.17.0. `std.ascii.indexOfIgnoreCase` -> `findIgnoreCase` (test). No behaviour change.

- **2026-10-18** — tests: mutation audit of the helmet-parity code (83/85, 2 equivalent). New: run-time CSP builder tests (override/remove order, flags and `sandbox`, `report-to`/`report-uri` tokens, exact-fit buffers, empty directive with a nonce, `NONE` case), every RFC 9110 token character in an `extra` name, and `applyStatic == apply` for every optional header and HSTS flag combination.
- **2026-10-18** — ADDED: `api_options`, the whole-set posture for a pure JSON/binary API (next to `csp_api`): `Options{}` without helmet 8.3.0's five legacy/cluster headers (`Origin-Agent-Cluster`, `X-DNS-Prefetch-Control`, `X-Download-Options`, `X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection`), i.e. the six-header set of before helmet parity. The default is unchanged. Measured in qap (h1/h2 over TLS, the security layer armed): the five headers cost +2300 instructions/request on h1 (bytes sealed and copied) and +3900 on h2 (HPACK lookups) -- what an API pays for nothing.

- **2026-10-17** — Browser oracle (`tools/browser_oracle.js`) sees an out-of-process iframe: with the default `Origin-Agent-Cluster: ?1` Chrome isolates the origin and the framed page left the parent's frame tree, so `relaxed` read as not framed; the oracle now asks the iframe target its own location (a refused frame is chrome-error://). Tooling only.

- **2026-10-17** — Example: the `init` error switches name `InvalidHstsPreload` (the example no longer compiled). Example only.

- **2026-10-17** — `csp.renderNonce`/`applyCspNonce`: `error.NonceDirectiveInvalid` for a nonce on a `'none'` source list (it silently turned "nothing" into "this nonce") or on a non-source-list directive; documented that a nonce disables `'unsafe-inline'` in the same directive (CSP semantics).

- **2026-10-17** — Comparative benchmark against unrolled/secure v1.17.0 (`tools/bench.zig`, `tools/go_bench/`, `zig build bench-security-headers`): default set (`apply`, `applyStatic`) and CSP with a per-response nonce (`applyCspNonce`), header work only, no HTTP stack; ours/Go 0.03, 0.01, 0.70 (x86-64). Tooling only, no code change.
- **2026-10-17** — ADDED: `SecurityHeaders.staticHeaders(comptime options)` — the `applyStatic` header set as data, for `http.Server.Options.error_headers`, so the server's own 4xx/5xx answers (which no middleware sees) carry the same headers. `applyStatic` is now built on it (same bytes, same order).

- **2026-10-17** — **helmet 8.3.0 parity (scope core -> parity).** **BEHAVIOUR CHANGE:** `Options{}` now also
  emits `Origin-Agent-Cluster: ?1`, `X-DNS-Prefetch-Control: off`, `X-Download-Options: noopen`,
  `X-Permitted-Cross-Domain-Policies: none`, `X-XSS-Protection: 0` (helmet's defaults, each with a knob:
  `origin_agent_cluster`, `x_dns_prefetch_control`, `x_download_options`, `x_permitted_cross_domain_policies`,
  `x_xss_protection`), after COEP; 5 more header slots and 125 bytes of the `apply` budget. HSTS `preload` is
  validated like helmet (max-age >= 31536000 and includeSubDomains): `InitError.InvalidHstsPreload`,
  `@compileError` in `applyStatic`; `Hsts.preloadValid`, `hsts_preload_min_age_s`. New `csp` namespace
  (`src/csp.zig`): typed `Name`/`Directive`/`Spec`, `build` (comptime) and `render` (runtime) with helmet's
  `useDefaults` merge and validation (unquoted keywords, quotes, `;` `,` whitespace, control, non-ASCII, empty,
  duplicate), `Nonce` (`fromBytes`, `secure(io)`), `renderNonce`; `applyCspNonce` / `applyCspWithNonce` put a
  per-response `'nonce-…'` into named directives. `csp.build(.{})` == `csp_helmet_default`. Docs: stale "helmet
  v7" and `Clear-Site-Data` claims fixed, comparison table gains unrolled/secure (fastest candidate) and
  gin-contrib/secure. Mutation not rerun on the new code.

- **2026-10-05** — **Anchoring: headless Chrome** (`tools/interop.zig`, `tools/browser_oracle.js`,
  `src/browser_oracle_test.zig`): seven configurations, a page with every kind of subresource, framed,
  embedded and opened from another origin; Chrome's behaviour equals each header's specified effect and it
  complains about no real configuration (a malformed control draws three complaints). `csp_helmet_default`
  is now browser-judged. Anchor grade MIXED → EXTERNAL. No defect found; no code change.

- **2026-10-04** — Tests: mutation schemata run (26 mutants, all killed). One new test: the
  `init`-time header-budget sum equals the bytes `apply` serializes, every header enabled.
  No behaviour change.
- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the reproduced
  OWASP example header lines "add no condition beyond MIT's own" and pointed the reader
  at upstream's `LICENSE.txt` — not a file in this tree. Apache-2.0 §4(a) is now
  discharged by reproducing the License in full. §4(b) records that the lines are
  byte-for-byte unmodified (which is the point of the anchor); §4(d) records that
  upstream ships no `NOTICE` (HTTP 404, re-verified 2026-09-09). The file also now says
  explicitly that it does NOT rest on the argument that five one-line header values are
  too short to protect — that argument may be right, but it is not the one this
  repository's own rule makes.
- **2026-08-12** — **BREAKING** `SecurityHeaders.init` now returns `InitError!SecurityHeaders`
  instead of `SecurityHeaders`. Every call site needs a `try` (or equivalent
  error handling) added; there were no in-repo consumers outside this
  module's own tests, so nothing else in the collection is affected. It
  exists because `http`'s response writer now copies header name/value bytes
  into a fixed per-response budget (`f5007ef`, see `http`'s own changelog
  entry for `error.HeaderBytesExhausted`) — a budget that did not exist
  before that fix. `SecurityHeaders.apply`/`.middleware` already propagated
  `error.HeaderBytesExhausted` (part of `http.Server.ResponseWriter
  .SetHeaderError`) uncaught, which is the right instinct (silently dropping
  a security header via `catch {}` would leave a response looking normal
  while unprotected — strictly worse than failing), but it left a real
  footgun: since this middleware is meant to run first in the chain, whether
  it fails depends only on its *own* configured header set (a
  `content_security_policy` large enough, especially paired with a
  comparably large `content_security_policy_report_only` while trialing a
  stricter policy — this module's own documented use case), never on what
  other middleware adds — yet that failure only ever surfaced at request
  time, as `http.Server`'s automatic 500 with *none* of this module's
  headers on it either (its own "Known limitation"). `init` now runs the
  exact same byte-accounting `apply` would and rejects an over-budget
  configuration with `InitError.HeaderBudgetExceeded` up front, in every
  build mode — a misconfiguration is refused once, at startup, not
  discovered by every caller as a mysterious 500 in production. The budget
  itself is read off `http.Server.ResponseWriter`'s actual field via
  `@FieldType`, not duplicated as a literal, so it cannot drift out of sync
  with `http`'s real value.
- **2026-07-19** — Security audit: no findings. Modeled on helmet.js, OWASP Secure
  Headers Project, gin-contrib/secure (design reference, not a test anchor).
