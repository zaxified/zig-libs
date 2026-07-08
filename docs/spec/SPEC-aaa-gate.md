# SPEC — `aaa-gate`

**Purpose** — The authentication + audit front for an API: a `router` middleware that gates requests
by **Bearer token** or **API key**, records an audit trail of mutations, and throttles denied
attempts. The minimal "who are you, are you allowed, write it down" layer any exposed API needs
(distinct from `jwt`, which validates OAuth2/OIDC tokens — `aaa-gate` is static-credential AuthN/audit).

**Model after / Seed** — extracted from the authors' axp `axp-central/rest.zig` (token gate +
`auditMutation` + `AuditThrottle`; Apache-2.0, relicensed MIT). Behavior refs: Envoy `ext_authz`,
oauth2-proxy (bearer behavior only), RFC 6750. See NOTICE.

**Design & invariants**
- **Credential check is constant-time** — Bearer tokens and API keys are compared with a
  constant-time equality (`std.crypto.timing_safe`-style), never a short-circuiting `mem.eql`, so a
  network attacker can't recover a valid credential byte-by-byte via timing.
- **Audit hook:** mutations (or all requests, configurable) emit a structured audit entry
  (identity + method + path + resulting status) through a caller sink.
- **Denied-request throttle:** repeated auth failures are rate-limited (per the `AuditThrottle`
  seed) to blunt credential-stuffing / brute force at the gate.
- Threadsafe; identity is attached for downstream handlers. RFC 6750 challenge on failure (401).

**Threat model / out of scope**
- **Defends:** credential brute-force (constant-time compare + denied-throttle), and gives an audit
  trail for post-incident review.
- **Static credentials** — Bearer/API-key are shared secrets the caller provisions; this is not
  token issuance, not OAuth2/OIDC (use `jwt` for signed-token validation), and not per-user session
  management. Credential storage/rotation is the caller's; no zeroization.
- **AuthZ is coarse** — it authenticates and can gate, but fine-grained scopes/RBAC are the
  application's or `jwt`'s (scope enforcement) job.
- **Out of scope:** transport security (TLS via the server/proxy), rate limiting of *successful*
  traffic (`ratelimit`), and DoS/abuse controls (`abuseguard`/`throttle`).

**Verification** — Tests: constant-time compare accept/reject, Bearer + API-key paths, audit-entry
emission on mutations, denied-throttle triggering, and the RFC 6750 challenge on missing/invalid
credentials. 28 tests.

**Status** — `extract · any · server · threadsafe` · deps: `router`, `http`.
