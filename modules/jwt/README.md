# jwt

A JWT/JWS validator for OAuth2/OIDC resource servers: compact-serialization
parsing (RFC 7515 §3.1) into typed models plus registered-claims validation
(RFC 7519 §4.1). std-only and dependency-free — `std.base64.url_safe_no_pad`
for the segments, `std.json` for header/payload.

Provenance: clean-room from RFC 7515 (JWS), RFC 7519 (JWT) and RFC 7518
(algorithm names), with RFC 8725 (JWT Best Current Practices) consulted for
validation semantics. No third-party JWT source consulted or copied.

- **Status:** `gap`.
- **Model after:** RFC 7515 (JWS) + RFC 7519 (JWT); OAuth2/OIDC resource
  server.
- **Platform:** any. **Role:** util (Part 6 adds the resource-server
  middleware). **Concurrency:** reentrant — no shared or global state; each
  `ParsedToken` owns its own arena.
- **Deps:** none (std only).

## SECURITY — Part 1 does NOT verify signatures

This part only *decodes* tokens and checks claim semantics. A `ParsedToken`
is **untrusted, attacker-controlled input** until Part 2's `verify(parsed,
key)` (or the all-in-one `parseAndVerify`) has run — anyone can mint a
syntactically valid token with any claims, and passing `validateClaims` does
not change that. Never authorize from a `ParsedToken` alone. The parsed
`signing_input` (`BASE64URL(header) || '.' || BASE64URL(payload)`),
raw `signature` bytes and typed `alg` are preserved exactly so the verify
step layers on without re-parsing.

Delivery plan: **P1 (this)** parse + claims · P2 signature verify · P3 RSA ·
P4 JWKS key sets · P5 fetch/OIDC discovery · P6 middleware.

## API

| Item | What |
|---|---|
| `parse(gpa, token) ParseError!ParsedToken` | split → base64url-decode → JSON → typed models; owns copies (one arena), input may be freed immediately |
| `ParsedToken` | `header`, `claims`, `signing_input`, `signature` (raw bytes), `alg` (typed enum) + `deinit()` |
| `Header` | `alg` (required), `typ`/`kid`/`cty` (optional) |
| `Claims` | `iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti` + `raw` payload; `claim`/`claimStr`/`claimInt`/`claimBool` getters for custom claims (`scope`, …) |
| `Audience` | `none` \| `single` \| `many` — `aud` as string OR array, with `contains()` |
| `validateClaims(claims, Options) ValidateError!void` | RFC 7519 §4.1 checks; pure, allocation-free |
| `Alg` | RFC 7518 names (`HS256`…`EdDSA`, `none`, `unknown`) for Part 2's dispatch |

`Options`: `now_s` (REQUIRED — caller-supplied seconds since epoch, no
hidden clock, same injected-time rule as `resilience`/`probe`), `leeway_s`
(default 60), `issuer`, `audience` (must be contained in `aud`),
`require_exp` (default true), `reject_future_iat` (default false — `iat` is
informational per RFC 7519).

Typed errors, never a panic: `ParseError` = `MalformedToken` ·
`InvalidBase64` · `InvalidJson` · `NotAnObject` · `MissingAlg` ·
`InvalidClaim` · `OutOfMemory`; `ValidateError` = `Expired` · `NotYetValid`
· `IssuedInFuture` · `IssuerMismatch` · `AudienceMismatch` · `MissingExp`.

## Usage

```zig
const jwt = @import("jwt");

var parsed = try jwt.parse(gpa, bearer_token);
defer parsed.deinit();
// parsed is NOT verified — see the security note above.

try jwt.validateClaims(parsed.claims, .{
    .now_s = now_seconds, // caller-supplied clock
    .issuer = "https://issuer.example",
    .audience = "api://my-service",
});
const scope = parsed.claims.claimStr("scope") orelse "";
```

## Semantics notes

- **base64url, no padding** (RFC 7515 §2): URL alphabet only; `=`, `+`, `/`
  and impossible lengths are rejected as `InvalidBase64`.
- **NumericDate** (RFC 7519 §2): seconds since epoch as `i64`; a fractional
  JSON number is truncated toward zero; NaN/inf/out-of-range → `InvalidClaim`.
- **Leeway** applies to `exp`, `nbf` and `iat` symmetrically; the boundary
  is inclusive (`exp + leeway == now` still passes). Comparisons use
  saturating arithmetic — extreme i64 timestamps cannot overflow the check.
- **Unsecured JWTs** (`alg: "none"`, empty third segment) *parse* (typed as
  `Alg.none`, empty `signature`) — rejecting them is the verify step's job
  (RFC 8725 §2.1), and Part 2 does exactly that.
- Wrong-typed registered claims (string `exp`, numeric `iss`, non-string
  entry in an `aud` array, …) are rejected at parse time (`InvalidClaim`)
  rather than silently dropped.

## Verification

`zig build test-jwt` — 19 fully offline tests: the RFC 7519 §3.1 example
token end-to-end (header, claims incl. the `http://example.com/is_root`
custom claim, signing input, 32-byte HS256 signature base64url round-trip);
`aud` as string and as array with membership checks; claims-validation KATs
(expired / just-expired-within-leeway / boundary / `nbf` future /
opt-in future-`iat` / issuer+audience match & mismatch / missing `exp` vs
`require_exp`); i64-extreme saturation; malformed-token matrix (1/2/4
segments, empty segments, bad base64url incl. standard-alphabet chars and
padding, non-JSON and non-object header/payload, missing/non-string `alg`,
wrong-typed claims); and a 512-case deterministic garbage-bytes sweep
(never panics, never leaks). Green under Debug and ReleaseFast.
