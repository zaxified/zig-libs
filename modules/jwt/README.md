# jwt

A JWT/JWS validator for OAuth2/OIDC resource servers: compact-serialization
parsing (RFC 7515 §3.1) into typed models, registered-claims validation
(RFC 7519 §4.1), and JWS signature verification (RFC 7515 §5.2 + RFC 7518)
for **HS256/384/512** (HMAC-SHA-2), **ES256/ES384** (ECDSA P-256/P-384),
**EdDSA** (Ed25519, RFC 8037) and **RS256/384/512** (RSASSA-PKCS1-v1_5,
RFC 8017 — the OIDC default). std-only and dependency-free —
`std.base64.url_safe_no_pad` for the segments, `std.json` for
header/payload, `std.crypto` for the signatures (RSA via
`std.crypto.Certificate.rsa`'s PKCS1-v1_5 verify over `std.crypto.ff`
modexp).

Provenance: clean-room from RFC 7515 (JWS), RFC 7519 (JWT), RFC 7518 (JWA),
RFC 8037 (EdDSA in JOSE), RFC 8017 (PKCS #1 v2.2) and RFC 8725 (JWT Best
Current Practices). No third-party JWT source consulted or copied.

- **Status:** `gap`.
- **Model after:** RFC 7515 (JWS) + RFC 7519 (JWT) + RFC 7518 (JWA) verify
  incl. RS256 (RSASSA-PKCS1-v1_5, RFC 8017), RFC 8725 hardening;
  OAuth2/OIDC resource server.
- **Platform:** any. **Role:** util (Part 6 adds the resource-server
  middleware). **Concurrency:** reentrant — no shared or global state; each
  `ParsedToken` owns its own arena.
- **Deps:** none (std only).

## SECURITY

`parse()` alone does **not** verify signatures — a `ParsedToken` is
**untrusted, attacker-controlled input** until `verify(parsed, key)` (or
the all-in-one `parseAndVerify`) has run; anyone can mint a syntactically
valid token with any claims, and passing `validateClaims` does not change
that. Never authorize from a `ParsedToken` alone.

`verify` implements the RFC 8725 hardening rules:

- **`alg: "none"` is always rejected** (`UnsecuredToken`), key or no key.
- **The token's `alg` must match the provided key's type**
  (`AlgKeyMismatch`) — an HS token offered an EC/Ed public key refuses
  *before any MAC math*, which blocks the classic RS/ES→HS downgrade where
  an attacker HMACs a forged token with the server's *public* key bytes.
  The wrong curve within a family (ES256 vs a P-384 key) also refuses.
- **HMAC comparison is constant-time** (`std.crypto.timing_safe.eql`).
- **JWS ECDSA signatures are the raw fixed-width `R‖S`** (RFC 7518 §3.4;
  32+32 for P-256, 48+48 for P-384) — not DER.
- **RS\* signatures must be exactly the modulus length** (RFC 7518 §3.3);
  the full EMSA-PKCS1-v1_5 encoding (`0x00 01 FF…FF 00 || DigestInfo`) is
  checked, including the SHA-2 OID — wrong length, `s ≥ n`, bad padding or
  a wrong-hash DigestInfo are all `BadSignature`. Keys are validated at
  construction (2048/3072/4096-bit modulus; odd exponent in `[3, 2^32)`).
- Unknown or not-yet-implemented algs (`PS*` — RSA-PSS; ES512 — no P-521
  in std) → `UnsupportedAlg`; wrong-length or garbage signatures →
  `BadSignature`, never a panic.

Delivery plan: P1 parse + claims · P2 signature verify (HS/ES/EdDSA) ·
P3 RSA (RS256/384/512) — **all three done** · P4 JWKS key sets ·
P5 fetch/OIDC discovery · P6 middleware.

## API

| Item | What |
|---|---|
| `parse(gpa, token) ParseError!ParsedToken` | split → base64url-decode → JSON → typed models; owns copies (one arena), input may be freed immediately |
| `ParsedToken` | `header`, `claims`, `signing_input`, `signature` (raw bytes), `alg` (typed enum) + `deinit()` |
| `Header` | `alg` (required), `typ`/`kid`/`cty` (optional) |
| `Claims` | `iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti` + `raw` payload; `claim`/`claimStr`/`claimInt`/`claimBool` getters for custom claims (`scope`, …) |
| `Audience` | `none` \| `single` \| `many` — `aud` as string OR array, with `contains()` |
| `validateClaims(claims, Options) ValidateError!void` | RFC 7519 §4.1 checks; pure, allocation-free |
| `Alg` | RFC 7518 names (`HS256`…`EdDSA`, `none`, `unknown`) — the verify dispatch |
| `Key` | tagged union: `.hmac` (secret bytes) \| `.ecdsa_p256` \| `.ecdsa_p384` \| `.ed25519` (std public keys) \| `.rsa` (`RsaPublicKey`); constructors `ecdsaP256FromCoords(x, y)` / `ecdsaP384FromCoords(x, y)` / `ed25519FromBytes(x)` / `rsaFromModExp(n, e)` take exactly a JWK's decoded parameters (`KeyError.InvalidKey` on bad points/moduli/exponents) |
| `verify(&parsed, key) VerifyError!void` | recompute/check the signature over `signing_input`; RFC 8725 defenses baked in |
| `parseAndVerify(gpa, token, key, Options) !ParsedToken` | the one-call API: parse → verify → validateClaims; frees on any failure |

`Options`: `now_s` (REQUIRED — caller-supplied seconds since epoch, no
hidden clock, same injected-time rule as `resilience`/`probe`), `leeway_s`
(default 60), `issuer`, `audience` (must be contained in `aud`),
`require_exp` (default true), `reject_future_iat` (default false — `iat` is
informational per RFC 7519).

Typed errors, never a panic: `ParseError` = `MalformedToken` ·
`InvalidBase64` · `InvalidJson` · `NotAnObject` · `MissingAlg` ·
`InvalidClaim` · `OutOfMemory`; `ValidateError` = `Expired` · `NotYetValid`
· `IssuedInFuture` · `IssuerMismatch` · `AudienceMismatch` · `MissingExp`;
`VerifyError` = `UnsecuredToken` · `AlgKeyMismatch` · `UnsupportedAlg` ·
`BadSignature` · `InvalidKey`.

## Usage

```zig
const jwt = @import("jwt");

// One call: parse → verify signature → validate claims.
var token = try jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
    .now_s = now_seconds, // caller-supplied clock
    .issuer = "https://issuer.example",
    .audience = "api://my-service",
});
defer token.deinit();
const scope = token.claims.claimStr("scope") orelse "";

// Or step by step — e.g. pick the key from the header's kid first
// (Part 4's JWKS will do exactly this):
var parsed = try jwt.parse(gpa, bearer_token);
defer parsed.deinit();
const key = try jwt.Key.ecdsaP256FromCoords(jwk_x, jwk_y);
try jwt.verify(&parsed, key);
try jwt.validateClaims(parsed.claims, .{ .now_s = now_seconds });
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
  `Alg.none`, empty `signature`) — `verify` then always rejects them
  (`UnsecuredToken`, RFC 8725 §2.1).
- Wrong-typed registered claims (string `exp`, numeric `iss`, non-string
  entry in an `aud` array, …) are rejected at parse time (`InvalidClaim`)
  rather than silently dropped.
- **HMAC keys are borrowed** — `Key.hmac` slices are not copied; they only
  need to outlive the `verify` call itself.

## Verification

`zig build test-jwt` — 37 fully offline tests (19 from P1, 12 from P2,
6 from P3), green under Debug and ReleaseFast.

P1 (parse + claims): the RFC 7519 §3.1 example token end-to-end (header,
claims incl. the `http://example.com/is_root` custom claim, signing input,
32-byte HS256 signature base64url round-trip); `aud` as string and as array
with membership checks; claims-validation KATs (expired /
just-expired-within-leeway / boundary / `nbf` future / opt-in future-`iat` /
issuer+audience match & mismatch / missing `exp` vs `require_exp`);
i64-extreme saturation; malformed-token matrix (1/2/4 segments, empty
segments, bad base64url incl. standard-alphabet chars and padding, non-JSON
and non-object header/payload, missing/non-string `alg`, wrong-typed
claims); and a 512-case deterministic garbage-bytes sweep (never panics,
never leaks).

P2 (signature verify) — RFC known-answer vectors, all transcribed from the
RFCs and cryptographically self-checking:

- **RFC 7515 A.1 (HS256)**: the RFC's exact token + HMAC key verify; a
  flipped signature byte, a truncated signature and a wrong secret each →
  `BadSignature`.
- **RFC 7515 A.3 (ES256)**: the RFC's exact token + public key (from the
  JWK `x`/`y` coordinates) verify; the same signature over a tampered
  payload → `BadSignature`.
- **RFC 8037 A.4 (Ed25519)**: the RFC's exact signing input, public key and
  signature verify (its payload is a plain string, not JSON, so this vector
  exercises `verify` directly); flipped signature byte / signing input →
  `BadSignature`.

Plus generated round-trips for every family (HS384/HS512 computed MACs;
ES256/ES384 and EdDSA with deterministic std keypairs: sign → assemble
token → parse → verify OK; tampered payload, corrupted signature and
wrong-keypair key each → `BadSignature`); the RFC 8725 alg-confusion
matrix (`alg:none` with any key → `UnsecuredToken`; HS token vs EC/Ed keys
and ES/EdDSA tokens vs HMAC keys and cross-curve keys → `AlgKeyMismatch`;
unknown/`PS*`/`ES512` → `UnsupportedAlg`); wrong-length and
garbage-but-right-length signatures → `BadSignature`, never a panic;
invalid key bytes (off-curve points, non-canonical Ed25519) →
`KeyError.InvalidKey`; and `parseAndVerify` end-to-end (good → claims
readable; bad key / wrong key type / expired / malformed → the right typed
error, with `std.testing.allocator` proving nothing leaks on failure).

P3 (RSA, RS256/384/512):

- **RFC 7515 A.2 (RS256)**: the RFC's exact token verifies against the key
  built by `rsaFromModExp` from the RFC JWK's `n`/`e` — exactly the path
  Part 4's JWKS will feed; a flipped signature byte and the RFC signature
  over a tampered payload each → `BadSignature`.
- **RS256/RS384/RS512 round-trips** with a test-local RFC 8017 §8.2.1
  signer (EMSA-PKCS1-v1_5 encode + `em^d mod n` via `std.crypto.ff`, using
  the RFC A.2 private exponent `d`): verify OK; tampered payload /
  corrupted signature / an RS256 signature under an RS512 header (right
  length, wrong DigestInfo) each → `BadSignature`.
- **Alg confusion**: the RS256 token vs HMAC/EC/Ed keys and HS/ES/EdDSA
  tokens vs the RSA key → `AlgKeyMismatch`; `alg:none` with an RSA key →
  `UnsecuredToken`.
- **Robustness**: every wrong signature length (0/1/64/255/257/384/512 vs
  the 256-byte modulus) and right-length garbage (`s ≥ n`, all-zero, …) →
  `BadSignature`; `rsaFromModExp` rejects empty/all-zero, too-small,
  odd-sized and oversized moduli, even moduli, and even/tiny/oversized
  exponents → `InvalidKey` — never a panic.
- **`parseAndVerify` RS256 end-to-end** (good → claims readable; expired /
  wrong key type → typed errors; the RFC KAT through the one-call API).
