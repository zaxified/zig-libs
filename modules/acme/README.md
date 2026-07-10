# acme

ACME v2 (RFC 8555) client: automated certificate issuance + renewal over
HTTP with the **HTTP-01** challenge (Let's Encrypt et al.) — directory
discovery, nonce management, ES256 account (JWS), order → authorization →
challenge → CSR finalize → PEM chain download, plus the renewal predicate.

- No ACME client exists in Zig std or as a maintained
  pure-Zig library worth adopting.
- **Model after:** `golang.org/x/crypto/acme` (client semantics: nonce
  refill from every response, badNonce retry, POST-as-GET) and certbot's
  flow shape. Wire behavior straight from RFC 8555 (+ RFC 7515 JWS,
  RFC 7638 JWK thumbprint, RFC 2986 PKCS#10, RFC 5915 EC keys).
- **Deps:** `http` (all ACME requests via `http.Client`; the challenge
  server is `http.Server`), `router` (the challenge responder middleware),
  `std.crypto` (ecdsa P-256, sha2, Certificate), `std.json`, `std.base64`.

Provenance: clean-room implementation from RFC 8555 / RFC 7515 / RFC 7638 /
RFC 2986 / RFC 5915. Design references only (no code copied):
`golang.org/x/crypto/acme` (BSD-3-Clause), certbot (Apache-2.0).

## ⚠ Staging by default

`Client.Options.directory_url` defaults to the **Let's Encrypt STAGING**
environment. Staging issues certificates that are **not publicly trusted**
— but it has generous rate limits, so development can never lock your
domain out of production quotas. Going live is a deliberate opt-in:

```zig
.directory_url = acme.letsencrypt_production,
```

## Layout

| File | Role |
|------|------|
| `src/Client.zig` | The RFC 8555 protocol client (`register`, `obtain`) + `Responder`, the HTTP-01 challenge middleware. Robust nonce handling (`Replay-Nonce` harvested from every response, transparent `badNonce` retry), status polling with `Retry-After`, problem-document diagnostics via `lastProblem()`. |
| `src/jws.zig` | JOSE layer: base64url (no pad), canonical P-256 JWK, RFC 7638 thumbprint, RFC 8555 §8.1 key authorization, ES256 flattened-JSON JWS sign **and verify** (the verify half powers the mock CA). |
| `src/x509.zig` | Minimal DER encoder + PKCS#10 CSR (empty subject, SAN dNSNames — the modern Let's Encrypt shape), bounds-checked CSR parse-back, PEM, RFC 5915 `EC PRIVATE KEY` read/write, certificate `notAfter` via `std.crypto.Certificate`. |
| `src/root.zig` | Re-exports + `needsRenewal(cert_pem, now, within_days)`. |

## Usage

```zig
const acme = @import("acme");

var transport = http.Client.init(io, gpa, .{});
defer transport.deinit();

// The account key IS the account identity — generate once, persist:
const account_key = acme.jws.KeyPair.generate(io);
// persist: acme.x509.ecPrivateKeyToPem / load: acme.x509.ecPrivateKeyFromPem

var client = acme.Client.init(io, gpa, &transport, account_key, .{
    .contact = &.{"mailto:ops@example.org"},
    // staging by default; production is explicit (see above)
});
defer client.deinit();

// The CA dials http://<domain>/.well-known/acme-challenge/<token> on port
// 80 — wire the responder into that server's router BEFORE routes:
try app_router.use(client.challengeResponder().middleware());

var cert = try client.obtain(&.{ "example.org", "www.example.org" });
defer cert.deinit(gpa);
// cert.chain_pem (leaf first) + cert.key_pem → feed your TLS server.

// The renewal loop (x/crypto/autocert renews with 30 days left):
if (acme.needsRenewal(cert.chain_pem, now_unix, 30)) {
    // re-run obtain(); on parse failure it errs toward renewal
}
```

Scope notes: HTTP-01 only (dns-01/tls-alpn-01 out of scope), therefore no
wildcard certificates; P-256/ES256 keys only (account and certificate);
key/cert PEM I/O covers RFC 5915 `EC PRIVATE KEY` (no PKCS#8).

## Verification

`zig build test-acme` — all offline + loopback, **no real CA is ever
contacted**:

- **Offline units:** ES256 known-answer vector (RFC 7515 A.3 signature
  verifies; key derivation reproduces the RFC's JWK), JWK thumbprint
  against the RFC 7638 §3.1 example, key-authorization computation,
  base64url vectors, JWS sign→verify round-trips (jwk + kid modes,
  tampering fails), CSR DER build → parse-back (SANs + self-signature;
  also externally spot-checked with `openssl req -verify`), PEM and EC-key
  round-trips (openssl fixtures cross-parsed), `certNotAfter` on an
  openssl-generated fixture, `needsRenewal` boundaries, challenge
  responder over the socket-free server codec.
- **Mock-ACME integration (dogfood):** a fake CA built on `http.Server` +
  `router` serves the full RFC 8555 state machine on loopback while the
  real `Client` drives it through `http.Client`. The mock *verifies* every
  JWS signature server-side, enforces nonce freshness (each nonce valid
  once, issued-by-CA only), injects one `badNonce` rejection to prove the
  retry, fetches the key authorization from the client's responder over
  real HTTP (and probes that unknown tokens 404), and parses + verifies
  the CSR before "issuing" the fixture chain. Skipped only if the
  loopback bind itself fails.

## Manual staging/production recipe (out of CI scope)

A real end-to-end needs a public domain with port 80 reachable:

1. Run an `http.Server` + `router` on `:80` of the target host with
   `client.challengeResponder().middleware()` registered.
2. Point `directory_url` at staging (default), call
   `obtain(&.{"your.domain"})`, and confirm a chain arrives (staging chain
   → "(STAGING) Pretend Pear X1" issuer).
3. Verify the chain: `openssl crl2pkcs7 -nocrl -certfile chain.pem |
   openssl pkcs7 -print_certs -noout`.
4. Only then flip to `letsencrypt_production` (rate limits:
   ~50 certs/domain/week — keep staging for all experiments).
5. Renewal: cron/loop `needsRenewal(chain_pem, now, 30)` → `obtain` again;
   the account key must be the persisted one (re-registering with it is
   idempotent).
