# acme

ACME v2 (RFC 8555) client: automated certificate issuance + renewal with the
**HTTP-01** and **TLS-ALPN-01** (RFC 8737) challenges (Let's Encrypt et al.) —
directory discovery, nonce management, ES256 account (JWS), order →
authorization → challenge → CSR finalize → PEM chain download, plus the
renewal predicate.

- No ACME client exists in Zig std or as a maintained
  pure-Zig library worth adopting.
- **Model after:** `golang.org/x/crypto/acme` (client semantics: nonce
  refill from every response, badNonce retry, POST-as-GET) and certbot's
  flow shape. Wire behavior straight from RFC 8555 (+ RFC 7515 JWS,
  RFC 7638 JWK thumbprint, RFC 2986 PKCS#10, RFC 5915 EC keys).
- **Deps:** `http` (all ACME requests via `http.Client`; the challenge
  server is `http.Server`), `router` (the challenge responder middleware),
  `std.crypto` (ecdsa P-256, sha2, Certificate), `std.json`, `std.base64`.

Provenance: clean-room implementation from RFC 8555 (ACME), RFC 7515 (JWS),
RFC 7638 (JWK thumbprint), RFC 2986 (PKCS#10) and RFC 5915 (EC private keys).
Design references only, behavior only, no code copied:
`golang.org/x/crypto/acme` (BSD-3-Clause, The Go Authors; nonce-refill /
badNonce-retry + POST-as-GET client semantics) and certbot (Apache-2.0; flow
shape only).

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
| `src/Client.zig` | The RFC 8555 protocol client (`register`, `obtain`) + `Responder` (HTTP-01 middleware) + `TlsAlpnResponder` (TLS-ALPN-01 validation-cert store). Robust nonce handling (`Replay-Nonce` harvested from every response, transparent `badNonce` retry), status polling with `Retry-After`, problem-document diagnostics via `lastProblem()`. Challenge type is `Options.challenge_type`. |
| `src/jws.zig` | JOSE layer: base64url (no pad), canonical P-256 JWK, RFC 7638 thumbprint, RFC 8555 §8.1 key authorization, RFC 8737 §3 `acmeIdentifier` (`SHA-256(keyAuthorization)`), ES256 flattened-JSON JWS sign **and verify** (the verify half powers the mock CA). |
| `src/x509.zig` | Minimal DER encoder + PKCS#10 CSR (empty subject, SAN dNSNames — the modern Let's Encrypt shape), bounds-checked CSR parse-back, **RFC 8737 TLS-ALPN-01 self-signed validation cert** (`tlsAlpnCertDer` / `tlsAlpnCert`: dNSName SAN + critical `id-pe-acmeIdentifier` extension), PEM, RFC 5915 `EC PRIVATE KEY` read/write, certificate `notAfter` via `std.crypto.Certificate`. |
| `src/root.zig` | Re-exports + `needsRenewal(cert_pem, now, within_days)`. |

## Usage

```zig
const acme = @import("acme");

var transport = http.Client.init(io, gpa, .{});
defer transport.deinit();

// The account key IS the account identity — generate once, persist:
const account_key = acme.jws.generateKeyPair(io); // fail-closed; NOT std's KeyPair.generate
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

Scope notes: HTTP-01 and TLS-ALPN-01 (dns-01 out of scope), therefore no
wildcard certificates; P-256/ES256 keys only (account and certificate);
key/cert PEM I/O covers RFC 5915 `EC PRIVATE KEY` (no PKCS#8).

## TLS-ALPN-01 (RFC 8737)

When port 80 is unavailable (or you terminate TLS on 443), select the
TLS-ALPN-01 challenge. The library computes
`acmeIdentifier = SHA-256(keyAuthorization)`, builds the self-signed
validation certificate (dNSName SAN + the critical `id-pe-acmeIdentifier`
extension), and stores it in `TlsAlpnResponder` keyed by domain. **Your TLS
listener** must, on a ClientHello that offers ALPN `acme-tls/1`, look the SNI
up and serve that certificate under that ALPN protocol — running that
listener is app-side (out of scope for this module):

```zig
var client = acme.Client.init(io, gpa, &transport, account_key, .{
    .challenge_type = .tls_alpn_01,
});
defer client.deinit();

// Wire the store into your acme-tls/1 TLS listener BEFORE calling obtain:
const store = client.tlsAlpnResponder();
// … in the TLS handshake, when ClientHello ALPN offers acme.TlsAlpnResponder.alpn_protocol:
//   var mat = (try store.getMaterial(gpa, server_name)) orelse fall through;
//   defer mat.deinit(gpa);   // serve mat.cert_der + mat.key_pem, negotiate "acme-tls/1"

var cert = try client.obtain(&.{"example.org"});
defer cert.deinit(gpa);
```

The standalone cert builder is also exposed for out-of-band setups:
`acme.x509.tlsAlpnCert(gpa, domain, acme_identifier, random)` →
`{ cert_der, key_pem }` (keygen takes a `std.Random`, no `std.crypto.random`),
or the deterministic `acme.x509.tlsAlpnCertDer(...)` with an explicit key,
serial and validity.

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
