# acme

ACME v2 (RFC 8555) client: automated certificate issuance + renewal with the
**HTTP-01**, **TLS-ALPN-01** (RFC 8737) and **DNS-01** challenges, wildcard
certificates included (Let's Encrypt et al.) —
directory discovery, nonce management, ES256 / ES384 account (JWS), order →
authorization → challenge → CSR finalize → PEM chain download, external
account binding, key rollover, revocation, ARI renewal timing, plus the
renewal predicate.

- No ACME client exists in Zig std or as a maintained
  pure-Zig library worth adopting.
- **Model after:** `golang.org/x/crypto/acme` (client semantics: nonce
  refill from every response, badNonce retry, POST-as-GET) and certbot's
  flow shape. Wire behavior straight from RFC 8555 (+ RFC 7515 JWS,
  RFC 7638 JWK thumbprint, RFC 2986 PKCS#10, RFC 5915 EC keys).
- **Deps:** `http` (all ACME requests via `http.Client`; the challenge
  server is `http.Server`), `router` (the challenge responder middleware),
  `p256` / `p384` (the ES256 / ES384 account and certificate key types),
  `entropy` (key generation), `datefmt` (RFC 3339 times in ARI responses),
  `std.crypto` (sha2, hmac, Certificate),
  `std.json`, `std.base64`.

Provenance: clean-room implementation from RFC 8555 (ACME), RFC 7515 (JWS),
RFC 7638 (JWK thumbprint), RFC 2986 (PKCS#10) and RFC 5915 (EC private keys).
Design references only, behavior only, no code copied:
`golang.org/x/crypto/acme` (BSD-3-Clause, The Go Authors; nonce-refill /
badNonce-retry + POST-as-GET client semantics) and certbot (Apache-2.0; flow
shape only). Test data: `src/testdata/pebble_transcript.zig` is a capture
of what Pebble (Let's Encrypt's ACME test CA, MPL-2.0, run as a black-box
oracle binary outside the repository) answered this client, recorded by our own
tooling (`tools/pebble.sh`, `tools/pebble_helper`); no Pebble code is in it.

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
| `src/jws.zig` | JOSE layer: base64url (no pad), canonical P-256 / P-384 JWK, RFC 7638 thumbprint, RFC 8555 §8.1 key authorization, RFC 8737 §3 `acmeIdentifier` (`SHA-256(keyAuthorization)`), ES256 / ES384 flattened-JSON JWS sign **and verify** (the verify half powers the mock CA), the HS256 external-account-binding JWS (`signEab` / `verifyEab`), `Alg` / `AnyKeyPair` / `AnyPublicKey`. |
| `src/x509.zig` | PKCS#10 CSR (DER through `rsa.der_writer`; empty subject, SAN dNSNames — the modern Let's Encrypt shape; ecdsa-with-SHA256/384), bounds-checked CSR parse-back, **RFC 8737 TLS-ALPN-01 self-signed validation cert** (`tlsAlpnCertDer` / `tlsAlpnCert`: dNSName SAN + critical `id-pe-acmeIdentifier` extension), PEM, RFC 5915 `EC PRIVATE KEY` and RFC 5958 PKCS#8 `PRIVATE KEY` read/write (P-256, P-384), the RFC 9773 ARI CertID (`ariCertId`), certificate `notAfter` via `std.crypto.Certificate`. |
| `src/Manager.zig` | Certificates that renew themselves (`autocert` / CertMagic): managed set, ARI/ratio renewal with back-off, issuer fallback (`Issuer`, `AcmeIssuer`), on-demand issuance, fleet locks, HTTP-01 middleware with redirect, TLS-ALPN-01 lookup, `checkPair` (chain, names, key). |
| `src/storage.zig` | `Storage` (load / atomic store / delete / lease locks), `DirStorage` (0700/0600, fsync + rename), `MemStorage`. |
| `src/root.zig` | Re-exports + `needsRenewal(cert_pem, now, within_days)`. |

## Usage

```zig
const acme = @import("acme");

var transport = http.Client.init(io, gpa, .{});
defer transport.deinit();

// The account key IS the account identity — generate once, persist:
var account_key: acme.jws.KeyPair = undefined;
acme.jws.generateKeyPair(&account_key, io); // fail-closed; NOT std's KeyPair.generate
defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
// persist: acme.x509.ecPrivateKeyToPem / load: acme.x509.ecPrivateKeyFromPem

var client = acme.Client.init(io, gpa, &transport, &account_key, .{
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

Scope notes: HTTP-01, TLS-ALPN-01 and DNS-01 (wildcards with DNS-01 only);
ES256 / ES384 / ES512 and RS256 keys, account and certificate; key PEM I/O
covers RFC 5915 `EC PRIVATE KEY`, RFC 5958 PKCS#8 `PRIVATE KEY` and PKCS#1;
external account binding, account update / key rollover / deactivation,
revocation and ARI renewal timing (below). For a server that should simply
*have* current certificates, use the `Manager` (next section) instead of
driving `obtain` yourself.

## Certificates that renew themselves: `Manager`

The `autocert` / CertMagic layer. A `Manager` keeps a set of certificates
current: it loads them from storage, obtains what is missing, renews on the
CA's ARI window (RFC 9773) or two thirds into the lifetime, backs off on
failure (a valid certificate keeps serving), and checks every issued chain
before it stores or serves it.

```zig
var dir = try std.Io.Dir.cwd().openDir(io, "/var/lib/myapp/acme", .{}); // create it 0700
var store = acme.DirStorage.init(io, dir);

var manager = acme.Manager.init(io, gpa, .{
    .storage = store.storage(),
    .on_event = .{ .ctx = &my_tls, .call = installIntoMyTlsStore }, // optional
    .http_redirect = true, // port 80: challenges + redirect to https
});
defer manager.deinit();

// One ACME account per CA, kept in the same storage.
var account_key: acme.jws.AnyKeyPair = undefined;
try acme.Manager.loadOrCreateAccountKey(&account_key, io, gpa, store.storage(), "letsencrypt", .es256);
var client = acme.Client.init(io, gpa, &transport, &account_key, .{
    .directory_url = acme.letsencrypt_production,
    .contact = &.{"mailto:ops@example.org"},
    .solvers = manager.challengeSolvers(), // the manager answers HTTP-01 / TLS-ALPN-01
});
var le: acme.Manager.AcmeIssuer = .{ .client = &client, .name = "letsencrypt" };
try manager.addIssuer(le.issuer()); // add more for fallback (ZeroSSL, GTS, ...)

try manager.manage(&.{ "example.org", "www.example.org" });

try port80_router.use(manager.httpMiddleware());
// In the TLS listener: manager.certificate(gpa, sni) per handshake, or
// manager.tlsAlpnMaterial(gpa, sni) when the ClientHello offers acme-tls/1.

// The upkeep: call maintain() from your own timer (it returns when it next
// has work), or let run() loop on a thread of its own.
const next_due = manager.maintain();
```

- **Your clock or ours.** `maintain` is one step and returns the epoch second
  it next has work; `run` is the loop. A server that already has a timer
  (qap does) calls `maintain` from it.
- **Storage** is an interface: `DirStorage` on disk, `MemStorage` in memory,
  or your own (a database, a key-value service). Layout:
  `certificates/<name>.pem` (key + chain, one atomic write), `accounts/<issuer>/account.key`,
  `locks/<name>.lock`.
- **On-demand** (`Options.on_demand`): the first handshake for a name nobody
  managed obtains its certificate, if `allow(name)` says yes and the rate
  limit permits. `allow` is required — without it anyone could make the
  server order certificates for arbitrary names.
- **A fleet** sharing one storage: issuance runs under a storage lock, and
  `distributed_challenges = true` puts challenge data into storage so the node
  the CA reaches can answer for another node's order.
- **Issued chains are checked**: verified to `trust_anchors` (default: the
  chain's own top certificate — set the CA roots when the storage is shared),
  every name covered, the key matching. A bad chain is a failure, never served.
- DNS-01 stays the client's (`dns_publisher`, or `acmedns.Dns01Solver` in
  `solvers`); a wildcard needs it.

## Account, revocation, renewal timing

```zig
// External account binding (RFC 8555 §7.3.4) — ZeroSSL, Google Trust Services, ...
// hmac_key is the raw MAC key: the CA hands it out base64url-encoded, decode it first.
var client = acme.Client.init(io, gpa, &transport, &account_key, .{
    .directory_url = ca_directory,
    .eab = .{ .kid = "kid-from-the-ca", .hmac_key = mac_key_bytes },
});

// ES384 account key and certificate keys (any of Es256.KeyPair, Es384.KeyPair,
// or the jws.AnyKeyPair union is accepted wherever a key pair is):
var key: acme.jws.AnyKeyPair = undefined;
acme.jws.generateAnyKeyPair(&key, .es384, io);
var client384 = acme.Client.init(io, gpa, &transport, &key, .{ .cert_key_alg = .es384 });

// Account lifecycle (x/crypto/acme UpdateReg, AccountKeyRollover, DeactivateReg):
try client.updateContact(&.{"mailto:new@example.org"});
try client.rolloverKey(&new_key);   // RFC 8555 §7.3.5; persist new_key afterwards
try client.deactivate();            // irreversible

// Revocation (RevokeCert): by the account, or by the certificate's own key.
try client.revoke(cert_der, .key_compromise);
try client.revokeWithCertKey(cert_der, &cert_key, null);

// ARI (RFC 9773): when does the CA want this certificate renewed?
var info = client.renewalInfoPem(cert.chain_pem) catch |err| switch (err) {
    error.NotSupported => null, // CA without ARI: fall back to acme.needsRenewal
    else => return err,
};
// info.window_start / window_end (epoch s), info.pickTime(random), info.retry_after_s
const id = try acme.x509.ariCertIdFromPem(gpa, cert.chain_pem);
var renewed = try client.obtainWith(&.{"example.org"}, .{ .replaces = id });
```

`error.NotSupported` means the CA's directory lacks `keyChange`, `revokeCert` or
`renewalInfo`. `Reason` is the RFC 5280 CRLReason code (non-exhaustive: the CA
refuses an unwanted one with `badRevocationReason`).

## Order options: profiles, chains, CSR, rate limits

```zig
// Directory presets: letsencrypt_staging (default), letsencrypt_production,
// zerossl, google_trust_services, google_trust_services_staging (the last three need EAB).

// Profiles (draft-ietf-acme-profiles): what the CA offers, then order one.
for (try client.profiles()) |p| std.log.info("{s}: {s}", .{ p.name, p.description });
var short = try client.obtainWith(&.{"example.org"}, .{
    .profile = "shortlived",          // .profile_mode = .preferred → order without it if absent
    .preferred_chain = "ISRG Root X2", // issuer CN of the chain's topmost certificate; else the default chain
    .csr_extensions = &.{acme.x509.must_staple}, // or any x509.Extension the CA honours
});

// Issue for your own CSR (HSM key, key reused across renewals, a CSR from openssl):
var chain = try client.obtainWithCsr(csr_der, .{});
defer chain.deinit(gpa); // chain.chain_pem, chain.not_after — no key: it is yours

// Rate limits: error.RateLimited, and how long the CA asked to wait.
_ = client.obtain(&.{"example.org"}) catch |err| switch (err) {
    error.RateLimited => std.log.warn("retry in {?d} s", .{client.retryAfter()}),
    else => return err,
};
```

RSA (RS256) keys are 2048–4096 bits and, being tens of KiB, are held by pointer: the
account pair stays the caller's (it must outlive the `Client`, and the caller wipes it);
certificate keys are minted on the heap by `obtain` with `.cert_key_alg = .rs256` (and
`.cert_rsa_bits`, default 2048), and come back as an `RSA PRIVATE KEY` PEM.

```zig
const account = try gpa.create(acme.jws.rsa.KeyPair); // or x509.rsaPrivateKeyFromPem
try acme.jws.generateRsaKeyPair(account, 3072, io);
var client = acme.Client.init(io, gpa, &transport, account, .{ .cert_key_alg = .rs256 });
```

IP certificates (RFC 8738): pass the address in RFC 5952 form (`"192.0.2.1"`, `"2001:db8::1"`)
among the names. It is validated over HTTP-01 or TLS-ALPN-01 (the TLS listener is asked for the
reverse name, `1.2.0.192.in-addr.arpa`, which `tlsAlpnResponder().getMaterial` answers), never
DNS-01. Let's Encrypt issues IP certificates only on the `shortlived` profile.

`ES512` (P-521, via `p521`) is the third key type next to ES256 and ES384:
`jws.generateAnyKeyPair(&key, .es512, io)`, `Options.cert_key_alg = .es512`.
A `503` is resent up to `Options.max_unavailable_retries` times (default 2) when the CA's
`Retry-After` is at most 30 s; a longer one comes back as the problem, with `retryAfter()` set.
`notBefore`/`notAfter` (`ObtainOptions.not_before`/`not_after`, epoch seconds) go on the order
only when set — Let's Encrypt refuses orders that carry them.

## The order flow step by step, and your own challenge solver

`obtain` is these calls in a row; use them directly to resume an order after a
restart (persist `order.url`), to solve an authorization by hand, or to give up
one (`deactivateAuthorization`):

```zig
var order = try client.newOrder(&.{"example.org"}, .{}); // .replaces, .profile, .not_before, …
defer order.deinit();                                     // persist order.url; later: client.fetchOrder(url)
for (order.authorizations) |url| {
    var authz = try client.fetchAuthorization(url);       // .identifier, .wildcard, .challenges
    defer authz.deinit();
    const ch = authz.challenge(.dns_01) orelse return error.NoDns01;
    var buf: [acme.jws.max_key_authorization_len]u8 = undefined;
    const key_auth = try client.keyAuthorization(&buf, ch.token);
    // … publish the proof for key_auth yourself …
    try client.acceptChallenge(ch.url);
    try client.waitAuthorization(url);                    // or: client.solveAuthorization(url)
}
try client.waitOrder(&order, .ready);
try client.finalize(&order, csr_der);
try client.waitOrder(&order, .valid);
var chain = try client.downloadChain(&order, null);       // or a preferred issuer CN
defer chain.deinit(gpa);
```

A `Solver` (lego's provider, certmagic's solver) puts one challenge's proof in
place and takes it away; one in `Options.solvers` replaces the built-in of its
type (`challengeResponder`, `tlsAlpnResponder`, `dns_publisher`), for
`obtain` and `solveAuthorization` alike. The `ChallengeRequest` it gets
carries the identifier, the token and the key authorization, and derives the
rest: `dnsRecordName`, `dnsTxtValue`, `tlsAlpnIdentifier`, `tlsAlpnSni`.

```zig
const MySolver = struct {
    fn present(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) acme.Client.SolverError!void {
        var name_buf: [acme.Client.dns01_max_name_len]u8 = undefined;
        const value = req.dnsTxtValue();
        // add TXT `value` at `req.dnsRecordName(&name_buf)`, wait for propagation;
        // return error.SolverFailed to abort the authorization
        _ = .{ ctx, &value };
    }
    fn cleanup(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) void {
        _ = .{ ctx, req };
    }
};
const solvers = [_]acme.Client.Solver{.{ .type = .dns_01, .present = MySolver.present, .cleanup = MySolver.cleanup }};
var client = acme.Client.init(io, gpa, &http_client, &account_key, .{ .challenge_type = .dns_01, .solvers = &solvers });
```

A failing solver is `error.SolverFailed` (`error.DnsPublishFailed` for DNS-01);
`cleanup` runs once for every `present` that succeeded.

## DNS-01 (RFC 8555 §8.4) and wildcard certificates

For a host with no port the CA can reach, or for a wildcard, select
`.challenge_type = .dns_01` and hand the client a publisher for your DNS
provider. The library computes the record and drives the order; publishing is
yours, because it is the provider-specific part.

**Most setups want the sibling module [`acmedns`](../acmedns) instead of the
raw publisher below:** its `Dns01Solver` (into `Options.solvers`) follows the
`_acme-challenge` CNAME delegation, finds the zone, waits until every
authoritative server answers, and comes with RFC 2136 + TSIG, acme-dns,
httpreq and exec publishers. It is a separate module so that a consumer of
`acme` that never solves DNS-01 does not carry a resolver. The raw seam:

```zig
const Zone = struct {
    // your provider's API client, an RFC 2136 updater, a zone file, ...
    fn present(ctx: ?*anyopaque, name: []const u8, value: []const u8) bool {
        // add TXT `value` at `name` ("_acme-challenge.example.org"), then
        // wait until the CA's resolvers can see it; false aborts
        _ = .{ ctx, name, value };
        return true;
    }
    fn cleanup(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        _ = .{ ctx, name, value }; // remove exactly that value
    }
};
var client = acme.Client.init(io, gpa, &http_client, &account_key, .{
    .challenge_type = .dns_01,
    .dns_publisher = .{ .present = Zone.present, .cleanup = Zone.cleanup },
});
var cert = try client.obtain(&.{ "*.example.org", "example.org" });
```

- The value is `base64url(SHA-256(keyAuthorization))`
  (`acme.jws.dns01TxtValue`), the name `_acme-challenge.<domain>`
  (`acme.Client.dns01RecordName`). A wildcard's authorization names the base
  domain, so `*.example.org` and `example.org` validate at the **same name**:
  `present` must add a value, not replace the record set.
- `present` returns only once the record is visible — the CA is told to
  validate the moment it returns. Waiting out propagation is the publisher's.
- `cleanup` runs once for every successful `present`, whatever the outcome.
- A wildcard with any other challenge type is `error.InvalidDomain` (only
  DNS-01 can validate one); `.dns_01` without a publisher is
  `error.DnsPublisherMissing`; `present` returning false is
  `error.DnsPublishFailed`.

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
var client = acme.Client.init(io, gpa, &transport, &account_key, .{
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
- **Lifecycle (same mock CA):** the external-account-binding JWS (checked
  against std's HMAC-SHA256 and verified by the CA), a rollover ES256 → ES384
  with both JWS layers checked and the old key refused afterwards,
  contact update and deactivation, revocation by account and by certificate
  key, ARI against the RFC 9773 §4.1 CertID example, an ES384 account +
  certificate key through the whole flow. ES384 JWK / thumbprint / PKCS#8 /
  CSR cases are checked against openssl and python.

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
