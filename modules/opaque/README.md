# opaque

RFC 9807 OPAQUE — an augmented password-authenticated key exchange
(aPAKE), 3DH key exchange, **ristretto255-SHA-512 configuration** (top
level) and **P256-SHA256** (`opaque.P256Sha256`, same function names). The server never sees the password (not even at
registration) and stores a record that resists precomputation attacks;
each login yields a mutually authenticated `session_key` (both sides)
plus a client-only `export_key`. OPRF layer reused from the sibling
`voprf` module (RFC 9497 modeOPRF) and secret-scalar DH through its group
layer (for ristretto255 the sibling `ct25519`); the rest is pure std
(HKDF, HMAC, SHA-2, Ristretto255). No allocation, no
internal RNG (all nonces/blinds/seeds are caller-supplied CSPRNG
output; blinds via `scalarFromWideBytes`).

KAT-validated byte-exact against RFC 9807 Appendix C.1.1 + C.1.2 + C.2.1
(ristretto255) and C.1.5 + C.1.6 + C.2.3 (P-256): registration record,
KE1/KE2/KE3, session_key, export_key, fake credential response.

```zig
const opaque_pake = @import("opaque");

// Registration (over a confidential, server-authenticated channel).
// Secrets go in by pointer, secret results come back through `out`.
const request = try opaque_pake.createRegistrationRequest(password, &blind_reg);
const response = try opaque_pake.createRegistrationResponse(
    request, server_keys.public_key, credential_identifier, &oprf_seed);
var registered: opaque_pake.FinalizeRegistrationResult = undefined;
try opaque_pake.finalizeRegistrationRequest(
    password, &blind_reg, response, identities, envelope_nonce, ksf, &registered);
// server stores registered.record; client may use registered.export_key

// Login (any channel)
var client: opaque_pake.GenerateKE1Result = undefined;
try opaque_pake.generateKE1(password, &blind_login, client_nonce, &client_keyshare_seed, &client);
var server: opaque_pake.GenerateKE2Result = undefined;
try opaque_pake.generateKE2(
    &server_keys.private_key, server_keys.public_key, record,
    credential_identifier, &oprf_seed, client.ke1, identities, context,
    masking_nonce, server_nonce, &server_keyshare_seed, &server);
var finished: opaque_pake.GenerateKE3Result = undefined;
try opaque_pake.generateKE3(&client.state, identities, context, server.ke2, ksf, &finished);
var session_key: [opaque_pake.Nx]u8 = undefined;
try opaque_pake.serverFinish(&server.state, finished.ke3, &session_key);
// finished.session_key == session_key; finished.export_key == registered.export_key
```

Every secret-handling entry point burns the stack it used before it returns
(`SPEC.md` § Secret residue on the dead stack).

Wrong password ⇒ `error.EnvelopeRecovery` (client side); tampered or
mis-keyed MACs ⇒ `error.ServerAuthentication` / 
`error.ClientAuthentication` — all timing-safe, all fail closed.

See `SPEC.md` for the threat model, the internal-keying envelope, and
the 3DH schedule.

## Not provided

The curve25519 3DH configuration (RFC 9807 C.1.3/C.1.4), a bundled Argon2id/scrypt KSF (the caller supplies the
mandatory `Ksf`), a fake-record helper, HMQV/SIGMA-I and the `randomized_password` backup login: see `SPEC.md`
*What is deliberately not done* and *Backlog / deferred*.

Provenance: clean-room from RFC 9807, a public IRTF specification, with its own
test vectors as the byte-exact anchor. No reference implementation consulted.
Detail in this module's own [`NOTICE`](NOTICE); it carries no condition beyond
zig-libs' MIT license.

Test: `zig build test-opaque`
