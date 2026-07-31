# opaque

RFC 9807 OPAQUE — an augmented password-authenticated key exchange
(aPAKE), **ristretto255-SHA-512 configuration, 3DH key exchange,
Identity KSF**. The server never sees the password (not even at
registration) and stores a record that resists precomputation attacks;
each login yields a mutually authenticated `session_key` (both sides)
plus a client-only `export_key`. OPRF layer reused from the sibling
`voprf` module (RFC 9497 modeOPRF); the rest is pure std
(HKDF-SHA-512, HMAC-SHA-512, SHA-512, Ristretto255). No allocation, no
internal RNG (all nonces/blinds/seeds are caller-supplied CSPRNG
output; blinds via `scalarFromWideBytes`).

KAT-validated byte-exact against RFC 9807 Appendix C.1.1 + C.1.2
(registration record, KE1/KE2/KE3, session_key, export_key).

```zig
const opaque_pake = @import("opaque");

// Registration (over a confidential, server-authenticated channel)
const request = try opaque_pake.createRegistrationRequest(password, blind_reg);
const response = try opaque_pake.createRegistrationResponse(
    request, server_keys.public_key, credential_identifier, oprf_seed);
const registered = try opaque_pake.finalizeRegistrationRequest(
    password, blind_reg, response, identities, envelope_nonce);
// server stores registered.record; client may use registered.export_key

// Login (any channel)
const client = try opaque_pake.generateKE1(password, blind_login, client_nonce, client_keyshare_seed);
const server = try opaque_pake.generateKE2(
    server_keys.private_key, server_keys.public_key, record,
    credential_identifier, oprf_seed, client.ke1, identities, context,
    masking_nonce, server_nonce, server_keyshare_seed);
const finished = try opaque_pake.generateKE3(client.state, identities, context, server.ke2);
const session_key = try opaque_pake.serverFinish(server.state, finished.ke3);
// finished.session_key == session_key; finished.export_key == registered.export_key
```

Wrong password ⇒ `error.EnvelopeRecovery` (client side); tampered or
mis-keyed MACs ⇒ `error.ServerAuthentication` / 
`error.ClientAuthentication` — all timing-safe, all fail closed.

See `SPEC.md` for the threat model, the internal-keying envelope, and
the 3DH schedule.

Provenance: clean-room from RFC 9807, a public IRTF specification, with its own
test vectors as the byte-exact anchor. No reference implementation consulted.
Detail in this module's own [`NOTICE`](NOTICE); it carries no condition beyond
zig-libs' MIT license.

Test: `zig build test-opaque`
