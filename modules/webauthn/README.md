# webauthn

W3C Web Authentication (WebAuthn) Level 3 / FIDO2 **Relying-Party verifier**:
authentication-assertion verification (§7.2) and registration-attestation
verification (§7.1/§8). This is a spec-assembly layer over already-KAT'd
primitives — `p256` (ES256), `p384` (ES384), `p521` (ES512), `std.crypto.sign.Ed25519` (EdDSA), `rsa`
(RS256) for signatures, and the sibling `cbor`/`cbor.cose` codec for
CBOR/COSE — not a new crypto implementation.

**Status: assertion verify complete (ES256/ES384/ES512/EdDSA/RS256). Attestation verify
complete for `none`/`packed`/`fido-u2f`/`apple`/`tpm`; `android-key` is implemented but blocked on `x509.safe`.** See `SPEC.md`
for the full threat model and *Backlog / deferred*.

**Deps:** `cbor` (CBOR/COSE), `rsa`, `p256`, `p384`, `p521`, `x509` (certificate parsing through
`x509.safe`, the AAGUID extension walk).

| File | Contents |
|---|---|
| `root.zig` | `parseClientData`, `parseAuthenticatorData`, `parseCredentialKey` (extends `cbor.cose` with RFC 8230 RSA keys), `verifySignature`, `verifyAssertion`, `verifyRegistration`, `verifyAttestation` |
| `vectors.zig` | W3C WebAuthn Level 3 §16 official test vectors, mechanically extracted from the spec text (not hand-transcribed) |
| `clientdata_test.zig` | `clientDataJSON` parsing — real-vector + adversarial |
| `assertion_test.zig` | `verifyAssertion` — real-vector anchors (ES256/EdDSA/RS256) + reject-teeth |
| `attestation_test.zig` | `verifyAttestation`/`verifyRegistration` — real-vector anchors (`none`/`packed`/`fido-u2f`) + unsupported-format + ceremony-binding and statement reject-teeth |
| `attestation_fixtures.zig` | synthetic attestation certificates and RSA keys (producer `tools/gen_attestation_fixtures.py`) |
| `fuzz_test.zig` | `WEBAUTHN_FUZZ` deterministic fuzz harnesses over the §16 ceremonies |

Provenance: clean-room from the W3C WebAuthn Level 3 recommendation, a public
specification; the §16 test vectors were fetched from w3.org and mechanically
extracted (an early hand-copy introduced a transcription slip, which is why they
are machine-extracted). Every signature check routes through an already-KAT'd
primitive — no new crypto here. No third-party relying-party source consulted,
so no third-party-source `NOTICE` entry is required; the module's own [`NOTICE`](NOTICE)
instead carries the W3C licence condition for the §16 test vectors reproduced in `src/vectors.zig`.

## Import

```zig
const webauthn = @import("webauthn");
```

## API surface

### Assertion (authentication ceremony, §7.2)

```zig
const result = try webauthn.verifyAssertion(
    allocator, // an arena is the natural fit
    authenticator_data, // raw bytes, from the client
    client_data_json,   // raw bytes, from the client
    signature,           // raw bytes, from the client
    stored_credential_public_key, // webauthn.CoseKey, from your credential store
    .{
        .rp_id = "example.org",
        .expected_challenge = issued_challenge_bytes, // raw bytes you generated/stored
        .expected_origin = "https://example.org",
        .require_user_verification = false, // set true to enforce UV
    },
);
// result.sign_count      -> persist + compare against the previously stored
//                            value yourself (clone-detection heuristic,
//                            §6.1.1 -- this module does not own that state)
// result.user_present / result.user_verified
```

### Registration ceremony (§7.1/§8)

```zig
const result = try webauthn.verifyRegistration(
    allocator,           // an arena is the natural fit
    attestation_object,  // raw bytes, from the client
    client_data_json,    // raw bytes, from the client
    .{
        .rp_id = "example.org",
        .expected_challenge = issued_challenge_bytes, // raw bytes you generated/stored
        .expected_origin = "https://example.org",
        .require_user_verification = false, // set true to enforce UV
        .require_attestation = false,       // set true to refuse fmt=="none"
    },
);
// result.attestation_type      -> .none / .basic / .self_attestation
// result.aaguid, result.sign_count, result.rp_id_hash, result.flags -> plain values

// ⚠ result.credential_id / .credential_public_key / .format / .leaf_cert_der
// BORROW from `allocator`. `cbor.decode` dupes every byte string into it, so
// they do not even alias `attestation_object`. To persist them -- and the
// credential id and public key are exactly what an RP must persist -- take an
// owning copy first, or they become pointers into recycled heap and every
// later login verifies against whatever the next request wrote there.
const stored = try result.dupe(gpa);   // gpa, NOT the request arena
defer stored.deinit(gpa);              // when the credential is deleted
// stored.credential_id, stored.credential_public_key -> feed back into
// verifyAssertion for future logins.
```

`type == "webauthn.create"`, the challenge, the origin, `rpIdHash` and the
User Present flag are all checked here — an authentication response, a
response minted for another site, or a replay of an earlier registration is
rejected with a specific typed error. `attestation_type == .none` means the
response carried **no** attestation statement: legitimate (§7.1 step 20, and
what most platform authenticators send), and accepted by default, but nothing
about the authenticator was proven — set `require_attestation` to refuse it.
Even `.basic` only means the statement is internally consistent; no chain is
built (see `SPEC.md` *Backlog / deferred*).

If you are splitting the ceremony and have already done those checks
yourself, `verifyAttestation(allocator, attestation_object, client_data_hash)`
verifies the attestation **statement** alone. It cannot check the ceremony —
it never sees the clientDataJSON.

`tpm` attestation (§8.3: `pubArea` / `certInfo` binding, AIK certificate profile; type `attestation_ca`) is verified; ECDAA is not.

### Signature verification alone

```zig
// If you already have a parsed CoseKey + know the alg, e.g. for a
// non-WebAuthn COSE_Sign1 consumer:
try webauthn.verifySignature(key, alg, msg, sig);
```

## Typed errors

Every public function has a named error set (`ClientDataError`,
`AuthDataError`, `SignatureError`, `AssertionError`, `AttestationError`,
`RegistrationError`, `KeyError`) — no panics, no OOB reads on attacker-controlled bytes; every
rejection is a specific typed error, proven by the adversarial test suite
(see `SPEC.md` "Verification").

## Not provided

Options generation and any credential or session model (verification only), FIDO MDS lookups (the
caller supplies trust anchors to `verifyAttestationChain`), a
signature-counter policy and a `crossOrigin` policy (both returned to the caller). See SPEC *What
is deliberately not done* and *Backlog / deferred*.
