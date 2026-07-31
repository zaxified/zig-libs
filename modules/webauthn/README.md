# webauthn

W3C Web Authentication (WebAuthn) Level 3 / FIDO2 **Relying-Party verifier**:
authentication-assertion verification (§7.2) and registration-attestation
verification (§7.1/§8). This is a spec-assembly layer over already-KAT'd
primitives — `p256` (ES256), `std.crypto.sign.Ed25519` (EdDSA), `rsa`
(RS256) for signatures, and the sibling `cbor`/`cbor.cose` codec for
CBOR/COSE — not a new crypto implementation.

**Status: assertion verify complete (ES256/EdDSA/RS256). Attestation verify
complete for `none`/`packed`/`fido-u2f`; `tpm`/`android-key` structurally
DEFERRED (`error.UnsupportedFormat`, not half-implemented).** See `SPEC.md`
for the full threat model and deferred-work rationale.

| File | Contents |
|---|---|
| `root.zig` | `parseClientData`, `parseAuthenticatorData`, `parseCredentialKey` (extends `cbor.cose` with RFC 8230 RSA keys), `verifySignature`, `verifyAssertion`, `verifyAttestation` |
| `vectors.zig` | W3C WebAuthn Level 3 §16 official test vectors, mechanically extracted from the spec text (not hand-transcribed) |
| `clientdata_test.zig` | `clientDataJSON` parsing — real-vector + adversarial |
| `assertion_test.zig` | `verifyAssertion` — real-vector anchors (ES256/EdDSA/RS256) + reject-teeth |
| `attestation_test.zig` | `verifyAttestation` — real-vector anchors (`none`/`packed`/`fido-u2f`) + deferred-format + reject-teeth |

Provenance: clean-room from the W3C WebAuthn Level 3 recommendation, a public
specification; the §16 test vectors were fetched from w3.org and mechanically
extracted (an early hand-copy introduced a transcription slip, which is why they
are machine-extracted). Every signature check routes through an already-KAT'd
primitive — no new crypto here. No third-party relying-party source consulted,
so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).

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

### Attestation (registration ceremony, §7.1/§8)

```zig
var client_data_hash: [32]u8 = undefined;
std.crypto.hash.sha2.Sha256.hash(client_data_json, &client_data_hash, .{});

// Also run parseClientData + check type=="webauthn.create"/challenge/origin
// yourself (verifyAttestation only covers the attestation STATEMENT --
// "none" has no signature to anchor a clientData check to).
const cd = try webauthn.parseClientData(allocator, client_data_json);
if (!std.mem.eql(u8, cd.type, "webauthn.create")) return error.TypeMismatch;
// ... challenge / origin checks ...

const result = try webauthn.verifyAttestation(allocator, attestation_object, client_data_hash);
// result.attestation_type      -> .none / .basic / .self_attestation
// result.credential_id         -> store this
// result.credential_public_key -> store this (webauthn.CoseKey) -- feed back
//                                  into verifyAssertion for future logins
// result.aaguid, result.sign_count
```

`tpm`/`android-key` attestation objects return `error.UnsupportedFormat` —
see `SPEC.md` "Deferred" for why, and what it would take to add them.

### Signature verification alone

```zig
// If you already have a parsed CoseKey + know the alg, e.g. for a
// non-WebAuthn COSE_Sign1 consumer:
try webauthn.verifySignature(key, alg, msg, sig);
```

## Typed errors

Every public function has a named error set (`ClientDataError`,
`AuthDataError`, `SignatureError`, `AssertionError`, `AttestationError`,
`KeyError`) — no panics, no OOB reads on attacker-controlled bytes; every
rejection is a specific typed error, proven by the adversarial test suite
(see `SPEC.md` "Verification").
