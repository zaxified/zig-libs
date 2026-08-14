# webauthn — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance:
see this module's README "Provenance" note — clean-room from the W3C spec, so
there is deliberately no root `/NOTICE` entry to point at.

## Design & invariants

- **Spec-assembly, not new crypto.** Every signature check routes through an existing,
  independently-KAT'd primitive: `p256`'s `EcdsaP256Sha256`/`ecdsaVerify` for ES256,
  `std.crypto.sign.Ed25519` for EdDSA, `rsa.verifyPkcs1v15` for RS256. Every CBOR/COSE parse
  routes through the sibling `cbor`/`cbor.cose` codec. This module contributes only the WebAuthn
  verification *procedure* (W3C WebAuthn Level 3 §7.1/§7.2/§8) — clientData/authData layout,
  which bytes get hashed/signed, which flags gate what, and dispatch across the three mandated
  algorithms and three implemented attestation formats.
- **RFC 8230 RSA COSE keys, added on top of `cbor.cose`.** The sibling `cbor.cose` module
  deliberately does not model RSA (`kty=3`) or symmetric COSE key types — see its own doc
  comment. `webauthn` is the first consumer that needs RS256, so `parseCredentialKey` extends
  `cbor.cose.parseKey`: EC2/OKP still go through `cbor.cose.parseKey` unchanged; `kty==3` is
  parsed locally (`n`=label -1, `e`=label -2, same label *numbers* RFC 9053 reuses for EC2's
  `crv`/`x` — not a collision, RFC 8152's own design).
- **Algorithm binding, not algorithm negotiation.** `verifySignature` ties `alg` tightly to the
  key's own `crv`/`kty`: an ES256 `alg` against anything but a P-256 EC2 key, or an RS256 `alg`
  against anything but an RSA key, is `error.UnsupportedAlgorithm` — never coerced, never
  "closest match". This is the algorithm-confusion defense (the same class of bug JWT's `alg:
  none`/HS-vs-RS confusion made infamous); see `assertion_test.zig`'s
  "wrong key algorithm family" reject-tooth.
- **Certificate PARSING, not chain validation, for `packed`/`fido-u2f` x5c.** `verifyLeafCertSignature`
  uses `std.crypto.Certificate.parse` (the same primitive the sibling `x509` module's chain
  validator builds on) to pull the leaf certificate's own public key and verify `attStmt.sig`
  against it — but **only through `x509.safe.safeCertificate`**, never on the raw `x5c[0]` bytes.
  std's DER reader is not total on attacker-controlled input (a 4-byte `30 02 30 00` walks it off
  the end of the buffer: a Debug panic that aborts the relying-party server, a silent
  out-of-bounds read under ReleaseFast), and `x509/src/safe.zig` is this collection's single
  reconciled guard for exactly that hazard. It does
  **not** build or validate a trust chain to a root, check `basicConstraints`/
  `keyUsage`, or check certificate validity dates — WebAuthn attestation trust decisions (is this
  authenticator model acceptable?) are a metadata-service (FIDO MDS) / RP-policy concern layered
  above signature verification, and are explicitly out of scope here (see "Threat model" below).
- **`authenticatorData`'s CBOR credential public key has no length prefix (WebAuthn §6.5.2) —
  handled via full-buffer CBOR decode, extensions therefore DEFERRED.** The wire format is
  `aaguid(16) ‖ credentialIdLength(2) ‖ credentialId(L) ‖ credentialPublicKey(CBOR, variable)
  ‖ [extensions(CBOR, variable)]`. There is no byte count for the CBOR credential public key
  item — a correct parser needs either a byte-accounting CBOR decoder (decode one item, report
  how many bytes it consumed) or the guarantee that nothing follows it. `cbor.decode` requires
  exactly one item consuming the *entire* input (`error.TrailingGarbage` otherwise) — by design,
  see that module's doc comment. `parseAuthenticatorData` therefore only supports the (extremely
  common, and the *only* shape in the W3C §16 vectors) case where the ED (extension data) flag is
  clear: the credential public key is provably the last thing in the buffer, so `cbor.decode` on
  the remainder is correct. When ED is set, `parseAuthenticatorData` returns
  `error.ExtensionsNotSupported` rather than guessing a boundary — a structural, typed rejection,
  not a silent misparse. See "Deferred" below for what it would take to lift this.

## Threat model / out of scope

This is a security-critical verifier of fully attacker-controlled wire bytes (an assertion or
attestation response is produced by whatever ran in the browser/authenticator, which an attacker
fully controls up to the cryptographic binding). Every check below is proven load-bearing by a
dedicated adversarial test (`assertion_test.zig` / `attestation_test.zig` "reject:" tests) that
tampers exactly one input and asserts the *specific* typed error, not merely "some error":

- **Both ceremonies are bound, and the binding lives in one place each.** `verifyAssertion` (§7.2)
  and `verifyRegistration` (§7.1) each run the full clientData + `rpIdHash` + User-Present check
  set described below. `verifyAttestation` is the **statement-only** entry point underneath
  `verifyRegistration`: it takes an opaque `client_data_hash`, so it structurally cannot check
  `type`, `challenge` or `origin`, and its doc comment says so. An RP that calls it directly owns
  those checks itself — the returned `rp_id_hash`/`flags` are there for exactly that.
- **Origin/RP binding (confused-deputy defense):** `clientDataJSON.origin` must equal the RP's
  configured origin, and `authenticatorData`'s `rpIdHash` must equal `SHA-256(rpId)` — an
  assertion or a registration minted for a different site cannot be replayed against this RP.
- **Challenge binding (replay defense):** `clientDataJSON.challenge` (base64url-decoded to raw
  bytes, never compared as encoded text) must equal the exact challenge the RP issued for this
  ceremony — the RP is responsible for challenge freshness/single-use bookkeeping; this module
  only proves the *presented* challenge matches the *expected* one byte-for-byte. This is the
  **only** thing tying a registration to a ceremony: an attestation statement signs
  `authData ‖ clientDataHash`, which binds the authenticator to some clientData but never binds
  that clientData to a challenge this RP issued — and with `fmt == "none"` there is no statement
  signature at all.
- **Type confusion defense:** an assertion (`webauthn.get`) response cannot be replayed as a
  registration (`webauthn.create`) response or vice versa — `type` is checked exactly, in both
  directions (`verifyAssertion` and `verifyRegistration` respectively).
- **`fmt == "none"` is accepted, and says so.** A registration with no attestation statement is a
  conforming §7.1 outcome and is what most platform authenticators send, so refusing it by default
  would be wrong. It is accepted **only** through the ceremony checks above — with no statement
  signature they are the whole of the verification — and the caller is told: `attestation_type ==
  .none`. `RegistrationOptions.require_attestation` refuses it outright for an RP whose policy
  depends on the authenticator's identity; such an RP must also chain the leaf certificate,
  because `.basic` here means "the statement is internally consistent", not "vouched for" (see
  "Deferred").
- **Algorithm confusion defense:** see "Design & invariants" above — `verifySignature` refuses to
  verify under a mismatched key/alg pairing.
- **User Present / User Verified:** `verifyAssertion` always requires the UP flag; UV is required
  only when the caller sets `require_user_verification = true` (a caller enforcing step-up auth
  or a UV-required credential policy opts in explicitly — there is no silent default that skips
  UV, but there is also no default that *demands* it, since not every RP requires it).
- **Signature-count monotonicity (WebAuthn §6.1.1, clone-detection heuristic): NOT enforced by
  this module.** `signCount` is returned in `AssertionResult`/`AttestationResult` for the caller
  to persist and compare against the previous stored value (a non-increasing counter across two
  uses of the same credential is *suspicious*, not necessarily an attack — many platform
  authenticators always report `0`) — that stateful comparison is a caller/storage-layer concern,
  not something a stateless verifier function can own.
- **Out of scope, by design (not silently skipped):**
  - **`tpm`/`android-key` attestation formats** — see "Deferred" below.
  - **Attestation trust-chain validation / FIDO Metadata Service (MDS) lookups** — this module
    proves the attestation statement's signature is internally consistent (the leaf cert really
    signed this blob with its own key), not that the leaf cert chains to a trusted root or that
    the authenticator model is one the RP is willing to accept. A caller that cares wires the
    returned leaf-cert-adjacent data (todo: not currently exposed — see "Deferred") into the
    sibling `x509` module's `verifyChain` against its own trust store / MDS-derived roots.
  - **CBOR extension data in `authenticatorData`** — see "Design & invariants" above.
  - **Account-recovery / backup codes** — a product-level fallback authentication mechanism
    layered *above* WebAuthn (e.g. "lost your passkey? use a recovery code"), not part of the W3C
    verification procedure this module implements. There is nothing WebAuthn-specific to verify
    here; a recovery-code scheme is an ordinary shared-secret/OTP check (see the sibling `otp`
    module for HOTP/TOTP) with its own storage and rate-limiting concerns.
  - **`crossOrigin`/`topOrigin` clientData fields** — the W3C §16 vectors include cases for both
    (§16.4/§16.5); this module parses `crossOrigin` into `ClientData.cross_origin` but does not
    enforce a policy on it (a caller wanting to reject cross-origin iframes checks the returned
    field itself). Not a security regression: `origin` is still checked exactly, so a genuinely
    different top-level site cannot pass.

## Deferred

- **`tpm` attestation (WebAuthn §8.3):** requires parsing TCG's `TPMS_ATTEST`/`TPMT_SIGNATURE`/
  `TPMT_PUBLIC` wire structs (TPM 2.0 structures, not CBOR/ASN.1 — a third wire format this
  module would otherwise need to introduce) and validating the `certInfo`/`pubArea` binding back
  to the credential public key, plus (for full trust) an EK/AIK certificate chain. This is a
  project of its own, orthogonal to the WebAuthn verification procedure itself — `verifyAttestation`
  structurally recognizes `fmt == "tpm"` and returns `error.UnsupportedFormat` rather than
  half-parsing the TPM structures (which would be worse than rejecting: a partially-checked
  attestation is a false sense of security).
- **`android-key` attestation (WebAuthn §8.4):** requires parsing the Android Keystore attestation
  X.509 extension (OID `1.3.6.1.4.1.11129.2.1.17`, itself a nested ASN.1 `KeyDescription`
  structure with its own `AuthorizationList` semantics — Android-specific, not a general X.509
  extension `x509`'s `extensions.zig` models) and validating the credential public key /
  challenge binding inside it. Same call as `tpm`: structurally rejected, not half-verified.
- **Byte-accounting CBOR decode for `authenticatorData` extensions** — would need a `cbor` API
  addition (decode-one-item-and-report-bytes-consumed, distinct from today's
  decode-exactly-one-item-consuming-everything contract) to correctly split
  `credentialPublicKey ‖ extensions` when both are present. Tracked as a `cbor` follow-up, not a
  `webauthn`-local one.
- **Attestation trust-chain validation / MDS integration** — see "Threat model" above; would
  layer the sibling `x509`/`rsa` (already a dep) `verifyChain` on top of the leaf cert this module
  already parses, plus a metadata-lookup seam. Not built because it needs a trust-store/MDS
  design decision this module shouldn't make unilaterally for every caller.
- **Backup/recovery codes** — see "Threat model" above; not a WebAuthn concern.

## Verification

External, byte-exact anchor: the **W3C WebAuthn Level 3 specification's own §16 "Test Vectors"**
(https://www.w3.org/TR/webauthn-3/#sctn-test-vectors — non-normative but the spec authors' own
reproducible-by-construction conformance vectors, generated deterministically via
HKDF-SHA-256/RFC 6979 per the section's preamble). Fetched directly from w3.org and mechanically
extracted (not hand-transcribed, after an early hand-copy attempt introduced a transcription slip
that mechanical extraction makes structurally impossible) into `src/vectors.zig`; independently
cross-checked byte-for-byte against a second, independent re-hosting of the same vectors
(go-webauthn/webauthn's `specification_vectors_e2e_test.go`, which cites the identical W3C
section numbers). Covers:

- **Assertion, all three mandated algorithms:** §16.2 (ES256, `none`), §16.3 (ES256, `packed`
  self-attested), §16.10 (RS256, `packed` x5c), §16.11 (EdDSA, `packed` x5c) — plus §16.16
  (`fido-u2f`-registered credential, ES256 assertion).
- **Attestation, all three implemented formats:** §16.2 (`none`), §16.3 (`packed` self), §16.7/
  §16.10/§16.11 (`packed` x5c/basic — ES256/RS256/EdDSA credentials, all signed by the shared
  spec-CA's EC P-256 attestation key), §16.16 (`fido-u2f`).
- **Deferred-format structural rejection:** §16.13 (`tpm`) and §16.14 (`android-key`) real spec
  vectors fed to `verifyAttestation`, proving `error.UnsupportedFormat` fires on real (not
  synthetic) inputs.

The registration ceremony is anchored on the same corpus: all six implemented §16 registration
vectors verify through `verifyRegistration` against their own separately-stated
`registration_challenge`, `rp_id` and `origin`.

Adversarial reject-teeth (`assertion_test.zig`/`attestation_test.zig`, each tampering exactly one
input off a real-vector baseline — or, for the ceremony-binding tests, tampering *nothing* and
supplying a genuine §16 artefact from the wrong ceremony): tampered `authenticatorData` byte,
tampered signature byte, tampered `clientDataHash`, wrong `rpId`, User Present flag cleared, User
Verified required-but-clear, wrong challenge, wrong origin, wrong `type` (registration clientData
replayed as an assertion, and §16.2's real assertion clientData replayed as a registration),
a valid §16.2/§16.7 registration response replayed into a ceremony whose issued challenge was a
different vector's, `require_attestation` against `fmt == "none"`,
cross-algorithm key swap (EdDSA key against an ES256 assertion), cross-credential key swap (right
algorithm, wrong actual key), non-empty `attStmt` on `fmt=="none"`, and an unrecognized `fmt`
string. Run: `zig build test-webauthn`.

## Status

`extract · any · util · reentrant` + deps `cbor`, `rsa`, `p256`, `x509` — canonical source is
`pub const meta` in `src/root.zig`. Assertion verify: ES256/EdDSA/RS256, complete. Attestation
verify: `none`/`packed`/`fido-u2f`, complete; `tpm`/`android-key` deferred (see above).

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** W3C sec.16 vectors, cross-checked vs go-webauthn's re-hosting of same vectors
