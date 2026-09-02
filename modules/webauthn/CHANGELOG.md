# webauthn — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — Drift re-audit (window `d163578..HEAD`, +1376/-57). **No authentication bypass
  found**: every §7.1/§7.2 binding check is present and, after this pass, every one of them has a
  test with teeth. What the drift had introduced was a documented storage instruction that produces
  dangling keys, a key-parse arm that walks around the hardening `cbor` added for this caller, and
  three normative steps that were never implemented. **BREAKING (minor):** `AuthDataError` gains
  `CredentialIdTooLong`/`BackupStateInconsistent`, `RegistrationError` gains `AlgorithmNotAllowed`,
  and `require_attestation` is now satisfied by `.basic` only.

  - **HIGH, the README told an RP to persist dangling pointers.** `cbor.decode` dupes every byte
    string into the allocator, so `credential_id`, `credential_public_key`, `format` and
    `leaf_cert_der` are arena-owned and do not even alias the caller's `attestation_object_raw` —
    while `credential_id` and `credential_public_key` are exactly the two fields an RP must keep.
    With the per-request arena the README itself showed, a stored key became pointers into
    recycled heap and every later login verified against whatever the next request wrote there,
    silently in ReleaseFast. `leaf_cert_der` carried a full lifetime paragraph; the fields you are
    told to store carried none. Added: a lifetime paragraph on the struct, `AttestationResult.dupe`
    /`deinit` and `CoseKey.dupe`/`freeOwned` so the correct thing is one call, and a README that
    shows it.

  - **MEDIUM, the RSA arm dropped RFC 9052 §3.** `parseCredentialKey` returns before
    `cbor.cose.parseKey` for `kty == 3`, so label uniqueness and `max_map_entries` — the cap `cbor`
    added *because* `webauthn` hands this function the unbounded tail of client-supplied
    `authData` — silently did not apply to it. A modulus read first-wins here and last-wins by a
    `python-fido2` peer is a credential-identity split. Fixed for both arms, above the `kty` read,
    and the same rule now applies to the attestation object's top-level map.

  - **MEDIUM, `require_attestation` accepted self attestation.** Signed by the credential's own
    key, so anything an attacker generates in a browser satisfies it — and it carries no
    certificate, so the follow-up the option's own doc recommends is not available. A caller who
    only checked that the flag passed had gained nothing over `none`.

  - **MEDIUM, §7.1 step 11 / §7.2 step 17 (BE=0 ⇒ BS=0) was not implemented** and was framed in
    the docs as a policy choice rather than a skipped step.

  - **MEDIUM, three checks had no teeth.** `verifyRegistration`'s User-Present check, both arms of
    the extension-data rejection, and the `alg` half of the algorithm binding could each be deleted
    with 55/55 green — SPEC claimed every check was "proven load-bearing by a dedicated adversarial
    test". The §16 corpus is structurally blind here: every registration vector has UP set and ED
    clear, and `fuzzRegistrationBinding` only ever feeds real vectors.

  - **LOW/MEDIUM, §7.1 step 14 was unenforceable.** No API expressed `pubKeyCredParams`, so an
    authenticator could register under any algorithm this module supports regardless of what the RP
    offered. Added `RegistrationOptions.allowed_algorithms` (`null` keeps the old behaviour).

  - **LOW:** `fido-u2f` accepted an `x5c` with more than one element (§8.6 step 2 says exactly one;
    `packed` legitimately carries a chain, and still may); `credentialIdLength` had no §6.5.2 1023
    cap; the attestation certificate's RSA key had no modulus floor while the credential key has
    had one since the last audit; and `firstX5cDer`'s empty-array guard — a memory-safety guard —
    had no test.

  Disclosure: SPEC listed the certificate gaps as "no chain / no `basicConstraints` / no dates" and
  omitted **§8.2.1's `id-fido-gen-ce-aaguid` binding**, which is the one that ties the certificate
  to the AAGUID an RP reads to decide *which authenticator model* this is. Still not implemented —
  no §16 vector carries the extension — but now stated.


- **2026-08-22** — `parseCredentialKey` explicitly refuses the AKP key type
  (RFC 9964 `kty` 7, which carries ML-DSA) with `error.UnsupportedKty`.
  WebAuthn has not registered ML-DSA — draft-vitap-ml-dsa-webauthn is still a
  draft with no COSE algorithm assigned for WebAuthn use — so accepting one
  would claim a verification path that does not exist. Prompted by `cbor`
  gaining AKP support; caught by `check-pubfn-reach`, not by this module's own
  tests, because nothing in them reaches that switch.
- **2026-08-06** — Security audit: `verifyAttestation` passed an attacker-supplied
  certificate straight to std's DER parser, which aborts the process on malformed input;
  fixed by routing through this collection's own defensive x509 parser, along with 6
  further findings.
- **2026-07-21** — New module: WebAuthn / FIDO2 Relying-Party VERIFIER (W3C WebAuthn
  Level 3).
