# webauthn — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **A1 F4 closed: §8.2.1's `id-fido-gen-ce-aaguid` certificate binding was
  never checked.** `verifyLeafCertSignature` (the `packed`/x5c path) now calls
  `checkAaguidExtension`, an independent DER walk over the leaf certificate via
  `x509.extensions` (std's own `Certificate.parse` never surfaces an OID it does not
  recognize, and this one — 1.3.6.1.4.1.45724.1.1.4 — is not in its table). When the
  extension is present its value must equal `authData.aaguid`; absence is not an error
  (§8.2.1 does not require it). Without this, a certificate that chains to a trusted
  attestation root but was never issued for the claimed authenticator model could still
  make `result.aaguid` say otherwise, spoofing which MODEL an RP's metadata-service
  policy is trusting. `fido-u2f` is unaffected — §8.6 does not name this extension.
  Measured: a hand-built DER fixture in `root.zig`'s own test (no real §16 vector carries
  the extension) — disabling the equality check turns 1 of 74 `test-webauthn` tests red
  (`error.AaguidExtensionMismatch` expected, `void` returned); restoring it is 74/74 green.
  Still open, unchanged: no trust-chain validation, `basicConstraints`/`keyUsage`/validity
  dates (see SPEC.md).

- **2026-09-09** — The module has a `NOTICE` for the first time, and it carries a condition.
  `src/vectors.zig` reproduces W3C WebAuthn Level 3 §16's test vectors verbatim — the same
  rights holder `modules/tracecontext` already carries a full attribution for, while this
  module had nothing. ⚠ It is a DIFFERENT W3C licence: tracecontext's vectors come from the
  `w3c/trace-context` test suite, whose own LICENSE.md puts tests under the W3C 3-clause BSD
  and Reports under the W3C Software and Document License. These vectors are read out of the
  specification document, which is a Report — so the Software and Document License is what
  applies, and its notice is retained here.

- **2026-09-07** — **All four fuzz harnesses ran one fixed input for their whole
  lives, and one of them never reached its own oracle.**

  `fuzzParseClientData` and `fuzzParseAuthenticatorData` opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes`
  consumes `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as
  a little-endian u64, returning the range minimum when fewer remain, so the drawn
  length was 0 for every input a seed can carry. `fuzzVerifyAttestation` and
  `fuzzRegistrationBinding` took *every* choice from a ranged draw and opened with
  one, so each collapsed to its minimum and the harness built the same object every
  iteration. All four now take their bytes in one `smith.slice(&buf)` draw — the two
  shape-drawing harnesses read their whole script off it through
  `testkit.fuzz.Cursor` — and all four have a corpus with a guard test in the ordinary
  lane.

  ⛔ **`fuzzRegistrationBinding` had never executed a single one of its assertions.**
  Its options came out `rp_id = "example.com"` (against vectors signed for
  example.org) and `expected_challenge` a zero-length slice, because
  `smith.value(bool)` reads eight octets and returns false on a short read and both
  booleans take the *else* arm. `verifyRegistration` refused, the `catch return`
  fired, and the §7.1 binding checks after it — that the accepted registration is
  bound to the challenge, origin and RP id it was verified against — never ran. An
  oracle-on-success harness that never succeeds is green for ever. The neighbouring
  reachability test did not catch it: it counts accepted registrations in a loop of
  its own, calling `verifyRegistration` directly, and only asks of the harness that
  its body runs to completion. Both facts are now pinned by
  *"the collapsed registration harness never reached its own oracle"*. After: 18
  scripts, **all 6 vectors, all 4 clientData modes, 2 origins, 7 accepted and 11
  refused** (1/1/1 and never accepted before).

  ⛔ **`fuzzVerifyAttestation` built one attestation object, ever**: fmt "packed",
  alg -7, x5c `.absent`, zero-length signature. Its `.der_framed`, `.real_truncated`
  and `.real_mutated` certificate paths — the reason the reachability test beside it
  exists — had never been taken by the harness itself. After: **all 6 fmt strings, all
  5 x5c modes**, 2883 certificate octets and 2808 authData octets across 16 scripts.

  ⛔ **Both parser buffers were smaller than this module's own W3C §16 vectors.**
  `clientDataJSON` is 255 octets in four of six vectors against a 256-octet buffer,
  and a registration `authenticatorData` carrying attested credential data is 539
  octets for RS256 — more than double it. A seed longer than the buffer arrives
  *empty*, not truncated, so the largest blob this parser sees in production could not
  have passed through its own harness. 512 and 1024 now.

  Neither parser guard uses `accepted > 0`: `{"type":"t","challenge":"","origin":""}`
  parses cleanly (an empty challenge is legal base64url) and 37 octets of anything is
  a legal assertion `authenticatorData`. The pinned numbers are challenge octets
  decoded (137) and attested credential data recovered (3 credentials, 96 octets).

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
