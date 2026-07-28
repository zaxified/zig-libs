# saml

SAML 2.0 **Web Browser SSO, Service-Provider (relying-party) side** in pure Zig.
Consumes an IdP's `<samlp:Response>`, defends against XML-Signature-Wrapping
(XSW), validates conditions / subject confirmation against a caller-supplied
clock, and returns a trusted `AuthnResult`.

Top of the SAML cluster: `xml` → `xmldsig` → **`saml`** (plus `xmlenc` + `rsa`
for the optional encrypted-assertion path). See `SPEC.md` for the full profile,
the XSW defense model, and fixture provenance.

Security posture in one breath: the IdP key is configured out-of-band and is the
only thing signatures are checked against (**never** `<KeyInfo>`); a valid
signature must be *pinned by pointer identity* to the exact assertion consumed;
no signature ⇒ rejected (no downgrade); the system clock is never read;
malformed/adversarial input yields typed errors, never a panic. Encrypted
assertions (`<saml:EncryptedAssertion>`, the eIDAS encrypt profile) are decrypted
transparently **when the SP configures `sp_decrypt_key`** — decrypt-then-verify,
via the `xmlenc` module — and refused (`error.EncryptedAssertionUnsupported`)
otherwise. The same key also unwraps an encrypted `<saml:EncryptedID>` (Subject
NameID) and `<saml:EncryptedAttribute>`s, decrypted only **after** the enclosing
assertion is signature-verified. **Holder-of-Key**, **sender-vouches** and
**Bearer** subject confirmation are selected via `Config.subject_confirmation`
(`.bearer` | `.holder_of_key` | `.sender_vouches` | `.either`). HoK matches the
presenter's key — supplied as a certificate DER (`presented_holder_cert_der`)
and/or a bare public key (`presented_holder_key`: an RSA modulus+exponent or a
SEC1 P-256 point) — against whatever the confirmation names, **same-form**
(cert↔cert DER byte-equality, `<ds:KeyValue>`↔key structural equality) **and
cross-form** (cert↔`<ds:KeyValue>`, via the certificate's SubjectPublicKeyInfo
extracted with `x509.spkiOf` — never `std.crypto.Certificate.parse` — then
compared by key parameters, so re-encoding cannot spoof it).
Sender-vouches trusts the signature alone (no key/recipient binding — the caller
must trust `idp_key` as the attesting authority). An optional eIDAS
`Config.required_loa` enforces a minimum `<AuthnContextClassRef>` (low <
substantial < high; exact match for non-eIDAS class refs). See `SPEC.md` for the
encrypted-ID/attribute error model, the full HoK matching matrix, the
sender-vouches trust assumption, and the LoA semantics.

## Worked example — verify a POST-binding Response

```zig
const std = @import("std");
const saml = @import("saml");
const xmldsig = @import("xmldsig");

// Configure the SP once, out-of-band, from IdP metadata (see parseIdpMetadata).
// idp_pubkey is an rsa.PublicKey you parsed/pinned yourself.
fn handleAcs(
    gpa: std.mem.Allocator,
    saml_response_field: []const u8, // the POST form field, base64
    idp_pubkey: xmldsig.VerifyKey,
    pending_request_id: []const u8,  // the AuthnRequest ID you sent
    now_unix: i64,                   // your clock, not the module's
) !void {
    var result = saml.consumeResponse(gpa, saml_response_field, .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = idp_pubkey,
        .sp_entity_id = "https://sp.example.org/metadata", // must be in <Audience>
        .acs_url = "https://sp.example.org/acs",           // must be the Recipient
        .now_unix = now_unix,
        .clock_skew_secs = 60,
        .expected_in_response_to = pending_request_id,
        // .allow_idp_initiated = true,  // only if you accept unsolicited SSO
        // .signature_policy = .assertion, // require the Assertion (not Response) be signed
    }) catch |err| switch (err) {
        error.SignatureWrappingDetected => return, // an XSW attack — reject the login
        error.SignatureMissing, error.SignatureInvalid => return,
        error.AssertionExpired, error.AudienceMismatch, error.RecipientMismatch => return,
        else => return err,
    };
    defer result.deinit();

    // The subject is now trusted.
    std.log.info("authenticated {s}", .{result.name_id});
    if (result.attribute("groups")) |groups| {
        for (groups) |g| std.log.info("  group: {s}", .{g});
    }
    if (result.session_index) |sid| {
        // stash for Single-Logout correlation
        _ = sid;
    }
}
```

## SP-initiated SSO — build an AuthnRequest

```zig
// You generate the ID (and remember it as expected_in_response_to) and the
// timestamp — the module has no RNG and no clock.
const xml = try saml.buildAuthnRequest(gpa, .{
    .id = my_request_id,
    .issue_instant = "2024-06-01T12:00:00Z",
    .issuer = "https://sp.example.org/metadata",
    .acs_url = "https://sp.example.org/acs",
    .destination = "https://idp.example.org/sso",
    .name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
});
defer gpa.free(xml);
// Apply the binding yourself: deflate + base64 + URL-encode for HTTP-Redirect.
```

## Bindings

- **POST**: `consumeResponse(alloc, field, config)` decodes base64 then verifies.
  `consumeResponseXml(alloc, xml_bytes, config)` skips the decode.
- **Redirect**: `decodeRedirectField(alloc, field)` does base64 → raw DEFLATE
  (you URL-decode first); mostly relevant for requests.

## Tests

`zig build test-saml` (and `-Doptimize=ReleaseFast`). The suite includes the full
XSW attack battery (each attack rejected, with a passing control), the
conditions / subject / status / issuer "teeth" (each with a positive control),
and an end-to-end positive control over a genuinely-signed fixture produced by an
independent toolchain (openssl + libxml2) — see `SPEC.md` for provenance.
