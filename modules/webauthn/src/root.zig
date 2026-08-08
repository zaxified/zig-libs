// SPDX-License-Identifier: MIT
//! webauthn — W3C Web Authentication (WebAuthn) Level 3 / FIDO2 RELYING-PARTY
//! verifier: assertion (authentication) verification and attestation
//! (registration) verification over untrusted, attacker-controlled wire
//! bytes. This module is a spec-assembly layer, not a new crypto primitive —
//! every signature check routes through an existing, independently-KAT'd
//! primitive (`p256`'s ES256, `std.crypto.sign.Ed25519`'s EdDSA, `rsa`'s
//! RS256 PKCS1-v1.5) and every CBOR/COSE parse routes through the sibling
//! `cbor`/`cbor.cose` codec — this module never hand-rolls a bignum or a
//! CBOR decoder.
//!
//! **Assertion (authentication) verify — `verifyAssertion`**: given the
//! authenticator's raw `authenticatorData`, the raw `clientDataJSON`, the
//! signature, and the stored credential's COSE public key, checks (WebAuthn
//! §7.2, "Verifying an Authentication Assertion"):
//!   - `clientDataJSON` parses as JSON, `type == "webauthn.get"`, the
//!     decoded `challenge` matches the expected challenge bytes, `origin`
//!     matches;
//!   - `authenticatorData`'s leading 32 bytes (`rpIdHash`) equal
//!     `SHA-256(rpId)`;
//!   - the User Present flag is set (and User Verified, when the caller
//!     requires it);
//!   - the signature over `authenticatorData || SHA-256(clientDataJSON)`
//!     verifies under the stored credential's COSE key + algorithm
//!     (ES256/EdDSA/RS256).
//! Returns the parsed `signCount` + flags on success, a typed error on any
//! failure — see "Threat model" in SPEC.md for what each check defends
//! against and the adversarial test suite (`assertion_test.zig`) that proves
//! each one is load-bearing (tamper any one input, verification fails).
//!
//! **Registration ceremony verify — `verifyRegistration`**: the §7.1
//! counterpart of `verifyAssertion`, and the entry point a relying party
//! wants. Checks `type == "webauthn.create"`, the challenge, the origin,
//! `rpIdHash == SHA-256(rpId)` and the User Present/User Verified flags,
//! *then* the attestation statement. Without those first four a registration
//! response from a different ceremony or a different site verifies happily —
//! the attestation statement binds the authenticator to a clientDataHash, it
//! never binds that clientDataHash to a challenge this RP issued (and with
//! `fmt == "none"` there is no statement signature at all).
//!
//! **Attestation-statement verify — `verifyAttestation`**: parses the
//! CBOR `attestationObject` (`{fmt, attStmt, authData}`), extracts the
//! attested credential's COSE public key from `authData`, and verifies the
//! attestation statement for `fmt` in {`none`, `packed`, `fido-u2f`}
//! (WebAuthn §8.2/§8.3/§8.6) — the statement half only, for a caller that
//! does the ceremony binding itself. `tpm` and `android-key` are DEFERRED —
//! structurally recognized and rejected with `error.UnsupportedFormat`
//! rather than half-implemented (see SPEC.md "Deferred" for the rationale:
//! both require parsing/validating a manufacturer certificate-chain format
//! — TPM's `TPMS_ATTEST`/`TPMT_SIGNATURE` wire structs, Android's key
//! attestation X.509 extension — that is a project of its own, orthogonal
//! to the WebAuthn verification procedure itself).
//!
//! **Out of scope, by design (not silently skipped):** account-recovery /
//! backup codes are a product concern layered *above* WebAuthn, not part of
//! the W3C verification procedure — see SPEC.md.
//!
//! Provenance: clean-room from W3C Web Authentication (WebAuthn) Level 3
//! (https://www.w3.org/TR/webauthn-3/) §6 (authenticator data), §7.1/§7.2
//! (registration/authentication ceremony verification), §8.2/§8.3/§8.6
//! (packed / none / fido-u2f attestation statement formats); RFC 8152/9053
//! (COSE, via the sibling `cbor.cose`); RFC 8230 (RFC 8152 RSA COSE key
//! parameters, `kty=3`/`n=-1`/`e=-2` — not modeled by `cbor.cose`, so this
//! module parses that key shape itself, see `parseCredentialKey`). See
//! NOTICE for the citation entry.

const std = @import("std");
const Allocator = std.mem.Allocator;
const cbor = @import("cbor");
const rsa = @import("rsa");
const p256 = @import("p256");
const x509 = @import("x509");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure verification logic — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no shared/global state; every function takes its inputs as parameters
    .model_after = "W3C WebAuthn Level 3 (https://www.w3.org/TR/webauthn-3/) — clean-room from the spec",
    .deps = .{ "cbor", "rsa", "p256", "x509" },
};

// RFC 8812 §2 COSE algorithm identifier for RS256 (RSASSA-PKCS1-v1_5 w/
// SHA-256) — not in `cbor.cose` (that module only lists algs its own
// EC2/OKP key types use); webauthn is the first consumer that needs RSA.
const alg_rs256: i64 = -257;

/// Minimum RS256 **credential** key modulus size this module accepts (W2
/// `webauthn` F7). `rsa.PublicKey.fromBytes` alone only enforces its own
/// generic `min_modulus_bits = 512` floor — a size chosen for RSA as a
/// primitive in general, not for WebAuthn specifically. Every RS256 FIDO2/
/// WebAuthn authenticator in practice generates 2048-bit keys (it is what
/// the CTAP2/FIDO Alliance certification test suites require), so a
/// credential key below that is not a smaller-but-legitimate authenticator —
/// it is a signal something is wrong (a forged/downgraded credential, or a
/// non-conforming authenticator this RP should not trust for RS256).
const rs256_min_modulus_bits: usize = 2048;

// ── COSE key extraction (extends cbor.cose with RFC 8230 RSA keys) ─────────

/// An RSA `COSE_Key` (RFC 8230 §4, `kty=3`): the modulus `n` (label -1) and
/// public exponent `e` (label -2), both big-endian byte strings — the same
/// label *numbers* `cbor.cose` uses for EC2's `crv`/`x` (label reuse across
/// key types is RFC 8152's design, not a collision).
pub const RsaKey = struct {
    alg: ?i64,
    n: []const u8,
    e: []const u8,
};

/// The credential public key, extended over `cbor.cose.Key` to add the RSA
/// case (RS256) `cbor.cose` deliberately does not model (see that module's
/// doc comment: "RSA and symmetric COSE key types are not modeled").
pub const CoseKey = union(enum) {
    ec2: cbor.cose.Ec2Key,
    okp: cbor.cose.OkpKey,
    rsa: RsaKey,

    fn alg(self: CoseKey) ?i64 {
        return switch (self) {
            .ec2 => |k| k.alg,
            .okp => |k| k.alg,
            .rsa => |k| k.alg,
        };
    }
};

pub const KeyError = cbor.cose.KeyError;

fn cborMapGetInt(entries: []const cbor.MapEntry, label: i64) ?cbor.Value {
    for (entries) |e| {
        switch (e.key) {
            .uint, .negint => {
                const k = e.key.toI64() orelse continue;
                if (k == label) return e.value;
            },
            else => {},
        }
    }
    return null;
}

fn cborMapGetStr(entries: []const cbor.MapEntry, key: []const u8) ?cbor.Value {
    for (entries) |e| {
        switch (e.key) {
            .text => |t| if (std.mem.eql(u8, t, key)) return e.value,
            else => {},
        }
    }
    return null;
}

/// Parse a `COSE_Key` map that may be EC2 (`cbor.cose`), OKP (`cbor.cose`),
/// or RSA (RFC 8230, this module). This is `webauthn`'s key parser — it is
/// the one to use for a credential public key pulled out of `authData`, in
/// place of calling `cbor.cose.parseKey` directly (which returns
/// `error.UnsupportedKty` for RSA).
pub fn parseCredentialKey(value: cbor.Value) KeyError!CoseKey {
    const entries = switch (value) {
        .map => |m| m,
        else => return error.NotAMap,
    };
    const kty_v = cborMapGetInt(entries, cbor.cose.label_kty) orelse return error.MissingField;
    const kty = kty_v.toI64() orelse return error.WrongType;
    if (kty == 3) { // RFC 8230 kty "RSA"
        const alg_v = cborMapGetInt(entries, cbor.cose.label_alg);
        const alg: ?i64 = if (alg_v) |v| (v.toI64() orelse return error.WrongType) else null;
        const n_v = cborMapGetInt(entries, cbor.cose.label_crv) orelse return error.MissingField; // label -1
        const e_v = cborMapGetInt(entries, cbor.cose.label_x) orelse return error.MissingField; // label -2
        const n = switch (n_v) {
            .bytes => |b| b,
            else => return error.WrongType,
        };
        const e = switch (e_v) {
            .bytes => |b| b,
            else => return error.WrongType,
        };
        return .{ .rsa = .{ .alg = alg, .n = n, .e = e } };
    }
    return switch (try cbor.cose.parseKey(value)) {
        .ec2 => |k| .{ .ec2 = k },
        .okp => |k| .{ .okp = k },
    };
}

// ── clientDataJSON (WebAuthn §5.8.1 CollectedClientData) ───────────────────

pub const ClientDataError = error{ InvalidJson, Base64DecodeError, OutOfMemory };

pub const ClientData = struct {
    type: []const u8,
    /// Decoded from the JSON's base64url `challenge` field — raw bytes, to
    /// be compared against the RP's own raw challenge bytes (never compare
    /// the base64url text directly: two different encodings of the same
    /// bytes must still match).
    challenge: []const u8,
    origin: []const u8,
    cross_origin: ?bool,
};

/// Parse `client_data_json` (WebAuthn §5.8.1). Allocates via `allocator`
/// (an arena is the natural fit — nothing here needs individual freeing).
pub fn parseClientData(allocator: Allocator, client_data_json: []const u8) ClientDataError!ClientData {
    const Raw = struct {
        type: []const u8,
        challenge: []const u8,
        origin: []const u8,
        crossOrigin: ?bool = null,
    };
    const raw = std.json.parseFromSliceLeaky(Raw, allocator, client_data_json, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidJson;

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const chal_len = decoder.calcSizeForSlice(raw.challenge) catch return error.Base64DecodeError;
    const chal = try allocator.alloc(u8, chal_len);
    decoder.decode(chal, raw.challenge) catch return error.Base64DecodeError;

    return .{
        .type = raw.type,
        .challenge = chal,
        .origin = raw.origin,
        .cross_origin = raw.crossOrigin,
    };
}

// ── authenticatorData (WebAuthn §6.1) ───────────────────────────────────────

pub const AuthDataError = error{ Truncated, ExtensionsNotSupported, OutOfMemory } || cbor.DecodeError || KeyError;

pub const AttestedCredentialData = struct {
    aaguid: [16]u8,
    credential_id: []const u8,
    credential_public_key: CoseKey,
};

pub const AuthenticatorData = struct {
    rp_id_hash: [32]u8,
    flags: Flags,
    sign_count: u32,
    attested_credential_data: ?AttestedCredentialData,

    /// WebAuthn §6.1 flags byte, bit 0 (LSB) first.
    pub const Flags = packed struct(u8) {
        user_present: bool,
        rfu1: bool,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        rfu2: bool,
        attested_credential_data: bool,
        extension_data: bool,
    };
};

/// Parse `authenticatorData` (WebAuthn §6.1): `rpIdHash(32) || flags(1) ||
/// signCount(4, BE) || [attestedCredentialData]`. Extension data (flags bit
/// ED) is structurally detected and rejected with
/// `error.ExtensionsNotSupported` — this module has no byte-accounting CBOR
/// decoder to know where the (variable-length) credential public key ends
/// and trailing extensions begin when both are present; see SPEC.md
/// "Deferred". `allocator` is used only when `attestedCredentialData` is
/// present (to decode its CBOR credential public key).
pub fn parseAuthenticatorData(allocator: Allocator, raw: []const u8) AuthDataError!AuthenticatorData {
    if (raw.len < 37) return error.Truncated;
    var rp_id_hash: [32]u8 = undefined;
    @memcpy(&rp_id_hash, raw[0..32]);
    const flags: AuthenticatorData.Flags = @bitCast(raw[32]);
    const sign_count = std.mem.readInt(u32, raw[33..37], .big);

    var attested: ?AttestedCredentialData = null;
    if (flags.attested_credential_data) {
        if (raw.len < 37 + 16 + 2) return error.Truncated;
        var aaguid: [16]u8 = undefined;
        @memcpy(&aaguid, raw[37..53]);
        const cred_id_len = std.mem.readInt(u16, raw[53..55], .big);
        const cred_id_start: usize = 55;
        const cred_id_end = cred_id_start + cred_id_len;
        if (raw.len < cred_id_end) return error.Truncated;
        const credential_id = raw[cred_id_start..cred_id_end];

        if (flags.extension_data) return error.ExtensionsNotSupported;
        const pubkey_bytes = raw[cred_id_end..];

        const decoded = try cbor.decode(allocator, pubkey_bytes, .{});
        const key = try parseCredentialKey(decoded);
        attested = .{ .aaguid = aaguid, .credential_id = credential_id, .credential_public_key = key };
    } else if (flags.extension_data) {
        return error.ExtensionsNotSupported;
    }

    return .{ .rp_id_hash = rp_id_hash, .flags = flags, .sign_count = sign_count, .attested_credential_data = attested };
}

// ── signature verification dispatch (ES256 / EdDSA / RS256) ────────────────

pub const SignatureError = error{ UnsupportedAlgorithm, InvalidKey, InvalidSignature, BadSignature };

/// Verify `sig` over `msg` under `key`, per the COSE algorithm identifier
/// `alg` — the alg is bound tightly to the key's own curve/type (an ES256
/// `alg` against a P-384 key, or any `alg` that doesn't match the key's
/// `kty`/`crv`, is `error.UnsupportedAlgorithm`, never silently coerced —
/// this is the algorithm-confusion defense).
pub fn verifySignature(key: CoseKey, alg: i64, msg: []const u8, sig: []const u8) SignatureError!void {
    switch (key) {
        .ec2 => |ec2| {
            if (ec2.crv != cbor.cose.crv_p256 or alg != cbor.cose.alg_es256) return error.UnsupportedAlgorithm;
            if (ec2.x.len != 32 or ec2.y.len != 32) return error.InvalidKey;
            var sec1: [65]u8 = undefined;
            sec1[0] = 0x04;
            @memcpy(sec1[1..33], ec2.x);
            @memcpy(sec1[33..65], ec2.y);
            const parsed_sig = p256.EcdsaP256Sha256.Signature.fromDer(sig) catch return error.InvalidSignature;
            if (!p256.sign.ecdsaVerify(&sec1, msg, parsed_sig.toBytes())) return error.BadSignature;
        },
        .okp => |okp| {
            if (okp.crv != cbor.cose.crv_ed25519 or alg != cbor.cose.alg_eddsa) return error.UnsupportedAlgorithm;
            if (okp.x.len != 32) return error.InvalidKey;
            if (sig.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const pk = Ed25519.PublicKey.fromBytes(okp.x[0..32].*) catch return error.InvalidKey;
            const s = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
            s.verify(msg, pk) catch return error.BadSignature;
        },
        .rsa => |rk| {
            if (alg != alg_rs256) return error.UnsupportedAlgorithm;
            const pk = rsa.PublicKey.fromBytes(rk.n, rk.e) catch return error.InvalidKey;
            // W2 `webauthn` F7: WebAuthn RS256 credential keys are always
            // 2048-bit in practice; `rsa`'s own floor (512) is a generic
            // primitive-level bound, not a WebAuthn policy. Reject a
            // credential key below the size every conforming authenticator
            // actually generates, rather than accept whatever `rsa` alone
            // considers merely "not too small to compute with".
            if (pk.n.bits() < rs256_min_modulus_bits) return error.InvalidKey;
            rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig) catch return error.BadSignature;
        },
    }
}

// ── assertion (authentication) verify — WebAuthn §7.2 ───────────────────────

pub const AssertionError = ClientDataError || AuthDataError || SignatureError || error{
    TypeMismatch,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserNotPresent,
    UserNotVerified,
    MissingAlgorithm,
};

pub const AssertionOptions = struct {
    /// The Relying Party ID (WebAuthn §4) — `authenticatorData`'s
    /// `rpIdHash` must equal `SHA-256(rp_id)`.
    rp_id: []const u8,
    /// The exact raw challenge bytes the RP issued (not base64url text).
    expected_challenge: []const u8,
    /// The exact origin the RP expects (e.g. `"https://example.org"`).
    expected_origin: []const u8,
    require_user_verification: bool = false,
};

pub const AssertionResult = struct {
    sign_count: u32,
    user_present: bool,
    user_verified: bool,
};

/// Verify a WebAuthn assertion (authentication ceremony, §7.2): clientData
/// type/challenge/origin, `rpIdHash`, User Present (+ User Verified if
/// required), and the signature over `authenticatorData ||
/// SHA-256(clientDataJSON)` under `credential_public_key`'s own algorithm.
/// `allocator` is used for JSON parsing and the signed-message concat (an
/// arena is the natural fit).
pub fn verifyAssertion(
    allocator: Allocator,
    authenticator_data: []const u8,
    client_data_json: []const u8,
    signature: []const u8,
    credential_public_key: CoseKey,
    options: AssertionOptions,
) AssertionError!AssertionResult {
    const client_data = try parseClientData(allocator, client_data_json);
    if (!std.mem.eql(u8, client_data.type, "webauthn.get")) return error.TypeMismatch;
    if (!std.mem.eql(u8, client_data.challenge, options.expected_challenge)) return error.ChallengeMismatch;
    if (!std.mem.eql(u8, client_data.origin, options.expected_origin)) return error.OriginMismatch;

    const auth_data = try parseAuthenticatorData(allocator, authenticator_data);

    var expected_rp_id_hash: [32]u8 = undefined;
    Sha256.hash(options.rp_id, &expected_rp_id_hash, .{});
    if (!std.mem.eql(u8, &auth_data.rp_id_hash, &expected_rp_id_hash)) return error.RpIdMismatch;

    if (!auth_data.flags.user_present) return error.UserNotPresent;
    if (options.require_user_verification and !auth_data.flags.user_verified) return error.UserNotVerified;

    var client_data_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &client_data_hash, .{});
    const msg = try std.mem.concat(allocator, u8, &.{ authenticator_data, &client_data_hash });

    const alg = credential_public_key.alg() orelse return error.MissingAlgorithm;
    try verifySignature(credential_public_key, alg, msg, signature);

    return .{
        .sign_count = auth_data.sign_count,
        .user_present = auth_data.flags.user_present,
        .user_verified = auth_data.flags.user_verified,
    };
}

// ── attestation (registration) verify — WebAuthn §7.1/§8 ───────────────────

pub const AttestationObjectError = error{ NotAMap, MissingField, WrongType, OutOfMemory } || cbor.DecodeError;

pub const AttestationError = AttestationObjectError || AuthDataError || SignatureError || error{
    MissingAttestedCredentialData,
    InvalidAttestationStatement,
    InvalidCertificate,
    UnsupportedFormat,
};

pub const AttestationType = enum { none, basic, self_attestation };

pub const AttestationResult = struct {
    attestation_type: AttestationType,
    format: []const u8,
    credential_id: []const u8,
    credential_public_key: CoseKey,
    aaguid: [16]u8,
    sign_count: u32,
    /// `authenticatorData`'s leading 32 bytes. `verifyRegistration` has
    /// already compared this against `SHA-256(rp_id)`; a caller using the
    /// lower-level `verifyAttestation` must do that comparison itself.
    rp_id_hash: [32]u8,
    /// §6.1 flags as they arrived. `verifyRegistration` enforces UP (and UV
    /// on request); `backup_eligible`/`backup_state` are reported for a
    /// caller with a passkey-portability policy, never acted on here.
    flags: AuthenticatorData.Flags,
    /// The `x5c[0]` leaf certificate DER, when `attestation_type == .basic`
    /// (i.e. `fmt` was `packed` with an `x5c` or `fido-u2f`) — `null` for
    /// `.none`/`.self_attestation`, which have no certificate. This module
    /// only parses and signature-checks the leaf (via `x509.safe`, W2
    /// `webauthn` F1); it does NOT chain it, check validity dates, or check
    /// `basicConstraints` (W2 `webauthn` F6 — that is why `.basic` means "the
    /// statement is internally consistent", not "an authenticator vendor
    /// vouched for this", see `AttestationResult.require_attestation`'s doc).
    /// A caller that wants that stronger guarantee runs `x509.verifyChain`
    /// (or an MDS-derived trust-store check of its own) against this DER
    /// itself. Borrows from the `attestation_object_raw`/CBOR-arena bytes the
    /// caller passed to `verifyAttestation`/`verifyRegistration` — valid only
    /// as long as that input (and, for the allocating decode path, the arena)
    /// is still alive.
    leaf_cert_der: ?[]const u8 = null,
};

const AttestationObject = struct {
    fmt: []const u8,
    att_stmt: []const cbor.MapEntry,
    auth_data_raw: []const u8,
    auth_data: AuthenticatorData,
};

fn parseAttestationObject(allocator: Allocator, raw: []const u8) (AttestationObjectError || AuthDataError)!AttestationObject {
    const decoded = try cbor.decode(allocator, raw, .{});
    const entries = switch (decoded) {
        .map => |m| m,
        else => return error.NotAMap,
    };
    const fmt_v = cborMapGetStr(entries, "fmt") orelse return error.MissingField;
    const fmt = switch (fmt_v) {
        .text => |t| t,
        else => return error.WrongType,
    };
    const att_stmt_v = cborMapGetStr(entries, "attStmt") orelse return error.MissingField;
    const att_stmt = switch (att_stmt_v) {
        .map => |m| m,
        else => return error.WrongType,
    };
    const auth_data_v = cborMapGetStr(entries, "authData") orelse return error.MissingField;
    const auth_data_raw = switch (auth_data_v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const auth_data = try parseAuthenticatorData(allocator, auth_data_raw);

    return .{ .fmt = fmt, .att_stmt = att_stmt, .auth_data_raw = auth_data_raw, .auth_data = auth_data };
}

/// Verify a leaf X.509 certificate's signature over `msg`, dispatching on
/// its own SubjectPublicKeyInfo algorithm (EC P-256, Ed25519, or RSA) and
/// requiring it agree with the attestation statement's declared COSE `alg`
/// — used by both `packed` (x5c/basic) and `fido-u2f`. Certificate PARSING
/// (not chain validation — no trust-store lookup, no expiry/policy check;
/// see SPEC.md "Deferred") is `std.crypto.Certificate.parse`, the same
/// primitive the sibling `x509` module builds its chain validator on.
///
/// `leaf_der` is `attStmt.x5c[0]` — fully attacker-controlled bytes off the
/// registration ceremony's wire. `std.crypto.Certificate.parse` is NOT total
/// on such input: it indexes past the end of the buffer for a truncated or
/// minimally-shaped DER (`30 02 30 00` panics `index out of bounds: index 4,
/// len 4` in Debug and reads out of bounds silently under ReleaseFast), so it
/// is only ever reached here through `x509.safe.safeCertificate`, the
/// collection's single reconciled guard for exactly this std hazard — see
/// `modules/x509/src/safe.zig`. Never call `cert.parse()` on `leaf_der`
/// directly.
fn verifyLeafCertSignature(leaf_der: []const u8, alg: i64, msg: []const u8, sig: []const u8) AttestationError!void {
    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(leaf_der, &scratch) catch return error.InvalidCertificate;
    const parsed = cert.parse() catch return error.InvalidCertificate;
    switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |named_curve| {
            if (named_curve != .X9_62_prime256v1) return error.UnsupportedAlgorithm;
            if (alg != cbor.cose.alg_es256) return error.UnsupportedAlgorithm;
            const sec1_pub_key = parsed.pubKey();
            const parsed_sig = p256.EcdsaP256Sha256.Signature.fromDer(sig) catch return error.InvalidSignature;
            if (!p256.sign.ecdsaVerify(sec1_pub_key, msg, parsed_sig.toBytes())) return error.BadSignature;
        },
        .curveEd25519 => {
            if (alg != cbor.cose.alg_eddsa) return error.UnsupportedAlgorithm;
            const raw_pk = parsed.pubKey();
            if (raw_pk.len != 32) return error.InvalidCertificate;
            if (sig.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const pk = Ed25519.PublicKey.fromBytes(raw_pk[0..32].*) catch return error.InvalidKey;
            const s = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
            s.verify(msg, pk) catch return error.BadSignature;
        },
        .rsaEncryption => {
            if (alg != alg_rs256) return error.UnsupportedAlgorithm;
            const components = std.crypto.Certificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch return error.InvalidCertificate;
            const pk = rsa.PublicKey.fromBytes(components.modulus, components.exponent) catch return error.InvalidKey;
            rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig) catch return error.BadSignature;
        },
        .rsassa_pss => return error.UnsupportedAlgorithm,
    }
}

fn firstX5cDer(att_stmt: []const cbor.MapEntry) AttestationError!?[]const u8 {
    const x5c_v = cborMapGetStr(att_stmt, "x5c") orelse return null;
    const arr = switch (x5c_v) {
        .array => |a| a,
        else => return error.WrongType,
    };
    if (arr.len == 0) return error.MissingField;
    return switch (arr[0]) {
        .bytes => |b| b,
        else => error.WrongType,
    };
}

/// The attestation-statement dispatch result: the type, plus the leaf
/// certificate DER when one was verified (`.basic` only — see
/// `AttestationResult.leaf_cert_der`).
const StatementResult = struct {
    attestation_type: AttestationType,
    leaf_cert_der: ?[]const u8 = null,
};

/// `packed` attestation statement (WebAuthn §8.2): x5c present -> basic
/// attestation, verify `sig` over `authData || clientDataHash` with the
/// leaf certificate's key; x5c absent -> self attestation, verify with the
/// credential's own public key (the `alg` in `attStmt` and the algorithm
/// bound to `credential_key` must agree — enforced inside `verifySignature`
/// itself, which rejects any alg/key-family mismatch).
fn verifyPacked(att_stmt: []const cbor.MapEntry, msg: []const u8, credential_key: CoseKey) AttestationError!StatementResult {
    const alg_v = cborMapGetStr(att_stmt, "alg") orelse return error.MissingField;
    const alg = alg_v.toI64() orelse return error.WrongType;
    const sig_v = cborMapGetStr(att_stmt, "sig") orelse return error.MissingField;
    const sig = switch (sig_v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };

    if (try firstX5cDer(att_stmt)) |leaf_der| {
        try verifyLeafCertSignature(leaf_der, alg, msg, sig);
        return .{ .attestation_type = .basic, .leaf_cert_der = leaf_der };
    }
    try verifySignature(credential_key, alg, msg, sig);
    return .{ .attestation_type = .self_attestation };
}

/// `fido-u2f` attestation statement (WebAuthn §8.6, U2F-era authenticators):
/// ES256/P-256 only. The signed blob is NOT `authData || clientDataHash` —
/// it is U2F's own `0x00 || rpIdHash || clientDataHash || credentialId ||
/// publicKeyU2F` (`publicKeyU2F` = the credential's EC point re-encoded as a
/// raw 65-byte SEC1-uncompressed point, `0x04 || x || y`).
fn verifyFidoU2f(
    allocator: Allocator,
    att_stmt: []const cbor.MapEntry,
    auth_data: AuthenticatorData,
    client_data_hash: [32]u8,
) AttestationError!StatementResult {
    const sig_v = cborMapGetStr(att_stmt, "sig") orelse return error.MissingField;
    const sig = switch (sig_v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const leaf_der = (try firstX5cDer(att_stmt)) orelse return error.MissingField;

    const att = auth_data.attested_credential_data orelse return error.MissingAttestedCredentialData;
    const ec2 = switch (att.credential_public_key) {
        .ec2 => |k| k,
        else => return error.UnsupportedAlgorithm, // fido-u2f credentials are always EC2/P-256
    };
    if (ec2.crv != cbor.cose.crv_p256 or ec2.x.len != 32 or ec2.y.len != 32) return error.InvalidKey;

    var public_key_u2f: [65]u8 = undefined;
    public_key_u2f[0] = 0x04;
    @memcpy(public_key_u2f[1..33], ec2.x);
    @memcpy(public_key_u2f[33..65], ec2.y);

    const verification_data = try std.mem.concat(allocator, u8, &.{
        &[_]u8{0x00},
        &auth_data.rp_id_hash,
        &client_data_hash,
        att.credential_id,
        &public_key_u2f,
    });

    try verifyLeafCertSignature(leaf_der, cbor.cose.alg_es256, verification_data, sig);
    return .{ .attestation_type = .basic, .leaf_cert_der = leaf_der };
}

/// The attestation-statement half of §7.1 (steps 19-21): dispatch on `fmt`
/// and verify the statement over `authData || clientDataHash`. Says nothing
/// about which ceremony the `clientDataHash` came from — that binding is the
/// caller's, and `verifyRegistration` is where it lives.
fn verifyStatement(
    allocator: Allocator,
    obj: AttestationObject,
    att: AttestedCredentialData,
    client_data_hash: [32]u8,
) AttestationError!StatementResult {
    if (std.mem.eql(u8, obj.fmt, "none")) {
        if (obj.att_stmt.len != 0) return error.InvalidAttestationStatement;
        return .{ .attestation_type = .none };
    } else if (std.mem.eql(u8, obj.fmt, "packed")) {
        const msg = try std.mem.concat(allocator, u8, &.{ obj.auth_data_raw, &client_data_hash });
        return verifyPacked(obj.att_stmt, msg, att.credential_public_key);
    } else if (std.mem.eql(u8, obj.fmt, "fido-u2f")) {
        return verifyFidoU2f(allocator, obj.att_stmt, obj.auth_data, client_data_hash);
    }
    return error.UnsupportedFormat; // covers "tpm", "android-key", and anything unrecognized
}

fn attestationResult(
    obj: AttestationObject,
    att: AttestedCredentialData,
    statement: StatementResult,
) AttestationResult {
    return .{
        .attestation_type = statement.attestation_type,
        .format = obj.fmt,
        .credential_id = att.credential_id,
        .credential_public_key = att.credential_public_key,
        .aaguid = att.aaguid,
        .sign_count = obj.auth_data.sign_count,
        .rp_id_hash = obj.auth_data.rp_id_hash,
        .flags = obj.auth_data.flags,
        .leaf_cert_der = statement.leaf_cert_der,
    };
}

/// Verify only the **attestation statement** of a registration response:
/// parses `attestation_object_raw` and dispatches on `fmt` to `none`/
/// `packed`/`fido-u2f`. `tpm`/`android-key` (and any other fmt) return
/// `error.UnsupportedFormat` — structurally recognized, not silently
/// accepted, not half-verified.
///
/// **This is not the registration ceremony.** It takes an opaque
/// `client_data_hash` and therefore cannot check `type`, `challenge`,
/// `origin` or `rpIdHash`: it proves the attestation statement is internally
/// consistent with *some* clientData, not that the response answers the
/// ceremony this relying party started. With `fmt == "none"` there is no
/// signature in the statement at all, so nothing whatsoever is bound. Use
/// `verifyRegistration` unless you are deliberately splitting the ceremony
/// (a two-stage pipeline that has already done the §7.1 clientData and
/// `rpIdHash` checks itself) — the returned `rp_id_hash` and `flags` are
/// there so such a caller can.
pub fn verifyAttestation(
    allocator: Allocator,
    attestation_object_raw: []const u8,
    client_data_hash: [32]u8,
) AttestationError!AttestationResult {
    const obj = try parseAttestationObject(allocator, attestation_object_raw);
    const att = obj.auth_data.attested_credential_data orelse return error.MissingAttestedCredentialData;
    const statement = try verifyStatement(allocator, obj, att, client_data_hash);
    return attestationResult(obj, att, statement);
}

// ── registration ceremony — WebAuthn §7.1 ──────────────────────────────────

pub const RegistrationError = AttestationError || ClientDataError || error{
    TypeMismatch,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserNotPresent,
    UserNotVerified,
    AttestationNotProvided,
};

pub const RegistrationOptions = struct {
    /// The Relying Party ID (WebAuthn §4) — `authenticatorData`'s
    /// `rpIdHash` must equal `SHA-256(rp_id)`.
    rp_id: []const u8,
    /// The exact raw challenge bytes the RP issued **for this registration**
    /// (not base64url text). The RP owns freshness and single-use; this only
    /// proves the presented challenge is the expected one byte-for-byte.
    expected_challenge: []const u8,
    /// The exact origin the RP expects (e.g. `"https://example.org"`).
    expected_origin: []const u8,
    require_user_verification: bool = false,
    /// Refuse `fmt == "none"` (`error.AttestationNotProvided`).
    ///
    /// Left **off** by default deliberately. `none` is a legitimate and, in
    /// practice, dominant choice — §7.1 step 20 lists "no attestation
    /// statement" as a conforming outcome, platform authenticators
    /// (Windows Hello, iCloud Keychain, Android) commonly send it, and an RP
    /// that is not running an MDS-backed authenticator allow-list gains
    /// nothing by demanding a statement it will not check against a trust
    /// store. What is *not* optional is that the caller knows: with `none`
    /// nothing about the authenticator is proven, and `attestation_type ==
    /// .none` in the result says so. Turn this on when a policy actually
    /// depends on the authenticator's identity — and then also chain the
    /// leaf certificate, because `basic` here still only means "the
    /// statement is internally consistent" (see SPEC.md "Deferred").
    require_attestation: bool = false,
};

/// Verify a WebAuthn **registration ceremony** (§7.1) end to end: the
/// clientData half (`type == "webauthn.create"`, challenge, origin), the
/// authenticator-data half (`rpIdHash == SHA-256(rp_id)`, User Present, User
/// Verified when required), and then the attestation statement over
/// `authData || SHA-256(clientDataJSON)`.
///
/// The clientData and `rpIdHash` checks are what make the response answer
/// *this* ceremony. Without them a registration response is accepted from a
/// different ceremony, a different site, or (for `fmt == "none"`, which
/// carries no signature) simply replayed — the attestation statement binds
/// the authenticator to a clientDataHash, never the clientDataHash to a
/// challenge this RP issued. `type` is checked exactly in both directions:
/// §7.2's `"webauthn.get"` in `verifyAssertion`, §7.1's `"webauthn.create"`
/// here, so neither ceremony's response is the other's.
///
/// `allocator` is used for JSON/CBOR parsing and the signed-message concat
/// (an arena is the natural fit).
pub fn verifyRegistration(
    allocator: Allocator,
    attestation_object_raw: []const u8,
    client_data_json: []const u8,
    options: RegistrationOptions,
) RegistrationError!AttestationResult {
    const client_data = try parseClientData(allocator, client_data_json);
    if (!std.mem.eql(u8, client_data.type, "webauthn.create")) return error.TypeMismatch;
    if (!std.mem.eql(u8, client_data.challenge, options.expected_challenge)) return error.ChallengeMismatch;
    if (!std.mem.eql(u8, client_data.origin, options.expected_origin)) return error.OriginMismatch;

    const obj = try parseAttestationObject(allocator, attestation_object_raw);
    const att = obj.auth_data.attested_credential_data orelse return error.MissingAttestedCredentialData;

    var expected_rp_id_hash: [32]u8 = undefined;
    Sha256.hash(options.rp_id, &expected_rp_id_hash, .{});
    if (!std.mem.eql(u8, &obj.auth_data.rp_id_hash, &expected_rp_id_hash)) return error.RpIdMismatch;

    if (!obj.auth_data.flags.user_present) return error.UserNotPresent;
    if (options.require_user_verification and !obj.auth_data.flags.user_verified) return error.UserNotVerified;

    var client_data_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &client_data_hash, .{});
    const statement = try verifyStatement(allocator, obj, att, client_data_hash);
    if (options.require_attestation and statement.attestation_type == .none) return error.AttestationNotProvided;

    return attestationResult(obj, att, statement);
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = @import("clientdata_test.zig");
    _ = @import("assertion_test.zig");
    _ = @import("attestation_test.zig");
}

test "smoke: module compiles and CoseKey.alg dispatch works" {
    const key: CoseKey = .{ .ec2 = .{ .alg = cbor.cose.alg_es256, .crv = cbor.cose.crv_p256, .x = &[_]u8{0} ** 32, .y = &[_]u8{0} ** 32 } };
    try std.testing.expectEqual(@as(?i64, cbor.cose.alg_es256), key.alg());
}

// Regression (audit W2 `webauthn` F7): an RS256 CREDENTIAL key below the
// 2048-bit floor every conforming WebAuthn/FIDO2 authenticator actually
// generates must be rejected — `rsa.PublicKey.fromBytes`'s own floor (512)
// is a generic RSA-primitive bound, not a WebAuthn policy, so a genuinely
// well-formed (real prime-product, real signature) 512-bit key must still be
// refused HERE. Uses a real generated key + real signature — not a malformed
// blob — so the rejection is specifically the modulus-size policy, not
// `InvalidKey`/`BadSignature` for an unrelated reason.
test "F7: an RS256 credential key below 2048 bits is rejected, not merely small-but-valid" {
    var prng = std.Random.DefaultPrng.init(0x7732_5f66_375f_6b65); // "w2_f7_ke" tests only
    const random = prng.random();

    // 512 bits: passes rsa's own floor (512) and is a completely valid,
    // freshly generated RSA key — the ONLY thing wrong with it is its size.
    const kp = try rsa.generate(random, 512, 65537);
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    kp.public_key.n.toBytes(&n_buf, .big) catch unreachable;
    var e_buf: [rsa.max_modulus_len]u8 = undefined;
    kp.public_key.e.toBytes(&e_buf, .big) catch unreachable;

    const msg = "webauthn F7 regression";
    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig = try rsa.signPkcs1v15(kp.secret_key, std.crypto.hash.sha2.Sha256, msg, &sig_buf);

    // Sanity: `rsa` itself is happy with this key (it is a real, valid
    // 512-bit RSA key and a real signature) — proves the rejection below
    // comes from webauthn's OWN 2048-bit floor, not from `rsa` refusing a
    // malformed key.
    const pk = try rsa.PublicKey.fromBytes(&n_buf, &e_buf);
    try rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);

    const key: CoseKey = .{ .rsa = .{ .alg = alg_rs256, .n = &n_buf, .e = &e_buf } };
    try std.testing.expectError(error.InvalidKey, verifySignature(key, alg_rs256, msg, sig));
}

// ── fuzz: clientDataJSON + authenticatorData, never panic ──────────────────
//
// `parseClientData` runs on `clientDataJSON` — JSON the browser sends,
// itself echoing an origin the *client* asserts (exactly the field a
// malicious page controls). `parseAuthenticatorData` runs on
// `authenticatorData`, a binary blob from the browser's WebAuthn API that
// in turn embeds a CBOR credential public key — both are the untrusted
// wire this collection's threat model calls out (a relying-party server
// verifying a credential from an arbitrary client).

test "fuzz: parseClientData never panics on arbitrary JSON" {
    try std.testing.fuzz({}, fuzzParseClientData, .{});
}

fn fuzzParseClientData(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = parseClientData(arena.allocator(), buf[0..len]) catch return;
}

test "fuzz: parseAuthenticatorData never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzParseAuthenticatorData, .{});
}

fn fuzzParseAuthenticatorData(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = parseAuthenticatorData(arena.allocator(), buf[0..len]) catch return;
}

test "F4: parseAuthenticatorData reads signCount big-endian, pinned byte-exact" {
    // SPEC.md hands signCount to the caller as the clone-detection signal,
    // but every real W3C §16 vector's signCount is 0 (a fresh authenticator
    // counter) -- 0 reads identically regardless of byte order, so no
    // amount of asserting against the real corpus alone can catch a
    // `.big` -> `.little` regression. Drive `parseAuthenticatorData`
    // directly with a hand-built, asymmetric 4-byte value: a
    // little-endian read of 01 02 03 04 would yield 0x04030201, not
    // 0x01020304.
    var raw: [37]u8 = undefined;
    @memset(raw[0..32], 0xCC); // rp_id_hash, irrelevant to this check
    raw[32] = 0x01; // flags: user_present only, no attested credential data
    raw[33..37].* = .{ 0x01, 0x02, 0x03, 0x04 }; // signCount, big-endian

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parseAuthenticatorData(arena.allocator(), &raw);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.sign_count);
}

test "F5: parseAuthenticatorData decodes aaguid + user_present/user_verified byte-exact" {
    // aaguid and the user_present/user_verified flag bits were likewise
    // never asserted anywhere in the suite. Build a synthetic
    // authenticatorData with attested credential data present (a real,
    // valid COSE EC2 key so the CBOR decode succeeds -- the same
    // credential_public_key bytes as vectors.none_es256, inlined here so
    // this "production" file does not import the test-only vectors
    // module) and an asymmetric aaguid, and pin all three against the
    // exact bytes/bits that went in.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(std.testing.allocator);
    const a = std.testing.allocator;

    try raw.appendSlice(a, &([_]u8{0xCC} ** 32)); // rp_id_hash
    // flags: user_present=1, user_verified=1, attested_credential_data=1.
    // (bit0 | bit2 | bit6)
    try raw.append(a, 0b0100_0101);
    try raw.appendSlice(a, &[_]u8{ 0, 0, 0, 0 }); // signCount, irrelevant here
    const aaguid = [16]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    try raw.appendSlice(a, &aaguid);
    try raw.appendSlice(a, &[_]u8{ 0, 0 }); // credentialIdLength = 0
    const cose_key_hex = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    var cose_key: [cose_key_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cose_key, cose_key_hex);
    try raw.appendSlice(a, &cose_key);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parseAuthenticatorData(arena.allocator(), raw.items);

    try std.testing.expect(parsed.flags.user_present);
    try std.testing.expect(parsed.flags.user_verified);
    try std.testing.expect(parsed.attested_credential_data != null);
    try std.testing.expectEqualSlices(u8, &aaguid, &parsed.attested_credential_data.?.aaguid);
}
