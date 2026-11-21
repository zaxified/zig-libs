// SPDX-License-Identifier: MIT
//! webauthn — W3C Web Authentication (WebAuthn) Level 3 / FIDO2 RELYING-PARTY
//! verifier: assertion (authentication) verification and attestation
//! (registration) verification over untrusted, attacker-controlled wire
//! bytes. This module is a spec-assembly layer, not a new crypto primitive —
//! every signature check routes through an existing, independently-KAT'd
//! primitive (`p256`'s ES256, `p384`/`p521`'s ES384/ES512, `std.crypto.sign.Ed25519`'s EdDSA, `rsa`'s
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
//!     (ES256/ES384/ES512/EdDSA/RS256).
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
//! attestation statement for `fmt` in {`none`, `packed`, `fido-u2f`, `apple`, `android-key`, `tpm`}
//! (WebAuthn §8.2-§8.8) — the statement half only, for a caller that
//! does the ceremony binding itself. Any other `fmt` is `error.UnsupportedFormat`.
//! (`android-key` is implemented but cannot run until `x509.safe` accepts the high-tag-number
//! tags of an Android KeyDescription, see SPEC.md.)
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
const p384 = @import("p384");
const p521 = @import("p521");
const x509 = @import("x509");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "WebAuthn / FIDO2 Relying-Party **verifier** (W3C Level 3) — assertion + registration ceremony checks, plus attestation verification. Verification only.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure verification logic — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no shared/global state; every function takes its inputs as parameters
    .model_after = "W3C WebAuthn Level 3 (https://www.w3.org/TR/webauthn-3/) — clean-room from the spec",
    .deps = .{ "cbor", "rsa", "p256", "p384", "p521", "x509" },
};

// RFC 8812 §2 COSE algorithm identifier for RS256 (RSASSA-PKCS1-v1_5 w/
// SHA-256) — not in `cbor.cose` (that module only lists algs its own
// EC2/OKP key types use); webauthn is the first consumer that needs RSA.
pub const alg_rs256: i64 = -257;

/// Minimum RS256 **credential** key modulus size this module accepts (W2
/// `webauthn` F7). `rsa.PublicKey.fromBytes` alone only enforces its own
/// generic `min_modulus_bits = 1024` floor — a size chosen for RSA as a
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

    /// An owning copy. The coordinates a parsed key carries are borrowed from
    /// the allocator the CBOR was decoded into (`cbor.decode` dupes each byte
    /// string into it), so a key an RP intends to STORE — which is every
    /// credential key — has to be copied out before that allocator is reset.
    /// Free with `freeOwned`.
    pub fn dupe(self: CoseKey, gpa: Allocator) Allocator.Error!CoseKey {
        switch (self) {
            .ec2 => |k| {
                const x = try gpa.dupe(u8, k.x);
                errdefer gpa.free(x);
                const y = try gpa.dupe(u8, k.y);
                return .{ .ec2 = .{ .alg = k.alg, .crv = k.crv, .x = x, .y = y } };
            },
            .okp => |k| {
                const x = try gpa.dupe(u8, k.x);
                return .{ .okp = .{ .alg = k.alg, .crv = k.crv, .x = x } };
            },
            .rsa => |k| {
                const n = try gpa.dupe(u8, k.n);
                errdefer gpa.free(n);
                const e = try gpa.dupe(u8, k.e);
                return .{ .rsa = .{ .alg = k.alg, .n = n, .e = e } };
            },
        }
    }

    /// Free a copy made by `dupe`. Never call it on a key returned straight
    /// from parsing — that one borrows.
    pub fn freeOwned(self: CoseKey, gpa: Allocator) void {
        switch (self) {
            .ec2 => |k| {
                gpa.free(k.x);
                gpa.free(k.y);
            },
            .okp => |k| gpa.free(k.x),
            .rsa => |k| {
                gpa.free(k.n);
                gpa.free(k.e);
            },
        }
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
    // RFC 9052 §3: labels MUST be unique. `cbor.cose.parseKey` enforces this
    // for the key types it handles — and the RSA arm below returns before
    // ever reaching it, so this key type silently lost the rule. Hoisted
    // above the `kty` read so a duplicated `kty` is caught too. It also
    // reinstates `max_map_entries` for this arm, the cap `cbor` added
    // specifically because `webauthn` hands this function the unbounded tail
    // of client-supplied `authData`.
    try cbor.cose.checkLabels(entries);
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
        // AKP (RFC 9964, `kty` 7) carries ML-DSA keys. WebAuthn has not
        // registered ML-DSA -- draft-vitap-ml-dsa-webauthn is a draft, with no
        // COSE algorithm assigned for WebAuthn use -- so a credential
        // presenting one is a key type this module cannot verify with, and
        // saying so is the honest answer. Accepting it here would mean
        // claiming an attestation path that does not exist yet.
        .akp => error.UnsupportedKty,
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

/// §6.5.2 / CTAP2 cap on `credentialIdLength`.
pub const max_credential_id_len: u16 = 1023;

pub const AuthDataError = error{
    Truncated,
    /// ED (flags bit 7) is set but what follows is not exactly one CBOR map
    /// (§6.1: "extensions ... a CBOR map").
    InvalidExtensions,
    /// Bytes remain after the last structure the flags announce — §6.1's
    /// layout is exact.
    TrailingData,
    /// `credentialIdLength` exceeds `max_credential_id_len` (§6.5.2).
    CredentialIdTooLong,
    /// BE=0 with BS=1 — an authenticator state §6.1 forbids.
    BackupStateInconsistent,
    OutOfMemory,
} || cbor.DecodeError || KeyError;

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
    /// The authenticator extension outputs (ED set): the raw CBOR map,
    /// borrowed from the input like `credential_id` — decode it with `cbor`
    /// when an extension matters (`credProtect`, `hmac-secret`, …). Null when
    /// ED is clear.
    extensions: ?[]const u8 = null,

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
/// signCount(4, BE) || [attestedCredentialData] || [extensions]`. The
/// credential public key is a CBOR item with no length of its own, so it is
/// decoded with `cbor.decodePrefix` to learn where it ends; the extensions
/// (ED set) must then be exactly one CBOR map, returned raw in `extensions`.
/// Anything after the last structure the flags announce is
/// `error.TrailingData`. `allocator` holds the decoded credential key and
/// transient CBOR trees.
pub fn parseAuthenticatorData(allocator: Allocator, raw: []const u8) AuthDataError!AuthenticatorData {
    if (raw.len < 37) return error.Truncated;
    var rp_id_hash: [32]u8 = undefined;
    @memcpy(&rp_id_hash, raw[0..32]);
    const flags: AuthenticatorData.Flags = @bitCast(raw[32]);
    const sign_count = std.mem.readInt(u32, raw[33..37], .big);

    var attested: ?AttestedCredentialData = null;
    var rest: []const u8 = raw[37..];
    if (flags.attested_credential_data) {
        if (raw.len < 37 + 16 + 2) return error.Truncated;
        var aaguid: [16]u8 = undefined;
        @memcpy(&aaguid, raw[37..53]);
        const cred_id_len = std.mem.readInt(u16, raw[53..55], .big);
        // §6.5.2 / CTAP2: a credential ID is at most 1023 bytes. The only
        // length field in `authData` the spec caps, and the one this module
        // did not.
        if (cred_id_len > max_credential_id_len) return error.CredentialIdTooLong;
        const cred_id_start: usize = 55;
        const cred_id_end = cred_id_start + cred_id_len;
        if (raw.len < cred_id_end) return error.Truncated;
        const credential_id = raw[cred_id_start..cred_id_end];

        const decoded = try cbor.decodePrefix(allocator, raw[cred_id_end..], .{});
        const key = try parseCredentialKey(decoded.value);
        attested = .{ .aaguid = aaguid, .credential_id = credential_id, .credential_public_key = key };
        rest = raw[cred_id_end + decoded.len ..];
    }

    var extensions: ?[]const u8 = null;
    if (flags.extension_data) {
        const ext = cbor.decode(allocator, rest, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidExtensions, // truncated, not one item, trailing bytes
        };
        defer cbor.freeValue(allocator, ext);
        if (ext != .map) return error.InvalidExtensions;
        extensions = rest;
        rest = &.{};
    }
    if (rest.len != 0) return error.TrailingData;

    // WebAuthn L3 §6.1: BE=0 means the credential cannot be backed up, so
    // BS=1 alongside it is a contradiction the authenticator must not emit —
    // §7.1 step 11 / §7.2 step 17 make rejecting it normative. Checked here,
    // once, so both ceremonies get it. Reported-but-not-acted-on was framed
    // as a policy choice; it was a skipped step.
    if (!flags.backup_eligible and flags.backup_state) return error.BackupStateInconsistent;

    return .{ .rp_id_hash = rp_id_hash, .flags = flags, .sign_count = sign_count, .attested_credential_data = attested, .extensions = extensions };
}

// ── signature verification dispatch (ES256 / ES384 / ES512 / EdDSA / RS256) ────────────────

pub const SignatureError = error{ UnsupportedAlgorithm, InvalidKey, InvalidSignature, BadSignature };

/// ECDSA over a sibling curve module's `Ecdsa(Hash)` type (P-384 / P-521):
/// uncompressed SEC1 point from the COSE coordinates, DER signature.
fn verifyEcdsaDer(comptime E: type, comptime coord_len: usize, x: []const u8, y: []const u8, msg: []const u8, sig: []const u8) SignatureError!void {
    if (x.len != coord_len or y.len != coord_len) return error.InvalidKey;
    var sec1: [1 + 2 * coord_len]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..][0..coord_len], x);
    @memcpy(sec1[1 + coord_len ..][0..coord_len], y);
    const pk = E.PublicKey.fromSec1(&sec1) catch return error.InvalidKey;
    const parsed_sig = E.Signature.fromDer(sig) catch return error.InvalidSignature;
    parsed_sig.verify(msg, pk) catch return error.BadSignature;
}

/// Verify `sig` over `msg` under `key`, per the COSE algorithm identifier
/// `alg` — the alg is bound tightly to the key's own curve/type: an ES256
/// `alg` against a P-384 key (or ES384 against a P-256 key), or any `alg`
/// that does not match the key's `kty`/`crv`, is `error.UnsupportedAlgorithm`,
/// never silently coerced — this is the algorithm-confusion defense.
pub fn verifySignature(key: CoseKey, alg: i64, msg: []const u8, sig: []const u8) SignatureError!void {
    switch (key) {
        .ec2 => |ec2| {
            // ES384 / ES512 (RFC 9053 §2.1): the curve and the alg must pair
            // exactly (P-384/-35, P-521/-36); any other combination is refused.
            // Like ES256 below, no low-S requirement (WebAuthn does not impose one).
            if (ec2.crv == cbor.cose.crv_p384 and alg == cbor.cose.alg_es384) {
                return verifyEcdsaDer(p384.EcdsaP384Sha384, 48, ec2.x, ec2.y, msg, sig);
            }
            if (ec2.crv == cbor.cose.crv_p521 and alg == cbor.cose.alg_es512) {
                return verifyEcdsaDer(p521.EcdsaP521Sha512, 66, ec2.x, ec2.y, msg, sig);
            }
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
            // 2048-bit in practice; `rsa`'s own floor (1024) is a generic
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
    /// WebAuthn §8.2.1: the `packed` attestation certificate carries the
    /// id-fido-gen-ce-aaguid extension (OID 1.3.6.1.4.1.45724.1.1.4) and its
    /// value does not match `authData.aaguid`. The extension exists so a
    /// relying party can trust the AAGUID it reads from `authData` — an
    /// attacker who controls `authData` but not the attestation key cannot
    /// also forge this binding, so a mismatch means the certificate was not
    /// issued for the authenticator model `authData` claims to be.
    AaguidExtensionMismatch,
};

pub const AttestationType = enum {
    none,
    basic,
    self_attestation,
    /// WebAuthn "AnonCA" (`apple`, §8.8): a certificate issued per credential by the vendor's anonymization CA.
    anonymization_ca,
    /// WebAuthn "AttCA" (`tpm`, §8.3): an AIK certificate issued by an attestation CA for this TPM key; the caller
    /// checks the chain (`AttestationResult.leaf_cert_der`, `verifyAttestationChain`).
    attestation_ca,
};

/// The outcome of a registration ceremony.
///
/// ⚠ **Lifetime.** `format`, `credential_id`, `leaf_cert_der` and every byte
/// slice inside `credential_public_key` are **borrowed from the allocator you
/// passed in** — `cbor.decode` dupes each byte string into it, so they do not
/// even alias your `attestation_object_raw`. Reset or free that allocator and
/// they dangle. This matters because the two fields an RP must *persist* are
/// exactly `credential_id` and `credential_public_key`: with a per-request
/// arena (the natural fit for the rest of the call, and what the README used
/// to show) a stored key becomes pointers into recycled heap, and the next
/// login verifies against whatever the following request wrote there — silent
/// in ReleaseFast. `dupe` returns an owning copy for storage; `deinit` frees
/// one. Only `aaguid`, `sign_count`, `rp_id_hash`, `flags` and
/// `attestation_type` are plain values that outlive the allocator.
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

    /// An owning copy, safe to keep after the verification allocator is gone.
    /// Free it with `deinit(gpa)`. This is what an RP stores.
    pub fn dupe(self: AttestationResult, gpa: Allocator) Allocator.Error!AttestationResult {
        var out = self;
        var done: usize = 0;
        errdefer {
            // Unwind exactly what was allocated, in order.
            if (done > 0) gpa.free(out.format);
            if (done > 1) gpa.free(out.credential_id);
            if (done > 2) out.credential_public_key.freeOwned(gpa);
        }
        out.format = try gpa.dupe(u8, self.format);
        done = 1;
        out.credential_id = try gpa.dupe(u8, self.credential_id);
        done = 2;
        out.credential_public_key = try self.credential_public_key.dupe(gpa);
        done = 3;
        if (self.leaf_cert_der) |der| out.leaf_cert_der = try gpa.dupe(u8, der);
        return out;
    }

    /// Free a copy made by `dupe`. Never call this on the value
    /// `verifyRegistration` returned directly — that one borrows.
    pub fn deinit(self: AttestationResult, gpa: Allocator) void {
        gpa.free(self.format);
        gpa.free(self.credential_id);
        self.credential_public_key.freeOwned(gpa);
        if (self.leaf_cert_der) |der| gpa.free(der);
    }
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
    // Same rule one layer up: `{fmt:"none", fmt:"tpm", authData:A, authData:B}`
    // was accepted first-wins, so which `authData` this verifier signed over
    // was a parser-differential away from what another implementation reads.
    try cbor.cose.checkLabels(entries);
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
/// WebAuthn §8.2.1's id-fido-gen-ce-aaguid extension OID, 1.3.6.1.4.1.45724.1.1.4,
/// as its DER `OBJECT IDENTIFIER` content octets (X.690 §8.19): arc 1.3 packs
/// to 0x2B, then 6/1/4/1 as single bytes, then 45724 as the base-128 triple
/// 0x82 0xE5 0x1C, then 1/1/4.
const fido_gen_ce_aaguid_oid = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04 };

/// WebAuthn §8.2.1: "If x5c is present, ... the Basic Constraints extension
/// MUST have the CA component set to false" is chain-validation territory
/// this module already documents as deferred (see SPEC.md), but the id-fido-
/// gen-ce-aaguid binding is not — it is a same-certificate content check: IF
/// the leaf carries that extension, its value MUST equal `authData.aaguid`
/// (the very aaguid this call is verifying an attestation for). Absence of
/// the extension is not itself a fault; §8.2.1 only constrains it when present.
///
/// `cert` must already have had `cert.parse()` called and checked — this
/// walks the same buffer with `x509.extensions`' independent DER traversal
/// (std's own `Certificate.parse` never surfaces unrecognized extension OIDs,
/// which is exactly what this one is).
fn checkAaguidExtension(cert: std.crypto.Certificate, expected_aaguid: [16]u8) AttestationError!void {
    const maybe_slice = x509.extensions.findExtensions(cert) catch return error.InvalidCertificate;
    const slice = maybe_slice orelse return; // v1/v2, or a v3 cert with no extensions field
    var it = x509.extensions.iterate(slice, cert);
    while (it.next() catch return error.InvalidCertificate) |entry| {
        if (!std.mem.eql(u8, entry.oid, &fido_gen_ce_aaguid_oid)) continue;
        // extnValue's content is itself `OCTET STRING (SIZE(16))` wrapping
        // the raw AAGUID (WebAuthn §8.2.1) — one more DER unwrap.
        const inner = x509.extensions.parseElement(entry.value, 0) catch return error.InvalidCertificate;
        if (inner.identifier.tag != .octetstring) return error.InvalidCertificate;
        const aaguid_bytes = entry.value[inner.slice.start..inner.slice.end];
        if (!std.mem.eql(u8, aaguid_bytes, &expected_aaguid)) return error.AaguidExtensionMismatch;
        return; // extension found and matches — done
    }
}

/// `expected_aaguid` is non-null only for `packed` (§8.2.1 names this
/// extension for that format specifically); `fido-u2f` (§8.6) has no such
/// requirement, so its call site passes `null` and this check is skipped.
fn verifyLeafCertSignature(leaf_der: []const u8, alg: i64, msg: []const u8, sig: []const u8, expected_aaguid: ?[16]u8) AttestationError!void {
    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(leaf_der, &scratch) catch return error.InvalidCertificate;
    const parsed = cert.parse() catch return error.InvalidCertificate;
    if (expected_aaguid) |aaguid| try checkAaguidExtension(cert, aaguid);
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
            // The same floor the CREDENTIAL key gets (audit W2 F7). The
            // asymmetry — enforced on one RSA key in this module and not the
            // other — was not a decision anyone recorded.
            if (pk.n.bits() < rs256_min_modulus_bits) return error.InvalidKey;
            rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig) catch return error.BadSignature;
        },
        .rsassa_pss => return error.UnsupportedAlgorithm,
    }
}

/// `attStmt.x5c[0]`. `require_single` implements §8.6 step 2 for `fido-u2f`
/// ("Check that x5c has exactly one element"); `packed` (§8.2) legitimately
/// carries the attestation certificate followed by its chain, so it passes
/// false. The empty-array guard is a memory-safety guard, not a policy one:
/// without it `arr[0]` on `x5c: []` is an out-of-bounds index — a Debug panic
/// and, in ReleaseFast, a read of whatever follows.
fn firstX5cDer(att_stmt: []const cbor.MapEntry, require_single: bool) AttestationError!?[]const u8 {
    const x5c_v = cborMapGetStr(att_stmt, "x5c") orelse return null;
    const arr = switch (x5c_v) {
        .array => |a| a,
        else => return error.WrongType,
    };
    if (arr.len == 0) return error.MissingField;
    if (require_single and arr.len != 1) return error.InvalidAttestationStatement;
    return switch (arr[0]) {
        .bytes => |b| b,
        else => error.WrongType,
    };
}

// ── DER helpers for the `apple` and `android-key` statements ─────────────────

/// One DER TLV: the tag as (class bits, constructed, number — high-tag-number form supported), its content and
/// what follows.
const Tlv = struct {
    class: u2,
    constructed: bool,
    tag: u32,
    content: []const u8,
    rest: []const u8,

    fn read(buf: []const u8) error{InvalidCertificate}!Tlv {
        if (buf.len < 2) return error.InvalidCertificate;
        var i: usize = 0;
        const b0 = buf[i];
        i += 1;
        var tag: u32 = b0 & 0x1f;
        if (tag == 0x1f) {
            tag = 0;
            while (true) {
                if (i >= buf.len or tag > (1 << 24)) return error.InvalidCertificate;
                const b = buf[i];
                i += 1;
                tag = (tag << 7) | (b & 0x7f);
                if (b & 0x80 == 0) break;
            }
        }
        if (i >= buf.len) return error.InvalidCertificate;
        var len: usize = buf[i];
        i += 1;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 4 or i + n > buf.len) return error.InvalidCertificate;
            len = 0;
            for (buf[i..][0..n]) |b| len = (len << 8) | b;
            i += n;
        }
        if (len > buf.len - i) return error.InvalidCertificate;
        return .{
            .class = @intCast(b0 >> 6),
            .constructed = b0 & 0x20 != 0,
            .tag = tag,
            .content = buf[i..][0..len],
            .rest = buf[i + len ..],
        };
    }

    fn universal(buf: []const u8, tag: u32) error{InvalidCertificate}!Tlv {
        const t = try read(buf);
        if (t.class != 0 or t.tag != tag) return error.InvalidCertificate;
        return t;
    }
};

fn derInteger(content: []const u8) error{InvalidCertificate}!i64 {
    if (content.len == 0 or content.len > 8) return error.InvalidCertificate;
    var v: i64 = if (content[0] & 0x80 != 0) -1 else 0;
    for (content) |b| v = (v << 8) | b;
    return v;
}

/// The `extnValue` content of the certificate extension with this DER-encoded OID content, or null.
fn certExtension(cert: std.crypto.Certificate, oid: []const u8) AttestationError!?[]const u8 {
    const maybe_slice = x509.extensions.findExtensions(cert) catch return error.InvalidCertificate;
    const slice = maybe_slice orelse return null;
    var it = x509.extensions.iterate(slice, cert);
    while (it.next() catch return error.InvalidCertificate) |entry| {
        if (std.mem.eql(u8, entry.oid, oid)) return entry.value;
    }
    return null;
}

/// True iff the certificate's subject public key is the credential public key (WebAuthn §8.4 / §8.8: the
/// attestation certificate attests the credential's own key).
fn certKeyIsCredentialKey(parsed: std.crypto.Certificate.Parsed, key: CoseKey) bool {
    switch (key) {
        .ec2 => |k| {
            if (parsed.pub_key_algo != .X9_62_id_ecPublicKey) return false;
            const want_len: usize = switch (k.crv) {
                cbor.cose.crv_p256 => 32,
                else => return false,
            };
            if (k.x.len != want_len or k.y.len != want_len) return false;
            const pk = parsed.pubKey();
            return pk.len == 1 + 2 * want_len and pk[0] == 0x04 and
                std.mem.eql(u8, pk[1..][0..want_len], k.x) and std.mem.eql(u8, pk[1 + want_len ..], k.y);
        },
        .okp => |k| {
            if (parsed.pub_key_algo != .curveEd25519) return false;
            return std.mem.eql(u8, parsed.pubKey(), k.x);
        },
        .rsa => |k| {
            if (parsed.pub_key_algo != .rsaEncryption) return false;
            const c = std.crypto.Certificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch return false;
            return std.mem.eql(u8, std.mem.trimStart(u8, c.modulus, "\x00"), std.mem.trimStart(u8, k.n, "\x00")) and
                std.mem.eql(u8, std.mem.trimStart(u8, c.exponent, "\x00"), std.mem.trimStart(u8, k.e, "\x00"));
        },
    }
}

/// `apple` anonymous attestation (WebAuthn §8.8): `attStmt = {x5c}`. The credential certificate carries, in the
/// extension 1.2.840.113635.100.8.2, `SEQUENCE { [1] EXPLICIT OCTET STRING nonce }` with
/// `nonce = SHA-256(authData || clientDataHash)`, and its public key is the credential public key. There is no
/// signature in the statement; trust is the chain to Apple's anonymization CA, which the caller checks
/// (`AttestationResult.leaf_cert_der`).
fn verifyApple(
    allocator: Allocator,
    att_stmt: []const cbor.MapEntry,
    obj: AttestationObject,
    att: AttestedCredentialData,
    client_data_hash: [32]u8,
) AttestationError!StatementResult {
    const leaf_der = (try firstX5cDer(att_stmt, false)) orelse return error.MissingField;
    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(leaf_der, &scratch) catch return error.InvalidCertificate;
    const parsed = cert.parse() catch return error.InvalidCertificate;

    const msg = try std.mem.concat(allocator, u8, &.{ obj.auth_data_raw, &client_data_hash });
    var nonce: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &nonce, .{});

    const ext = (try certExtension(cert, &apple_nonce_oid)) orelse return error.InvalidAttestationStatement;
    // SEQUENCE { [1] EXPLICIT { OCTET STRING } }
    const seq = Tlv.universal(ext, 0x10) catch return error.InvalidCertificate;
    const ctx = Tlv.read(seq.content) catch return error.InvalidCertificate;
    if (ctx.class != 2 or ctx.tag != 1 or !ctx.constructed or ctx.rest.len != 0 or seq.rest.len != 0) return error.InvalidCertificate;
    const oct = Tlv.universal(ctx.content, 0x04) catch return error.InvalidCertificate;
    if (oct.rest.len != 0) return error.InvalidCertificate;
    if (!std.mem.eql(u8, oct.content, &nonce)) return error.BadSignature;
    if (!certKeyIsCredentialKey(parsed, att.credential_public_key)) return error.InvalidAttestationStatement;
    return .{ .attestation_type = .anonymization_ca, .leaf_cert_der = leaf_der };
}

const apple_nonce_oid = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02 };
/// 1.3.6.1.4.1.11129.2.1.17, the Android Keystore attestation extension.
const android_key_description_oid = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11 };

/// What `android-key` needs out of one `AuthorizationList`: the `purpose` set, `origin`, and whether
/// `allApplications` is present.
const AuthList = struct {
    purpose_sign: bool = false,
    purpose_other: bool = false,
    origin: ?i64 = null,
    all_applications: bool = false,
};

fn readAuthList(content: []const u8, out: *AuthList) error{InvalidCertificate}!void {
    var rest = content;
    while (rest.len != 0) {
        const t = try Tlv.read(rest);
        rest = t.rest;
        if (t.class != 2 or !t.constructed) continue; // every AuthorizationList field is [n] EXPLICIT
        switch (t.tag) {
            1 => { // purpose: SET OF INTEGER
                const set = try Tlv.universal(t.content, 0x11);
                var items = set.content;
                while (items.len != 0) {
                    const it = try Tlv.universal(items, 0x02);
                    items = it.rest;
                    if ((try derInteger(it.content)) == 2) out.purpose_sign = true else out.purpose_other = true;
                }
            },
            702 => { // origin: INTEGER
                const v = try Tlv.universal(t.content, 0x02);
                out.origin = try derInteger(v.content);
            },
            600 => out.all_applications = true,
            else => {},
        }
    }
}

/// `android-key` attestation (WebAuthn §8.4): `attStmt = {alg, sig, x5c}`. The signature is over
/// `authData || clientDataHash` under the credential certificate's key, which must be the credential public key;
/// the certificate's Android KeyDescription extension carries `attestationChallenge == clientDataHash`, and in
/// `softwareEnforced` and `teeEnforced` taken together `allApplications` is absent, `origin` is
/// `KM_ORIGIN_GENERATED` (0) and `purpose` is exactly `{KM_PURPOSE_SIGN (2)}`. Which of the two lists vouches
/// for a property (hardware-backed or not) is the caller's policy: `leaf_cert_der` is returned for that.
fn verifyAndroidKey(
    allocator: Allocator,
    att_stmt: []const cbor.MapEntry,
    obj: AttestationObject,
    att: AttestedCredentialData,
    client_data_hash: [32]u8,
) AttestationError!StatementResult {
    const alg_v = cborMapGetStr(att_stmt, "alg") orelse return error.MissingField;
    const alg = alg_v.toI64() orelse return error.WrongType;
    const sig_v = cborMapGetStr(att_stmt, "sig") orelse return error.MissingField;
    const sig = switch (sig_v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const leaf_der = (try firstX5cDer(att_stmt, false)) orelse return error.MissingField;

    const msg = try std.mem.concat(allocator, u8, &.{ obj.auth_data_raw, &client_data_hash });
    try verifyLeafCertSignature(leaf_der, alg, msg, sig, null);

    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(leaf_der, &scratch) catch return error.InvalidCertificate;
    const parsed = cert.parse() catch return error.InvalidCertificate;
    if (!certKeyIsCredentialKey(parsed, att.credential_public_key)) return error.InvalidAttestationStatement;

    const ext = (try certExtension(cert, &android_key_description_oid)) orelse return error.InvalidAttestationStatement;
    // KeyDescription ::= SEQUENCE { attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
    //   keymasterVersion INTEGER, keymasterSecurityLevel ENUMERATED, attestationChallenge OCTET STRING,
    //   uniqueId OCTET STRING, softwareEnforced AuthorizationList, teeEnforced AuthorizationList }
    const seq = Tlv.universal(ext, 0x10) catch return error.InvalidCertificate;
    var rest = seq.content;
    var fields: [8]Tlv = undefined;
    for (&fields) |*f| {
        f.* = Tlv.read(rest) catch return error.InvalidCertificate;
        rest = f.rest;
    }
    if (fields[4].class != 0 or fields[4].tag != 0x04) return error.InvalidCertificate;
    if (!std.mem.eql(u8, fields[4].content, &client_data_hash)) return error.InvalidAttestationStatement;
    var al: AuthList = .{};
    readAuthList(fields[6].content, &al) catch return error.InvalidCertificate;
    readAuthList(fields[7].content, &al) catch return error.InvalidCertificate;
    if (al.all_applications) return error.InvalidAttestationStatement;
    if (al.origin == null or al.origin.? != 0) return error.InvalidAttestationStatement;
    if (!al.purpose_sign or al.purpose_other) return error.InvalidAttestationStatement;
    return .{ .attestation_type = .basic, .leaf_cert_der = leaf_der };
}

// ── tpm attestation (WebAuthn §8.3) ─────────────────────────────────────────

/// RS1 (RSASSA-PKCS1-v1_5 with SHA-1, COSE -65535): the algorithm TPM 1.2-era and many TPM 2.0 attestation statements
/// carry. Accepted for the `tpm` format only, where §8.3 names it; no credential key may use it.
const alg_rs1: i64 = -65535;

/// A big-endian TPM structure reader (TPM 2.0 Part 2 marshalling).
const TpmReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn bytes(self: *TpmReader, n: usize) error{InvalidAttestationStatement}![]const u8 {
        if (n > self.buf.len - self.pos) return error.InvalidAttestationStatement;
        const out = self.buf[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    fn int(self: *TpmReader, comptime T: type) error{InvalidAttestationStatement}!T {
        const b = try self.bytes(@sizeOf(T));
        return std.mem.readInt(T, b[0..@sizeOf(T)], .big);
    }

    /// TPM2B_*: a 16-bit size and that many bytes.
    fn tpm2b(self: *TpmReader) error{InvalidAttestationStatement}![]const u8 {
        return self.bytes(try self.int(u16));
    }

    fn done(self: *const TpmReader) bool {
        return self.pos == self.buf.len;
    }
};

const tpm_alg_null: u16 = 0x0010;
const tpm_alg_rsa: u16 = 0x0001;
const tpm_alg_ecc: u16 = 0x0023;
const tpm_generated_value: u32 = 0xff544347;
const tpm_st_attest_certify: u16 = 0x8017;

/// The hash of a TPM_ALG_ID (`nameAlg`), or null for one this module does not compute.
fn tpmNameHash(alg: u16, data: []const u8, out: *[64]u8) ?[]const u8 {
    switch (alg) {
        0x0004 => {
            std.crypto.hash.Sha1.hash(data, out[0..20], .{});
            return out[0..20];
        },
        0x000B => {
            std.crypto.hash.sha2.Sha256.hash(data, out[0..32], .{});
            return out[0..32];
        },
        0x000C => {
            std.crypto.hash.sha2.Sha384.hash(data, out[0..48], .{});
            return out[0..48];
        },
        0x000D => {
            std.crypto.hash.sha2.Sha512.hash(data, out[0..64], .{});
            return out[0..64];
        },
        else => return null,
    }
}

/// Skip a TPMT_*_SCHEME or TPMT_KDF_SCHEME: the scheme id, and its hash algorithm unless the scheme is NULL.
fn tpmSkipScheme(r: *TpmReader) error{InvalidAttestationStatement}!void {
    const scheme = try r.int(u16);
    if (scheme != tpm_alg_null) _ = try r.int(u16);
}

/// Parse a TPMT_PUBLIC (`pubArea`) and check that its `unique` is the credential public key (§8.3: "the credential
/// public key ... MUST match the unique field of pubArea"). Returns `nameAlg`.
fn checkTpmPubArea(pub_area: []const u8, key: CoseKey) AttestationError!u16 {
    var r: TpmReader = .{ .buf = pub_area };
    const ty = try r.int(u16);
    const name_alg = try r.int(u16);
    _ = try r.int(u32); // objectAttributes
    _ = try r.tpm2b(); // authPolicy
    switch (ty) {
        tpm_alg_rsa => {
            // TPMS_RSA_PARMS: symmetric (a signing key has none), scheme, keyBits, exponent.
            const sym = try r.int(u16);
            if (sym != tpm_alg_null) return error.InvalidAttestationStatement;
            try tpmSkipScheme(&r);
            _ = try r.int(u16); // keyBits
            const exp = try r.int(u32);
            const modulus = try r.tpm2b();
            if (!r.done()) return error.InvalidAttestationStatement;
            const rk = switch (key) {
                .rsa => |k| k,
                else => return error.InvalidAttestationStatement,
            };
            const want_e: u32 = if (exp == 0) 65537 else exp; // TPM2: 0 stands for 2^16 + 1
            var e: u64 = 0;
            for (std.mem.trimStart(u8, rk.e, "\x00")) |b| e = (e << 8) | b;
            if (std.mem.trimStart(u8, rk.e, "\x00").len > 4 or e != want_e) return error.InvalidAttestationStatement;
            if (!std.mem.eql(u8, std.mem.trimStart(u8, modulus, "\x00"), std.mem.trimStart(u8, rk.n, "\x00"))) return error.InvalidAttestationStatement;
        },
        tpm_alg_ecc => {
            // TPMS_ECC_PARMS: symmetric, scheme, curveID, kdf.
            const sym = try r.int(u16);
            if (sym != tpm_alg_null) return error.InvalidAttestationStatement;
            try tpmSkipScheme(&r);
            const curve = try r.int(u16);
            try tpmSkipScheme(&r); // kdf
            const x = try r.tpm2b();
            const y = try r.tpm2b();
            if (!r.done()) return error.InvalidAttestationStatement;
            const ec = switch (key) {
                .ec2 => |k| k,
                else => return error.InvalidAttestationStatement,
            };
            const want_curve: u16 = switch (ec.crv) {
                cbor.cose.crv_p256 => 0x0003,
                cbor.cose.crv_p384 => 0x0004,
                cbor.cose.crv_p521 => 0x0005,
                else => return error.InvalidAttestationStatement,
            };
            if (curve != want_curve) return error.InvalidAttestationStatement;
            if (!std.mem.eql(u8, x, ec.x) or !std.mem.eql(u8, y, ec.y)) return error.InvalidAttestationStatement;
        },
        else => return error.UnsupportedAlgorithm,
    }
    return name_alg;
}

/// Parse a TPMS_ATTEST (`certInfo`) and check §8.3's bindings: magic and type, `extraData` equal to the hash of
/// `attToBeSigned` (the hash of the statement's `alg`), and `attested.name` the `nameAlg` id followed by that hash of `pubArea`.
fn checkTpmCertInfo(cert_info: []const u8, pub_area: []const u8, name_alg: u16, extra_data_expected: []const u8) AttestationError!void {
    var r: TpmReader = .{ .buf = cert_info };
    if ((try r.int(u32)) != tpm_generated_value) return error.InvalidAttestationStatement;
    if ((try r.int(u16)) != tpm_st_attest_certify) return error.InvalidAttestationStatement;
    _ = try r.tpm2b(); // qualifiedSigner
    const extra = try r.tpm2b();
    if (!std.mem.eql(u8, extra, extra_data_expected)) return error.InvalidAttestationStatement;
    _ = try r.bytes(8 + 4 + 4 + 1); // clockInfo
    _ = try r.bytes(8); // firmwareVersion
    const name = try r.tpm2b(); // attested.name
    _ = try r.tpm2b(); // attested.qualifiedName
    if (!r.done()) return error.InvalidAttestationStatement;
    var digest: [64]u8 = undefined;
    const h = tpmNameHash(name_alg, pub_area, &digest) orelse return error.UnsupportedAlgorithm;
    if (name.len != 2 + h.len) return error.InvalidAttestationStatement;
    if (std.mem.readInt(u16, name[0..2], .big) != name_alg or !std.mem.eql(u8, name[2..], h)) return error.InvalidAttestationStatement;
}

/// 2.5.29.17 subjectAltName, 2.5.29.37 extKeyUsage, 2.5.29.19 basicConstraints.
const oid_san = [_]u8{ 0x55, 0x1D, 0x11 };
const oid_eku = [_]u8{ 0x55, 0x1D, 0x25 };
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };
/// 2.23.133.8.3 tcg-kp-AIKCertificate; 2.23.133.2.1 / .2 / .3 tcg-at-tpmManufacturer / -tpmModel / -tpmVersion.
const oid_tcg_kp_aik = [_]u8{ 0x67, 0x81, 0x05, 0x08, 0x03 };
const oid_tpm_manufacturer = [_]u8{ 0x67, 0x81, 0x05, 0x02, 0x01 };
const oid_tpm_model = [_]u8{ 0x67, 0x81, 0x05, 0x02, 0x02 };
const oid_tpm_version = [_]u8{ 0x67, 0x81, 0x05, 0x02, 0x03 };

/// §8.3 step "Verify that aikCert meets the requirements in §8.3.1": version 3, empty subject, a subjectAltName
/// carrying the TPM manufacturer, model and firmware version in a directoryName, extKeyUsage with
/// tcg-kp-AIKCertificate, and CA false; the id-fido-gen-ce-aaguid extension, if present, equals the AAGUID.
fn checkAikCertificate(cert: std.crypto.Certificate, parsed: std.crypto.Certificate.Parsed, aaguid: [16]u8) AttestationError!void {
    if (parsed.version != .v3) return error.InvalidAttestationStatement;
    if (parsed.subject().len != 0) return error.InvalidAttestationStatement;

    const san = (try certExtension(cert, &oid_san)) orelse return error.InvalidAttestationStatement;
    // GeneralNames ::= SEQUENCE OF GeneralName; the TPM attributes sit in a [4] directoryName.
    var seen_man = false;
    var seen_model = false;
    var seen_version = false;
    const names = Tlv.universal(san, 0x10) catch return error.InvalidCertificate;
    var rest = names.content;
    while (rest.len != 0) {
        const gn = Tlv.read(rest) catch return error.InvalidCertificate;
        rest = gn.rest;
        if (gn.class != 2 or gn.tag != 4 or !gn.constructed) continue;
        const name = Tlv.universal(gn.content, 0x10) catch return error.InvalidCertificate; // Name = SEQUENCE OF RDN
        var rdns = name.content;
        while (rdns.len != 0) {
            const rdn = Tlv.universal(rdns, 0x11) catch return error.InvalidCertificate;
            rdns = rdn.rest;
            var atvs = rdn.content;
            while (atvs.len != 0) {
                const atv = Tlv.universal(atvs, 0x10) catch return error.InvalidCertificate;
                atvs = atv.rest;
                const oid = Tlv.universal(atv.content, 0x06) catch return error.InvalidCertificate;
                if (std.mem.eql(u8, oid.content, &oid_tpm_manufacturer)) seen_man = true;
                if (std.mem.eql(u8, oid.content, &oid_tpm_model)) seen_model = true;
                if (std.mem.eql(u8, oid.content, &oid_tpm_version)) seen_version = true;
            }
        }
    }
    if (!(seen_man and seen_model and seen_version)) return error.InvalidAttestationStatement;

    const eku = (try certExtension(cert, &oid_eku)) orelse return error.InvalidAttestationStatement;
    const purposes = Tlv.universal(eku, 0x10) catch return error.InvalidCertificate;
    var aik = false;
    var p = purposes.content;
    while (p.len != 0) {
        const o = Tlv.universal(p, 0x06) catch return error.InvalidCertificate;
        p = o.rest;
        if (std.mem.eql(u8, o.content, &oid_tcg_kp_aik)) aik = true;
    }
    if (!aik) return error.InvalidAttestationStatement;

    if (try certExtension(cert, &oid_basic_constraints)) |bc| {
        const seq = Tlv.universal(bc, 0x10) catch return error.InvalidCertificate;
        if (seq.content.len != 0) {
            const first = Tlv.read(seq.content) catch return error.InvalidCertificate;
            if (first.class == 0 and first.tag == 0x01 and first.content.len == 1 and first.content[0] != 0) return error.InvalidAttestationStatement;
        }
    }
    try checkAaguidExtension(cert, aaguid);
}

/// `tpm` attestation (WebAuthn §8.3): `attStmt = {ver: "2.0", alg, x5c, sig, certInfo, pubArea}`. `pubArea`'s `unique`
/// is the credential public key; `certInfo` is a TPMS_ATTEST of type CERTIFY whose `extraData` is the hash of
/// `authData || clientDataHash` (the hash of `alg`: SHA-1 for RS1, SHA-256 for RS256 / ES256) and whose attested
/// `name` is `nameAlg || H(pubArea)`; `sig` is the AIK certificate key's signature over `certInfo` (RS1, RS256 or ES256);
/// and the AIK certificate meets §8.3.1. Trust is the chain to the attestation CA: `AttestationResult.leaf_cert_der`
/// (`verifyAttestationChain`). ECDAA (removed from the specification) is not supported.
fn verifyTpm(
    allocator: Allocator,
    att_stmt: []const cbor.MapEntry,
    obj: AttestationObject,
    att: AttestedCredentialData,
    client_data_hash: [32]u8,
) AttestationError!StatementResult {
    const ver = cborMapGetStr(att_stmt, "ver") orelse return error.MissingField;
    switch (ver) {
        .text => |t| if (!std.mem.eql(u8, t, "2.0")) return error.InvalidAttestationStatement,
        else => return error.WrongType,
    }
    const alg = (cborMapGetStr(att_stmt, "alg") orelse return error.MissingField).toI64() orelse return error.WrongType;
    const sig = switch (cborMapGetStr(att_stmt, "sig") orelse return error.MissingField) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const cert_info = switch (cborMapGetStr(att_stmt, "certInfo") orelse return error.MissingField) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const pub_area = switch (cborMapGetStr(att_stmt, "pubArea") orelse return error.MissingField) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const leaf_der = (try firstX5cDer(att_stmt, false)) orelse return error.MissingField;

    const name_alg = try checkTpmPubArea(pub_area, att.credential_public_key);
    const to_be_signed = try std.mem.concat(allocator, u8, &.{ obj.auth_data_raw, &client_data_hash });
    var extra: [32]u8 = undefined;
    var extra_len: usize = 32;
    switch (alg) {
        alg_rs1 => {
            std.crypto.hash.Sha1.hash(to_be_signed, extra[0..20], .{});
            extra_len = 20;
        },
        alg_rs256, cbor.cose.alg_es256 => std.crypto.hash.sha2.Sha256.hash(to_be_signed, &extra, .{}),
        else => return error.UnsupportedAlgorithm,
    }
    try checkTpmCertInfo(cert_info, pub_area, name_alg, extra[0..extra_len]);

    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(leaf_der, &scratch) catch return error.InvalidCertificate;
    const parsed = cert.parse() catch return error.InvalidCertificate;
    switch (parsed.pub_key_algo) {
        .rsaEncryption => {
            const components = std.crypto.Certificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch return error.InvalidCertificate;
            const pk = rsa.PublicKey.fromBytes(components.modulus, components.exponent) catch return error.InvalidKey;
            if (pk.n.bits() < rs256_min_modulus_bits) return error.InvalidKey;
            switch (alg) {
                alg_rs1 => rsa.verifyPkcs1v15(pk, std.crypto.hash.Sha1, cert_info, sig) catch return error.BadSignature,
                alg_rs256 => rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, cert_info, sig) catch return error.BadSignature,
                else => return error.UnsupportedAlgorithm,
            }
        },
        .X9_62_id_ecPublicKey => |named_curve| {
            if (named_curve != .X9_62_prime256v1 or alg != cbor.cose.alg_es256) return error.UnsupportedAlgorithm;
            const parsed_sig = p256.EcdsaP256Sha256.Signature.fromDer(sig) catch return error.InvalidSignature;
            if (!p256.sign.ecdsaVerify(parsed.pubKey(), cert_info, parsed_sig.toBytes())) return error.BadSignature;
        },
        else => return error.UnsupportedAlgorithm,
    }
    try checkAikCertificate(cert, parsed, att.aaguid);
    return .{ .attestation_type = .attestation_ca, .leaf_cert_der = leaf_der };
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
fn verifyPacked(att_stmt: []const cbor.MapEntry, msg: []const u8, credential_key: CoseKey, aaguid: [16]u8) AttestationError!StatementResult {
    const alg_v = cborMapGetStr(att_stmt, "alg") orelse return error.MissingField;
    const alg = alg_v.toI64() orelse return error.WrongType;
    const sig_v = cborMapGetStr(att_stmt, "sig") orelse return error.MissingField;
    const sig = switch (sig_v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };

    if (try firstX5cDer(att_stmt, false)) |leaf_der| {
        try verifyLeafCertSignature(leaf_der, alg, msg, sig, aaguid);
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
    const leaf_der = (try firstX5cDer(att_stmt, true)) orelse return error.MissingField;

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

    try verifyLeafCertSignature(leaf_der, cbor.cose.alg_es256, verification_data, sig, null);
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
        return verifyPacked(obj.att_stmt, msg, att.credential_public_key, att.aaguid);
    } else if (std.mem.eql(u8, obj.fmt, "fido-u2f")) {
        return verifyFidoU2f(allocator, obj.att_stmt, obj.auth_data, client_data_hash);
    } else if (std.mem.eql(u8, obj.fmt, "apple")) {
        return verifyApple(allocator, obj.att_stmt, obj, att, client_data_hash);
    } else if (std.mem.eql(u8, obj.fmt, "android-key")) {
        return verifyAndroidKey(allocator, obj.att_stmt, obj, att, client_data_hash);
    } else if (std.mem.eql(u8, obj.fmt, "tpm")) {
        return verifyTpm(allocator, obj.att_stmt, obj, att, client_data_hash);
    }
    return error.UnsupportedFormat; // anything unrecognized
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

// ── attestation trust chain ─────────────────────────────────────────────────

pub const ChainError = error{
    /// The attestation statement has no `x5c` (`none`, self attestation): there is no certificate to chain.
    NoCertificateChain,
} || AttestationObjectError || AuthDataError || x509.VerifyChainError;

/// Chain the attestation certificates of `attestation_object_raw` (`attStmt.x5c`, leaf first) to the caller's
/// `trust_anchors` with `x509.verifyChain` and return what it verified. This is the "is the attestation signed
/// by a CA I trust" half that `verifyAttestation` deliberately leaves out (`.basic` only means the statement
/// is internally consistent): call it after `verifyAttestation` / `verifyRegistration` succeeded, with the
/// anchors for the authenticator vendors the RP accepts (an MDS-derived store, or a pinned set). Fetching and
/// refreshing that store, and the validity time in `opts`, are the caller's. Free the result as
/// `x509.VerifiedChain` documents.
pub fn verifyAttestationChain(
    allocator: Allocator,
    attestation_object_raw: []const u8,
    trust_anchors: []const []const u8,
    opts: x509.Options,
) ChainError!x509.VerifiedChain {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const obj = try parseAttestationObject(a, attestation_object_raw);
    const x5c_v = cborMapGetStr(obj.att_stmt, "x5c") orelse return error.NoCertificateChain;
    const arr = switch (x5c_v) {
        .array => |arr| arr,
        else => return error.WrongType,
    };
    if (arr.len == 0) return error.NoCertificateChain;
    const certs = try a.alloc([]const u8, arr.len);
    for (arr, certs) |v, *c| c.* = switch (v) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    return x509.verifyChain(allocator, certs, trust_anchors, opts);
}

// ── authenticator and client extension outputs ──────────────────────────────

/// `credProtect` policy (CTAP 2.1 §12.1): the credential's protection level.
pub const CredProtect = enum(u8) {
    user_verification_optional = 1,
    user_verification_optional_with_credential_id_list = 2,
    user_verification_required = 3,
    _,
};

/// `hmac-secret` output: at registration a boolean (the authenticator supports it for this credential), at
/// assertion the encrypted HMAC outputs (decrypting them is the client's, with the shared secret).
pub const HmacSecretOutput = union(enum) {
    supported: bool,
    encrypted: []const u8,
};

/// The authenticator extension outputs this module understands; any other entry is ignored.
pub const ExtensionOutputs = struct {
    cred_protect: ?CredProtect = null,
    hmac_secret: ?HmacSecretOutput = null,
};

pub const ExtensionError = error{ WrongType, OutOfMemory } || cbor.DecodeError;

/// Decode `AuthenticatorData.extensions` (the raw CBOR map) into typed outputs. A recognized key with a value
/// of the wrong CBOR type is `error.WrongType`; unknown keys are skipped. `bytes` of `hmac_secret.encrypted`
/// are borrowed from `allocator`.
pub fn parseExtensionOutputs(allocator: Allocator, raw: []const u8) ExtensionError!ExtensionOutputs {
    const v = try cbor.decode(allocator, raw, .{});
    const entries = switch (v) {
        .map => |m| m,
        else => return error.WrongType,
    };
    var out: ExtensionOutputs = .{};
    if (cborMapGetStr(entries, "credProtect")) |cp| {
        const n = switch (cp) {
            .uint => |u| u,
            else => return error.WrongType,
        };
        if (n > 255) return error.WrongType;
        out.cred_protect = @fromBackingInt(@intCast(@as(u8, @intCast(n))));
    }
    if (cborMapGetStr(entries, "hmac-secret")) |hs| {
        out.hmac_secret = switch (hs) {
            .bool => |b| .{ .supported = b },
            .bytes => |b| .{ .encrypted = b },
            else => return error.WrongType,
        };
    }
    return out;
}

/// Client extension results (`getClientExtensionResults()` serialized as JSON) this module reads.
pub const ClientExtensionResults = struct {
    /// `credProps.rk`: whether the credential is client-side discoverable (a passkey); null when not reported.
    cred_props_rk: ?bool = null,
};

/// Parse the JSON of `getClientExtensionResults()`. Unknown members are ignored; a `credProps.rk` that is not a
/// boolean is `error.InvalidJson`.
pub fn parseClientExtensionResults(allocator: Allocator, json: []const u8) ClientDataError!ClientExtensionResults {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidJson,
    };
    var out: ClientExtensionResults = .{};
    if (root.get("credProps")) |cp| {
        const o = switch (cp) {
            .object => |o| o,
            else => return error.InvalidJson,
        };
        if (o.get("rk")) |rk| out.cred_props_rk = switch (rk) {
            .bool => |b| b,
            else => return error.InvalidJson,
        };
    }
    return out;
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
    /// The credential's COSE algorithm is not in
    /// `RegistrationOptions.allowed_algorithms` (§7.1 step 14).
    AlgorithmNotAllowed,
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
    ///
    /// Satisfied by `.basic` **only**. `.self_attestation` is signed by the
    /// credential's own key and carries no certificate, so it proves nothing
    /// about the authenticator and leaves nothing to chain.
    require_attestation: bool = false,
    /// §7.1 step 14: the COSE algorithms this RP offered in
    /// `pubKeyCredParams`. `null` (the default) skips the step, which is what
    /// this module did unconditionally before — every algorithm it supports
    /// is an acceptable one, so the practical impact is small, but a caller
    /// that offered only ES256 had no way to insist on it. Example:
    /// `.allowed_algorithms = &.{ cbor.cose.alg_es256 }`.
    allowed_algorithms: ?[]const i64 = null,
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
    // `.self_attestation` is signed by the credential's own key, so anything
    // an attacker generates in a browser satisfies it — it proves nothing
    // about the authenticator, and it carries no `leaf_cert_der`, so the
    // follow-up this option's own doc recommends ("then also chain the leaf
    // certificate") is not even available. A caller who only checks that
    // `require_attestation` passed had gained exactly nothing over `none`.
    if (options.require_attestation and statement.attestation_type != .basic) {
        return error.AttestationNotProvided;
    }
    // §7.1 step 14: the credential's algorithm must be one the RP offered in
    // `pubKeyCredParams`. Unenforceable before — there was no way to express
    // the list — so an authenticator could register under any algorithm this
    // module supports regardless of what was asked for.
    if (options.allowed_algorithms) |allowed| {
        const alg = att.credential_public_key.alg() orelse return error.AlgorithmNotAllowed;
        for (allowed) |a| {
            if (a == alg) break;
        } else return error.AlgorithmNotAllowed;
    }

    return attestationResult(obj, att, statement);
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = @import("clientdata_test.zig");
    _ = @import("assertion_test.zig");
    _ = @import("attestation_test.zig");
    _ = @import("fuzz_test.zig");
}

test "smoke: module compiles and CoseKey.alg dispatch works" {
    const key: CoseKey = .{ .ec2 = .{ .alg = cbor.cose.alg_es256, .crv = cbor.cose.crv_p256, .x = &@as([32]u8, @splat(0)), .y = &@as([32]u8, @splat(0)) } };
    try std.testing.expectEqual(@as(?i64, cbor.cose.alg_es256), key.alg());
}

// Regression (audit W2 `webauthn` F7): an RS256 CREDENTIAL key below the
// 2048-bit floor every conforming WebAuthn/FIDO2 authenticator actually
// generates must be rejected — `rsa.PublicKey.fromBytes`'s own floor (1024)
// is a generic RSA-primitive bound, not a WebAuthn policy, so a genuinely
// well-formed (real prime-product, real signature) 1024-bit key must still be
// refused HERE. Uses a real generated key + real signature — not a malformed
// blob — so the rejection is specifically the modulus-size policy, not
// `InvalidKey`/`BadSignature` for an unrelated reason.
test "F7: an RS256 credential key below 2048 bits is rejected, not merely small-but-valid" {
    var prng = std.Random.DefaultPrng.init(0x7732_5f66_375f_6b65); // "w2_f7_ke" tests only
    const random = prng.random();

    // 1024 bits: passes rsa's own floor (1024) and is a completely valid,
    // freshly generated RSA key — the ONLY thing wrong with it is its size.
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, random, 1024, 65537);
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    kp.public_key.n.toBytes(&n_buf, .big) catch unreachable;
    var e_buf: [rsa.max_modulus_len]u8 = undefined;
    kp.public_key.e.toBytes(&e_buf, .big) catch unreachable;

    const msg = "webauthn F7 regression";
    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig = try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.sha2.Sha256, msg, &sig_buf);

    // Sanity: `rsa` itself is happy with this key (it is a real, valid
    // 1024-bit RSA key and a real signature) — proves the rejection below
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

// ⚠ Both harnesses used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain -- so `len` was 0 for
// every input a corpus can carry and both parsers were handed an EMPTY slice
// with the blob sitting unread in `buf`. One `slice` draw reads the corpus
// entry's own length header and hands the bytes over intact.
//
// ⛔ The buffers were also too small for this module's own W3C vectors, in
// both harnesses. `clientDataJSON` is 255 octets in four of the six vectors,
// against a 256-octet buffer -- one field name of margin. And a registration
// `authenticatorData` carrying attested credential data is
// 32+1+4+16+2+32 = 87 octets of framing plus the COSE key, which is 452 octets
// for RS256: 539 in total, more than DOUBLE the old buffer. A seed longer than
// the buffer does not arrive truncated -- `Smith.slice` falls back to the range
// minimum and it arrives EMPTY -- so the RS256 registration blob, the largest
// thing this parser will ever see in production, could not have passed through
// its own harness. 512 and 1024 now.

/// `testkit.fuzz.seed`, aliased so the corpora below read as the
/// clientDataJSON documents and authenticatorData blobs they are. A corpus
/// entry is not the frame: the length draw reads a little-endian `u32` first,
/// so a raw blob would arrive minus its own first four octets -- for
/// authenticatorData, minus four octets of the RP ID hash, which no length
/// check would ever notice. `testkit/src/fuzz.zig` carries the other two
/// hazards.
const seed = @import("testkit").fuzz.seed;
const fuzz_vectors = @import("vectors.zig");

/// clientDataJSON documents, in the format the length draw reads. The real ones
/// are added at run time from the W3C §16 vectors; these are the shapes a
/// malicious page supplies.
const client_data_reject_seeds = [_][]const u8{
    seed("{\"type\":\"webauthn.create\",\"challenge\":\"AAAA\",\"origin\":\"https://example.org\"}"), // the minimal accepted document
    seed("{\"type\":\"webauthn.get\",\"challenge\":\"AAAA\",\"origin\":\"https://example.org\",\"crossOrigin\":true}"), // crossOrigin present and true
    seed("{\"type\":\"webauthn.create\",\"challenge\":\"\",\"origin\":\"\"}"), // an EMPTY challenge is still a legal base64url string
    seed("{\"type\":\"webauthn.create\",\"challenge\":\"AAAA\",\"origin\":\"https://example.org\",\"unknown\":[1,2]}"), // ignore_unknown_fields
    seed("{\"challenge\":\"AAAA\",\"origin\":\"o\"}"), // `type` missing: a required member
    seed("{\"type\":\"webauthn.create\",\"origin\":\"o\"}"), // `challenge` missing
    seed("{\"type\":\"webauthn.create\",\"challenge\":\"AAAA\"}"), // `origin` missing
    seed("{\"type\":42,\"challenge\":\"AAAA\",\"origin\":\"o\"}"), // `type` wrong-typed
    seed("{\"type\":\"t\",\"challenge\":\"AAAA\",\"origin\":\"o\",\"crossOrigin\":\"yes\"}"), // crossOrigin wrong-typed
    seed("{\"type\":\"t\",\"challenge\":\"A\",\"origin\":\"o\"}"), // a base64url length of 1: never valid
    seed("{\"type\":\"t\",\"challenge\":\"A+/A\",\"origin\":\"o\"}"), // '+' and '/' are the STANDARD alphabet, not url-safe
    seed("{\"type\":\"t\",\"challenge\":\"AAA=\",\"origin\":\"o\"}"), // padding, which the no-pad decoder refuses
    seed("{\"type\":\"t\",\"challenge\":\"!!!!\",\"origin\":\"o\"}"), // outside any base64 alphabet
    seed("[1,2,3]"), // valid JSON, not an object
    seed("{"), // truncated JSON
    seed("not json at all"), // not JSON
    seed(""), // the empty document
};

/// The whole corpus: the shapes above plus every real clientDataJSON the module
/// owns, registration and assertion.
///
/// ⭐ The harness and the guard below both build it from HERE -- a guard
/// measuring a different corpus from the one the harness gets is not a guard.
const ClientDataCorpus = struct {
    stores: [4][4 + 512]u8 = undefined,
    entries: [client_data_reject_seeds.len + 4][]const u8 = undefined,

    fn build(self: *ClientDataCorpus) []const []const u8 {
        @memcpy(self.entries[0..client_data_reject_seeds.len], &client_data_reject_seeds);
        const real = [_][]const u8{
            &fuzz_vectors.none_es256.registration_client_data_json,
            &fuzz_vectors.none_es256.assertion_client_data_json,
            &fuzz_vectors.packed_rs256.registration_client_data_json,
            &fuzz_vectors.fido_u2f_es256.assertion_client_data_json,
        };
        for (real, 0..) |doc, i| {
            self.entries[client_data_reject_seeds.len + i] =
                @import("testkit").fuzz.seedInto(&self.stores[i], doc);
        }
        return &self.entries;
    }
};

test "fuzz: parseClientData never panics on arbitrary JSON" {
    var corpus: ClientDataCorpus = .{};
    try std.testing.fuzz({}, fuzzParseClientData, .{ .corpus = corpus.build() });
}

fn fuzzParseClientData(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = parseClientData(arena.allocator(), buf[0..len]) catch return;
}

test "corpus: every clientData seed reaches the parser, and the challenge octets are pinned" {
    // ⛔ `accepted > 0` is not a guard here. `{"type":"t","challenge":"",
    // "origin":""}` parses cleanly -- an empty challenge is a legal base64url
    // string -- so a corpus of empty-field documents would read 100% accepted
    // while the base64url decoder never produced a byte. `challenge_octets` is
    // the number an empty or defaulted document cannot produce, and the
    // base64url decode is the only place in this function that can fail after
    // the JSON parse.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var challenge_octets: usize = 0;
    var cross_origin_seen: usize = 0;
    var corpus: ClientDataCorpus = .{};
    const entries = corpus.build();
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const cd = parseClientData(arena.allocator(), buf[0..len]) catch continue;
        accepted += 1;
        challenge_octets += cd.challenge.len;
        if (cd.cross_origin != null) cross_origin_seen += 1;
    }
    // One seed is deliberately the empty document.
    try std.testing.expectEqual(entries.len - 1, nonempty);
    // Measured: 0 of 21 seeds non-empty, 0 accepted, 0 challenge
    // octets before the draw was fixed.
    try std.testing.expectEqual(@as(usize, 8), accepted);
    try std.testing.expectEqual(@as(usize, 137), challenge_octets);
    try std.testing.expectEqual(@as(usize, 5), cross_origin_seen);
}

/// authenticatorData blobs, in the format the length draw reads. Real
/// registration blobs -- the ones carrying attested credential data and a COSE
/// key -- are assembled at run time from the vectors below.
const auth_data_reject_seeds = [_][]const u8{
    seed(""), // empty
    seed(strRepeat("\xCC", 36)), // one octet short of the fixed 37-octet header
    seed(strRepeat("\xCC", 32) ++ "\x01\x00\x00\x00\x00"), // the minimum: UP set, no attested credential data
    seed(strRepeat("\xCC", 32) ++ "\x01\x01\x02\x03\x04"), // an asymmetric signCount, for the big-endian read
    seed(strRepeat("\xCC", 32) ++ "\x00\x00\x00\x00\x00"), // UP clear: structurally fine, refused a layer up
    seed(strRepeat("\xCC", 32) ++ "\x81\x00\x00\x00\x00"), // the ED flag with no extension data
    seed(strRepeat("\xCC", 32) ++ "\x41\x00\x00\x00\x00"), // the AT flag with NO attested credential data behind it
    seed(strRepeat("\xCC", 32) ++ "\x41\x00\x00\x00\x00" ++ strRepeat("\x00", 16)), // AT, an AAGUID, and nothing else
    seed(strRepeat("\xCC", 32) ++ "\x41\x00\x00\x00\x00" ++ strRepeat("\x00", 16) ++ "\xff\xff"), // a credential-id length of 65535
    seed(strRepeat("\xCC", 32) ++ "\x41\x00\x00\x00\x00" ++ strRepeat("\x00", 16) ++ "\x00\x04" ++ "\xaa\xbb\xcc\xdd"), // a 4-octet credential id and no COSE key
    seed(strRepeat("\xCC", 32) ++ "\xc1\x00\x00\x00\x00" ++ strRepeat("\x00", 16) ++ "\x00\x01\xaa\xa0"), // AT and ED, an empty map where the COSE key belongs
    seed(strRepeat("\x00", 300)), // 300 zero octets: no AT/ED flag, so 263 trailing octets (TrailingData since 2026-09-30)
    seed(strRepeat("\xCC", 32) ++ "\x81\x00\x00\x00\x07" ++ "\xa1\x61x\x01"), // UP|ED and a one-entry extensions map {"x": 1}: accepted
};

/// The whole corpus: the shapes above plus a real registration
/// authenticatorData per COSE key type, assembled from the vectors as
/// `rp_id_hash || flags || signCount || aaguid || credIdLen || credId ||
/// coseKey` (WebAuthn §6.1 / §6.5.1).
///
/// ⭐ Assembled rather than pasted: the credential ids and COSE keys are the
/// vectors' own, so the corpus follows them instead of freezing a copy. The
/// RS256 entry is 539 octets and is the one that did not fit the old buffer.
const AuthDataCorpus = struct {
    frames: [3][1024]u8 = undefined,
    stores: [3][4 + 1024]u8 = undefined,
    entries: [auth_data_reject_seeds.len + 3][]const u8 = undefined,

    fn build(self: *AuthDataCorpus) []const []const u8 {
        @memcpy(self.entries[0..auth_data_reject_seeds.len], &auth_data_reject_seeds);
        const parts = [_]struct { id: []const u8, key: []const u8 }{
            .{ .id = &fuzz_vectors.none_es256.credential_id, .key = &fuzz_vectors.none_es256.credential_public_key },
            .{ .id = &fuzz_vectors.packed_rs256.credential_id, .key = &fuzz_vectors.packed_rs256.credential_public_key },
            .{ .id = &fuzz_vectors.packed_eddsa.credential_id, .key = &fuzz_vectors.packed_eddsa.credential_public_key },
        };
        for (parts, 0..) |part, i| {
            const f = &self.frames[i];
            @memset(f[0..32], 0xBF); // rp_id_hash
            f[32] = 0x41; // UP | AT
            @memset(f[33..37], 0);
            @memset(f[37..53], 0x84); // aaguid
            std.mem.writeInt(u16, f[53..55], @intCast(part.id.len), .big);
            var n: usize = 55;
            @memcpy(f[n..][0..part.id.len], part.id);
            n += part.id.len;
            @memcpy(f[n..][0..part.key.len], part.key);
            n += part.key.len;
            self.entries[auth_data_reject_seeds.len + i] =
                @import("testkit").fuzz.seedInto(&self.stores[i], f[0..n]);
        }
        return &self.entries;
    }
};

test "fuzz: parseAuthenticatorData never panics on arbitrary bytes" {
    var corpus: AuthDataCorpus = .{};
    try std.testing.fuzz({}, fuzzParseAuthenticatorData, .{ .corpus = corpus.build() });
}

fn fuzzParseAuthenticatorData(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = parseAuthenticatorData(arena.allocator(), buf[0..len]) catch return;
}

test "corpus: every authData seed reaches the parser, and the credentials parsed are pinned" {
    // ⛔ `accepted > 0` would be satisfied by 37 octets of anything: a blob
    // with the AT flag clear is a perfectly legal assertion authenticatorData
    // and parses with `attested_credential_data == null`. So the guard pins
    // `with_credential` and `credential_octets` -- the attested credential data
    // and its embedded COSE key, which is where every length arithmetic in this
    // parser lives and which no short blob can produce.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var with_credential: usize = 0;
    var credential_octets: usize = 0;
    var corpus: AuthDataCorpus = .{};
    const entries = corpus.build();
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const ad = parseAuthenticatorData(arena.allocator(), buf[0..len]) catch continue;
        accepted += 1;
        const acd = ad.attested_credential_data orelse continue;
        with_credential += 1;
        credential_octets += acd.credential_id.len;
    }
    // One seed is deliberately empty.
    try std.testing.expectEqual(entries.len - 1, nonempty);
    // Measured: 0 of 15 seeds non-empty and every counter 0 before
    // the draw was fixed.
    try std.testing.expectEqual(@as(usize, 7), accepted);
    try std.testing.expectEqual(@as(usize, 3), with_credential);
    try std.testing.expectEqual(@as(usize, 96), credential_octets);
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

    try raw.appendSlice(a, &(@as([32]u8, @splat(0xCC)))); // rp_id_hash
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

/// Hand-builds a minimal DER `Certificate` for `checkAaguidExtension` (audit
/// `webauthn` F4): `x509.extensions.findExtensions` only needs a
/// structurally valid path down to the `[3] EXPLICIT` extensions field (RFC
/// 5280 §4.1) — issuer/validity/subject/subjectPublicKeyInfo can be empty
/// SEQUENCEs, since nothing here calls `cert.parse()` (which would reject
/// them). `ext_aaguid` non-null embeds one id-fido-gen-ce-aaguid extension
/// carrying that value; `null` omits the extensions field entirely.
fn buildMinimalCertWithAaguidExt(buf: []u8, ext_aaguid: ?[16]u8) []const u8 {
    const version = [_]u8{ 0xA0, 0x03, 0x02, 0x01, 0x02 }; // [0] EXPLICIT INTEGER 2 (v3)
    const serial = [_]u8{ 0x02, 0x01, 0x01 }; // INTEGER 1
    const sig_alg = [_]u8{ 0x30, 0x03, 0x06, 0x01, 0x2A }; // SEQUENCE { OID }
    const empty_seq = [_]u8{ 0x30, 0x00 }; // issuer / validity / subject / spki

    var tbs_inner: [128]u8 = undefined;
    var t: usize = 0;
    @memcpy(tbs_inner[t..][0..version.len], &version);
    t += version.len;
    @memcpy(tbs_inner[t..][0..serial.len], &serial);
    t += serial.len;
    @memcpy(tbs_inner[t..][0..sig_alg.len], &sig_alg);
    t += sig_alg.len;
    inline for (0..4) |_| { // issuer, validity, subject, subjectPublicKeyInfo
        @memcpy(tbs_inner[t..][0..empty_seq.len], &empty_seq);
        t += empty_seq.len;
    }

    if (ext_aaguid) |aaguid| {
        var ext_entry: [64]u8 = undefined;
        var e: usize = 0;
        ext_entry[e] = 0x06; // extnID OBJECT IDENTIFIER
        e += 1;
        ext_entry[e] = @intCast(fido_gen_ce_aaguid_oid.len);
        e += 1;
        @memcpy(ext_entry[e..][0..fido_gen_ce_aaguid_oid.len], &fido_gen_ce_aaguid_oid);
        e += fido_gen_ce_aaguid_oid.len;
        ext_entry[e] = 0x04; // extnValue OCTET STRING, content = OCTET STRING(16)
        e += 1;
        ext_entry[e] = 2 + 16;
        e += 1;
        ext_entry[e] = 0x04;
        e += 1;
        ext_entry[e] = 16;
        e += 1;
        @memcpy(ext_entry[e..][0..16], &aaguid);
        e += 16;

        var extension: [80]u8 = undefined;
        extension[0] = 0x30; // Extension SEQUENCE
        extension[1] = @intCast(e);
        @memcpy(extension[2..][0..e], ext_entry[0..e]);
        const ext_len = 2 + e;

        var extensions_seq: [90]u8 = undefined;
        extensions_seq[0] = 0x30; // Extensions ::= SEQUENCE OF Extension
        extensions_seq[1] = @intCast(ext_len);
        @memcpy(extensions_seq[2..][0..ext_len], extension[0..ext_len]);
        const eseq_len = 2 + ext_len;

        tbs_inner[t] = 0xA3; // [3] EXPLICIT
        t += 1;
        tbs_inner[t] = @intCast(eseq_len);
        t += 1;
        @memcpy(tbs_inner[t..][0..eseq_len], extensions_seq[0..eseq_len]);
        t += eseq_len;
    }

    var tbs: [140]u8 = undefined;
    tbs[0] = 0x30; // tbsCertificate SEQUENCE
    tbs[1] = @intCast(t);
    @memcpy(tbs[2..][0..t], tbs_inner[0..t]);
    const tbs_len = 2 + t;

    buf[0] = 0x30; // Certificate SEQUENCE (no signatureAlgorithm/signature —
    buf[1] = @intCast(tbs_len); // findExtensions never looks past tbsCertificate)
    @memcpy(buf[2..][0..tbs_len], tbs[0..tbs_len]);
    return buf[0 .. 2 + tbs_len];
}

test "F4: checkAaguidExtension enforces WebAuthn §8.2.1's id-fido-gen-ce-aaguid binding" {
    const aaguid = [16]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    var mismatched = aaguid;
    mismatched[7] ^= 0xFF; // single-byte mutation: same length, different value

    var buf: [256]u8 = undefined;

    // Positive control: a certificate whose extension MATCHES authData's
    // aaguid must be accepted. This one must survive.
    {
        const der_bytes = buildMinimalCertWithAaguidExt(&buf, aaguid);
        const cert: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
        try checkAaguidExtension(cert, aaguid);
    }
    // RED: a certificate that names a DIFFERENT AAGUID than authData claims
    // must be rejected, not silently accepted -- this is the binding F4
    // found completely unchecked.
    {
        const der_bytes = buildMinimalCertWithAaguidExt(&buf, mismatched);
        const cert: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
        try std.testing.expectError(error.AaguidExtensionMismatch, checkAaguidExtension(cert, aaguid));
    }
    // §8.2.1 does not require the extension -- its absence must not be an
    // error either.
    {
        const der_bytes = buildMinimalCertWithAaguidExt(&buf, null);
        const cert: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
        try checkAaguidExtension(cert, aaguid);
    }
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "parseCredentialKey: an RSA key's alg, n and e must have their COSE types" {
    const bytes_v: cbor.Value = .{ .bytes = &.{ 1, 2, 3 } };
    var entries = [_]cbor.MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 3 } }, // kty RSA
        .{ .key = .{ .uint = 3 }, .value = .{ .text = "RS256" } }, // alg: not an integer
        .{ .key = .{ .negint = 0 }, .value = bytes_v }, // -1: n
        .{ .key = .{ .negint = 1 }, .value = bytes_v }, // -2: e
    };
    try std.testing.expectError(error.WrongType, parseCredentialKey(.{ .map = &entries }));
    entries[1].value = .{ .negint = 256 }; // alg -257
    const k = try parseCredentialKey(.{ .map = &entries });
    try std.testing.expectEqual(@as(?i64, alg_rs256), k.rsa.alg);
    entries[2].value = .{ .uint = 5 };
    try std.testing.expectError(error.WrongType, parseCredentialKey(.{ .map = &entries }));
    entries[2].value = bytes_v;
    entries[3].value = .{ .uint = 5 };
    try std.testing.expectError(error.WrongType, parseCredentialKey(.{ .map = &entries }));
}

test "parseAuthenticatorData: a credential id cut short by one octet is Truncated, not read past" {
    // 37-octet header, AAGUID, credentialIdLength = 5, then only 4 id octets.
    var raw = @as([59]u8, @splat(0));
    raw[32] = 0x41; // UP | AT
    raw[54] = 5;
    try std.testing.expectError(error.Truncated, parseAuthenticatorData(std.testing.allocator, &raw));
}
