// SPDX-License-Identifier: MIT
//! opaque — the OPAQUE augmented password-authenticated key exchange
//! (aPAKE) per RFC 9807, **ristretto255-SHA-512 configuration only**
//! (OPRF: ristretto255-SHA512 per RFC 9497, KDF: HKDF-SHA-512, MAC:
//! HMAC-SHA-512, Hash: SHA-512, KSF: pluggable, default Identity (`Ksf`
//! below), Group: ristretto255)
//! with the **3DH** key exchange (§6.4). A client registers a password
//! with a server such that the server never learns the password (not
//! even at registration) and stores only a `RegistrationRecord`; on
//! login, client and server run a 3-message AKE (`KE1`/`KE2`/`KE3`)
//! that mutually authenticates via the password and derives a shared
//! `session_key` plus a client-only `export_key` — with forward
//! secrecy and resistance to pre-computation attacks on the server's
//! credential file.
//!
//! **Status: complete** — both flows implemented and KAT-validated
//! byte-exact against RFC 9807 Appendix C.1's official OPAQUE-3DH
//! "Real" test vectors for ristretto255-SHA-512 (C.1.1 without and
//! C.1.2 with application identities; `kat_vectors.zig` /
//! `kat_test.zig`): `createRegistrationRequest` /
//! `createRegistrationResponse` / `finalizeRegistrationRequest`
//! reproduce `registration_request`/`registration_response`/
//! `registration_upload` (including the `envelope` and
//! `client_public_key` intermediates); `generateKE1`/`generateKE2`/
//! `generateKE3` reproduce `KE1`/`KE2`/`KE3`; and `export_key` +
//! `session_key` reproduce on both sides and agree. This module has
//! NO internal RNG: every nonce, blind, and keyshare seed is a
//! caller-supplied input (same discipline as the sibling `voprf`
//! module), so the KATs and callers with their own CSPRNG discipline
//! stay reproducible.
//!
//! ## Construction (RFC 9807)
//!
//! - **OPRF layer — reused from the sibling `voprf` module** (RFC 9497
//!   base OPRF mode, `modeOPRF = 0x00`, exactly what §2.1 requires):
//!   `voprf.blind`, `voprf.blindEvaluate`, `voprf.finalize`,
//!   `voprf.deriveKeyPair`, and `voprf.Element` for every group
//!   (de)serialization. Nothing OPRF-shaped is re-implemented here.
//! - **Key recovery / Envelope (§4)** — the *internal keying* mode:
//!   the envelope stores NO encrypted private key, only a nonce and an
//!   HMAC `auth_tag`; the client's AKE private key is deterministically
//!   re-derived from `randomized_password` via `Expand(...,
//!   envelope_nonce || "PrivateKey")` → `DeriveDiffieHellmanKeyPair`
//!   (§4.1.1), and the tag binds it to `server_public_key` and both
//!   identities. `Stretch` in `randomized_password` is a pluggable
//!   `Ksf` (audit finding M6): RFC 9807 §7 says the KSF "is determined
//!   by the application" (collision resistance is the only hard
//!   requirement) and its own Appendix C test vectors use Identity
//!   (`Stretch(msg) = msg`) purely for reproducibility — §7's three
//!   RECOMMENDED-absent-an-application-profile configurations all use a
//!   real KSF (two Argon2id, one scrypt). `finalizeRegistrationRequest`/
//!   `generateKE3` therefore take `ksf: Ksf` with NO default (this
//!   module has no `Allocator`/`Io` dependency anywhere else and stays
//!   that way — a real KSF like Argon2id needs both, so it lives on
//!   the CALLER's side of the `Ksf` callback, not inside this module,
//!   and it cannot pick a secure one for you): every caller states its
//!   choice explicitly, `Ksf.identity` included. See `Ksf`'s doc
//!   comment.
//! - **Registration (§5)**: blinded OPRF round + `Store` → the
//!   `RegistrationRecord` (`client_public_key`, `masking_key`,
//!   `envelope`).
//! - **Login (§6)**: credential retrieval with the `masking_key` XOR
//!   pad (`Expand(masking_key, masking_nonce ||
//!   "CredentialResponsePad")`, §6.3.2.2 — client-enumeration
//!   defense) run concurrently with the 3DH AKE: `IKM = dh1 || dh2 ||
//!   dh3` (ephemeral-ephemeral, static-ephemeral both ways), the TLS
//!   1.3-style `Expand-Label`/`Derive-Secret` schedule over
//!   `Hash(preamble)` (§6.4.2) → `Km2`/`Km3`/`session_key`, and
//!   `server_mac`/`client_mac` over the transcript.
//!
//! ## std recon (all MIT, part of Zig itself)
//!
//! - `std.crypto.kdf.hkdf.HkdfSha512` — §2.2 `Extract` (`.extract` /
//!   streaming `.extractInit`) and single-slice-`info` `Expand`
//!   (`.expand`). Multi-part `info` values (the RFC composes every
//!   `Expand` info by concatenation) go through `expandMulti`, a
//!   2-block RFC 5869 HKDF-Expand over `HmacSha512` pinned against
//!   `HkdfSha512.expand` by a test below.
//! - `std.crypto.auth.hmac.sha2.HmacSha512` — §2.2 `MAC` (the envelope
//!   `auth_tag`, `server_mac`, `client_mac`), streaming `init`/
//!   `update`/`final` plus one-shot `create`.
//! - `std.crypto.hash.sha2.Sha512` — §2.3 `Hash` (the AKE transcript).
//! - `std.crypto.ecc.Ristretto255` (via `voprf.Element`) — §6.4.1.1
//!   3DH input validation: `voprf.Element.fromBytes` is the §10.7
//!   canonical-decode + identity-rejection check on the PEER's element.
//!   The multiply itself is NOT std's: see the Security notes.
//! - `std.crypto.timing_safe.eql` — every MAC comparison (§1.2
//!   `ct_equal`): envelope `auth_tag`, `server_mac` on the client,
//!   `client_mac` on the server. All fail CLOSED to typed errors.
//!
//! ## Security notes
//!
//! - Secrets (`server_private_key`, the derived client private key,
//!   ephemeral secrets, OPRF blinds, `randomized_password` and every
//!   key expanded from it) only touch constant-time paths. HMAC and
//!   HKDF are std's. The 3DH scalar multiplication is **not** — this
//!   doc used to say `Ristretto255.mul` and that was wrong: std's `mul`
//!   is a constant-time ladder that then ends with
//!   `try q.rejectIdentity()`, a branch on a scalar-derived value, and
//!   `diffieHellman` had to `catch` it, branching on the private key a
//!   second time. It now uses the sibling `ct25519` (same ladder,
//!   trailing rejection removed, no error union). Verification MACs
//!   compare via
//!   `timing_safe.eql` and fail closed (`error.EnvelopeRecovery`,
//!   `error.ServerAuthentication`, `error.ClientAuthentication`) —
//!   never a panic. Working copies of `randomized_password`-derived
//!   material are `secureZero`ed before return where they are purely
//!   intermediate.
//! - A wrong password surfaces on the CLIENT as
//!   `error.EnvelopeRecovery` (the unmasked credentials fail the
//!   envelope auth_tag check) — before any DH with attacker-visible
//!   effect, per §6.3.2.3.
//! - Per §9.1, all previously computed intermediates are discarded on
//!   every error path (nothing escapes: results are only assembled
//!   after all checks pass).
//! - The "Fake" credential-response flow for unregistered users
//!   (§6.3.2.2) is a server-side POLICY built on this API: keep one
//!   fake `RegistrationRecord` (a randomly generated **public key** +
//!   `masking_key`, all-zero envelope) and call `generateKE2` with it;
//!   nothing extra is needed from this module. ⚠ "Randomly generated
//!   public key" is NOT 32 uniformly random bytes reinterpreted as
//!   `client_public_key` (A1/opaque.md M1: 93.754% of those are
//!   rejected by `generateKE2`'s peer-element check as
//!   `error.InvalidPublicKey`, since ristretto255 only accepts
//!   canonically-encoded points — a server that builds its one fake
//!   record that way has nothing valid to send an attacker enumerating
//!   users, which defeats the whole point of §6.3.2.2). Build it the
//!   same way any other AKE public key here is built: a random 32-byte
//!   seed through `deriveAkeKeyPair`, keeping only `.public_key`.
//!   KAT'd against RFC 9807 Appendix C.2.1 (see the "fake credential
//!   response" test below).
//!
//! Wire sizes (§2/§6.1, ristretto255-SHA-512): Nn = Nseed = 32,
//! Noe = Nok = Npk = Nsk = 32, Nh = Nm = Nx = 64; KE1 = 96, KE2 = 320,
//! KE3 = 64, RegistrationRecord = 192 bytes.

const std = @import("std");
const voprf = @import("voprf");
const ct25519 = @import("ct25519");

const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const HkdfSha512 = std.crypto.kdf.hkdf.HkdfSha512;
const timing_safe = std.crypto.timing_safe;
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "OPAQUE — an asymmetric PAKE (RFC 9807), ristretto255-SHA-512 or P256-SHA256 + 3DH — registration and login/AKE. Server compromise reveals no password.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all state is caller-held values
    .model_after = "RFC 9807 (\"The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol\"), ristretto255-SHA-512 and P256-SHA256 configurations, 3DH AKE, internal-keying Envelope (§4.1), KSF = pluggable (default Identity, see Ksf); OPRF layer = the sibling voprf module (RFC 9497 modeOPRF); std supplies HKDF-SHA-512 / HMAC-SHA-512 / SHA-512 / Ristretto255",
    .deps = .{ "voprf", "ct25519" },
};

// ── configurations (RFC 9807 §7) ──────────────────────────────────────

pub const Opaque = @import("protocol.zig").Opaque;

/// ristretto255-SHA512 / HKDF-SHA-512 / HMAC-SHA-512 / SHA-512 / ristretto255 — the
/// configuration of RFC 9807 C.1.1/C.1.2/C.2.1 and this file's top-level API.
pub const Ristretto255Sha512 = Opaque(struct {
    pub const Oprf = voprf.Ristretto255Sha512;
    pub const Hash = Sha512;
    pub const Hmac = HmacSha512;
    pub const Hkdf = HkdfSha512;
});

/// P256-SHA256 / HKDF-SHA-256 / HMAC-SHA-256 / SHA-256 / P-256 — RFC 9807 §7's
/// NIST configuration (C.1.5/C.1.6 vectors). Same function names as the top
/// level; `Npk = Noe = 33` (SEC1 compressed), `Nsk = Nok = Ns = 32`, `Nh = Nm = Nx = 32`.
pub const P256Sha256 = Opaque(struct {
    pub const Oprf = voprf.P256Sha256;
    pub const Hash = std.crypto.hash.sha2.Sha256;
    pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    pub const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
});

const Default = Ristretto255Sha512;

pub const Nn = Default.Nn;
pub const Nseed = Default.Nseed;
pub const Nh = Default.Nh;
pub const Npk = Default.Npk;
pub const Nsk = Default.Nsk;
pub const Nm = Default.Nm;
pub const Nx = Default.Nx;
pub const Nok = Default.Nok;
pub const Noe = Default.Noe;
pub const Ns = Default.Ns;
pub const masked_response_length = Default.masked_response_length;
pub const scalarFromWideBytes = Default.scalarFromWideBytes;
pub const EnvelopeRecoveryError = Default.EnvelopeRecoveryError;
pub const ServerAuthenticationError = Default.ServerAuthenticationError;
pub const ClientAuthenticationError = Default.ClientAuthenticationError;
pub const Envelope = Default.Envelope;
pub const RegistrationRequest = Default.RegistrationRequest;
pub const RegistrationResponse = Default.RegistrationResponse;
pub const RegistrationRecord = Default.RegistrationRecord;
pub const CredentialRequest = Default.CredentialRequest;
pub const CredentialResponse = Default.CredentialResponse;
pub const AuthRequest = Default.AuthRequest;
pub const KE1 = Default.KE1;
pub const AuthResponse = Default.AuthResponse;
pub const KE2 = Default.KE2;
pub const KE3 = Default.KE3;
pub const Identities = Default.Identities;
pub const AkeKeyPair = Default.AkeKeyPair;
const expandMulti = Default.expandMulti;
const i2osp2 = Default.i2osp2;
const checkIdentities = Default.checkIdentities;
pub const deriveAkeKeyPair = Default.deriveAkeKeyPair;
const deriveAkeKeyPairBody = Default.deriveAkeKeyPairBody;
const akeKeyPair = Default.akeKeyPair;
const deriveOprfKey = Default.deriveOprfKey;
const diffieHellman = Default.diffieHellman;
pub const Ksf = Default.Ksf;
const randomizedPassword = Default.randomizedPassword;
const envelopeAuthTag = Default.envelopeAuthTag;
const StoreResult = Default.StoreResult;
const store = Default.store;
const RecoverResult = Default.RecoverResult;
const recover = Default.recover;
pub const createRegistrationRequest = Default.createRegistrationRequest;
const createRegistrationRequestBody = Default.createRegistrationRequestBody;
pub const CreateRegistrationResponseError = Default.CreateRegistrationResponseError;
pub const createRegistrationResponse = Default.createRegistrationResponse;
const createRegistrationResponseBody = Default.createRegistrationResponseBody;
pub const FinalizeRegistrationError = Default.FinalizeRegistrationError;
pub const FinalizeRegistrationResult = Default.FinalizeRegistrationResult;
pub const finalizeRegistrationRequest = Default.finalizeRegistrationRequest;
const finalizeRegistrationRequestBody = Default.finalizeRegistrationRequestBody;
pub const ClientLoginState = Default.ClientLoginState;
pub const ServerLoginState = Default.ServerLoginState;
pub const GenerateKE1Error = Default.GenerateKE1Error;
pub const GenerateKE1Result = Default.GenerateKE1Result;
pub const generateKE1 = Default.generateKE1;
const generateKE1Body = Default.generateKE1Body;
pub const GenerateKE2Error = Default.GenerateKE2Error;
pub const GenerateKE2Result = Default.GenerateKE2Result;
pub const generateKE2 = Default.generateKE2;
const generateKE2Body = Default.generateKE2Body;
pub const GenerateKE3Error = Default.GenerateKE3Error;
pub const GenerateKE3Result = Default.GenerateKE3Result;
pub const generateKE3 = Default.generateKE3;
const generateKE3Body = Default.generateKE3Body;
pub const serverFinish = Default.serverFinish;
const serverFinishBody = Default.serverFinishBody;
const credentialResponsePad = Default.credentialResponsePad;
const deriveSecret = Default.deriveSecret;
const KeySchedule = Default.KeySchedule;
const runKeySchedule = Default.runKeySchedule;

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("kat_p256_test.zig");
}

// ── constant-time regression: the 3DH multiply does not report `k` ───────
//
// `diffieHellman` used to be `point.p.mul(private_key) catch return
// error.InvalidPublicKey`. std's `Ristretto255.mul` ends its constant-time
// ladder with `try q.rejectIdentity()`, so that `catch` fired on a
// condition decided entirely by the SECRET private key — and it blamed the
// PEER's public key for it, which was wrong twice over. The observable
// symptom was that a degenerate local key produced a distinct error instead
// of a group element. Restore the `.mul(...) catch ...` shape and this
// test goes red.
const shim = @import("test_shim.zig");

test "diffieHellman REPORTS NOTHING about a degenerate private key (ct25519)" {
    // A perfectly valid, non-identity peer element.
    const peer = voprf.Element.generator.toBytes();
    const shared = try diffieHellman(@as([Nsk]u8, @splat(0)), peer);
    // k = 0 => the identity, which ristretto255 encodes as 32 zero bytes.
    try std.testing.expectEqualSlices(u8, &@as([Npk]u8, @splat(0)), &shared);

    // std really does refuse this — pinning that the line above is a
    // behaviour change and not a tautology.
    const point = try voprf.Element.fromBytes(peer);
    try std.testing.expectError(error.IdentityElement, point.p.mul(@as([Nsk]u8, @splat(0))));

    // And a nonzero key still agrees with std byte-for-byte, so the swap
    // changed the leak and nothing else.
    const k = shim.scalarFromWideBytes(@as([64]u8, @splat(0x3c)));
    const want = try point.p.mul(k);
    try std.testing.expectEqualSlices(u8, &want.toBytes(), &(try diffieHellman(k, peer)));
}

test "public error sets name no variant their function cannot return (L2)" {
    // The compiler enforces the other direction: a path that returned a
    // removed variant would no longer build against the narrowed set.
    inline for (.{
        .{ CreateRegistrationResponseError, "InvalidSecretKey" },
        .{ GenerateKE2Error, "InvalidSecretKey" },
        .{ GenerateKE1Error, "InvalidBlind" },
    }) |case| {
        for (@typeInfo(case[0]).error_set.error_names.?) |e| {
            try std.testing.expect(!std.mem.eql(u8, e, case[1]));
        }
    }
    // Control: `InvalidBlind` stays where `voprf.finalize` can return it.
    inline for (.{ FinalizeRegistrationError, GenerateKE3Error }) |set| {
        var found = false;
        for (@typeInfo(set).error_set.error_names.?) |e| {
            if (std.mem.eql(u8, e, "InvalidBlind")) found = true;
        }
        try std.testing.expect(found);
    }
}

test "wire sizes match RFC 9807 §6.1 (ristretto255-SHA-512)" {
    try std.testing.expectEqual(@as(usize, 96), Envelope.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), RegistrationRequest.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), RegistrationResponse.encoded_length);
    try std.testing.expectEqual(@as(usize, 192), RegistrationRecord.encoded_length);
    try std.testing.expectEqual(@as(usize, 192), CredentialResponse.encoded_length);
    try std.testing.expectEqual(@as(usize, 96), KE1.encoded_length);
    try std.testing.expectEqual(@as(usize, 320), KE2.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), KE3.encoded_length);
    try std.testing.expectEqual(@as(usize, 128), masked_response_length);
}

test "expandMulti agrees with std HkdfSha512.expand" {
    const prk = HkdfSha512.extract("salt", "initial keying material");
    inline for ([_]usize{ 1, 32, 64, 65, 100, 128 }) |len| {
        var got: [len]u8 = undefined;
        expandMulti(&got, &prk, &.{ "cred-id", "OprfKey" });
        var want: [len]u8 = undefined;
        HkdfSha512.expand(&want, "cred-id" ++ "OprfKey", prk);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

// ── fuzz: untrusted-wire decoders never panic/OOB on arbitrary bytes ──────
//
// KE1/KE2/CredentialResponse.fromBytes take a compile-time-fixed-size
// array (no length ambiguity — the caller/transport layer is responsible
// for having exactly `encoded_length` bytes) and do plain field slicing
// with no cryptographic validation of their own, so there is no "too
// short" case to construct; fuzzing still exercises the full byte-value
// space of that fixed layout end-to-end (round-trip through toBytes).

fn fuzzKE1Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [KE1.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const ke1 = KE1.fromBytes(buf);
    _ = ke1.toBytes();
}
test "fuzz KE1.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzKE1Decode, .{});
}

fn fuzzKE2Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [KE2.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const ke2 = KE2.fromBytes(buf);
    _ = ke2.toBytes();
}
test "fuzz KE2.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzKE2Decode, .{});
}

fn fuzzCredentialResponseDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [CredentialResponse.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const cr = CredentialResponse.fromBytes(buf);
    _ = cr.toBytes();
}
test "fuzz CredentialResponse.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzCredentialResponseDecode, .{});
}

test "record and message serialization round-trips" {
    var bytes: [KE2.encoded_length]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    const ke2 = KE2.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &ke2.toBytes());
    const record = RegistrationRecord.fromBytes(bytes[0..RegistrationRecord.encoded_length].*);
    try std.testing.expectEqualSlices(
        u8,
        bytes[0..RegistrationRecord.encoded_length],
        &record.toBytes(),
    );
    const ke1 = KE1.fromBytes(bytes[0..KE1.encoded_length].*);
    try std.testing.expectEqualSlices(u8, bytes[0..KE1.encoded_length], &ke1.toBytes());
}

// ── fuzz + hostile-wire tests: the functions that VALIDATE, not just decode ──
//
// A1/opaque.md M4: the three harnesses above exercise `fromBytes`, which is
// plain field slicing with nothing to reject — every input is "valid". The
// functions where a hostile peer's bytes actually get checked
// (`createRegistrationResponse`, `generateKE2`, `generateKE3` — each starts
// from attacker-controlled wire bytes and calls into peer-element
// validation) had no fuzz target and no direct hostile-input test at all.
// Configuration (keys, seeds, context) is pinned to a real KAT vector so the
// only untrusted input is the wire message itself, same shape as the
// `fromBytes` harnesses above.
const kat_vectors = @import("kat_vectors.zig");

fn fuzzCreateRegistrationResponseOnHostileRequest(_: void, smith: *std.testing.Smith) !void {
    const v = kat_vectors.real_1;
    var buf: [RegistrationRequest.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const request = RegistrationRequest.fromBytes(buf);
    if (shim.createRegistrationResponse(request, v.server_public_key, v.credential_identifier, v.oprf_seed)) |r| {
        std.mem.doNotOptimizeAway(&r);
    } else |_| {}
}
test "fuzz createRegistrationResponse never panics on a hostile RegistrationRequest" {
    try std.testing.fuzz({}, fuzzCreateRegistrationResponseOnHostileRequest, .{});
}

fn fuzzGenerateKE2OnHostileKE1(_: void, smith: *std.testing.Smith) !void {
    const v = kat_vectors.real_1;
    const record = RegistrationRecord.fromBytes(v.registration_upload);
    var buf: [KE1.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const ke1 = KE1.fromBytes(buf);
    if (shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        ke1,
        .{},
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    )) |r| {
        std.mem.doNotOptimizeAway(&r);
    } else |_| {}
}
test "fuzz generateKE2 never panics on a hostile KE1" {
    try std.testing.fuzz({}, fuzzGenerateKE2OnHostileKE1, .{});
}

fn fuzzGenerateKE3OnHostileKE2(_: void, smith: *std.testing.Smith) !void {
    const v = kat_vectors.real_1;
    const login = shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed) catch return;
    var buf: [KE2.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const ke2 = KE2.fromBytes(buf);
    if (shim.generateKE3(login.state, .{}, v.context, ke2, .identity)) |r| {
        std.mem.doNotOptimizeAway(&r);
    } else |_| {}
}
test "fuzz generateKE3 never panics on a hostile KE2" {
    try std.testing.fuzz({}, fuzzGenerateKE3OnHostileKE2, .{});
}

// The fuzz harnesses above run once (no `--fuzz`) on an all-zero input,
// which decodes as the identity element — a *valid* canonical encoding — so
// a single default run never reaches the rejection branch. These three are
// deterministic instead: each hands the validating function one concrete
// non-canonical 32-byte string (0xFF x 32, confirmed below to be outside the
// canonical range) inside an otherwise-real KAT flow, and checks that the
// function's own typed error — not a panic, not a silent accept — is what
// comes back.

test "M4: createRegistrationResponse rejects a non-canonical blinded_message" {
    const v = kat_vectors.real_1;
    const request = RegistrationRequest{ .blinded_message = @as([32]u8, @splat(0xFF)) };
    try std.testing.expectError(
        error.InvalidMessage,
        shim.createRegistrationResponse(request, v.server_public_key, v.credential_identifier, v.oprf_seed),
    );
}

test "M4: generateKE2 rejects a non-canonical blinded_message in a hostile KE1" {
    const v = kat_vectors.real_1;
    const record = RegistrationRecord.fromBytes(v.registration_upload);
    var login = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    login.ke1.credential_request.blinded_message = @as([32]u8, @splat(0xFF));
    try std.testing.expectError(error.InvalidMessage, shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        login.ke1,
        .{},
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    ));
}

test "M4: generateKE3 rejects a non-canonical server_public_keyshare in a hostile KE2" {
    const v = kat_vectors.real_1;
    const record = RegistrationRecord.fromBytes(v.registration_upload);
    const login = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    var ke2 = (try shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        login.ke1,
        .{},
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    )).ke2;
    ke2.auth_response.server_public_keyshare = @as([32]u8, @splat(0xFF));
    try std.testing.expectError(
        error.InvalidPublicKey,
        shim.generateKE3(login.state, .{}, v.context, ke2, .identity),
    );
}

// ── audit L4: an INDEPENDENT construction of the AKE preamble ────────────
//
// L4's finding: every one of the seven pieces `runKeySchedule` streams
// into the transcript hash (context, client_identity, KE1,
// server_identity, credential_response, server_nonce,
// server_public_keyshare) is checked ONLY by the RFC KAT above -- a
// mutation that drops or reorders any one of them is invisible to the
// live end-to-end tests, because both the client and the server call
// the SAME `runKeySchedule`, so a bug there is self-consistent (the
// handshake still completes, just not to an RFC-conformant value).
// RFC 9807 does not publish "preamble" as a named vector field (it is
// never materialized as a discrete byte string, only streamed into a
// hash), so closing this means literally re-deriving §6.3.3's formula
// by hand from the RFC text and checking it against a value the RFC
// DOES publish directly: `handshake_secret`.
//
// `independentHandshakeSecret` below shares NO code with
// `runKeySchedule`/`deriveSecret`/`expandMulti`/`i2osp2` -- it is a
// second, separately-written implementation of RFC 9807 §6.3.3's
// `Preamble` and the `DeriveKeys`/`Derive-Secret` half of §6.4.2.2 that
// produces `handshake_secret`, built directly from `std.crypto.hash.
// sha2.Sha512` and `std.crypto.kdf.hkdf.HkdfSha512.extract`/`.expand`
// (trusted primitives, not what is in dispute) with its own I2OSP-2 and
// TLS-1.3-style CustomLabel encoding, copied from the RFC text quoted
// in this test, not from `root.zig`'s own doc comments elsewhere.
//
// What IS reused, deliberately: `ikm = dh1 ++ dh2 ++ dh3` is computed
// with the SAME private helpers (`recover`, `diffieHellman`,
// `randomizedPassword`, `expandMulti` for `masking_key`) `generateKE3`
// itself calls -- ristretto255 DH and envelope recovery are NOT what L4
// disputes (they are covered elsewhere: C3/C4 in the audit, H2's
// zeroization work), and reimplementing them independently here would
// be exactly the "rushed, uncertain result" this pass was told to avoid.
// `client_secret` and `ke1` come from a real `generateKE1` call (already
// pinned byte-exact against `v.ke1` by the KAT test above), and
// `credential_response`/`server_nonce`/`server_public_keyshare` are
// sliced directly out of the RFC's own published `v.ke2` bytes -- this
// test never calls `generateKE2` at all.
fn independentHandshakeSecret(
    ikm: []const u8,
    context: []const u8,
    client_identity: []const u8,
    server_identity: []const u8,
    ke1_bytes: []const u8,
    credential_response_bytes: []const u8,
    server_nonce: []const u8,
    server_public_keyshare: []const u8,
) [64]u8 {
    // RFC 9807 §6.3.3, quoted:
    //   preamble = concat("OPAQUEv1-",
    //                      I2OSP(len(context), 2), context,
    //                      I2OSP(len(client_identity), 2), client_identity,
    //                      ke1,
    //                      I2OSP(len(server_identity), 2), server_identity,
    //                      credential_response,
    //                      server_nonce,
    //                      server_public_keyshare)
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update("OPAQUEv1-");
    var len2: [2]u8 = undefined;
    std.mem.writeInt(u16, &len2, @intCast(context.len), .big);
    h.update(&len2);
    h.update(context);
    std.mem.writeInt(u16, &len2, @intCast(client_identity.len), .big);
    h.update(&len2);
    h.update(client_identity);
    h.update(ke1_bytes);
    std.mem.writeInt(u16, &len2, @intCast(server_identity.len), .big);
    h.update(&len2);
    h.update(server_identity);
    h.update(credential_response_bytes);
    h.update(server_nonce);
    h.update(server_public_keyshare);
    var preamble_hash: [64]u8 = undefined;
    h.final(&preamble_hash);

    // RFC 9807 §6.4.2.1, quoted:
    //   Derive-Secret(Secret, Label, Transcript-Hash) =
    //       Expand-Label(Secret, Label, Transcript-Hash, Nx)
    //   CustomLabel = I2OSP(Nx, 2) ||
    //                 I2OSP(len("OPAQUE-" || Label), 1) ||
    //                 "OPAQUE-" || Label ||
    //                 I2OSP(len(Context), 1) || Context
    // and §6.4.2.2:
    //   prk = Extract("", ikm)
    //   handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    const prk = std.crypto.kdf.hkdf.HkdfSha512.extract("", ikm);
    const full_label = "OPAQUE-HandshakeSecret";
    var info: [2 + 1 + full_label.len + 1 + 64]u8 = undefined;
    var w: usize = 0;
    std.mem.writeInt(u16, info[w..][0..2], 64, .big);
    w += 2;
    info[w] = full_label.len;
    w += 1;
    @memcpy(info[w..][0..full_label.len], full_label);
    w += full_label.len;
    info[w] = preamble_hash.len;
    w += 1;
    @memcpy(info[w..][0..preamble_hash.len], &preamble_hash);
    w += preamble_hash.len;

    var out: [64]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha512.expand(&out, info[0..w], prk);
    return out;
}

test "audit L4: an independent §6.3.3 preamble construction reproduces C.1.1/C.1.2's published handshake_secret" {
    for ([_]kat_vectors.RealVector{ kat_vectors.real_1, kat_vectors.real_2 }) |v| {
        // Real, RFC-pinned client ephemeral keyshare + KE1 -- reused, not
        // reimplemented (already checked byte-exact against v.ke1 above).
        const login = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);

        // credential_response / server_nonce / server_public_keyshare come
        // straight out of the RFC's OWN published KE2 bytes -- this test
        // never calls generateKE2.
        const ke2 = KE2.fromBytes(v.ke2);

        // Reused (not the disputed logic): unmask + recover the envelope,
        // exactly what `generateKE3` itself does, to get a real
        // client_private_key for dh3.
        var rp = try randomizedPassword(v.password, v.blind_login, ke2.credential_response.evaluated_message, .identity);
        defer std.crypto.secureZero(u8, &rp);
        var masking_key: [Nh]u8 = undefined;
        defer std.crypto.secureZero(u8, &masking_key);
        expandMulti(&masking_key, &rp, &.{"MaskingKey"});
        var plaintext = credentialResponsePad(&masking_key, ke2.credential_response.masking_nonce);
        for (&plaintext, ke2.credential_response.masked_response) |*b, m| b.* ^= m;
        const server_public_key: [Npk]u8 = plaintext[0..Npk].*;
        const envelope = Envelope.fromBytes(plaintext[Npk..].*);
        const identities: Identities = .{ .client = v.client_identity, .server = v.server_identity };
        var credentials = try recover(&rp, server_public_key, envelope, identities);
        defer std.crypto.secureZero(u8, &credentials.client_private_key);

        // ikm = dh1 ++ dh2 ++ dh3 -- the SAME three DH calls generateKE3
        // makes. NOT the disputed logic (covered by C3/C4 elsewhere).
        const dh1 = try diffieHellman(login.state.client_secret, ke2.auth_response.server_public_keyshare);
        const dh2 = try diffieHellman(login.state.client_secret, server_public_key);
        const dh3 = try diffieHellman(credentials.client_private_key, ke2.auth_response.server_public_keyshare);
        var ikm = dh1 ++ dh2 ++ dh3;
        defer std.crypto.secureZero(u8, &ikm);

        const client_identity = v.client_identity orelse &credentials.client_public_key;
        const server_identity = v.server_identity orelse &server_public_key;
        const cr_bytes = ke2.credential_response.toBytes();

        // THE independent part: my own Preamble + Derive-Secret, sharing
        // no code with runKeySchedule/deriveSecret/expandMulti/i2osp2.
        const got = independentHandshakeSecret(
            &ikm,
            v.context,
            client_identity,
            server_identity,
            &v.ke1,
            &cr_bytes,
            &ke2.auth_response.server_nonce,
            &ke2.auth_response.server_public_keyshare,
        );
        try std.testing.expectEqualSlices(u8, &v.handshake_secret, &got);
    }
}

test "audit L4: the independent preamble construction is NOT a silent no-op -- dropping any one of the seven pieces changes handshake_secret" {
    // A companion to the test above: proves `independentHandshakeSecret`
    // itself has teeth (each of the seven concatenated pieces is
    // load-bearing), the same way the campaign requires a positive
    // control for every mutation-style claim. Without this, a version of
    // `independentHandshakeSecret` that ignored `server_nonce` entirely
    // could still pass the test above by coincidence... except it
    // couldn't (SHA-512 is not that coincidental), which is exactly what
    // this proves rather than assumes.
    const v = kat_vectors.real_1;
    const login = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const ke2 = KE2.fromBytes(v.ke2);
    var rp = try randomizedPassword(v.password, v.blind_login, ke2.credential_response.evaluated_message, .identity);
    defer std.crypto.secureZero(u8, &rp);
    var masking_key: [Nh]u8 = undefined;
    defer std.crypto.secureZero(u8, &masking_key);
    expandMulti(&masking_key, &rp, &.{"MaskingKey"});
    var plaintext = credentialResponsePad(&masking_key, ke2.credential_response.masking_nonce);
    for (&plaintext, ke2.credential_response.masked_response) |*b, m| b.* ^= m;
    const server_public_key: [Npk]u8 = plaintext[0..Npk].*;
    const envelope = Envelope.fromBytes(plaintext[Npk..].*);
    var credentials = try recover(&rp, server_public_key, envelope, .{});
    defer std.crypto.secureZero(u8, &credentials.client_private_key);
    const dh1 = try diffieHellman(login.state.client_secret, ke2.auth_response.server_public_keyshare);
    const dh2 = try diffieHellman(login.state.client_secret, server_public_key);
    const dh3 = try diffieHellman(credentials.client_private_key, ke2.auth_response.server_public_keyshare);
    var ikm = dh1 ++ dh2 ++ dh3;
    defer std.crypto.secureZero(u8, &ikm);
    const client_identity = v.client_identity orelse &credentials.client_public_key;
    const server_identity = v.server_identity orelse &server_public_key;
    const cr_bytes = ke2.credential_response.toBytes();

    const baseline = independentHandshakeSecret(
        &ikm,
        v.context,
        client_identity,
        server_identity,
        &v.ke1,
        &cr_bytes,
        &ke2.auth_response.server_nonce,
        &ke2.auth_response.server_public_keyshare,
    );
    try std.testing.expectEqualSlices(u8, &v.handshake_secret, &baseline);

    // Drop each of the seven pieces to empty in turn (context and the two
    // identities are already variable-length; ke1/credential_response/
    // server_nonce/server_public_keyshare are fixed-width in the real
    // protocol, but this function takes plain slices, so an empty slice
    // is a valid, distinguishing probe even though the real callers could
    // never produce one).
    const empty: []const u8 = &.{};
    inline for (.{
        "context",             "client_identity", "ke1",                    "server_identity",
        "credential_response", "server_nonce",    "server_public_keyshare",
    }) |which| {
        const mutated = independentHandshakeSecret(
            &ikm,
            if (std.mem.eql(u8, which, "context")) empty else v.context,
            if (std.mem.eql(u8, which, "client_identity")) empty else client_identity,
            if (std.mem.eql(u8, which, "server_identity")) empty else server_identity,
            if (std.mem.eql(u8, which, "ke1")) empty else &v.ke1,
            if (std.mem.eql(u8, which, "credential_response")) empty else &cr_bytes,
            if (std.mem.eql(u8, which, "server_nonce")) empty else &ke2.auth_response.server_nonce,
            if (std.mem.eql(u8, which, "server_public_keyshare")) empty else &ke2.auth_response.server_public_keyshare,
        );
        if (std.mem.eql(u8, &mutated, &v.handshake_secret)) {
            std.debug.print("dropping '{s}' did not change handshake_secret\n", .{which});
            return error.PieceNotLoadBearing;
        }
    }
}
